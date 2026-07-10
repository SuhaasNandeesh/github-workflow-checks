import json
import os
import re
import urllib.error
import urllib.request

try:
    from ruamel.yaml.scalarstring import FoldedScalarString
except ImportError:
    FoldedScalarString = None

from logging_setup import get_logger
from copilot_client import SSLCertificateError

logger = get_logger()


# Permission widening: maps (workflow-level, job-level) to True when
# the job-level value is strictly wider than the workflow-level default.
_PERMISSION_WIDENING: dict[tuple[str, str], bool] = {
    ("read", "write"): True,
    ("none", "read"): True,
    ("none", "write"): True,
}
# "write" at workflow level means job can't widen further (it's already max),
# and "read" at both levels is not widening.

# First-party action org prefixes — considered trusted for the
# token-passed-to-third-party rule. Editable via rules_config["trusted_action_orgs"].
_DEFAULT_TRUSTED_ORGS = (
    "actions/", "github/", "azure/", "aws-actions/", "google-github-actions/",
)

# Run-line regexes for credential literals (secret-in-run-literal). Tunable.
_SECRET_LITERAL_PATTERNS = [
    # AWS access key id (long) + secret (40 base64 after AWS secret prefix is not unique;
    # we look for the documented AKIA... access key id and typical secret assignments).
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    # Generic password/secret/key assignments with a non-placeholder value.
    re.compile(r'(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|token)\b\s*[=:]\s*["\']?[^\s"\']{8,}'),
    # -----BEGIN PRIVATE KEY-----
    re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
]

# Expression interpolation directly in run: scripts (expression-in-run-injection).
_RUNEXPR_RE = re.compile(r'\$\{\{\s*[^}]*\s*\}\}')


class StaticAnalyzer:
    def __init__(self, rules_config=None, token: str | None = None,
                 endpoint: str | None = None, api_endpoint: str | None = None,
                 sha_cache_path: str | None = None):
        self.rules_config = rules_config or {}
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("COPILOT_TOKEN")
        # GitHub API endpoint for action SHA resolution. Defaults: GHES endpoint
        # if provided, else api.github.com.
        cfg_endpoint = self.rules_config.get("endpoint") if isinstance(self.rules_config, dict) else None
        cfg_api = self.rules_config.get("api_endpoint") if isinstance(self.rules_config, dict) else None
        self.endpoint = (
            api_endpoint or cfg_api or endpoint or cfg_endpoint or "https://api.github.com"
        ).rstrip("/")
        # Regex to match 40-character hex SHA
        self.sha_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        # Default secret pattern; overridable via rules_config["secret_keyword_pattern"].
        # No leading \b so that prefixed names like PROD_API_KEY still match the
        # API_KEY alternation; a trailing \b avoids matching KEYWORD/KEYBOARD.
        self.secret_keyword_pattern = re.compile(
            self.rules_config.get(
                "secret_keyword_pattern",
                r'(?:KEY|TOKEN|PASS|PASSWORD|SECRET|API[_-]?KEY|PAT|CRED|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)\b',
            ),
            re.IGNORECASE,
        )
        # Trusted org prefixes for token-passed-to-third-party.
        self.trusted_orgs = tuple(
            self.rules_config.get("trusted_action_orgs", _DEFAULT_TRUSTED_ORGS)
        )
        # Offline action-SHA cache: action@tag -> sha (or None on confirmed miss).
        self._sha_cache: dict[str, str | None] = {}
        self._sha_cache_dirty = False
        self._sha_cache_path = (
            sha_cache_path
            or (self.rules_config.get("sha_cache_path") if isinstance(self.rules_config, dict) else None)
            or "actions-sha-cache.json"
        )
        self._load_sha_cache()
        # Workflow scope cache per analyze_workflow call.
        self._scope: set[str] = set()

    def analyze_workflow(self, filepath, raw_data):
        """Runs offline static validation rules on raw parsed workflow dict."""
        findings = []

        if not raw_data:
            return findings

        self._workflow_env = raw_data.get("env", {}) if isinstance(raw_data.get("env"), dict) else {}
        # Determine workflow scope (source / image / deploy / all) for applies_to gating.
        self._scope = self._classify_workflow_scope(raw_data)

        # Run global checks
        findings.extend(self._check_dependency_cycles(raw_data))
        findings.extend(self._check_least_privilege_token(raw_data))
        findings.extend(self._check_concurrency_control(raw_data))
        findings.extend(self._check_unresolved_needs(raw_data))
        findings.extend(self._check_oidc_cloud_deploy(raw_data))

        jobs = raw_data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                findings.extend(self._check_job_artifacts_transfer(job_id, job_data, jobs))
                findings.extend(self._check_runner_shell_misalignment(job_id, job_data))
                findings.extend(self._check_job_permissions_escalation(job_id, job_data, raw_data))
                findings.extend(self._check_runner_version_pinned(job_id, job_data))
                findings.extend(self._check_job_timeout(job_id, job_data))
                findings.extend(self._check_reusable_workflow_job(job_id, job_data))

                steps = job_data.get("steps", [])
                if isinstance(steps, list):
                    for idx, step in enumerate(steps):
                        if not isinstance(step, dict):
                            continue
                        findings.extend(self._check_step_action_pinning(job_id, idx, step))
                        findings.extend(self._check_residual_gitlab_vars(job_id, idx, step))
                        findings.extend(self._check_unbound_secrets(job_id, job_data, idx, step))
                        findings.extend(self._check_multiline_block_scalar(job_id, idx, step))
                        findings.extend(self._check_enterprise_security_gates(job_id, idx, step))
                        findings.extend(self._check_checkout_persist_credentials(job_id, idx, step))
                        findings.extend(self._check_step_timeout(job_id, idx, step))
                        findings.extend(self._check_latest_runtime_version(job_id, idx, step))
                        findings.extend(self._check_deprecated_set_output(job_id, idx, step))
                        findings.extend(self._check_untrusted_input_injection(job_id, idx, step))
                        findings.extend(self._check_submodule_recursive(job_id, idx, step))
                        findings.extend(self._check_secret_in_run_literal(job_id, idx, step))
                        findings.extend(self._check_secret_echoed_in_logs(job_id, idx, step))
                        findings.extend(self._check_expression_in_run_injection(job_id, idx, step))
                        findings.extend(self._check_missing_set_x_pipefail(job_id, idx, step))

                findings.extend(self._check_always_deploy_after_failure(job_id, job_data, jobs))
                findings.extend(self._check_environment_protection(job_id, job_data))
                findings.extend(self._check_matrix_fail_fast(job_id, job_data))

        # Check global workflow-level security gates
        findings.extend(self._check_global_security_gates(raw_data))
        findings.extend(self._check_pull_request_target_danger(raw_data))
        findings.extend(self._check_self_hosted_runner(raw_data))
        findings.extend(self._check_docker_action_digest_pin(raw_data))
        findings.extend(self._check_token_passed_to_third_party(raw_data))

        return findings

    def _check_step_action_pinning(self, job_id, step_idx, step):
        uses_val = step.get("uses")
        if not uses_val or not isinstance(uses_val, str):
            return []

        # Local actions start with './' or relative paths, skip them
        if uses_val.startswith("./") or uses_val.startswith("../"):
            return []

        # Docker/Docker Hub actions e.g. docker://alpine are handled by the
        # docker-action-digest-pin rule instead.
        if uses_val.startswith("docker://"):
            return []

        if "@" not in uses_val:
            return [{
                "rule": "pin-action-sha",
                "location": f"jobs.{job_id}.steps[{step_idx}]",
                "message": f"Action '{uses_val}' does not specify a version or commit SHA ref.",
                "original": uses_val
            }]

        parts = uses_val.split("@")
        action_ref = parts[0]
        ref = parts[1]

        if not self.sha_pattern.match(ref):
            return [{
                "rule": "pin-action-sha",
                "location": f"jobs.{job_id}.steps[{step_idx}]",
                "message": f"Action '{action_ref}' is pinned to tag/branch '{ref}' instead of an immutable commit SHA.",
                "original": uses_val
            }]

        return []

    def _rule_applies(self, rule_id: str) -> bool:
        """Check a rule's applies_to against the current workflow scope (Phase 5)."""
        rule_info = self.rules_config.get("rules", {}).get(rule_id) if isinstance(self.rules_config, dict) else None
        if not isinstance(rule_info, dict):
            return True
        applies = rule_info.get("applies_to", ["all"])
        if not isinstance(applies, list) or not applies:
            return True
        if "all" in applies:
            return True
        return any(s in applies for s in self._scope)

    def _classify_workflow_scope(self, raw_data) -> set[str]:
        """Classify a workflow as source / image / deploy based on its contents."""
        scopes: set[str] = {"all"}
        jobs = raw_data.get("jobs", {})
        all_steps = []
        if isinstance(jobs, dict):
            for job_data in jobs.values():
                if isinstance(job_data, dict):
                    steps = job_data.get("steps", [])
                    if isinstance(steps, list):
                        all_steps.extend(s for s in steps if isinstance(s, dict))

        uses_list = [s.get("uses", "") for s in all_steps if isinstance(s.get("uses"), str)]
        run_scripts = _strip_noise(" ".join(
            str(s.get("run", "")) for s in all_steps if s.get("run")
        ))

        is_image = (
            "docker build" in run_scripts
            or "docker push" in run_scripts
            or "docker buildx" in run_scripts
            or "kaniko" in run_scripts
            or "buildah" in run_scripts
            or any("docker" in u.lower() for u in uses_list if isinstance(u, str))
            or "jf docker push" in run_scripts
            or "jf rt docker-push" in run_scripts
        )
        if is_image:
            scopes.add("image")

        # Source-bearing workflows: have a checkout, build tooling, or test runner.
        has_source = (
            any("actions/checkout" in u for u in uses_list)
            or "npm ci" in run_scripts or "npm run build" in run_scripts
            or "mvn " in run_scripts or "gradle" in run_scripts
            or "dotnet build" in run_scripts or "dotnet test" in run_scripts
            or "go build" in run_scripts or "go test" in run_scripts
            or "pip install" in run_scripts or "pytest" in run_scripts
            or "make" in run_scripts
        )
        if has_source:
            scopes.add("source")

        # Deploy workflows: name/trigger/keyword heuristics.
        name = (raw_data.get("name") or "").lower()
        triggers = raw_data.get("on")
        trigger_names: list[str] = []
        if isinstance(triggers, dict):
            trigger_names = [k.lower() for k in triggers.keys()]
        elif isinstance(triggers, str):
            trigger_names = [triggers.lower()]
        elif isinstance(triggers, list):
            trigger_names = [t.lower() for t in triggers if isinstance(t, str)]
        is_deploy = (
            "deploy" in name or "publish" in name or "release" in name
            or any(t in ("deployment", "release", "publish") for t in trigger_names)
            or "deploy" in run_scripts or "kubectl apply" in run_scripts
            or "helm upgrade" in run_scripts or "terraform apply" in run_scripts
        )
        if is_deploy:
            scopes.add("deploy")

        return scopes

    def _load_sha_cache(self) -> None:
        try:
            with open(self._sha_cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._sha_cache = {k: v for k, v in data.items() if v is None or (isinstance(v, str) and self.sha_pattern.match(v))}
        except (OSError, json.JSONDecodeError):
            self._sha_cache = {}

    def persist_sha_cache(self) -> None:
        """Flush the in-memory SHA cache to disk so it can be reused offline."""
        if not self._sha_cache_dirty:
            return
        try:
            tmp = self._sha_cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._sha_cache, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._sha_cache_path)
            self._sha_cache_dirty = False
        except OSError as e:
            logger.debug("Could not persist SHA cache to %s: %s", self._sha_cache_path, e)

    def _check_residual_gitlab_vars(self, job_id, step_idx, step):
        findings = []
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []

        # Word-boundary-aware: capture $CI_FOO or ${CI_FOO} but not
        # $CI_FOO_BACKUP or other tokens that share a prefix.
        for match in re.finditer(r"\$\{?CI_[A-Za-z0-9_]+\}?(?![A-Za-z0-9_])", run_val):
            token = match.group(0)
            findings.append({
                "rule": "residual-gitlab-vars",
                "location": f"jobs.{job_id}.steps[{step_idx}]",
                "message": f"Shell step contains residual GitLab CI variable reference '{token}'.",
                "original": token,
            })
        return findings

    def _check_unbound_secrets(self, job_id, job_data, step_idx, step):
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []

        findings = []
        # Distinguish between GitHub context vars (github.*, runner.*, env.*,
        # secrets.*, matrix.*, inputs.*) and arbitrary shell variables.
        shell_vars = re.findall(r'\$([A-Za-z0-9_]+)|\$\{([A-Za-z0-9_]+)\}', run_val)
        variables_used = set([v[0] or v[1] for v in shell_vars if v[0] or v[1]])

        # Filter for variables matching the secret keyword pattern.
        suspicious_vars = [
            v for v in variables_used
            if self.secret_keyword_pattern.search(v) and not self._is_context_var(v)
        ]

        # Collect all bound environment variables in scope (step-level + job-level + global env)
        bound_env: set[str] = set()

        step_env = step.get("env")
        if isinstance(step_env, dict):
            bound_env.update(step_env.keys())
        job_env = job_data.get("env")
        if isinstance(job_env, dict):
            bound_env.update(job_env.keys())

        if isinstance(getattr(self, '_workflow_env', None), dict):
            bound_env.update(self._workflow_env)

        # GITHUB_TOKEN is auto-injected by the runner; only flag if a job-level
        # permission scope has not been verified (A7). The job-level permission
        # check is performed separately; here we skip the variable name.
        for var in suspicious_vars:
            if var == "GITHUB_TOKEN":
                continue
            if var not in bound_env:
                findings.append({
                    "rule": "unbound-secrets",
                    "location": f"jobs.{job_id}.steps[{step_idx}]",
                    "message": (
                        f"Shell step references credentials variable '${var}' "
                        "which is not explicitly bound in 'env' parameters."
                    ),
                    "original": var,
                })
        return findings

    @staticmethod
    def _is_context_var(name: str) -> bool:
        """Return True if the name refers to a GitHub Actions context expression."""
        if "." in name:
            return True
        return name in {
            "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_SUMMARY",
            "GITHUB_STEP_SUMMARY", "GITHUB_TOKEN", "RUNNER_OS", "RUNNER_TEMP",
            "RUNNER_DEBUG", "CI",
        }

    def _check_runner_shell_misalignment(self, job_id, job_data):
        """Bidirectional shell/runner mismatch detection (B9).

        Flags:
        - Linux commands (grep, sed, etc.) on Windows without shell: bash
        - PowerShell cmdlets on macOS/Linux without shell: pwsh
        - Windows-only commands on non-Windows runners
        """
        runs_on = job_data.get("runs-on", "")
        runner_str = ""
        if isinstance(runs_on, str):
            runner_str = runs_on.lower()
        elif isinstance(runs_on, list):
            runner_str = " ".join(str(t).lower() for t in runs_on if isinstance(t, str))

        is_windows = "windows" in runner_str or "win" in runner_str
        is_macos   = "macos" in runner_str or "mac" in runner_str
        is_linux   = ("ubuntu" in runner_str or "linux" in runner_str or
                      "debian" in runner_str or "centos" in runner_str)
        is_non_windows = is_macos or is_linux

        if not is_windows and not is_non_windows:
            return []

        findings = []
        steps = job_data.get("steps", [])
        if not isinstance(steps, list):
            return findings

        for idx, step in enumerate(steps):
            if not isinstance(step, dict) or "run" not in step:
                continue
            shell = step.get("shell")
            run_cmd = step["run"]

            if is_windows and not shell:
                # Windows default is pwsh/cmd — flag Linux utilities without shell: bash
                linux_cmds = ["grep", "sed", "awk", "export", "rm -rf", "mkdir -p", "tar", "zip"]
                found = [c for c in linux_cmds if c in run_cmd]
                if found:
                    findings.append({
                        "rule": "runner-shell-misalignment",
                        "location": f"jobs.{job_id}.steps[{idx}]",
                        "message": f"Job runs on Windows, but step uses Linux commands {found} without setting 'shell: bash'.",
                        "original": run_cmd,
                    })

            if is_macos and not shell:
                # macOS default is zsh — flag PowerShell cmdlets and Windows-only commands.
                pwsh_cmds = [
                    "Get-ChildItem", "Select-Object", "ForEach-Object",
                    "Where-Object", "Set-Item", "New-Item", "Remove-Item",
                    "Write-Output", "Invoke-WebRequest", "Get-Content",
                ]
                win_cmds = ["powershell.exe", "cmd.exe", "winget", "msiexec"]
                found_pwsh = [c for c in pwsh_cmds if c in run_cmd]
                found_win  = [c for c in win_cmds  if c.lower() in run_cmd.lower()]
                all_found  = found_pwsh + found_win
                if all_found:
                    findings.append({
                        "rule": "runner-shell-misalignment",
                        "location": f"jobs.{job_id}.steps[{idx}]",
                        "message": f"Job runs on macOS, but step uses Windows/PowerShell commands {all_found} without setting the correct shell.",
                        "original": run_cmd,
                    })

        return findings

    def _check_runner_version_pinned(self, job_id, job_data):
        """Flag runs-on using 'latest' instead of a pinned version."""
        runs_on = job_data.get("runs-on", "")
        runner_str = ""
        if isinstance(runs_on, str):
            runner_str = runs_on.lower()
        elif isinstance(runs_on, list):
            runner_str = " ".join(str(t).lower() for t in runs_on if isinstance(t, str))
        if "latest" in runner_str:
            return [{
                "rule": "runner-version-pinned",
                "location": f"jobs.{job_id}",
                "message": f"Job '{job_id}' uses 'runs-on: latest' which is non-reproducible. Pin to a specific version.",
                "original": str(runs_on),
            }]
        return []

    def _check_multiline_block_scalar(self, job_id, step_idx, step):
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str) or '\n' not in run_val:
            return []

        # Check if the ruamel.yaml string is loaded as FoldedScalarString (representing > indicator)
        if FoldedScalarString and isinstance(run_val, FoldedScalarString):
            return [{
                "rule": "multiline-block-scalar",
                "location": f"jobs.{job_id}.steps[{step_idx}]",
                "message": "Multi-line run command is using folded block scalar (>) which collapses newlines, instead of literal block scalar (|).",
                "original": "> folded scalar"
            }]
        return []

    def _check_least_privilege_token(self, raw_data):
        permissions = raw_data.get("permissions")
        if permissions is None:
            return [{
                "rule": "least-privilege-token",
                "location": "workflow.permissions",
                "message": "Workflow does not declare explicit GITHUB_TOKEN permissions. Set default to read-only or empty 'permissions: {}' at the top-level.",
                "original": "missing"
            }]
        
        # If permissions block exists, check if it defaults to write-all
        if isinstance(permissions, str) and permissions == "write-all":
            return [{
                "rule": "least-privilege-token",
                "location": "workflow.permissions",
                "message": "Workflow permissions are explicitly set to 'write-all'. Enforce least privilege.",
                "original": "write-all"
            }]
        return []

    def _check_job_permissions_escalation(self, job_id, job_data, raw_data):
        """Detect if a job-level permissions block widens the workflow-level default.

        When a workflow declares `permissions: { contents: read }` and a job
        declares `permissions: { contents: write, issues: read }`, the job
        silently re-widens the scope, violating the least-privilege intent (A6).
        """
        workflow_perms = raw_data.get("permissions")
        if not isinstance(workflow_perms, dict):
            return []
        job_perms = job_data.get("permissions")
        if not isinstance(job_perms, dict):
            return []

        findings = []
        for scope, job_value in job_perms.items():
            workflow_value = workflow_perms.get(scope)
            if workflow_value is None:
                # Job declares a scope not declared at workflow level — escalation
                findings.append({
                    "rule": "job-permission-escalation",
                    "location": f"jobs.{job_id}.permissions",
                    "message": (
                        f"Job '{job_id}' grants '{scope}: {job_value}' which is not "
                        f"declared in the workflow-level permissions (defaulting to none). "
                        "Either add it to the workflow-level block with the intended value, "
                        "or remove it from the job to inherit the restrictive default."
                    ),
                    "original": f"{scope}: {job_value}",
                })
            elif _PERMISSION_WIDENING.get((workflow_value, job_value)):
                findings.append({
                    "rule": "job-permission-escalation",
                    "location": f"jobs.{job_id}.permissions",
                    "message": (
                        f"Job '{job_id}' widens '{scope}' from workflow-level "
                        f"'{workflow_value}' to job-level '{job_value}'."
                    ),
                    "original": f"{scope}: {workflow_value} -> {job_value}",
                })
        return findings

    def _check_concurrency_control(self, raw_data):
        # Deployment or publication workflows should define concurrency
        name = raw_data.get("name", "").lower()
        triggers = raw_data.get("on") or raw_data.get(True) or {}
        trigger_names = []
        if isinstance(triggers, dict):
            trigger_names = [k.lower() for k in triggers.keys()]
        elif isinstance(triggers, str):
            trigger_names = [triggers.lower()]
        elif isinstance(triggers, list):
            trigger_names = [t.lower() for t in triggers if isinstance(t, str)]
        
        is_deploy = (
            "deploy" in name or "publish" in name or "release" in name
            or any(t in ("deployment", "release", "publish") for t in trigger_names)
        )
        
        concurrency = raw_data.get("concurrency")
        if is_deploy and not concurrency:
            return [{
                "rule": "concurrency-control",
                "location": "workflow.concurrency",
                "message": "State-modifying workflow (deployment/release) should configure 'concurrency' to prevent execution collisions.",
                "original": "missing"
            }]
        return []

    def _check_job_artifacts_transfer(self, job_id, job_data, all_jobs):
        """Flag downstream jobs that need an artifact-producing job but neither
        download it nor reference its outputs (Phase 5 tightening).

        Prior implementation fired whenever ``needs`` was set and the upstream
        uploaded artifacts, producing false positives when ``needs`` was used
        only for ordering/gating. Now we require the downstream job to reference
        an artifact path or an upstream ``outputs.*`` to report.
        """
        needs = job_data.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        if not needs:
            return []

        findings = []
        steps = job_data.get("steps", [])
        if not isinstance(steps, list):
            return []

        run_cmds = _strip_noise(" ".join(
            str(s.get("run", "")) for s in steps if isinstance(s, dict) and "run" in s
        ))
        has_download = any(
            isinstance(s, dict) and "uses" in s and "actions/download-artifact" in s["uses"]
            for s in steps
        )
        # Reference to upstream job outputs, e.g. needs.<job>.outputs.<name>
        uses_upstream_outputs = bool(re.search(
            r'needs\.[A-Za-z0-9_\-]+\.outputs\.', run_cmds
        ))
        # Reference to an artifact name (heuristic: words artifact/file in run cmds).
        refs_artifact = "ARTIFACT" in run_cmds or "artifacts/" in run_cmds or "download-artifact" in run_cmds

        for needed_job in needs:
            needed_job_data = all_jobs.get(needed_job)
            if not isinstance(needed_job_data, dict):
                continue

            needed_steps = needed_job_data.get("steps", [])
            has_upload = any(
                isinstance(s, dict) and "uses" in s and "actions/upload-artifact" in s["uses"]
                for s in needed_steps if isinstance(needed_steps, list)
            )

            if has_upload and not has_download and not uses_upstream_outputs and not refs_artifact:
                findings.append({
                    "rule": "explicit-artifact-transfer",
                    "location": f"jobs.{job_id}",
                    "message": f"Job depends on '{needed_job}' which uploads artifacts, but this job does not invoke 'actions/download-artifact' or reference needs.{needed_job}.outputs.",
                    "original": f"needs: {needed_job}"
                })
        return findings

    def _check_dependency_cycles(self, raw_data):
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        adj = {}
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            needs = job_data.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            adj[job_id] = needs

        visited = {}  # 0: unvisited, 1: visiting, 2: visited
        for node in adj:
            visited[node] = 0

        cycle_nodes = []

        def dfs(u):
            visited[u] = 1
            for v in adj.get(u, []):
                if v not in visited:
                    continue  # dependency is external or misspelled, handled elsewhere
                if visited[v] == 1:
                    cycle_nodes.append((u, v))
                    return True
                if visited[v] == 0:
                    if dfs(v):
                        return True
            visited[u] = 2
            return False

        for node in adj:
            if visited[node] == 0:
                if dfs(node):
                    break

        if cycle_nodes:
            u, v = cycle_nodes[0]
            return [{
                "rule": "job-dependency-cycle",
                "location": "workflow.jobs",
                "message": f"Circular dependency deadlock detected between jobs '{u}' and '{v}'.",
                "original": f"{u} -> {v}"
            }]
        return []

    def _check_enterprise_security_gates(self, job_id, step_idx, step):
        # Look for explicit tooling parameters in step configurations to map security gates
        uses_val = step.get("uses")
        if not uses_val or not isinstance(uses_val, str):
            return []

        findings = []

        # Cosign Sign verification check:
        # Enforce that signing is done against digest, not tag
        if "cosign" in uses_val or (step.get("run") and "cosign sign" in step.get("run")):
            run_cmd = step.get("run", "")
            if run_cmd and "cosign sign" in run_cmd:
                # Simple check: does it sign using digest format e.g. '@sha256:'
                # If they do: cosign sign --yes registry/img:${TAG} it's mutable. It should contain @sha or @${{ steps... }}
                if "@sha256:" not in run_cmd and "@$" not in run_cmd:
                    findings.append({
                        "rule": "image-signing",
                        "location": f"jobs.{job_id}.steps[{step_idx}]",
                        "message": "Cosign signing should target container image with its immutable digest '@sha256:...' instead of tag.",
                        "original": run_cmd
                    })

        return findings

    def _check_global_security_gates(self, raw_data):
        # Scans the entire file to verify presence of critical security tasks.
        # Gating now respects per-rule ``applies_to`` (Phase 5): coverity applies
        # to source+image, while bdba/signing/jfrog apply to image only.
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        all_steps = []
        for job_data in jobs.values():
            if isinstance(job_data, dict) and "steps" in job_data:
                steps = job_data["steps"]
                if isinstance(steps, list):
                    all_steps.extend(steps)

        findings = []

        # Join step uses and scripts to simplify pattern scanning.
        # Use _strip_noise so comment lines and echoed strings don't match.
        uses_list = [s.get("uses", "") for s in all_steps if isinstance(s, dict)]
        run_scripts = _strip_noise(" ".join(
            str(s.get("run", "")) for s in all_steps
            if isinstance(s, dict) and s.get("run")
        ))

        has_jfrog_push = (
            any("setup-cli" in u for u in uses_list)
            or "jf docker push" in run_scripts
            or "jf rt docker-push" in run_scripts
            or "docker push" in run_scripts
        )

        # Image workflows: build/push docker (incl. buildx/kaniko), or docker actions.
        is_image_workflow = (
            has_jfrog_push
            or "docker build" in run_scripts
            or "docker push" in run_scripts
            or "docker buildx" in run_scripts
            or "kaniko" in run_scripts
            or "buildah" in run_scripts
            or any("docker" in u.lower() for u in uses_list if isinstance(u, str))
        )
        # Source-bearing workflows.
        is_source_workflow = (
            any("actions/checkout" in u for u in uses_list)
            or "npm ci" in run_scripts or "npm run build" in run_scripts
            or "mvn " in run_scripts or "gradle" in run_scripts
            or "dotnet build" in run_scripts or "dotnet test" in run_scripts
            or "go build" in run_scripts or "go test" in run_scripts
            or "pip install" in run_scripts or "pytest" in run_scripts
            or "make" in run_scripts
        )

        has_coverity = any(
            "black-duck-security-scan" in u or "synopsys-action" in u
            for u in uses_list
        ) or "cov-build" in run_scripts or "cov-analyze" in run_scripts

        has_bdba = any(
            "detect-action" in u or "black-duck-security-scan" in u
            for u in uses_list
        ) or "synopsys-detect" in run_scripts

        has_cosign = any(
            "cosign-installer" in u for u in uses_list
        ) or "cosign sign" in run_scripts

        def _gate(rule_id: str, message: str, cond: bool, missing_cond: bool):
            if not self._rule_applies(rule_id):
                return
            if cond and missing_cond:
                findings.append({
                    "rule": rule_id,
                    "location": "workflow",
                    "message": message,
                    "original": "missing",
                })

        _gate(
            "coverity-scan",
            "Coverity scan (SAST / secrets checking) is not configured in this workflow.",
            is_source_workflow or is_image_workflow,
            not has_coverity,
        )
        _gate(
            "image-build-jfrog",
            "Docker image building and push to JFrog Artifactory registry is not configured.",
            is_image_workflow,
            not has_jfrog_push,
        )
        _gate(
            "image-signing",
            "Artifacts pushed to JFrog are not signed using Cosign.",
            has_jfrog_push,
            not has_cosign,
        )
        _gate(
            "bdba-scan",
            "BDBA (Black Duck Binary Analysis) vulnerability scan is not configured on built images.",
            has_jfrog_push,
            not has_bdba,
        )

        return findings

    def fetch_latest_sha(self, action_name, tag):
        """Resolve an action's tag/branch to its immutable commit SHA.

        Uses a persistent offline cache (``sha_cache_path``) so fix mode works
        air-gapped. Subpath actions (e.g. ``org/repo/sub/dir@v1``) are rejected —
        they cannot be safely resolved by the public git-refs API (A9).
        """
        parts = action_name.split('/')
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
        if len(parts) > 2:
            logger.warning(
                "Cannot resolve subpath action '%s' to a SHA via API; "
                "use a full-length SHA instead.",
                action_name,
            )
            return None

        cache_key = f"{owner}/{repo}@{tag}"
        if cache_key in self._sha_cache:
            return self._sha_cache[cache_key]

        sha = self._fetch_tag_sha(owner, repo, tag)
        self._sha_cache[cache_key] = sha
        self._sha_cache_dirty = True
        return sha

    def _fetch_tag_sha(self, owner: str, repo: str, tag: str) -> str | None:
        url = f"{self.endpoint}/repos/{owner}/{repo}/git/ref/tags/{tag}"
        headers = {
            "User-Agent": "github-actions-checks/1.0",
            "Accept": "application/vnd.github+json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, headers=headers)

        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                logger.warning(
                    "Rate-limited resolving %s/%s@%s (HTTP %d); skipping.",
                    owner, repo, tag, e.code,
                )
                return None
            if e.code == 404:
                logger.debug("%s/%s@%s not found (HTTP 404).", owner, repo, tag)
                return None
            logger.warning("HTTP %d resolving %s/%s@%s: %s", e.code, owner, repo, tag, e.reason)
            return None
        except urllib.error.URLError as e:
            if isinstance(e.reason, Exception) and "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
                raise SSLCertificateError(
                    "TLS verification failed while resolving action SHAs. "
                    "Install root certificates (see README §1) and retry."
                ) from e
            logger.debug("Network error resolving %s/%s@%s: %s", owner, repo, tag, e)
            return None
        except OSError as e:
            logger.debug("OS error resolving %s/%s@%s: %s", owner, repo, tag, e)
            return None

        try:
            data = json.loads(response.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        obj = data.get("object", {})
        if obj.get("type") == "commit":
            return obj.get("sha")
        if obj.get("type") == "tag":
            tag_url = obj.get("url")
            if not tag_url:
                return None
            tag_req = urllib.request.Request(
                tag_url, headers={**headers, "Accept": "application/vnd.github+json"}
            )
            try:
                tag_resp = urllib.request.urlopen(tag_req, timeout=5)
            except (urllib.error.URLError, OSError) as e:
                logger.debug("Failed to follow tag URL for %s/%s@%s: %s", owner, repo, tag, e)
                return None
            try:
                tag_data = json.loads(tag_resp.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            return tag_data.get("object", {}).get("sha")
        return None

    # ─── PR 3: New rule implementations ────────────────────────────────

    def _check_unresolved_needs(self, raw_data):
        """Flag any needs: reference that doesn't resolve to a known job id (B8)."""
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        findings = []
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            needs = job_data.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            if not isinstance(needs, list):
                continue
            for dep in needs:
                if not isinstance(dep, str):
                    continue
                if dep not in jobs:
                    findings.append({
                        "rule": "unresolved-needs",
                        "location": f"jobs.{job_id}",
                        "message": (
                            f"Job '{job_id}' depends on '{dep}' which is not defined "
                            "in this workflow. Check for typos or missing job definitions."
                        ),
                        "original": f"needs: {dep}",
                    })
        return findings

    def _check_job_timeout(self, job_id, job_data):
        """Flag jobs without timeout-minutes (skip reusable workflow calls)."""
        if job_data.get("uses"):
            return []
        if "timeout-minutes" not in job_data:
            return [{
                "rule": "job-timeout-missing",
                "location": f"jobs.{job_id}",
                "message": f"Job '{job_id}' does not declare 'timeout-minutes'. Hung builds may consume runner resources indefinitely.",
                "original": "missing",
            }]
        return []

    def _check_reusable_workflow_job(self, job_id, job_data):
        """Flag job-level uses: org/repo/.github/workflows/file.yml@ref where ref is not a SHA."""
        uses_val = job_data.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        if "/.github/workflows/" not in uses_val:
            return []
        if "@" not in uses_val:
            return [{
                "rule": "reusable-workflow-pinned",
                "location": f"jobs.{job_id}",
                "message": f"Reusable workflow '{uses_val}' has no version reference. Pin to a commit SHA.",
                "original": uses_val,
            }]
        parts = uses_val.split("@")
        ref = parts[1] if len(parts) > 1 else ""
        if not self.sha_pattern.match(ref):
            return [{
                "rule": "reusable-workflow-pinned",
                "location": f"jobs.{job_id}",
                "message": f"Reusable workflow '{uses_val.split('@')[0]}' is pinned to tag/branch '{ref}' instead of an immutable SHA.",
                "original": uses_val,
            }]
        return []

    def _check_checkout_persist_credentials(self, job_id, idx, step):
        """Flag actions/checkout without persist-credentials: false."""
        uses_val = step.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        if "actions/checkout" not in uses_val:
            return []
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            with_block = {}
        persist = with_block.get("persist-credentials")
        if persist is not False and str(persist).lower() != "false":
            return [{
                "rule": "checkout-persist-credentials",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": "actions/checkout should set 'persist-credentials: false' to prevent the token from persisting in post-checkout steps.",
                "original": uses_val,
            }]
        return []

    def _check_step_timeout(self, job_id, idx, step):
        """Flag long run: steps without timeout-minutes."""
        if "run" not in step:
            return []
        if "timeout-minutes" in step:
            return []
        run_cmd = str(step.get("run", ""))
        lines = [l for l in run_cmd.split("\n") if l.strip()]
        if len(lines) > 15:
            return [{
                "rule": "step-timeout-missing",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": f"Step has {len(lines)} lines of script without timeout-minutes. Consider adding a timeout to prevent indefinite hangs.",
                "original": f"{len(lines)} lines",
            }]
        return []

    def _check_latest_runtime_version(self, job_id, idx, step):
        """Flag setup actions with *-version: latest or lts/*."""
        uses_val = step.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        if "actions/setup-" not in uses_val:
            return []
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            return []
        for key, val in with_block.items():
            if not key.endswith("-version") or not isinstance(val, str):
                continue
            if val.lower() in ("latest", "lts", "lts/*", "stable"):
                return [{
                    "rule": "latest-runtime-version",
                    "location": f"jobs.{job_id}.steps[{idx}]",
                    "message": f"Setup action '{uses_val}' uses '{key}: {val}' which is non-reproducible. Pin to a specific version.",
                    "original": f"{key}: {val}",
                }]
        return []

    def _check_deprecated_set_output(self, job_id, idx, step):
        """Flag deprecated ::set-output, ::set-env, ::add-path workflow commands."""
        run_cmd = step.get("run")
        if not run_cmd or not isinstance(run_cmd, str):
            return []
        patterns = [
            (r"::set-output\s+name=", "::set-output"),
            (r"::set-env\s+name=", "::set-env"),
            (r"::add-path\s+", "::add-path"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, run_cmd):
                return [{
                    "rule": "deprecated-set-output",
                    "location": f"jobs.{job_id}.steps[{idx}]",
                    "message": f"Workflow command '{label}' is deprecated and disabled. Use >> \"$GITHUB_OUTPUT\" or >> \"$GITHUB_ENV\" instead.",
                    "original": label,
                }]
        return []

    def _check_untrusted_input_injection(self, job_id, idx, step):
        """Flag GITHUB_ENV/GITHUB_OUTPUT writes from untrusted context expressions."""
        run_cmd = step.get("run")
        if not run_cmd or not isinstance(run_cmd, str):
            return []
        # Match: untrusted github context → $GITHUB_ENV or $GITHUB_OUTPUT
        untrusted = r"""\$\{\{\s*github\.(event\.\w+[\.\w]*|head_ref|pull_request\.\w+|issue\.\w+)\s*\}\}"""
        env_sink = re.compile(untrusted + r""".*>>\s*["']?\$GITHUB_ENV["']?""")
        output_sink = re.compile(untrusted + r""".*>>\s*["']?\$GITHUB_OUTPUT["']?""")
        if env_sink.search(run_cmd) or output_sink.search(run_cmd):
            return [{
                "rule": "untrusted-input-injection",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": "Untrusted github context is written directly to $GITHUB_ENV or $GITHUB_OUTPUT. Sanitize before assignment to prevent injection.",
                "original": run_cmd[:200],
            }]
        return []

    def _check_submodule_recursive(self, job_id, idx, step):
        """Flag actions/checkout with submodules: recursive."""
        uses_val = step.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        if "actions/checkout" not in uses_val:
            return []
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            return []
        subs = with_block.get("submodules")
        if subs is True or str(subs).lower() == "recursive":
            return [{
                "rule": "submodule-recursive",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": "actions/checkout uses 'submodules: recursive' which pulls arbitrary submodules and may expose secrets or introduce supply-chain risk.",
                "original": str(uses_val),
            }]
        return []

    def _check_oidc_cloud_deploy(self, raw_data):
        """Flag cloud-deploy actions without permissions: id-token: write."""
        OIDC_ACTIONS = ("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth")
        OIDC_SCRIPTS = ("aws sts get-caller-identity", "aws configure set", "az login", "gcloud auth")

        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        findings = []
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            steps = job_data.get("steps", [])
            if not isinstance(steps, list):
                continue
            has_oidc = False
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses_val = step.get("uses", "")
                if any(a in uses_val for a in OIDC_ACTIONS):
                    has_oidc = True
                    break
                run_cmd = step.get("run", "")
                if isinstance(run_cmd, str) and any(a in run_cmd for a in OIDC_SCRIPTS):
                    has_oidc = True
                    break
            if not has_oidc:
                continue
            job_perms = job_data.get("permissions")
            if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
                continue
            workflow_perms = raw_data.get("permissions")
            if isinstance(workflow_perms, dict) and workflow_perms.get("id-token") == "write":
                continue
            findings.append({
                "rule": "oidc-cloud-deploy",
                "location": f"jobs.{job_id}",
                "message": (
                    f"Job '{job_id}' uses an OIDC-based cloud deploy action but does not declare "
                    "'permissions: id-token: write'. The job may fail to authenticate."
                ),
                "original": "missing",
            })
        return findings

    # ─── PR 5: New production-grade rules (July 2026) ────────────────────

    def _check_pull_request_target_danger(self, raw_data):
        """Flag pull_request_target triggers combined with PR-head checkout.

        ``pull_request_target`` runs with the base branch's secrets. If the
        workflow also checks out ``github.event.pull_request.head.ref`` (or the
        PR SHA) and runs untrusted build/test code, that code executes with
        write access — a critical supply-chain vulnerability (tj-actions /
        reviewdog historical incidents). We flag the combination.
        """
        triggers = raw_data.get("on")
        trigger_names: list[str] = []
        if isinstance(triggers, dict):
            trigger_names = [k.lower() for k in triggers.keys()]
        elif isinstance(triggers, str):
            trigger_names = [triggers.lower()]
        elif isinstance(triggers, list):
            trigger_names = [t.lower() for t in triggers if isinstance(t, str)]
        if "pull_request_target" not in trigger_names:
            return []

        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        findings = []
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            steps = job_data.get("steps", [])
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses_val = str(step.get("uses", ""))
                with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
                ref = str(with_block.get("ref", ""))
                # If checkout references the PR head ref or SHA under prt → danger.
                if "actions/checkout" in uses_val and (
                    "head.ref" in ref
                    or "pull_request.head.sha" in ref
                    or ref.startswith("refs/pull/")
                ):
                    findings.append({
                        "rule": "pull-request-target-danger",
                        "location": f"jobs.{job_id}.steps[{idx}]",
                        "message": (
                            "Workflow uses pull_request_target and checks out PR head code; "
                            "this executes untrusted code with base-branch secrets. Avoid "
                            "checking out PR refs under pull_request_target, or run only "
                            "trusted label/comment actions."
                        ),
                        "original": uses_val,
                    })
                    break
                # Also flag run: scripts that build PR code under prt.
                run_cmd = str(step.get("run", ""))
                if run_cmd and (
                    "${{ github.event.pull_request.head.sha }}" in run_cmd
                    or "github.event.pull_request.head.ref" in run_cmd
                ):
                    findings.append({
                        "rule": "pull-request-target-danger",
                        "location": f"jobs.{job_id}.steps[{idx}]",
                        "message": (
                            "Workflow uses pull_request_target and a run step references the "
                            "PR head; untrusted code runs with base-branch secrets."
                        ),
                        "original": run_cmd[:200],
                    })
                    break
        return findings

    def _check_self_hosted_runner(self, raw_data):
        """Flag runs-on: self-hosted (broad label) — supply-chain RCE on public repos."""
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        findings = []
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            runs_on = job_data.get("runs-on")
            runner_str = ""
            if isinstance(runs_on, str):
                runner_str = runs_on.lower()
            elif isinstance(runs_on, list):
                runner_str = " ".join(str(t).lower() for t in runs_on if isinstance(t, str))
            # Bare "self-hosted" with no further org/runner-group label is risky.
            tokens = [t for t in re.split(r"[\s,]+", runner_str) if t]
            if tokens == ["self-hosted"] or "self-hosted" in tokens and len(tokens) == 1:
                findings.append({
                    "rule": "self-hosted-runner-public-repo",
                    "location": f"jobs.{job_id}",
                    "message": (
                        "Job uses 'runs-on: self-hosted' with no runner-group/org label. "
                        "On a public repository this exposes the runner to untrusted code "
                        "execution. Use GitHub-hosted runners or label-gated self-hosted "
                        "runners only on private repos."
                    ),
                    "original": str(runs_on),
                })
        return findings

    def _check_secret_in_run_literal(self, job_id, idx, step):
        """Flag hardcoded credentials embedded in run: scripts."""
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []
        noiseless = _strip_noise(run_val)
        for pattern in _SECRET_LITERAL_PATTERNS:
            if pattern.search(noiseless):
                return [{
                    "rule": "secret-in-run-literal",
                    "location": f"jobs.{job_id}.steps[{idx}]",
                    "message": "Hardcoded credential literal detected in run: script. Bind credentials via env: referencing secrets.<NAME> instead.",
                    "original": run_val[:200],
                }]
        return []

    def _check_secret_echoed_in_logs(self, job_id, idx, step):
        """Flag ${{ secrets.* }} interpolated directly into run: (echoed in logs)."""
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []
        if re.search(r"\$\{\{\s*secrets\.", run_val) and "env:" not in step:
            return [{
                "rule": "secret-echoed-in-logs",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": "Secret referenced via ${{ secrets.* }} directly in run: is echoed in workflow logs. Bind it through env: instead.",
                "original": run_val[:200],
            }]
        return []

    def _check_expression_in_run_injection(self, job_id, idx, step):
        """Flag untrusted ${{ github.event.* }} expressions in run: scripts."""
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []
        # Find expression interpolations in the run script.
        exprs = _RUNEXPR_RE.findall(run_val)
        if not exprs:
            return []
        # Untrusted contexts that should never be interpolated directly in run:.
        untrusted_pattern = re.compile(
            r"\$\{\{\s*(github\.(event\.(issue|pull_request|comment|discussion|"
            r"head_ref|base_ref|ref|ref_name|sha|actor|workflow_trigger)|"
            r"github\.head_ref|github\.base_ref))",
            re.IGNORECASE,
        )
        for expr in exprs:
            if untrusted_pattern.search(expr):
                return [{
                    "rule": "expression-in-run-injection",
                    "location": f"jobs.{job_id}.steps[{idx}]",
                    "message": (
                        f"Untrusted expression '{expr.strip()[:80]}' interpolated directly "
                        "into run: enables script injection. Assign to an env: var first."
                    ),
                    "original": run_val[:200],
                }]
        return []

    def _check_environment_protection(self, job_id, job_data):
        """Flag deploy/release jobs without an environment: declaration."""
        if not self._rule_applies("environment-protection"):
            return []
        name = str(job_data.get("name", "")).lower()
        job_id_l = str(job_id).lower()
        is_deploy = (
            "deploy" in name or "deploy" in job_id_l
            or "release" in name or "release" in job_id_l
            or "publish" in name or "publish" in job_id_l
        )
        if not is_deploy:
            return []
        if "environment" not in job_data:
            return [{
                "rule": "environment-protection",
                "location": f"jobs.{job_id}",
                "message": f"Deployment job '{job_id}' does not declare an 'environment:'. Use a protected environment with required reviewers for production.",
                "original": "missing",
            }]
        return []

    def _check_docker_action_digest_pin(self, raw_data):
        """Flag docker:// actions and container services pinned by tag (not digest)."""
        findings = []
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            # container: block
            container = job_data.get("container")
            if isinstance(container, dict):
                image = str(container.get("image", ""))
                if image and ":" in image and "@sha256:" not in image:
                    findings.append({
                        "rule": "docker-action-digest-pin",
                        "location": f"jobs.{job_id}.container",
                        "message": f"Container image '{image}' is pinned by tag, not digest. Pin to '@sha256:...'.",
                        "original": image,
                    })
            elif isinstance(container, str) and ":" in container and "@sha256:" not in container:
                findings.append({
                    "rule": "docker-action-digest-pin",
                    "location": f"jobs.{job_id}.container",
                    "message": f"Container image '{container}' is pinned by tag, not digest. Pin to '@sha256:...'.",
                    "original": container,
                })
            # services: blocks
            services = job_data.get("services")
            if isinstance(services, dict):
                for svc_name, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    image = str(svc.get("image", ""))
                    if image and ":" in image and "@sha256:" not in image:
                        findings.append({
                            "rule": "docker-action-digest-pin",
                            "location": f"jobs.{job_id}.services.{svc_name}",
                            "message": f"Service '{svc_name}' image '{image}' is pinned by tag, not digest.",
                            "original": image,
                        })
            # docker:// actions in steps
            steps = job_data.get("steps", [])
            if isinstance(steps, list):
                for idx, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    uses_val = str(step.get("uses", ""))
                    if uses_val.startswith("docker://") and "@" not in uses_val:
                        findings.append({
                            "rule": "docker-action-digest-pin",
                            "location": f"jobs.{job_id}.steps[{idx}]",
                            "message": f"Docker action '{uses_val}' is not pinned by digest. Use 'docker://image@sha256:...'.",
                            "original": uses_val,
                        })
        return findings

    def _check_missing_set_x_pipefail(self, job_id, idx, step):
        """Flag multi-line bash run: scripts lacking 'set -e -o pipefail'."""
        if not self._rule_applies("missing-set-x-pipefail"):
            return []
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []
        lines = [l for l in run_val.split("\n") if l.strip()]
        if len(lines) < 3:
            return []
        shell = str(step.get("shell", "")).lower()
        # Only flag bash/sh shells (not pwsh/cmd/python).
        if shell and shell not in ("bash", "sh"):
            return []
        first_lines = " ".join(lines[:2]).lower()
        if "set -e" in first_lines or "set -o pipefail" in first_lines:
            return []
        # Skip if there's an explicit `if:` guarding the whole step.
        return [{
            "rule": "missing-set-x-pipefail",
            "location": f"jobs.{job_id}.steps[{idx}]",
            "message": "Multi-line bash run: script lacks 'set -e -o pipefail'; failures may be masked. Add it at the top of the script.",
            "original": f"{len(lines)} lines",
        }]

    def _check_token_passed_to_third_party(self, raw_data):
        """Flag GITHUB_TOKEN/secrets passed via env: to non-first-party actions."""
        if not self._rule_applies("token-passed-to-third-party"):
            return []
        jobs = raw_data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        findings = []
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            steps = job_data.get("steps", [])
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses_val = str(step.get("uses", ""))
                if not uses_val or "@" not in uses_val:
                    continue
                action_ref = uses_val.split("@", 1)[0]
                env_block = step.get("env")
                if not isinstance(env_block, dict):
                    continue
                token_refs = [
                    k for k, v in env_block.items()
                    if isinstance(v, str) and re.search(r"\$\{\{\s*(secrets\.|github\.token|env\.GITHUB_TOKEN)", v)
                ]
                if not token_refs:
                    continue
                # First-party orgs are trusted.
                if any(action_ref.startswith(org) for org in self.trusted_orgs):
                    continue
                findings.append({
                    "rule": "token-passed-to-third-party",
                    "location": f"jobs.{job_id}.steps[{idx}]",
                    "message": (
                        f"Token/secret passed via env to third-party action '{action_ref}'. "
                        "Audit the action's trust level; third-party actions can exfiltrate credentials."
                    ),
                    "original": ", ".join(token_refs),
                })
        return findings

    def _check_always_deploy_after_failure(self, job_id, job_data, all_jobs):
        """Flag deploy jobs gated with if: always() after a test/build job."""
        if not self._rule_applies("always-deploy-after-failure"):
            return []
        if_expr = str(job_data.get("if", ""))
        if "always()" not in if_expr.replace(" ", ""):
            return []
        # Must be a deploy-ish job.
        name = str(job_data.get("name", "")).lower()
        if "deploy" not in name and "deploy" not in str(job_id).lower() and "release" not in name and "publish" not in name:
            return []
        needs = job_data.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        if not needs:
            return []
        # Report the upstream jobs that could fail silently.
        upstream = [n for n in needs if isinstance(n, str) and n in all_jobs]
        return [{
            "rule": "always-deploy-after-failure",
            "location": f"jobs.{job_id}",
            "message": (
                f"Deploy job '{job_id}' uses if: always() and depends on {upstream}; "
                "it will deploy even when an upstream job fails. Use "
                "if: success() or needs.<job>.result == 'success'."
            ),
            "original": if_expr,
        }]

    def _check_matrix_fail_fast(self, job_id, job_data):
        """Flag matrix jobs with fail-fast: true."""
        if not self._rule_applies("matrix-fail-fast"):
            return []
        strategy = job_data.get("strategy")
        if not isinstance(strategy, dict):
            return []
        if "fail-fast" not in strategy:
            return []
        if strategy.get("fail-fast") is True:
            return [{
                "rule": "matrix-fail-fast",
                "location": f"jobs.{job_id}.strategy",
                "message": "Matrix has fail-fast: true; the entire matrix aborts on the first failure, hiding later failures. Consider fail-fast: false for diagnostics.",
                "original": "fail-fast: true",
            }]
        return []


def _strip_noise(text: str) -> str:
    """Return text with shell comment lines and echo-quoted strings removed.

    Prevents false positives where a substring like ``docker push`` appears
    in a comment (``# docker push ...``) or inside an echo string
    (``echo "docker push not used"``). Lines are processed individually so
    inline comments after code are also stripped at the first ``#`` outside
    quotes.
    """
    if not text:
        return ""
    out_lines = []
    for line in text.splitlines():
        # Skip full-line comments.
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Strip trailing inline comment (naive: first unquoted #).
        in_single = in_double = False
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                cut = i
                break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)
