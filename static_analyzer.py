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


class StaticAnalyzer:
    def __init__(self, rules_config=None, token: str | None = None, endpoint: str | None = None):
        self.rules_config = rules_config or {}
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("COPILOT_TOKEN")
        self.endpoint = (endpoint or "https://api.github.com").rstrip("/")
        # Regex to match 40-character hex SHA
        self.sha_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        # Regex to match GitLab variables e.g., $CI_PROJECT_NAME, ${CI_COMMIT_SHA}
        self.gitlab_var_pattern = re.compile(r'\$CI_[A-Za-z0-9_]+|\$\{CI_[A-Za-z0-9_]+\}')
        # Default secret pattern; overridable via rules_config["secret_keyword_pattern"].
        self.secret_keyword_pattern = re.compile(
            self.rules_config.get(
                "secret_keyword_pattern",
                r'(?i)(KEY|TOKEN|PASS|PASSWORD|SECRET|API[_-]?KEY|PAT|CRED|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)',
            )
        )
        # Cache for resolved action SHAs: action@tag -> sha (or None on miss)
        self._sha_cache: dict[str, str | None] = {}

    def analyze_workflow(self, filepath, raw_data):
        """Runs offline static validation rules on raw parsed workflow dict."""
        findings = []

        if not raw_data:
            return findings

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
                        findings.extend(self._check_checkout_fetch_depth(job_id, idx, step))
                        findings.extend(self._check_step_timeout(job_id, idx, step))
                        findings.extend(self._check_latest_runtime_version(job_id, idx, step))
                        findings.extend(self._check_deprecated_set_output(job_id, idx, step))
                        findings.extend(self._check_untrusted_input_injection(job_id, idx, step))
                        findings.extend(self._check_submodule_recursive(job_id, idx, step))
                        findings.extend(self._check_reusable_workflow_pinned(job_id, idx, step))

        # Check global workflow-level security gates
        findings.extend(self._check_global_security_gates(raw_data))

        return findings

    def _check_step_action_pinning(self, job_id, step_idx, step):
        uses_val = step.get("uses")
        if not uses_val or not isinstance(uses_val, str):
            return []

        # Local actions start with './' or relative paths, skip them
        if uses_val.startswith("./") or uses_val.startswith("../"):
            return []

        # Docker/Docker Hub actions e.g. docker://alpine, skip them
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
        is_deploy = "deploy" in name or "publish" in name or "release" in name
        
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
        needs = job_data.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        
        if not needs:
            return []

        findings = []
        steps = job_data.get("steps", [])
        if not isinstance(steps, list):
            return []

        # See if there are references to directories or outputs from other jobs in shell command
        run_cmds = " ".join([step.get("run", "") for step in steps if isinstance(step, dict) and "run" in step])
        
        # Check if step downloads artifacts
        has_download = any(
            isinstance(step, dict) and "uses" in step and "actions/download-artifact" in step["uses"]
            for step in steps
        )

        for needed_job in needs:
            needed_job_data = all_jobs.get(needed_job)
            if not isinstance(needed_job_data, dict):
                continue
            
            # Check if needed job generates artifacts (indicated by actions/upload-artifact usage)
            needed_steps = needed_job_data.get("steps", [])
            has_upload = any(
                isinstance(step, dict) and "uses" in step and "actions/upload-artifact" in step["uses"]
                for step in needed_steps if isinstance(needed_steps, list)
            )

            # If job B needs job A, and Job A generates an artifact but Job B doesn't download it, flag warning
            if has_upload and not has_download:
                findings.append({
                    "rule": "explicit-artifact-transfer",
                    "location": f"jobs.{job_id}",
                    "message": f"Job depends on '{needed_job}' which uploads artifacts, but this job does not invoke 'actions/download-artifact'.",
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
        # Scans the entire file to verify presence of critical security tasks
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
        
        # Join step uses and scripts to simplify pattern scanning
        uses_list = [s.get("uses", "") for s in all_steps if isinstance(s, dict)]
        run_scripts = " ".join([s.get("run", "") for s in all_steps if isinstance(s, dict) and "run" in s])

        has_coverity = any(
            "black-duck-security-scan" in u or "synopsys-action" in u
            for u in uses_list
        ) or "cov-build" in run_scripts or "cov-analyze" in run_scripts

        has_bdba = any(
            "detect-action" in u or "black-duck-security-scan" in u
            for u in uses_list
        ) or "synopsys-detect" in run_scripts

        has_jfrog_push = any(
            "setup-cli" in u for u in uses_list
        ) or "jf docker push" in run_scripts or "jf rt docker-push" in run_scripts or "docker push" in run_scripts

        has_cosign = any(
            "cosign-installer" in u for u in uses_list
        ) or "cosign sign" in run_scripts

        if not has_coverity:
            findings.append({
                "rule": "coverity-scan",
                "location": "workflow",
                "message": "Coverity scan (SAST / secrets checking) is not configured in this workflow.",
                "original": "missing"
            })
            
        if not has_jfrog_push:
            findings.append({
                "rule": "image-build-jfrog",
                "location": "workflow",
                "message": "Docker image building and push to JFrog Artifactory registry is not configured.",
                "original": "missing"
            })

        if has_jfrog_push and not has_cosign:
            findings.append({
                "rule": "image-signing",
                "location": "workflow",
                "message": "Artifacts pushed to JFrog are not signed using Cosign.",
                "original": "missing"
            })

        if has_jfrog_push and not has_bdba:
            findings.append({
                "rule": "bdba-scan",
                "location": "workflow",
                "message": "BDBA (Black Duck Binary Analysis) vulnerability scan is not configured on built images.",
                "original": "missing"
            })

        return findings

    def fetch_latest_sha(self, action_name, tag):
        """Resolve an action's tag/branch to its immutable commit SHA.

        Subpath actions (e.g. `org/repo/sub/dir@v1`) are rejected — they
        cannot be safely resolved by the public git-refs API (A9).
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
        """Flag jobs without timeout-minutes."""
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

    def _check_checkout_fetch_depth(self, job_id, idx, step):
        """Flag actions/checkout with fetch-depth: 0 when not explicitly needed."""
        uses_val = step.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        if "actions/checkout" not in uses_val:
            return []
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            with_block = {}
        depth = with_block.get("fetch-depth")
        if depth == 0:
            return [{
                "rule": "checkout-fetch-depth",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": "actions/checkout uses fetch-depth: 0 (full history clone). Ensure this is intentional.",
                "original": str(uses_val),
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
        setup_actions = (
            "actions/setup-python", "actions/setup-node", "actions/setup-go",
            "actions/setup-java", "actions/setup-ruby", "actions/setup-dotnet",
        )
        is_setup = any(f"actions/setup-" in u for u in [uses_val])
        if not is_setup:
            return []
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            return []
        for key, val in with_block.items():
            if not key.endswith("-version") or not isinstance(val, str):
                continue
            if val.lower() in ("latest", "lts", "lts/*", "lts/*", "stable"):
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

    def _check_reusable_workflow_pinned(self, job_id, idx, step):
        """Flag reusable workflow calls (uses: org/repo/.github/workflows/...@ref) where ref is not a SHA."""
        uses_val = step.get("uses", "")
        if not uses_val or not isinstance(uses_val, str):
            return []
        # Reusable workflow syntax: org/repo/.github/workflows/file.yml@ref
        if "/.github/workflows/" not in uses_val:
            return []
        if "@" not in uses_val:
            return [{
                "rule": "reusable-workflow-pinned",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": f"Reusable workflow '{uses_val}' has no version reference. Pin to a commit SHA.",
                "original": uses_val,
            }]
        parts = uses_val.split("@")
        ref = parts[1] if len(parts) > 1 else ""
        if not self.sha_pattern.match(ref):
            return [{
                "rule": "reusable-workflow-pinned",
                "location": f"jobs.{job_id}.steps[{idx}]",
                "message": f"Reusable workflow '{uses_val.split('@')[0]}' is pinned to tag/branch '{ref}' instead of an immutable SHA.",
                "original": uses_val,
            }]
        return []

    def _check_oidc_cloud_deploy(self, raw_data):
        """Flag cloud-deploy actions without permissions: id-token: write."""
        OIDC_ACTIONS = ("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth")
        OIDC_SCRIPTS = ("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth")

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
            if isinstance(job_perms, dict) and job_perms.get("id-token") in ("write", "read"):
                continue
            workflow_perms = raw_data.get("permissions")
            if isinstance(workflow_perms, dict) and workflow_perms.get("id-token") in ("write", "read"):
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
