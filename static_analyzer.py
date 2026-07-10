import re
import urllib.request
import json
import os
import ssl


try:
    from ruamel.yaml.scalarstring import FoldedScalarString
except ImportError:
    FoldedScalarString = None

class StaticAnalyzer:
    def __init__(self, rules_config=None):
        self.rules_config = rules_config or {}
        # Regex to match 40-character hex SHA
        self.sha_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        # Regex to match GitLab variables e.g., $CI_PROJECT_NAME, ${CI_COMMIT_SHA}
        self.gitlab_var_pattern = re.compile(r'\$CI_[A-Za-z0-9_]+|\$\{CI_[A-Za-z0-9_]+\}')
        # Common secret variable suffix list
        self.secret_suffixes = ['KEY', 'TOKEN', 'PASS', 'PASSWORD', 'SECRET', 'API_KEY', 'PAT']

    def analyze_workflow(self, filepath, raw_data):
        """Runs offline static validation rules on raw parsed workflow dict."""
        findings = []

        if not raw_data:
            return findings

        # Run checks
        findings.extend(self._check_dependency_cycles(raw_data))
        findings.extend(self._check_least_privilege_token(raw_data))
        findings.extend(self._check_concurrency_control(raw_data))

        jobs = raw_data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                findings.extend(self._check_job_artifacts_transfer(job_id, job_data, jobs))
                findings.extend(self._check_runner_shell_misalignment(job_id, job_data))
                
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

        matches = self.gitlab_var_pattern.findall(run_val)
        if matches:
            for match in set(matches):
                findings.append({
                    "rule": "residual-gitlab-vars",
                    "location": f"jobs.{job_id}.steps[{step_idx}]",
                    "message": f"Shell step contains residual GitLab CI variable reference '{match}'.",
                    "original": match
                })
        return findings

    def _check_unbound_secrets(self, job_id, job_data, step_idx, step):
        run_val = step.get("run")
        if not run_val or not isinstance(run_val, str):
            return []

        findings = []
        # Find environment variables written as $VAR or ${VAR} in shell
        shell_vars = re.findall(r'\$([A-Za-z0-9_]+)|\$\{([A-Za-z0-9_]+)\}', run_val)
        variables_used = set([v[0] or v[1] for v in shell_vars if v[0] or v[1]])

        # Filter for variables containing security suffixes
        suspicious_vars = [v for v in variables_used if any(suffix in v.upper() for suffix in self.secret_suffixes)]

        # Collect all bound environment variables in scope (step-level + job-level + global env)
        bound_env = set()
        
        # We can look up environment mappings in step.env or job.env
        step_env = step.get("env")
        if isinstance(step_env, dict):
            bound_env.update(step_env.keys())
        job_env = job_data.get("env")
        if isinstance(job_env, dict):
            bound_env.update(job_env.keys())

        # If a secret variable is used but not bound to any env property, flag it
        for var in suspicious_vars:
            # Skip GITHUB_TOKEN which is injected automatically in some runner scopes but best explicitly bound anyway
            if var == "GITHUB_TOKEN":
                continue
            if var not in bound_env:
                findings.append({
                    "rule": "unbound-secrets",
                    "location": f"jobs.{job_id}.steps[{step_idx}]",
                    "message": f"Shell step references credentials variable '${var}' which is not explicitly bound in 'env' parameters.",
                    "original": var
                })
        return findings

    def _check_runner_shell_misalignment(self, job_id, job_data):
        runs_on = job_data.get("runs-on", "")
        
        # Check if Windows is targeted
        is_windows = False
        if isinstance(runs_on, str):
            is_windows = "windows" in runs_on.lower() or "win" in runs_on.lower()
        elif isinstance(runs_on, list):
            is_windows = any("windows" in tag.lower() or "win" in tag.lower() for tag in runs_on if isinstance(tag, str))

        if not is_windows:
            return []

        findings = []
        steps = job_data.get("steps", [])
        if isinstance(steps, list):
            for idx, step in enumerate(steps):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                
                shell = step.get("shell")
                if not shell:
                    # Windows default is pwsh/cmd. If bash commands are used, this will fail.
                    run_cmd = step["run"]
                    # Check for Linux utilities
                    linux_cmds = ["grep", "sed", "awk", "export", "rm -rf", "mkdir -p", "tar", "zip"]
                    found_cmds = [cmd for cmd in linux_cmds if cmd in run_cmd]
                    if found_cmds:
                        findings.append({
                            "rule": "runner-shell-misalignment",
                            "location": f"jobs.{job_id}.steps[{idx}]",
                            "message": f"Job runs on Windows, but step contains Linux commands {found_cmds} without setting 'shell: bash'.",
                            "original": run_cmd
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
        """Fetches the latest commit SHA from the public GitHub API for a given action and tag reference.

        E.g., fetch_latest_sha('actions/checkout', 'v4') -> 'a5ac7e51b41094c92402da3b24376905380afc29'
        Handles rate limits and offline situations gracefully.
        """
        # Parse owner and repository
        parts = action_name.split('/')
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]

        url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Antigravity-Pipeline-Analyzer/1.0",
                "Accept": "application/vnd.github+json"
            }
        )

        try:
            context = ssl.create_default_context()
        except Exception:
            context = None

        try:
            try:
                with urllib.request.urlopen(req, timeout=5, context=context) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode('utf-8'))
                        obj = data.get("object", {})
                        if obj.get("type") == "commit":
                            return obj.get("sha")
                        elif obj.get("type") == "tag":
                            tag_url = obj.get("url")
                            tag_req = urllib.request.Request(
                                tag_url,
                                headers={
                                    "User-Agent": "Antigravity-Pipeline-Analyzer/1.0",
                                    "Accept": "application/vnd.github+json"
                                }
                            )
                            with urllib.request.urlopen(tag_req, timeout=5, context=context) as tag_response:
                                if tag_response.status == 200:
                                    tag_data = json.loads(tag_response.read().decode('utf-8'))
                                    return tag_data.get("object", {}).get("sha")
            except Exception as e:
                # SSL verification failure fallback
                if "CERTIFICATE_VERIFY_FAILED" in str(e):
                    unverified_context = ssl._create_unverified_context()
                    with urllib.request.urlopen(req, timeout=5, context=unverified_context) as response:
                        if response.status == 200:
                            data = json.loads(response.read().decode('utf-8'))
                            obj = data.get("object", {})
                            if obj.get("type") == "commit":
                                return obj.get("sha")
                            elif obj.get("type") == "tag":
                                tag_url = obj.get("url")
                                tag_req = urllib.request.Request(
                                    tag_url,
                                    headers={
                                        "User-Agent": "Antigravity-Pipeline-Analyzer/1.0",
                                        "Accept": "application/vnd.github+json"
                                    }
                                )
                                with urllib.request.urlopen(tag_req, timeout=5, context=unverified_context) as tag_response:
                                    if tag_response.status == 200:
                                        tag_data = json.loads(tag_response.read().decode('utf-8'))
                                        return tag_data.get("object", {}).get("sha")
                else:
                    raise e
        except Exception:
            # Network issue, rate limited, or private repo - fail gracefully
            pass
        return None
