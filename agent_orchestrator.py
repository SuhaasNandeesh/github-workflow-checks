import os
import json
import difflib
import re
from parser import WorkflowParser
from static_analyzer import StaticAnalyzer
from copilot_client import CopilotClient
from reporter import ReportGenerator


DEFAULT_RULE_SEVERITIES = {
    "pin-action-sha": "error",
    "least-privilege-token": "error",
    "residual-gitlab-vars": "error",
    "runner-shell-misalignment": "error",
    "job-dependency-cycle": "error",
    "coverity-scan": "warning",
    "image-build-jfrog": "warning",
    "image-signing": "warning",
    "bdba-scan": "warning",
    "explicit-artifact-transfer": "warning",
    "unbound-secrets": "warning",
    "multiline-block-scalar": "warning",
    "concurrency-control": "warning"
}


class AgentOrchestrator:
    def __init__(self, mode="report", rules_path=".github-rules.json", templates_dir="templates", reset=False):
        self.mode = mode
        self.rules_path = rules_path
        self.templates_dir = templates_dir
        self.reset = reset
        self.state_db_path = ".actions_audit_state.json"
        
        self.parser = WorkflowParser()
        self.static_analyzer = StaticAnalyzer()
        self.copilot = None  # Instantiated lazily if LLM is required
        
        self.rules_config = self._load_rules_config()
        self.templates_data = self._load_templates()
        self.static_analyzer.rules_config = self.rules_config
        self.state_db = self._load_state_db()


    def _load_rules_config(self):
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to parse rules configuration file: {e}")
        return {"rules": {}, "suppressions": {"global": [], "by_repository": {}}}

    def _load_state_db(self):
        if not self.reset and os.path.exists(self.state_db_path):
            try:
                with open(self.state_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load audit state database: {e}")
        return {"processed_workflows": {}}

    def _save_state_db(self):
        try:
            with open(self.state_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.state_db, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save audit state database: {e}")


    def _load_templates(self):
        templates = {}
        if os.path.exists(self.templates_dir) and os.path.isdir(self.templates_dir):
            for filename in os.listdir(self.templates_dir):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    filepath = os.path.join(self.templates_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            templates[filename] = f.read()
                    except Exception:
                        pass
        return templates

    def _get_copilot_client(self):
        if self.copilot is None:
            # Check model name configuration from rules
            model_name = self.rules_config.get("model", "gpt-4o")
            self.copilot = CopilotClient(model_name=model_name)
        return self.copilot

    def run_on_directory(self, target_dir):
        """Scans the directory recursively and processes target GitHub Action YAML files."""
        if not os.path.exists(target_dir):
            raise FileNotFoundError(f"Target directory not found: {target_dir}")

        print(f"Initiating pipeline scan on: {target_dir}")
        print(f"Running in mode: {self.mode.upper()}")

        # Locate workflows
        workflows = []
        for root, dirs, files in os.walk(target_dir):
            # Ensure the path contains .github/workflows specifically as a segment
            normalized_path = os.path.normpath(root)
            if os.path.join(".github", "workflows") in normalized_path:
                for filename in files:
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        workflows.append(os.path.join(root, filename))

        if not workflows:
            print("No GitHub Actions workflows discovered in target directory structure.")
            return

        print(f"Discovered {len(workflows)} workflow file(s) for analysis.")

        results = {}
        repo_data = {}
        import datetime

        for workflow_path in workflows:
            rel_path = os.path.relpath(workflow_path, target_dir)
            repo_name = rel_path.split(os.sep)[0] if os.sep in rel_path else "root"
            
            # Check modification time
            try:
                mtime = os.path.getmtime(workflow_path)
            except Exception:
                mtime = 0.0

            # Resumption check
            if not self.reset and rel_path in self.state_db.get("processed_workflows", {}):
                entry = self.state_db["processed_workflows"][rel_path]
                if entry.get("status") == "completed" and entry.get("last_mtime") == mtime:
                    print(f"Skipping already processed workflow (resume mode): {rel_path}")
                    results[rel_path] = entry.get("violations_count", 0)
                    
                    if self.mode == "report":
                        if repo_name not in repo_data:
                            repo_dir = target_dir if repo_name == ".github" else os.path.join(target_dir, repo_name)
                            repo_data[repo_name] = {"repo_dir": repo_dir, "violations": [], "workflows": {}}
                        
                        file_violations = entry.get("violations", [])
                        for v in file_violations:
                            v_copy = dict(v)
                            v_copy["file"] = rel_path
                            repo_data[repo_name]["violations"].append(v_copy)
                        
                        repo_data[repo_name]["workflows"][rel_path] = entry.get("workflow_ast", {})
                    continue

            print(f"\nProcessing: {rel_path} (Repository: {repo_name})")
            
            try:
                # Load workflow using round-trip parser
                workflow_data = self.parser.load_workflow(workflow_path)
                
                # Step 1: Programmatic Static Auditing
                violations = self.static_analyzer.analyze_workflow(workflow_path, workflow_data)
                
                # Step 2: Semantic Review (LLM Subagent)
                semantic_violations = self._run_semantic_audit(workflow_data, violations, repo_name)
                violations.extend(semantic_violations)
                
                # Filter out suppressed violations
                filtered_violations = self._filter_suppressions(violations, repo_name)
                
                # Output results based on execution mode
                if self.mode == "dry-run":
                    self._handle_dry_run_mode(workflow_path, workflow_data, filtered_violations)
                elif self.mode == "fix":
                    self._handle_fix_mode(workflow_path, workflow_data, filtered_violations)
                
                results[rel_path] = len(filtered_violations)
                
                # Accumulate for consolidated report
                if self.mode == "report":
                    if repo_name not in repo_data:
                        repo_dir = target_dir if repo_name == ".github" else os.path.join(target_dir, repo_name)
                        repo_data[repo_name] = {"repo_dir": repo_dir, "violations": [], "workflows": {}}
                    
                    for v in filtered_violations:
                        v_copy = dict(v)
                        v_copy["file"] = rel_path
                        repo_data[repo_name]["violations"].append(v_copy)
                    
                    repo_data[repo_name]["workflows"][rel_path] = self.parser.extract_ast_summary(workflow_data)
                
                # Save status to state DB
                self.state_db["processed_workflows"][rel_path] = {
                    "status": "completed",
                    "last_mtime": mtime,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "violations_count": len(filtered_violations),
                    "violations": filtered_violations,
                    "workflow_ast": self.parser.extract_ast_summary(workflow_data)
                }
                self._save_state_db()
            except Exception as e:
                print(f"Error processing workflow {rel_path}: {e}")
                results[rel_path] = "Failed"
                self.state_db["processed_workflows"][rel_path] = {
                    "status": "failed",
                    "last_mtime": mtime,
                    "error": str(e),
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                }
                self._save_state_db()

        # Generate aggregated findings.md reports per repository
        if self.mode == "report":
            for r_name, r_info in repo_data.items():
                self._handle_report_mode_aggregated(r_name, r_info["repo_dir"], r_info["violations"], r_info["workflows"])

        print("\n=== Scan Complete ===")
        for path, count in results.items():
            print(f"- {path}: {count} violations")

    def _filter_suppressions(self, violations, repo_name):
        global_suppressions = self.rules_config.get("suppressions", {}).get("global", [])
        repo_suppressions = self.rules_config.get("suppressions", {}).get("by_repository", {}).get(repo_name, [])

        filtered = []
        for v in violations:
            rule_id = v.get("rule")
            if rule_id in global_suppressions:
                continue
            if rule_id in repo_suppressions:
                continue
            
            # Map severity based on rules config
            rule_info = self.rules_config.get("rules", {}).get(rule_id, {})
            default_severity = DEFAULT_RULE_SEVERITIES.get(rule_id, "warning")
            severity = default_severity
            if isinstance(rule_info, dict):
                severity = rule_info.get("severity", default_severity)
            elif isinstance(rule_info, str):
                severity = rule_info
                
            if severity == "ignore":
                continue
                
            v["severity"] = severity
            filtered.append(v)
        return filtered

    def _run_semantic_audit(self, workflow_data, static_findings, repo_name):
        """Prepares a minimized AST summary context and invokes the Semantic Auditor LLM sub-agent."""
        # Check if we should call the LLM: if semantic audit rules are active
        # We only call Copilot if there are rules enabled that need semantic analysis
        ast_summary = self.parser.extract_ast_summary(workflow_data)
        
        # Minimizing payload
        payload = {
            "workflow_ast": ast_summary,
            "static_findings": static_findings,
            "templates": list(self.templates_data.keys())
        }

        # Load Prompt
        prompt_path = os.path.join(os.path.dirname(__file__), "agents", "semantic_auditor_prompt.txt")
        if not os.path.exists(prompt_path):
            raise FileNotFoundError("Semantic Auditor prompt file missing.")
        
        with open(prompt_path, 'r', encoding='utf-8') as f:
            system_prompt = f.read()

        user_content = json.dumps(payload, indent=2)

        try:
            client = self._get_copilot_client()
            print("Invoking Semantic Auditor Agent...")
            response = client.request_completion(system_prompt, user_content)
            
            # Clean response from markdown json wrapper blocks if model wraps it
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()

            if not response:
                return []

            findings = json.loads(response)
            if isinstance(findings, list):
                return findings
        except Exception as e:
            print(f"Warning: Semantic Auditor Agent call failed: {e}")
        return []

    def _handle_report_mode_aggregated(self, repo_name, repo_dir, violations, workflows_dict):
        """Generates a single consolidated findings report for the entire repository."""
        # Save to .github/findings.md if .github directory exists, else directly in repo root
        github_dir = os.path.join(repo_dir, ".github")
        if os.path.exists(github_dir) and os.path.isdir(github_dir):
            report_path = os.path.join(github_dir, "findings.md")
        else:
            report_path = os.path.join(repo_dir, "findings.md")
            
        # Load Documenter Prompt
        prompt_path = os.path.join(os.path.dirname(__file__), "agents", "documenter_prompt.txt")
        with open(prompt_path, 'r', encoding='utf-8') as f:
            system_prompt = f.read()

        errors_count = sum(1 for v in violations if v.get("severity") == "error")
        warnings_count = sum(1 for v in violations if v.get("severity") == "warning")
        infos_count = sum(1 for v in violations if v.get("severity") == "info")

        payload = {
            "repository": repo_name,
            "summary": {
                "errors": errors_count,
                "warnings": warnings_count,
                "infos": infos_count,
                "total_violations": len(violations)
            },
            "violations": violations,
            "workflows": workflows_dict
        }

        try:
            client = self._get_copilot_client()
            print(f"Invoking Documenter Agent to generate consolidated report for {repo_name}...")
            report_md = client.request_completion(system_prompt, json.dumps(payload, indent=2))
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_md)
            print(f"Consolidated report generated successfully: {report_path}")
        except Exception as e:
            print(f"Warning: Failed to generate report with Documenter Agent ({e}). Falling back to static report generator...")
            static_report = ReportGenerator.generate_static_report(repo_name, violations)
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(static_report)
                print(f"Static backup report generated successfully: {report_path}")
            except Exception as read_err:
                print(f"Error: Failed to write static fallback report: {read_err}")


    def _handle_dry_run_mode(self, workflow_path, workflow_data, violations):
        """Performs remediation edits in-memory and outputs a Git-style diff."""
        print(f"Generating Git diff patch for {os.path.basename(workflow_path)}...")
        
        # Clone in-memory map
        # ruamel.yaml supports deepcopy to clone map preserving formatting structures
        import copy
        modified_data = copy.deepcopy(workflow_data)
        
        self._apply_fixes(workflow_path, modified_data, violations)
        
        # Load raw files for diff comparison
        # Dump modified map to string
        from io import StringIO
        stream = StringIO()
        self.parser.yaml.dump(workflow_data, stream)
        orig_str = stream.getvalue()
        
        stream_mod = StringIO()
        self.parser.yaml.dump(modified_data, stream_mod)
        mod_str = stream_mod.getvalue()

        # Generate Git Diff
        diff = difflib.unified_diff(
            orig_str.splitlines(keepends=True),
            mod_str.splitlines(keepends=True),
            fromfile=workflow_path,
            tofile=workflow_path + ".fixed"
        )
        
        diff_output = "".join(diff)
        if diff_output:
            print("\n=== Proposed Changes (Dry-Run Patch) ===")
            print(diff_output)
        else:
            print("No structural changes required. File matches standard policies.")

    def _handle_fix_mode(self, workflow_path, workflow_data, violations):
        """Applies programmatic changes and runs LLM self-correcting Fix loop on disk."""
        print(f"Remediating violations in-place for {os.path.basename(workflow_path)}...")
        
        self._apply_fixes(workflow_path, workflow_data, violations)
        
        # Self-correction check: dump and parse again
        from io import StringIO
        stream = StringIO()
        try:
            self.parser.yaml.dump(workflow_data, stream)
            rendered_str = stream.getvalue()
            # Verify parsed output is valid YAML structure
            self.parser.yaml.load(rendered_str)
            # Write back
            self.parser.save_workflow(workflow_path, workflow_data)
            print("Remediation completed and written to disk safely.")
        except Exception as e:
            print(f"Error: Parser validation failed after remediation fixes: {e}. Changes aborted to prevent corruption.")

    def _apply_fixes(self, workflow_path, data, violations):
        """Orchestrates standard programmatic fixes (0 cost) and routes complex ones to Fixer LLM."""
        # 1. Programmatic Fixes (SHA Pinning, GitLab standard replacements, Windows Shell bash insertion)
        self._apply_programmatic_fixes(data, violations)
        
        # 2. Complex step fixes utilizing Fixer Agent
        complex_violations = [v for v in violations if v.get("rule") in ["unbound-secrets", "coverity-scan", "bdba-scan"]]
        if complex_violations:
            self._apply_llm_fixer_loop(data, complex_violations)

    def _apply_programmatic_fixes(self, data, violations):
        # Cache standard conversions to prevent duplicate checks
        for violation in violations:
            rule_id = violation.get("rule")
            location = violation.get("location", "")
            original = violation.get("original", "")

            # A. Enforce Action Pinning to Commit SHA
            if rule_id == "pin-action-sha" and "steps" in location:
                # E.g. location: jobs.build.steps[2]
                self._programmatic_pin_sha(data, location, original)

            # B. Standard GitLab Variable Replacements
            elif rule_id == "residual-gitlab-vars" and "steps" in location:
                self._programmatic_replace_gitlab_vars(data, location, original)

            # C. Windows Runner Shell bash parameter mapping
            elif rule_id == "runner-shell-misalignment" and "steps" in location:
                self._programmatic_inject_bash_shell(data, location)

            # D. Least Privilege Default token permission insertion
            elif rule_id == "least-privilege-token":
                # Inject default read-only permissions block at workflow level
                if "permissions" not in data or data["permissions"] == "write-all":
                    # ruamel.yaml handles CommentsMap directly
                    data["permissions"] = {"contents": "read"}

            # E. Concurrency Groups
            elif rule_id == "concurrency-control":
                if "concurrency" not in data:
                    data["concurrency"] = {
                        "group": "${{ github.workflow }}-${{ github.ref }}",
                        "cancel-in-progress": True
                    }

    def _programmatic_pin_sha(self, data, location, original_uses):
        # Extract job_id and step index
        # location format: jobs.job_name.steps[idx]
        job_id, step_idx = self._parse_location(location)
        if job_id is None or step_idx is None:
            return

        step = data["jobs"][job_id]["steps"][step_idx]
        
        parts = original_uses.split("@")
        action_name = parts[0]
        tag = parts[1] if len(parts) > 1 else "main"

        # Resolve tag to SHA via GitHub API (graceful optional client check)
        sha = self.static_analyzer.fetch_latest_sha(action_name, tag)
        if sha:
            # Replace tag with SHA and append comment
            step["uses"] = f"{action_name}@{sha}"
            # ruamel.yaml allows attaching comments to mappings, but standard replacement is cleaner.
            # E.g., we set it to string uses: actions/checkout@SHA # tag
            # Because ruamel.yaml preserves raw values, setting step["uses"] updates the field cleanly.
            # To add an inline comment, we can use:
            # step.yaml_add_eol_comment(f" {tag}", key="uses")
            try:
                step.yaml_add_eol_comment(f" {tag}", key="uses")
            except Exception:
                # If yaml comments fail to bind, fallback to basic tag string
                step["uses"] = f"{action_name}@{sha} # {tag}"

    def _programmatic_replace_gitlab_vars(self, data, location, original_var):
        job_id, step_idx = self._parse_location(location)
        if job_id is None or step_idx is None:
            return

        step = data["jobs"][job_id]["steps"][step_idx]
        run_cmd = step.get("run")
        if not run_cmd or not isinstance(run_cmd, str):
            return

        # Variable conversions mapping
        mappings = {
            "$CI_PROJECT_NAME": "${{ github.event.repository.name }}",
            "${CI_PROJECT_NAME}": "${{ github.event.repository.name }}",
            "$CI_COMMIT_SHA": "${{ github.sha }}",
            "${CI_COMMIT_SHA}": "${{ github.sha }}",
            "$CI_COMMIT_REF_NAME": "${{ github.ref_name }}",
            "${CI_COMMIT_REF_NAME}": "${{ github.ref_name }}",
            "$CI_PIPELINE_ID": "${{ github.run_id }}",
            "${CI_PIPELINE_ID}": "${{ github.run_id }}",
            "$CI_PROJECT_DIR": "${{ github.workspace }}",
            "${CI_PROJECT_DIR}": "${{ github.workspace }}"
        }

        replacement = mappings.get(original_var)
        if replacement:
            step["run"] = run_cmd.replace(original_var, replacement)

    def _programmatic_inject_bash_shell(self, data, location):
        job_id, step_idx = self._parse_location(location)
        if job_id is None or step_idx is None:
            return
        step = data["jobs"][job_id]["steps"][step_idx]
        step["shell"] = "bash"

    def _apply_llm_fixer_loop(self, data, violations):
        """Invokes the Fixer Agent to rewrite complex step parameters with syntax validation loop (to-and-fro)."""
        prompt_path = os.path.join(os.path.dirname(__file__), "agents", "fixer_prompt.txt")
        with open(prompt_path, 'r', encoding='utf-8') as f:
            system_prompt = f.read()

        for violation in violations:
            location = violation.get("location", "")
            job_id, step_idx = self._parse_location(location)
            if job_id is None or step_idx is None:
                continue

            step = data["jobs"][job_id]["steps"][step_idx]

            payload = {
                "target_block": dict(step),
                "violation": violation.get("message"),
                "templates": list(self.templates_data.values())
            }

            # Self-correcting validation loop
            for attempt in range(3):
                try:
                    client = self._get_copilot_client()
                    print(f"Invoking Fixer Agent to remediate complex step at {location} (Attempt {attempt+1})...")
                    response = client.request_completion(system_prompt, json.dumps(payload, indent=2))
                    
                    response = response.strip()
                    if response.startswith("```json"):
                        response = response[7:]
                    if response.endswith("```"):
                        response = response[:-3]
                    response = response.strip()

                    fixed_step = json.loads(response)
                    if isinstance(fixed_step, dict):
                        # Merge the fixed step back into the round-trip sequentials
                        for k, v in fixed_step.items():
                            step[k] = v
                        # Check formatting dumps cleanly
                        from io import StringIO
                        test_stream = StringIO()
                        self.parser.yaml.dump(step, test_stream)
                        break  # Passed check, break retry loop
                except Exception as e:
                    print(f"Fixer Agent attempt failed: {e}")
                    payload["violation"] = f"Previous fix attempt failed with error: {str(e)}. Please correct syntax."

    def _parse_location(self, location):
        # location form: jobs.job_id.steps[step_idx]
        match = re.match(r'jobs\.([A-Za-z0-9_\-]+)\.steps\[(\d+)\]', location)
        if match:
            job_id = match.group(1)
            step_idx = int(match.group(2))
            return job_id, step_idx
        return None, None
