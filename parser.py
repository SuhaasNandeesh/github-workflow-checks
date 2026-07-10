import sys
import os

try:
    from ruamel.yaml import YAML
except ImportError:
    # Fallback to PyYAML or standard dict if ruamel.yaml is not yet installed
    # We will raise an error in production since we require ruamel.yaml
    pass

class WorkflowParser:
    def __init__(self):
        # Configure ruamel.yaml for strict round-trip preservation
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        # Ensure block sequences are printed with dash-under-indent alignment if required
        self.yaml.width = 4096  # Avoid wrapping long strings automatically

    def load_workflow(self, filepath):
        """Loads a GitHub Actions workflow file using ruamel.yaml round-trip parsing."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Workflow file not found at {filepath}")
        with open(filepath, 'r', encoding='utf-8') as f:
            return self.yaml.load(f)

    def save_workflow(self, filepath, data):
        """Saves a workflow data structure back to disk using ruamel.yaml to preserve formatting."""
        with open(filepath, 'w', encoding='utf-8') as f:
            self.yaml.dump(data, f)

    def extract_ast_summary(self, data):
        """Extracts a token-minimized JSON-serializable AST summary of the workflow data structure

        to minimize token consumption when passing workflow context to LLM agents.
        """
        if not data:
            return {}

        summary = {
            "name": data.get("name", "Unnamed Workflow"),
            "triggers": self._extract_triggers(data.get("on")),
            "concurrency": self._extract_concurrency(data.get("concurrency")),
            "global_permissions": data.get("permissions", "default"),
            "jobs": {}
        }

        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                
                summary["jobs"][job_id] = {
                    "name": job_data.get("name", job_id),
                    "runs_on": job_data.get("runs-on", "undefined"),
                    "needs": self._extract_needs(job_data.get("needs")),
                    "permissions": job_data.get("permissions", "inherited"),
                    "env_keys": list(job_data.get("env", {}).keys()) if isinstance(job_data.get("env"), dict) else [],
                    "steps": self._extract_steps_summary(job_data.get("steps", []))
                }

        return summary

    def _extract_triggers(self, on_block):
        if not on_block:
            return []
        if isinstance(on_block, str):
            return [on_block]
        if isinstance(on_block, list):
            return on_block
        if isinstance(on_block, dict):
            return list(on_block.keys())
        return ["complex_trigger"]

    def _extract_concurrency(self, concurrency_block):
        if not concurrency_block:
            return None
        if isinstance(concurrency_block, str):
            return {"group": concurrency_block}
        if isinstance(concurrency_block, dict):
            return {
                "group": concurrency_block.get("group"),
                "cancel_in_progress": concurrency_block.get("cancel-in-progress")
            }
        return "complex_concurrency"

    def _extract_needs(self, needs_block):
        if not needs_block:
            return []
        if isinstance(needs_block, str):
            return [needs_block]
        if isinstance(needs_block, list):
            return needs_block
        return []

    def _extract_steps_summary(self, steps):
        if not isinstance(steps, list):
            return []
        
        summaries = []
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            
            step_sum = {
                "index": idx,
                "name": step.get("name", f"Step {idx}"),
            }
            
            if "uses" in step:
                # E.g. actions/checkout@v4
                step_sum["uses"] = step["uses"]
                if "with" in step and isinstance(step["with"], dict):
                    # Only list the keys of the parameters passed to save tokens
                    step_sum["with_keys"] = list(step["with"].keys())
            
            if "run" in step:
                run_content = str(step["run"])
                # Extract first non-empty line of execution script or a short snippet
                lines = [line.strip() for line in run_content.split('\n') if line.strip()]
                first_line = lines[0] if lines else ""
                snippet = first_line[:80] + "..." if len(first_line) > 80 else first_line
                
                step_sum["run_snippet"] = snippet
                step_sum["run_line_count"] = len(lines)
                
                if "shell" in step:
                    step_sum["shell"] = step["shell"]
                    
            if "env" in step and isinstance(step["env"], dict):
                step_sum["env_keys"] = list(step["env"].keys())
                
            summaries.append(step_sum)
            
        return summaries
