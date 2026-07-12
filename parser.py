import sys
import os

try:
    from ruamel.yaml import YAML
except ImportError:
    raise ImportError(
        "ruamel.yaml is required for workflow round-trip parsing. "
        "Install it with: pip install ruamel.yaml"
    )

class WorkflowParseError(ValueError):
    """Raised when a workflow file cannot be parsed."""


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
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return self.yaml.load(f)
        except UnicodeDecodeError as e:
            raise WorkflowParseError(
                f"Workflow file {filepath} is not valid UTF-8: {e}"
            ) from e
        except Exception as e:
            raise WorkflowParseError(
                f"Failed to parse workflow {filepath}: {e}"
            ) from e

    def save_workflow(self, filepath, data):
        """Saves a workflow data structure back to disk atomically.

        Writes to a sibling temp file first, fsyncs, then ``os.replace`` onto
        the target path so a crash mid-write never leaves a truncated/corrupted
        workflow file (the previous file is either intact or fully replaced).
        """
        tmp_path = f"{filepath}.tmp"
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                self.yaml.dump(data, f)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync is best-effort on some filesystems / platforms.
                    pass
            os.replace(tmp_path, filepath)
        except Exception:
            # Clean up the temp file on any failure so we never leave a stale
            # ``<file>.tmp`` behind. Swallow the unlink error (file may not exist).
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def extract_ast_summary(self, data, *, flagged_step_locations=None):
        """Extracts a token-minimized JSON-serializable AST summary of the workflow.

        ``flagged_step_locations`` is an optional set of step location strings
        (e.g. ``{"jobs.build.steps[2]"}``) produced by the static analyzer. For
        *flagged* steps the FULL ``run`` content and ``with``/``env`` *values*
        are included so the LLM semantic auditor can see every line (preventing
        detail loss / missed findings). For unflagged steps only keys/snippets
        are included to minimize token cost. This targeted-context approach
        keeps credit usage low without sacrificing audit fidelity.
        """
        if not data:
            return {}

        flagged = set(flagged_step_locations or ())
        summary = {
            "name": data.get("name", "Unnamed Workflow"),
            "triggers": self._extract_triggers(data.get("on")),
            "concurrency": self._extract_concurrency(data.get("concurrency")),
            "global_permissions": data.get("permissions", "default"),
            "env": data.get("env") if isinstance(data.get("env"), dict) else {},
            "run_name": data.get("run-name"),
            "defaults": data.get("defaults") if isinstance(data.get("defaults"), dict) else {},
            "jobs": {}
        }

        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue

                job_summary = {
                    "name": job_data.get("name", job_id),
                    "runs_on": job_data.get("runs-on", "undefined"),
                    "needs": self._extract_needs(job_data.get("needs")),
                    "if": job_data.get("if"),
                    "permissions": job_data.get("permissions", "inherited"),
                    "environment": job_data.get("environment"),
                    "timeout_minutes": job_data.get("timeout-minutes"),
                    "continue_on_error": job_data.get("continue-on-error"),
                    "concurrency": self._extract_concurrency(job_data.get("concurrency")),
                    "env_keys": list(job_data.get("env", {}).keys()) if isinstance(job_data.get("env"), dict) else [],
                    "services": job_data.get("services") if isinstance(job_data.get("services"), dict) else None,
                    "container": job_data.get("container") if isinstance(job_data.get("container"), dict) else None,
                    "strategy": self._extract_strategy(job_data.get("strategy")),
                    "steps": self._extract_steps_summary(
                        job_data.get("steps", []),
                        job_id=job_id,
                        flagged=flagged,
                    )
                }
                # Drop None-valued keys to keep payloads compact.
                summary["jobs"][job_id] = {
                    k: v for k, v in job_summary.items() if v is not None
                }

        return summary

    def _extract_strategy(self, strategy_block):
        if not isinstance(strategy_block, dict):
            return None
        out = {}
        if "matrix" in strategy_block:
            out["matrix"] = strategy_block["matrix"]
        if "fail-fast" in strategy_block:
            out["fail_fast"] = strategy_block["fail-fast"]
        if "max-parallel" in strategy_block:
            out["max_parallel"] = strategy_block["max-parallel"]
        return out or None

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

    def _extract_steps_summary(self, steps, *, job_id=None, flagged=None):
        if not isinstance(steps, list):
            return []
        flagged = flagged or set()

        summaries = []
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            location = f"jobs.{job_id}.steps[{idx}]"
            is_flagged = location in flagged
            step_sum = {
                "index": idx,
                "name": step.get("name", f"Step {idx}"),
                "if": step.get("if"),
                "timeout_minutes": step.get("timeout-minutes"),
                "continue_on_error": step.get("continue-on-error"),
            }

            if "uses" in step:
                # E.g. actions/checkout@v4
                step_sum["uses"] = step["uses"]
                if "with" in step and isinstance(step["with"], dict):
                    if is_flagged:
                        # Full values so the LLM can evaluate the offending step.
                        step_sum["with"] = dict(step["with"])
                    else:
                        step_sum["with_keys"] = list(step["with"].keys())

            if "run" in step:
                run_content = str(step["run"])
                if is_flagged:
                    # Full script content for flagged steps — do NOT truncate,
                    # otherwise the LLM cannot see violations on later lines.
                    step_sum["run"] = run_content
                else:
                    lines = [line.strip() for line in run_content.split('\n') if line.strip()]
                    first_line = lines[0] if lines else ""
                    snippet = first_line[:80] + "..." if len(first_line) > 80 else first_line
                    step_sum["run_snippet"] = snippet
                    step_sum["run_line_count"] = len(lines)
                if "shell" in step:
                    step_sum["shell"] = step["shell"]

            if "env" in step and isinstance(step["env"], dict):
                if is_flagged:
                    step_sum["env"] = dict(step["env"])
                else:
                    step_sum["env_keys"] = list(step["env"].keys())

            # Keep payloads compact.
            summaries.append({
                k: v for k, v in step_sum.items() if v is not None
            })

        return summaries
