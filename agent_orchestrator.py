"""Multi-agent orchestrator for the GitHub Actions analyzer.

Replaces the prior implementation with:
- Atomic StateDB + content-hash resume (A4, B10)
- Single source of truth for severity from .github-rules.json (B14)
- Structured logging via logging_setup (D1)
- .bak backup for fix mode (per your answer)
- No unconditional defaults; schema validation up front
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import copy
import datetime
import difflib
import io
import json
import os
import re
from pathlib import Path
from typing import Any

from copilot_client import (
    AuthenticationError,
    CopilotAPIError,
    CopilotClient,
    SSLCertificateError,
)
from logging_setup import get_logger
from parser import WorkflowParser
from reporter import ReportGenerator
from rules_schema import RulesSchemaError, validate_rules_config
from state_db import StateDB, compute_file_sha256
from static_analyzer import StaticAnalyzer

logger = get_logger()


_EXIT_OK = 0
_EXIT_VIOLATIONS = 1
_EXIT_BAD_CONFIG = 2
_EXIT_INTERNAL = 3
_EXIT_AUTH = 4
_EXIT_BUDGET = 5


class OrchestratorError(RuntimeError):
    """Base class for orchestrator-level errors."""


class ConfigError(OrchestratorError):
    """Raised when configuration loading fails."""


class FixModeRequiresForceError(OrchestratorError):
    """Raised when --mode fix is requested without --force."""


class AgentOrchestrator:
    def __init__(
        self,
        mode: str = "report",
        rules_path: str | os.PathLike[str] = ".github-rules.json",
        templates_dir: str | os.PathLike[str] = "templates",
        state_db_path: str | os.PathLike[str] = ".actions_audit_state.json",
        reset: bool = False,
        force: bool = False,
        endpoint: str | None = None,
        max_credits: int | None = None,
        output_format: str = "markdown",
        output_dir: str | os.PathLike[str] | None = None,
        parallel: int = 1,
        fail_on_violation: bool = False,
        backup: bool = True,
    ) -> None:
        self.mode = mode
        self.rules_path = Path(rules_path)
        self.templates_dir = Path(templates_dir)
        self.state_db_path = Path(state_db_path)
        self.reset = reset
        self.force = force
        self.endpoint = endpoint
        self.max_credits = max_credits
        self.output_format = output_format
        self.output_dir = Path(output_dir) if output_dir else None
        self.parallel = max(1, parallel)
        self.fail_on_violation = fail_on_violation
        self.backup = backup

        if self.mode == "fix" and not self.force:
            raise FixModeRequiresForceError(
                "--mode fix overwrites files. Re-run with --force to acknowledge."
            )

        self.parser = WorkflowParser()
        self.rules_config = self._load_rules_config()
        self.static_analyzer = StaticAnalyzer(
            rules_config=self.rules_config,
            token=os.environ.get("GITHUB_TOKEN") or os.environ.get("COPILOT_TOKEN"),
            endpoint=self.endpoint,
        )
        self.templates_data = self._load_templates()
        self.state_db = StateDB(self.state_db_path, reset=self.reset)
        self.copilot: CopilotClient | None = None
        self._credits_used: int = 0
        import threading as _threading
        self._credits_lock = _threading.Lock()

    def _check_budget(self) -> None:
        """Raise _EXIT_BUDGET if credit budget is exhausted."""
        if self.max_credits is not None and self._credits_used >= self.max_credits:
            raise OrchestratorError(
                f"Credit budget exhausted ({self._credits_used}/{self.max_credits}). "
                "Aborting to prevent further LLM calls."
            )

    def _record_credits(self, count: int = 1) -> None:
        """Increment the credits-used counter (thread-safe)."""
        with self._credits_lock:
            self._credits_used += count

    def _load_rules_config(self) -> dict[str, Any]:
        if not self.rules_path.exists():
            raise ConfigError(
                f"Rules configuration not found at {self.rules_path}. "
                "Pass --config to point at the correct file."
            )
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {self.rules_path}: {e}") from e
        except OSError as e:
            raise ConfigError(f"Could not read {self.rules_path}: {e}") from e
        try:
            validate_rules_config(config)
        except RulesSchemaError as e:
            raise ConfigError(str(e)) from e
        return config

    def _load_templates(self) -> dict[str, str]:
        templates: dict[str, str] = {}
        if not self.templates_dir.exists() or not self.templates_dir.is_dir():
            return templates
        for filename in sorted(os.listdir(self.templates_dir)):
            if not (filename.endswith(".yml") or filename.endswith(".yaml")):
                continue
            filepath = self.templates_dir / filename
            try:
                templates[filename] = filepath.read_text(encoding="utf-8")
            except OSError as e:
                logger.warning("Could not read template %s: %s", filepath, e)
        return templates

    def _resolve_severity(self, rule_id: str) -> str:
        """Single source of truth for severity resolution (B14)."""
        rule_info = self.rules_config.get("rules", {}).get(rule_id)
        if isinstance(rule_info, dict):
            return rule_info.get("severity", "warning")
        if isinstance(rule_info, str):
            return rule_info
        return "warning"

    def _is_semantic_rule(self, rule_id: str) -> bool:
        rule_info = self.rules_config.get("rules", {}).get(rule_id)
        if isinstance(rule_info, dict):
            return bool(rule_info.get("semantic", False))
        return False

    def _semantic_rules_active(self) -> bool:
        return any(
            self._is_semantic_rule(rid) for rid in self.rules_config.get("rules", {})
        )

    def _get_copilot_client(self) -> CopilotClient:
        if self.copilot is None:
            self.copilot = CopilotClient.from_config(
                rules_config=self.rules_config,
                cli_endpoint=self.endpoint,
            )
        return self.copilot

    def close(self) -> None:
        self.state_db.close()

    def __enter__(self) -> "AgentOrchestrator":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def run_on_directory(self, target_dir: str | os.PathLike[str]) -> int:
        target = Path(target_dir)
        if not target.exists():
            raise FileNotFoundError(f"Target directory not found: {target}")

        logger.info("Initiating pipeline scan on: %s", target)
        logger.info("Running in mode: %s", self.mode.upper())

        workflows = self._discover_workflows(target)
        if not workflows:
            logger.warning(
                "No GitHub Actions workflows discovered in %s "
                "(expected nested .github/workflows directories).",
                target,
            )
            return _EXIT_OK

        logger.info("Discovered %d workflow file(s) for analysis.", len(workflows))

        results: dict[str, int | str] = {}
        repo_data: dict[str, dict[str, Any]] = {}
        import threading
        repo_data_lock = threading.Lock()

        def _process_one(workflow_path: Path) -> tuple[str, str, int | str, dict[str, Any] | None]:
            """Process a single workflow file. Returns (rel_path, repo_name, result, payload_or_None)."""
            rel_path = str(workflow_path.relative_to(target))
            repo_name = rel_path.split(os.sep)[0] if os.sep in rel_path else "root"

            try:
                mtime = workflow_path.stat().st_mtime
            except OSError:
                mtime = 0.0

            try:
                content_sha = compute_file_sha256(workflow_path)
            except OSError as e:
                logger.warning("Could not hash %s: %s", workflow_path, e)
                content_sha = ""

            if self.state_db.should_skip(rel_path, mtime, content_sha):
                entry = self.state_db.get(rel_path) or {}
                logger.info("Skipping already processed workflow (resume mode): %s", rel_path)
                return rel_path, repo_name, entry.get("violations_count", 0), entry

            logger.info("Processing: %s (Repository: %s)", rel_path, repo_name)

            try:
                workflow_data = self.parser.load_workflow(workflow_path)
            except Exception as e:
                logger.error("Failed to parse %s: %s", rel_path, e)
                self.state_db.record(rel_path, mtime, content_sha, {
                    "status": "failed",
                    "error": str(e),
                    "timestamp": _utcnow_iso(),
                })
                self.state_db.flush()
                return rel_path, repo_name, "Failed", None

            try:
                violations = self.static_analyzer.analyze_workflow(workflow_path, workflow_data)
                semantic = self._run_semantic_audit(workflow_data, violations, repo_name)
                violations.extend(semantic)
                filtered = self._filter_suppressions(violations, repo_name)

                if self.mode == "dry-run":
                    self._handle_dry_run_mode(workflow_path, workflow_data, filtered)
                elif self.mode == "fix":
                    self._handle_fix_mode(workflow_path, workflow_data, filtered)

                payload = {
                    "status": "completed",
                    "violations_count": len(filtered),
                    "violations": filtered,
                    "workflow_ast": self.parser.extract_ast_summary(workflow_data),
                    "timestamp": _utcnow_iso(),
                }
                self.state_db.record(rel_path, mtime, content_sha, payload)
                self.state_db.flush()
                return rel_path, repo_name, len(filtered), payload
            except Exception as e:
                logger.error("Error processing %s: %s", rel_path, e)
                self.state_db.record(rel_path, mtime, content_sha, {
                    "status": "failed",
                    "error": str(e),
                    "timestamp": _utcnow_iso(),
                })
                self.state_db.flush()
                return rel_path, repo_name, "Failed", None

        if self.parallel > 1:
            logger.info("Processing workflows with %d workers.", self.parallel)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as pool:
                futures = {pool.submit(_process_one, wp): wp for wp in workflows}
                for fut in concurrent.futures.as_completed(futures):
                    rel_path, repo_name, result, payload = fut.result()
                    results[rel_path] = result
                    if self.mode == "report" and payload is not None:
                        with repo_data_lock:
                            self._merge_into_repo_data(
                                repo_data, target, repo_name, rel_path, payload
                            )
        else:
            for workflow_path in workflows:
                rel_path, repo_name, result, payload = _process_one(workflow_path)
                results[rel_path] = result
                if self.mode == "report" and payload is not None:
                    self._merge_into_repo_data(
                        repo_data, target, repo_name, rel_path, payload
                    )

        if self.mode == "report":
            for r_name, r_info in repo_data.items():
                self._handle_report_mode_aggregated(
                    r_name, r_info["repo_dir"], r_info["violations"], r_info["workflows"]
                )

        # Print summary
        logger.info("=== Scan Complete ===")
        for path, count in results.items():
            if isinstance(count, int):
                logger.info("- %s: %d violations", path, count)
            else:
                logger.warning("- %s: %s", path, count)

        if self.fail_on_violation:
            total = sum(v for v in results.values() if isinstance(v, int))
            if total > 0:
                logger.info("Failing because --fail-on-violation set (%d total).", total)
                return _EXIT_VIOLATIONS
        return _EXIT_OK

    def _discover_workflows(self, target: Path) -> list[Path]:
        workflows: list[Path] = []
        for root, dirs, files in os.walk(target):
            normalized = os.path.normpath(root)
            if os.path.join(".github", "workflows") in normalized:
                for filename in sorted(files):
                    if filename.endswith(".yml") or filename.endswith(".yaml"):
                        workflows.append(Path(root) / filename)
        return workflows

    def _merge_into_repo_data(
        self,
        repo_data: dict[str, dict[str, Any]],
        target: Path,
        repo_name: str,
        rel_path: str,
        entry: dict[str, Any],
    ) -> None:
        if repo_name not in repo_data:
            repo_dir = target if repo_name == ".github" else (target / repo_name)
            repo_data[repo_name] = {
                "repo_dir": str(repo_dir),
                "violations": [],
                "workflows": {},
            }
        for v in entry.get("violations", []):
            v_copy = dict(v)
            v_copy["file"] = rel_path
            repo_data[repo_name]["violations"].append(v_copy)
        repo_data[repo_name]["workflows"][rel_path] = entry.get("workflow_ast", {})

    def _filter_suppressions(
        self, violations: list[dict[str, Any]], repo_name: str
    ) -> list[dict[str, Any]]:
        global_suppressions = set(
            self.rules_config.get("suppressions", {}).get("global", [])
        )
        repo_suppressions = set(
            self.rules_config.get("suppressions", {}).get("by_repository", {}).get(
                repo_name, []
            )
        )

        filtered: list[dict[str, Any]] = []
        for v in violations:
            rule_id = v.get("rule", "")
            if rule_id in global_suppressions or rule_id in repo_suppressions:
                continue
            severity = self._resolve_severity(rule_id)
            if severity == "ignore":
                continue
            v["severity"] = severity
            filtered.append(v)
        return filtered

    def _run_semantic_audit(
        self,
        workflow_data: Any,
        static_findings: list[dict[str, Any]],
        repo_name: str,
    ) -> list[dict[str, Any]]:
        """Invoke the LLM semantic auditor only if any semantic rule is active (B1)."""
        if not self._semantic_rules_active():
            return []

        prompt_path = Path(__file__).parent / "agents" / "semantic_auditor_prompt.txt"
        if not prompt_path.exists():
            logger.warning("Semantic Auditor prompt file missing at %s", prompt_path)
            return []
        system_prompt = prompt_path.read_text(encoding="utf-8")

        ast_summary = self.parser.extract_ast_summary(workflow_data)
        payload = {
            "workflow_ast": ast_summary,
            "static_findings": static_findings,
            "templates": [
                {"name": name, "content": content}
                for name, content in self.templates_data.items()
            ],
        }

        try:
            client = self._get_copilot_client()
            self._check_budget()
            logger.info("Invoking Semantic Auditor Agent...")
            response = client.request_completion(system_prompt, json.dumps(payload, indent=2))
            self._record_credits()
        except OrchestratorError:
            raise
        except (SSLCertificateError, AuthenticationError, CopilotAPIError) as e:
            logger.warning("Semantic Auditor Agent call failed: %s", e)
            return []
        except Exception as e:  # defensive
            logger.warning("Semantic Auditor Agent call failed: %s", e)
            return []

        cleaned = _strip_markdown_fence(response)
        try:
            findings = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning(
                "Semantic Auditor returned non-JSON; ignoring. Snippet: %r",
                response[:200],
            )
            return []
        if isinstance(findings, list):
            return findings
        return []

    def _handle_report_mode_aggregated(
        self,
        repo_name: str,
        repo_dir: str,
        violations: list[dict[str, Any]],
        workflows_dict: dict[str, Any],
    ) -> None:
        repo_dir_path = Path(repo_dir)
        github_dir = repo_dir_path / ".github"
        report_dir = github_dir if github_dir.is_dir() else repo_dir_path
        report_path = report_dir / "findings.md"

        errors = sum(1 for v in violations if v.get("severity") == "error")
        warnings = sum(1 for v in violations if v.get("severity") == "warning")
        infos = sum(1 for v in violations if v.get("severity") == "info")

        payload = {
            "repository": repo_name,
            "summary": {
                "errors": errors,
                "warnings": warnings,
                "infos": infos,
                "total_violations": len(violations),
            },
            "violations": violations,
            "workflows": workflows_dict,
        }

        if self.output_format == "sarif":
            content = ReportGenerator.generate_sarif(repo_name, violations)
            target = self._resolve_output_path(report_path, "findings.sarif.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            logger.info("SARIF report written to %s", target)
            return

        if self.output_format == "junit":
            content = ReportGenerator.generate_junit(repo_name, violations)
            target = self._resolve_output_path(report_path, "findings.junit.xml")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            logger.info("JUnit report written to %s", target)
            return

        # markdown (default)
        prompt_path = Path(__file__).parent / "agents" / "documenter_prompt.txt"
        markdown: str
        used_llm = False
        if prompt_path.exists():
            try:
                system_prompt = prompt_path.read_text(encoding="utf-8")
                client = self._get_copilot_client()
                self._check_budget()
                logger.info(
                    "Invoking Documenter Agent for consolidated report of %s...",
                    repo_name,
                )
                markdown = client.request_completion(
                    system_prompt, json.dumps(payload, indent=2)
                )
                self._record_credits()
                used_llm = True
            except OrchestratorError:
                raise
            except (SSLCertificateError, AuthenticationError, CopilotAPIError) as e:
                logger.warning("Documenter Agent failed (%s); using static fallback.", e)
                markdown = ReportGenerator.generate_static_report(repo_name, violations)
            except Exception as e:
                logger.warning("Documenter Agent failed (%s); using static fallback.", e)
                markdown = ReportGenerator.generate_static_report(repo_name, violations)
        else:
            logger.warning("Documenter prompt missing; using static fallback.")
            markdown = ReportGenerator.generate_static_report(repo_name, violations)

        target = self._resolve_output_path(report_path, "findings.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown, encoding="utf-8")
        logger.info(
            "Markdown report written to %s (source=%s)", target,
            "llm" if used_llm else "static",
        )

    def _resolve_output_path(self, default: Path, filename: str) -> Path:
        if self.output_dir is None:
            return default
        return self.output_dir / filename

    def _handle_dry_run_mode(
        self,
        workflow_path: Path,
        workflow_data: Any,
        violations: list[dict[str, Any]],
    ) -> None:
        logger.info("Generating Git diff patch for %s...", workflow_path.name)

        modified_data = copy.deepcopy(workflow_data)
        self._apply_programmatic_fixes(modified_data, violations)

        orig_stream = io.StringIO()
        self.parser.yaml.dump(workflow_data, orig_stream)
        orig_str = orig_stream.getvalue()

        mod_stream = io.StringIO()
        self.parser.yaml.dump(modified_data, mod_stream)
        mod_str = mod_stream.getvalue()

        diff = difflib.unified_diff(
            orig_str.splitlines(keepends=True),
            mod_str.splitlines(keepends=True),
            fromfile=str(workflow_path),
            tofile=f"{workflow_path}.fixed",
        )
        diff_output = "".join(diff)
        if diff_output:
            print("=== Proposed Changes (Dry-Run Patch) ===")
            print(diff_output)
        else:
            logger.info("No structural changes required for %s.", workflow_path.name)

    def _handle_fix_mode(
        self,
        workflow_path: Path,
        workflow_data: Any,
        violations: list[dict[str, Any]],
    ) -> None:
        logger.info("Remediating violations in-place for %s...", workflow_path.name)

        self._apply_programmatic_fixes(workflow_data, violations)

        stream = io.StringIO()
        try:
            self.parser.yaml.dump(workflow_data, stream)
            rendered = stream.getvalue()
            self.parser.yaml.load(rendered)
        except Exception as e:
            logger.error("Parser validation failed post-remediation: %s", e)
            logger.error("Aborting to prevent corruption; no file written.")
            return

        if self.backup:
            backup_path = workflow_path.with_suffix(workflow_path.suffix + ".bak")
            try:
                backup_path.write_text(
                    workflow_path.read_text(encoding="utf-8"), encoding="utf-8"
                )
                logger.info("Backup written to %s", backup_path)
            except OSError as e:
                logger.error("Failed to create backup at %s: %s", backup_path, e)
                return

        try:
            self.parser.save_workflow(workflow_path, workflow_data)
            logger.info("Remediation written to %s", workflow_path)
        except OSError as e:
            logger.error("Failed to write %s: %s", workflow_path, e)

    def _apply_programmatic_fixes(
        self, data: Any, violations: list[dict[str, Any]]
    ) -> None:
        for violation in violations:
            rule_id = violation.get("rule")
            location = violation.get("location", "")
            original = violation.get("original", "")

            if rule_id == "pin-action-sha" and "steps" in location:
                self._programmatic_pin_sha(data, location, original)
            elif rule_id == "residual-gitlab-vars" and "steps" in location:
                self._programmatic_replace_gitlab_vars(data, location, original)
            elif rule_id == "runner-shell-misalignment" and "steps" in location:
                self._programmatic_inject_bash_shell(data, location)
            elif rule_id == "least-privilege-token":
                self._programmatic_set_least_privilege(data)
            elif rule_id == "concurrency-control":
                self._programmatic_set_concurrency(data)

    def _programmatic_set_least_privilege(self, data: Any) -> None:
        existing = data.get("permissions")
        if existing is None:
            data["permissions"] = {"contents": "read"}
            return
        if isinstance(existing, str) and existing == "write-all":
            data["permissions"] = {"contents": "read"}
            return
        if isinstance(existing, dict) and "contents" not in existing:
            existing["contents"] = "read"

    def _programmatic_set_concurrency(self, data: Any) -> None:
        if "concurrency" not in data:
            data["concurrency"] = {
                "group": "${{ github.workflow }}-${{ github.ref }}",
                "cancel-in-progress": True,
            }

    def _programmatic_pin_sha(
        self, data: Any, location: str, original_uses: str
    ) -> None:
        job_id, step_idx = _parse_location(location)
        if job_id is None or step_idx is None:
            return

        try:
            step = data["jobs"][job_id]["steps"][step_idx]
        except (KeyError, IndexError, TypeError):
            return

        if "@" not in original_uses:
            return
        action_name, tag = original_uses.split("@", 1)
        sha = self.static_analyzer.fetch_latest_sha(action_name, tag)
        if not sha:
            logger.warning(
                "Could not resolve SHA for %s@%s; leaving step unchanged.",
                action_name, tag,
            )
            return
        step["uses"] = f"{action_name}@{sha}"
        try:
            step.yaml_add_eol_comment(f" {tag}", key="uses")
        except Exception as e:
            logger.debug("Could not attach EOL comment to uses: %s", e)

    def _programmatic_replace_gitlab_vars(
        self, data: Any, location: str, original_var: str
    ) -> None:
        job_id, step_idx = _parse_location(location)
        if job_id is None or step_idx is None:
            return
        try:
            step = data["jobs"][job_id]["steps"][step_idx]
        except (KeyError, IndexError, TypeError):
            return
        run_cmd = step.get("run")
        if not run_cmd or not isinstance(run_cmd, str):
            return
        replacement = GITLAB_VAR_MAP.get(original_var)
        if not replacement or original_var not in run_cmd:
            return
        # Use word-boundary-aware replacement so that, e.g.,
        # $CI_PROJECT_NAME_BACKUP is not partially rewritten.
        # Construct a pattern that matches $VAR or ${VAR} but is anchored
        # against trailing identifier characters.
        body = original_var.lstrip("$").rstrip("}").lstrip("{")
        pattern = re.compile(
            r"\$\{?" + re.escape(body) + r"\}?(?![A-Za-z0-9_])"
        )
        step["run"] = pattern.sub(replacement, run_cmd)

    def _programmatic_inject_bash_shell(self, data: Any, location: str) -> None:
        job_id, step_idx = _parse_location(location)
        if job_id is None or step_idx is None:
            return
        try:
            step = data["jobs"][job_id]["steps"][step_idx]
        except (KeyError, IndexError, TypeError):
            return
        step["shell"] = "bash"


GITLAB_VAR_MAP: dict[str, str] = {
    "$CI_PROJECT_NAME": "${{ github.event.repository.name }}",
    "${CI_PROJECT_NAME}": "${{ github.event.repository.name }}",
    "$CI_COMMIT_SHA": "${{ github.sha }}",
    "${CI_COMMIT_SHA}": "${{ github.sha }}",
    "$CI_COMMIT_REF_NAME": "${{ github.ref_name }}",
    "${CI_COMMIT_REF_NAME}": "${{ github.ref_name }}",
    "$CI_COMMIT_BRANCH": "${{ github.ref_name }}",
    "${CI_COMMIT_BRANCH}": "${{ github.ref_name }}",
    "$CI_COMMIT_TAG": "${{ github.ref_name }}",
    "${CI_COMMIT_TAG}": "${{ github.ref_name }}",
    "$CI_PIPELINE_ID": "${{ github.run_id }}",
    "${CI_PIPELINE_ID}": "${{ github.run_id }}",
    "$CI_PIPELINE_IID": "${{ github.run_number }}",
    "${CI_PIPELINE_IID}": "${{ github.run_number }}",
    "$CI_PROJECT_DIR": "${{ github.workspace }}",
    "${CI_PROJECT_DIR}": "${{ github.workspace }}",
    "$CI_JOB_NAME": "${{ github.job }}",
    "${CI_JOB_NAME}": "${{ github.job }}",
    "$CI_REGISTRY_USER": "${{ github.actor }}",
    "${CI_REGISTRY_USER}": "${{ github.actor }}",
    "$CI_DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
    "${CI_DEFAULT_BRANCH}": "${{ github.event.repository.default_branch }}",
}


def _parse_location(location: str) -> tuple[str | None, int | None]:
    match = re.match(r'jobs\.([A-Za-z0-9_\-]+)\.steps\[(\d+)\]', location)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def _utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _strip_markdown_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        else:
            text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()
