"""Tests for PR 4: Prompts, reporter completeness, SARIF location parsing."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from reporter import ReportGenerator, _parse_location_line


FIXER_PROMPT = Path(__file__).resolve().parent.parent / "agents" / "fixer_prompt.txt"
AUDITOR_PROMPT = Path(__file__).resolve().parent.parent / "agents" / "semantic_auditor_prompt.txt"
DOCUMENTER_PROMPT = Path(__file__).resolve().parent.parent / "agents" / "documenter_prompt.txt"


# ── Prompt file validation ────────────────────────────────────────────────────


class TestPromptsExist:
    def test_fixer_prompt_exists(self):
        assert FIXER_PROMPT.is_file(), f"Missing: {FIXER_PROMPT}"

    def test_auditor_prompt_exists(self):
        assert AUDITOR_PROMPT.is_file(), f"Missing: {AUDITOR_PROMPT}"

    def test_documenter_prompt_exists(self):
        assert DOCUMENTER_PROMPT.is_file(), f"Missing: {DOCUMENTER_PROMPT}"


class TestFixerPromptSchema:
    """Validate that the fixer prompt instructs the LLM to emit JSON Patch (RFC 6902)."""

    def _load(self) -> str:
        return FIXER_PROMPT.read_text()

    def test_mentions_json_patch(self):
        text = self._load()
        assert "JSON Patch" in text, "Fixer prompt must reference JSON Patch (RFC 6902)."

    def test_mentions_rfc_6902(self):
        text = self._load()
        assert "RFC 6902" in text, "Fixer prompt must cite RFC 6902."

    def test_valid_ops_only(self):
        """Prompt must only list valid JSON Patch operations."""
        text = self._load().lower()
        for op in ("replace", "add", "remove"):
            assert f'"{op}"' in text or f"'{op}'" in text, f"Fixer prompt must list op '{op}'."

    def test_valid_paths_documented(self):
        text = self._load()
        for path in ("/name", "/uses", "/run", "/shell", "/env/", "/with/", "/if", "/timeout-minutes"):
            assert path in text, f"Fixer prompt must document path '{path}'."

    def test_few_shot_examples_present(self):
        text = self._load()
        assert "Few-shot" in text or "few-shot" in text.lower(), "Fixer prompt must include few-shot examples."


class TestAuditorPromptSchema:
    def _load(self) -> str:
        return AUDITOR_PROMPT.read_text()

    def test_mentions_json_schema(self):
        text = self._load()
        assert "JSON" in text and ("schema" in text.lower() or "Schema" in text), \
            "Auditor prompt must reference JSON Schema."

    def test_severity_enum(self):
        # Phase 1: the semantic auditor no longer emits severities (they are
        # owned by .github-rules.json). Instead it must reference the rules list.
        text = self._load()
        assert "rules" in text.lower(), "Auditor prompt must reference the active rules list."
        assert "severity" in text.lower() or "Severity" in text, (
            "Auditor prompt must note that severity is not emitted by the LLM."
        )

    def test_few_shot_present(self):
        text = self._load()
        assert "few-shot" in text.lower() or "Few-shot" in text, "Auditor prompt must include few-shot examples."


class TestDocumenterPromptSchema:
    def _load(self) -> str:
        return DOCUMENTER_PROMPT.read_text()

    def test_mentions_jobs_array(self):
        text = self._load()
        # Documenter prompt now emits Markdown and references per-job sections.
        assert "jobs" in text.lower() or "Jobs" in text, "Documenter prompt must reference jobs."

    def test_few_shot_present(self):
        text = self._load()
        assert "few-shot" in text.lower() or "Few-shot" in text, "Documenter prompt must include few-shot examples."


# ── SARIF location parsing ────────────────────────────────────────────────────


class TestParseLocationLine:
    def test_extracts_step_index(self):
        assert _parse_location_line("jobs.build.steps[3]") == 4  # 1-based

    def test_step_zero(self):
        assert _parse_location_line("jobs.build.steps[0]") == 1

    def test_no_steps_returns_none(self):
        assert _parse_location_line("jobs.build") is None

    def test_empty_string(self):
        assert _parse_location_line("") is None

    def test_none_input(self):
        assert _parse_location_line(None) is None  # type: ignore[arg-type]


# ── Reporter completeness ─────────────────────────────────────────────────────


class TestReporterUncategorized:
    """Uncategorized violations (severity not in error/warning/info) must appear in the report."""

    def test_uncategorized_violations_rendered(self):
        violations = [
            {"rule": "test-rule", "location": "jobs.x.steps[0]", "message": "something", "severity": "debug"},
        ]
        md = ReportGenerator.generate_static_report("repo", violations)
        assert "test-rule" in md
        assert "Other Findings" in md  # the uncategorized section header

    def test_uncategorized_not_empty(self):
        violations = [
            {"rule": "a", "location": "l", "message": "m", "severity": "error"},
            {"rule": "b", "location": "l", "message": "m", "severity": "unknown"},
        ]
        md = ReportGenerator.generate_static_report("repo", violations)
        assert "a" in md
        assert "b" in md

    def test_suggestion_for_all_static_rules(self):
        """Every rule with a static suggestion must produce one (regression guard)."""
        rules_with_suggestions = [
            "pin-action-sha", "pin-setup-actions-sha", "pin-artifact-actions-sha",
            "reusable-workflow-pinned", "coverity-scan", "image-build-jfrog",
            "image-signing", "bdba-scan", "concurrency-control", "least-privilege-token",
            "oidc-cloud-deploy", "checkout-persist-credentials",
            "job-timeout-missing", "step-timeout-missing", "runner-version-pinned",
            "deprecated-set-output", "untrusted-input-injection", "submodule-recursive",
            "job-permission-escalation", "residual-gitlab-vars", "runner-shell-misalignment",
            "explicit-artifact-transfer", "unbound-secrets", "multiline-block-scalar",
            "job-dependency-cycle", "unresolved-needs", "latest-runtime-version",
            # Phase 5 new rules
            "pull-request-target-danger", "self-hosted-runner-public-repo",
            "secret-in-run-literal", "secret-echoed-in-logs",
            "expression-in-run-injection", "environment-protection",
            "docker-action-digest-pin", "missing-set-x-pipefail",
            "token-passed-to-third-party", "always-deploy-after-failure",
            "matrix-fail-fast",
        ]
        for rule in rules_with_suggestions:
            result = ReportGenerator._get_suggestion(rule, "owner/action@v4")
            assert result is not None, f"Missing suggestion for rule '{rule}'"


class TestReporterSarif:
    def test_sarif_json_valid(self):
        violations = [
            {"rule": "pin-action-sha", "location": "jobs.build.steps[0]",
             "message": "Not pinned", "severity": "error", "file": "ci.yml"},
        ]
        raw = ReportGenerator.generate_sarif("repo", violations)
        sarif = json.loads(raw)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_includes_line_number_when_parseable(self):
        violations = [
            {"rule": "pin-action-sha", "location": "jobs.build.steps[5]",
             "message": "Not pinned", "severity": "warning", "file": "ci.yml"},
        ]
        raw = ReportGenerator.generate_sarif("repo", violations)
        sarif = json.loads(raw)
        result = sarif["runs"][0]["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 6  # index 5 → 1-based 6

    def test_sarif_no_line_when_unparseable(self):
        violations = [
            {"rule": "pin-action-sha", "location": "jobs.build",
             "message": "Not pinned", "severity": "warning", "file": "ci.yml"},
        ]
        raw = ReportGenerator.generate_sarif("repo", violations)
        sarif = json.loads(raw)
        result = sarif["runs"][0]["results"][0]
        phys = result["locations"][0]["physicalLocation"]
        assert "region" not in phys
