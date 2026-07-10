"""PR 2 tests: YAML round-trip preservation, permission escalation, non-destructive var replacement.

Verifies:
- Anchors & aliases survive a load/dump/merge cycle
- Comments survive a load/dump/merge cycle
- LiteralScalarString is preserved, not folded
- Permission escalation is correctly detected
- GitLab var replacement does not corrupt surrounding YAML
"""
from __future__ import annotations

import copy
import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_orchestrator import AgentOrchestrator, GITLAB_VAR_MAP
from parser import WorkflowParser
from static_analyzer import StaticAnalyzer
from reporter import ReportGenerator


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    import json

    rules_payload = {
        "rules": {
            "pin-action-sha": {"severity": "error", "description": "Pinned to SHA"},
            "least-privilege-token": {"severity": "error", "description": "Token scope"},
            "residual-gitlab-vars": {"severity": "error", "description": "GitLab vars"},
            "runner-shell-misalignment": {"severity": "error", "description": "Shell"},
            "job-dependency-cycle": {"severity": "error", "description": "Cycle"},
            "coverity-scan": {"severity": "warning", "description": "Coverity"},
            "image-build-jfrog": {"severity": "warning", "description": "JFrog"},
            "image-signing": {"severity": "warning", "description": "Cosign"},
            "bdba-scan": {"severity": "warning", "description": "BDBA"},
            "explicit-artifact-transfer": {"severity": "warning", "description": "Artifact"},
            "unbound-secrets": {"severity": "warning", "description": "Secrets"},
            "multiline-block-scalar": {"severity": "warning", "description": "Scalar"},
            "concurrency-control": {"severity": "warning", "description": "Concurrency"},
            "job-permission-escalation": {"severity": "error", "description": "Escalation"},
        },
        "suppressions": {"global": [], "by_repository": {}},
    }

    rules_path = tmp_path / ".github-rules.json"
    rules_path.write_text(json.dumps(rules_payload), encoding="utf-8")
    repo_dir = tmp_path / "mock_repo"
    workflow_dir = repo_dir / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    return tmp_path


@pytest.fixture
def orchestrator(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> AgentOrchestrator:
    for var in ("GITHUB_TOKEN", "COPILOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return AgentOrchestrator(
        mode="fix",
        rules_path=str(workspace / ".github-rules.json"),
        templates_dir=str(workspace / "templates"),
        state_db_path=str(workspace / "state.json"),
        reset=True,
        force=True,
        backup=False,
    )


def test_yaml_anchor_survives_round_trip(workspace: Path, orchestrator) -> None:
    """Anchors and aliases must be preserved after load → merge → dump."""
    wf = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    wf.write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    env: &default_env\n"
        "      NODE_ENV: production\n"
        "    steps:\n"
        "      - run: echo hi\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    env: *default_env\n"
        "    steps:\n"
        "      - run: echo test\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workspace / "mock_repo" / ".github" / "workflows" / "ci.yml")
    # Simulate a non-destructive fix that only touches the run script
    data["jobs"]["build"]["steps"][0]["run"] = "echo fixed"

    stream = io.StringIO()
    orchestrator.parser.yaml.dump(data, stream)
    output = stream.getvalue()

    # The anchor name (&default_env) and alias (*default_env) should survive
    assert "&default_env" in output
    assert "*default_env" in output


def test_yaml_comment_survives_round_trip(workspace: Path, orchestrator) -> None:
    """Inline comments should survive a load → merge → dump."""
    wf = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    wf.write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4 # important pin\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workspace / "mock_repo" / ".github" / "workflows" / "ci.yml")
    stream = io.StringIO()
    orchestrator.parser.yaml.dump(data, stream)
    output = stream.getvalue()
    assert "important pin" in output


def test_literal_scalar_string_preserved(workspace: Path, orchestrator) -> None:
    """LiteralScalarString (|) must not be silently converted to folded (>)."""
    from ruamel.yaml.scalarstring import LiteralScalarString

    wf = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    wf.write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: |\n          echo hi\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workspace / "mock_repo" / ".github" / "workflows" / "ci.yml")
    run_val = data["jobs"]["build"]["steps"][0]["run"]
    assert isinstance(run_val, LiteralScalarString)
    # After a merge (e.g., adding shell: bash), the scalar type should remain.
    data["jobs"]["build"]["steps"][0]["shell"] = "bash"
    stream = io.StringIO()
    orchestrator.parser.yaml.dump(data, stream)
    output = stream.getvalue()
    assert "run: |" in output
    assert "run: >" not in output


def test_permission_escalation_detected(workspace: Path) -> None:
    """Job declaring a scope not in workflow-level permissions triggers escalation."""
    analyzer = StaticAnalyzer(
        rules_config={"rules": {"job-permission-escalation": {"severity": "error"}}}
    )
    data = {
        "permissions": {"contents": "read"},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "read", "issues": "read"},
                "steps": [{"run": "echo deploy"}],
            }
        },
    }
    findings = analyzer.analyze_workflow("/fake/path.yml", data)
    esc = [v for v in findings if v["rule"] == "job-permission-escalation"]
    assert len(esc) == 1
    assert "issues" in esc[0]["message"]


def test_permission_widening_detected(workspace: Path) -> None:
    """Job widening a declared scope triggers escalation."""
    analyzer = StaticAnalyzer(
        rules_config={"rules": {"job-permission-escalation": {"severity": "error"}}}
    )
    data = {
        "permissions": {"contents": "read"},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "write"},
                "steps": [{"run": "echo deploy"}],
            }
        },
    }
    findings = analyzer.analyze_workflow("/fake/path.yml", data)
    esc = [v for v in findings if v["rule"] == "job-permission-escalation"]
    assert len(esc) == 1
    assert "write" in esc[0]["message"]


def test_permission_escalation_not_triggered_on_matching(workspace: Path) -> None:
    """Same scope at same level does not trigger escalation."""
    analyzer = StaticAnalyzer(
        rules_config={"rules": {"job-permission-escalation": {"severity": "error"}}}
    )
    data = {
        "permissions": {"contents": "read"},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "read"},
                "steps": [{"run": "echo deploy"}],
            }
        },
    }
    findings = analyzer.analyze_workflow("/fake/path.yml", data)
    esc = [v for v in findings if v["rule"] == "job-permission-escalation"]
    assert len(esc) == 0


def test_gitlab_var_not_affects_yaml_key(workspace: Path, orchestrator) -> None:
    """Var replacement only touches string values, never YAML map keys."""
    wf = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    wf.write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Build\n        run: echo $CI_PROJECT_NAME\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workspace / "mock_repo" / ".github" / "workflows" / "ci.yml")
    orchestrator._apply_programmatic_fixes(data, [
        {"rule": "residual-gitlab-vars", "location": "jobs.build.steps[0]", "original": "$CI_PROJECT_NAME"}
    ])
    run_cmd = data["jobs"]["build"]["steps"][0]["run"]
    assert "${{ github.event.repository.name }}" in run_cmd
    assert "$CI_PROJECT_NAME" not in run_cmd
    # The step name should be unchanged
    assert data["jobs"]["build"]["steps"][0]["name"] == "Build"


def test_sarif_output_includes_all_rules(workspace: Path, monkeypatch) -> None:
    """SARIF output references every violation ruleId."""
    for var in ("GITHUB_TOKEN", "COPILOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    violations = [
        {"rule": "pin-action-sha", "severity": "error", "file": "a.yml",
         "location": "jobs.build.steps[0]", "message": "unpinned", "original": "actions/checkout@v4"},
        {"rule": "coverity-scan", "severity": "warning", "file": "b.yml",
         "location": "workflow", "message": "missing coverity"},
        {"rule": "job-permission-escalation", "severity": "error", "file": "a.yml",
         "location": "jobs.deploy.permissions", "message": "widens",
         "original": "contents: read -> write"},
    ]
    sarif_json = ReportGenerator.generate_sarif("test-repo", violations)
    import json
    sarif = json.loads(sarif_json)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"pin-action-sha", "coverity-scan", "job-permission-escalation"}
    result_rules = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert result_rules == {"pin-action-sha", "coverity-scan", "job-permission-escalation"}


def test_junit_output_for_error_and_warning(workspace: Path, monkeypatch) -> None:
    """JUnit XML emits <failure> for error severity and <skipped> for warning."""
    for var in ("GITHUB_TOKEN", "COPILOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    violations = [
        {"rule": "pin-action-sha", "severity": "error", "file": "a.yml",
         "location": "jobs.build.steps[0]", "message": "unpinned"},
        {"rule": "coverity-scan", "severity": "warning", "file": "b.yml",
         "location": "workflow", "message": "missing coverity"},
    ]
    xml = ReportGenerator.generate_junit("test-repo", violations)
    assert '<failure type="pin-action-sha"' in xml
    assert '<skipped message="missing coverity"/>' in xml
    assert 'tests="2"' in xml


def test_static_report_uses_severity_field_not_hardcoded(workspace: Path, monkeypatch) -> None:
    """Static report classifies by the severity field, not a hardcoded list."""
    for var in ("GITHUB_TOKEN", "COPILOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    violations = [
        {"rule": "pin-action-sha", "severity": "warning", "file": "a.yml",
         "location": "jobs.build.steps[0]", "message": "unpinned"},
    ]
    report = ReportGenerator.generate_static_report("test-repo", violations)
    # pin-action-sha is "warning" here, so it should NOT appear under the errors section.
    assert "pin-action-sha" not in report.split("## [Critical Errors]")[1] if "## [Critical Errors]" in report else True
