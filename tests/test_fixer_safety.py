"""Fixer safety tests: backups, least-privilege non-clobbering, SHA-pinning
non-corruption, permissions escalation, GitLab var coverage.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_orchestrator import AgentOrchestrator


@pytest.fixture
def orchestrator(workspace: Path, clean_env) -> AgentOrchestrator:
    rules = str(workspace / ".github-rules.json")
    return AgentOrchestrator(
        mode="fix",
        rules_path=rules,
        templates_dir=str(workspace / "templates"),
        state_db_path=str(workspace / "state.json"),
        reset=True,
        force=True,
        backup=True,
    )


def test_fix_mode_creates_bak_file(workspace: Path, clean_env, orchestrator) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    original = workflow.read_text()

    # Trigger a fix programmatically: record a violation + apply.
    from agent_orchestrator import _utcnow_iso
    workflow_data = orchestrator.parser.load_workflow(workflow)
    violations = [
        {
            "rule": "least-privilege-token",
            "location": "workflow.permissions",
            "message": "missing",
            "original": "missing",
        }
    ]
    orchestrator._handle_fix_mode(workflow, workflow_data, violations)
    bak = workflow.with_suffix(workflow.suffix + ".bak")
    assert bak.exists()
    assert bak.read_text() == original


def test_least_privilege_does_not_clobber_existing_dict(
    workspace: Path, clean_env, orchestrator
) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        "name: CI\n"
        "on: [push]\n"
        "permissions:\n"
        "  issues: read\n"
        "  pull-requests: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workflow)
    orchestrator._programmatic_set_least_privilege(data)
    perms = data["permissions"]
    assert perms["issues"] == "read"
    assert perms["pull-requests"] == "read"
    assert perms.get("contents") == "read"   # added, not replaced


def test_least_privilege_replaces_write_all(workspace: Path, clean_env, orchestrator) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        "name: CI\non: [push]\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workflow)
    orchestrator._programmatic_set_least_privilege(data)
    assert data["permissions"] == {"contents": "read"}


def test_sha_pinning_does_not_corrupt_uses_value(
    workspace: Path, clean_env, orchestrator, monkeypatch
) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    # Stub fetch to return a deterministic SHA.
    orchestrator.static_analyzer.fetch_latest_sha = lambda name, tag: (
        "a" * 40 if name == "actions/checkout" and tag == "v4" else None
    )
    data = orchestrator.parser.load_workflow(workflow)
    orchestrator._programmatic_pin_sha(
        data, "jobs.build.steps[0]", "actions/checkout@v4"
    )
    uses_value = data["jobs"]["build"]["steps"][0]["uses"]
    assert "#" not in uses_value
    assert uses_value == f"actions/checkout@{'a' * 40}"


def test_gitlab_var_map_canonical_entries(workspace: Path, clean_env, orchestrator) -> None:
    from agent_orchestrator import GITLAB_VAR_MAP
    # Spot-check the canonical mappings we promised in the plan.
    assert GITLAB_VAR_MAP["$CI_PROJECT_NAME"] == "${{ github.event.repository.name }}"
    assert GITLAB_VAR_MAP["$CI_COMMIT_SHA"] == "${{ github.sha }}"
    assert GITLAB_VAR_MAP["$CI_COMMIT_REF_NAME"] == "${{ github.ref_name }}"
    assert GITLAB_VAR_MAP["$CI_PIPELINE_ID"] == "${{ github.run_id }}"
    assert GITLAB_VAR_MAP["$CI_PIPELINE_IID"] == "${{ github.run_number }}"
    assert GITLAB_VAR_MAP["$CI_PROJECT_DIR"] == "${{ github.workspace }}"
    assert GITLAB_VAR_MAP["$CI_JOB_NAME"] == "${{ github.job }}"
    assert GITLAB_VAR_MAP["$CI_REGISTRY_USER"] == "${{ github.actor }}"
    assert GITLAB_VAR_MAP["$CI_DEFAULT_BRANCH"] == "${{ github.event.repository.default_branch }}"


def test_gitlab_var_replacement_does_not_touch_similar_tokens(
    workspace: Path, clean_env, orchestrator
) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo $CI_PROJECT_NAME && echo $CI_PROJECT_NAME_BACKUP\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workflow)
    # Only the exact match should be replaced, not a longer identifier that
    # happens to start with the same prefix.
    orchestrator._programmatic_replace_gitlab_vars(
        data, "jobs.build.steps[0]", "$CI_PROJECT_NAME"
    )
    run_cmd = data["jobs"]["build"]["steps"][0]["run"]
    assert "${{ github.event.repository.name }}" in run_cmd
    assert "$CI_PROJECT_NAME_BACKUP" in run_cmd


def test_bash_shell_injection_on_windows_step(workspace: Path, clean_env, orchestrator) -> None:
    workflow = workspace / "mock_repo" / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: |\n          mkdir -p build\n",
        encoding="utf-8",
    )
    data = orchestrator.parser.load_workflow(workflow)
    orchestrator._programmatic_inject_bash_shell(data, "jobs.build.steps[0]")
    assert data["jobs"]["build"]["steps"][0]["shell"] == "bash"
