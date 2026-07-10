"""CLI tests: --force gating, exit codes, bad config rejection."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import cli
from agent_orchestrator import _EXIT_AUTH, _EXIT_BAD_CONFIG, _EXIT_OK


def test_fix_mode_requires_force(workspace: Path, clean_env) -> None:
    rules = str(workspace / ".github-rules.json")
    code = cli.main([
        "--mode", "fix",
        "--dir", str(workspace / "mock_repo"),
        "--config", rules,
        "--state-db", str(workspace / "state.json"),
    ])
    assert code == _EXIT_BAD_CONFIG


def test_report_mode_succeeds_without_force(workspace: Path, clean_env) -> None:
    rules = str(workspace / ".github-rules.json")
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", rules,
        "--state-db", str(workspace / "state.json"),
        "--quiet",
    ])
    assert code == _EXIT_OK


def test_missing_config_returns_bad_config(workspace: Path, clean_env) -> None:
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", str(workspace / "does-not-exist.json"),
        "--state-db", str(workspace / "state.json"),
    ])
    assert code == _EXIT_BAD_CONFIG


def test_invalid_config_schema_returns_bad_config(workspace: Path, clean_env) -> None:
    bad = workspace / "bad-rules.json"
    bad.write_text(json.dumps({"rules": {"x": {"foo": "bar"}}}), encoding="utf-8")
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", str(bad),
        "--state-db", str(workspace / "state.json"),
    ])
    assert code == _EXIT_BAD_CONFIG


def test_invalid_severity_value_returns_bad_config(workspace: Path, clean_env) -> None:
    bad = workspace / "bad-rules.json"
    bad.write_text(
        json.dumps({
            "rules": {"pin-action-sha": {"severity": "fatal", "description": "x"}},
            "suppressions": {"global": [], "by_repository": {}},
        }),
        encoding="utf-8",
    )
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", str(bad),
        "--state-db", str(workspace / "state.json"),
    ])
    assert code == _EXIT_BAD_CONFIG


def test_missing_target_dir_returns_bad_config(workspace: Path, clean_env) -> None:
    rules = str(workspace / ".github-rules.json")
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "no-such-dir"),
        "--config", rules,
        "--state-db", str(workspace / "state.json"),
    ])
    assert code == _EXIT_BAD_CONFIG


def test_sarif_output_format_writes_file(workspace: Path, clean_env) -> None:
    rules = str(workspace / ".github-rules.json")
    out_dir = workspace / "out"
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", rules,
        "--state-db", str(workspace / "state.json"),
        "--output-format", "sarif",
        "--output-dir", str(out_dir),
        "--quiet",
    ])
    assert code == _EXIT_OK
    sarif_files = list(out_dir.glob("*.sarif.json"))
    assert sarif_files, "Expected SARIF file to be written"
    data = json.loads(sarif_files[0].read_text())
    assert data["version"] == "2.1.0"
    assert "runs" in data


def test_junit_output_format_writes_xml(workspace: Path, clean_env) -> None:
    rules = str(workspace / ".github-rules.json")
    out_dir = workspace / "out"
    code = cli.main([
        "--mode", "report",
        "--dir", str(workspace / "mock_repo"),
        "--config", rules,
        "--state-db", str(workspace / "state.json"),
        "--output-format", "junit",
        "--output-dir", str(out_dir),
        "--quiet",
    ])
    assert code == _EXIT_OK
    junit_files = list(out_dir.glob("*.junit.xml"))
    assert junit_files
    body = junit_files[0].read_text()
    assert body.startswith("<?xml")
    assert "<testsuite" in body
