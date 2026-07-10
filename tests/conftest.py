"""Shared test fixtures.

Every test runs in an isolated tmp_path, with environment variables
backed up and restored. The conftest also seeds a minimal
.github-rules.json and a mock workflow tree per test when requested.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

import pytest


RULES_PAYLOAD = {
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
    },
    "suppressions": {"global": [], "by_repository": {}},
}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """An isolated workspace with config + mock repo tree."""
    rules_path = tmp_path / ".github-rules.json"
    rules_path.write_text(json.dumps(RULES_PAYLOAD), encoding="utf-8")

    repo_dir = tmp_path / "mock_repo"
    workflow_dir = repo_dir / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)

    ci = workflow_dir / "ci.yml"
    ci.write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Ensure no GITHUB_TOKEN or COPILOT_TOKEN leaks into tests."""
    for var in ("GITHUB_TOKEN", "COPILOT_TOKEN", "GH_TOKEN", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    yield
