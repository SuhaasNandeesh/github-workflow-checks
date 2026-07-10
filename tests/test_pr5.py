"""Tests for PR 5: GHES client, parallel processing, credit budget."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot_client import CopilotClient

# Minimal valid rules config matching the schema
_MINIMAL_RULES_CONFIG = '{"rules": {"pin-action-sha": {"severity": "error", "description": "test"}}, "suppressions": {"global": [], "by_repository": {}}}'


# ── GHES endpoint support ─────────────────────────────────────────────────────


class TestGHESDetection:
    def test_ghes_returns_true_for_non_github_com(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com",
            token="tok",
        )
        assert client._is_ghes() is True

    def test_ghes_returns_false_for_github_com(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://api.githubcopilot.com",
            token="tok",
        )
        assert client._is_ghes() is False

    def test_ghes_host_extracts_hostname(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com/api/v3",
            token="tok",
        )
        assert client._ghes_host() == "github.mycompany.com"

    def test_ghes_host_returns_none_for_github_com(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://api.githubcopilot.com",
            token="tok",
        )
        assert client._ghes_host() is None


class TestGHESTokenResolution:
    @patch.dict(os.environ, {"GITHUB_TOKEN": "env-token"})
    def test_env_token_takes_priority_over_ghes(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com",
        )
        assert client.token == "env-token"

    @patch.dict(os.environ, {"COPILOT_TOKEN": "copilot-env"})
    def test_copilot_token_takes_priority(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com",
        )
        assert client.token == "copilot-env"


class TestGHESEndpointStored:
    def test_custom_endpoint_stored(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com",
            token="tok",
        )
        assert client.endpoint == "https://github.mycompany.com"

    def test_endpoint_stripped_of_trailing_slash(self):
        client = CopilotClient(
            model_name="test",
            endpoint="https://github.mycompany.com/",
            token="tok",
        )
        assert client.endpoint == "https://github.mycompany.com"


# ── Credit budget ─────────────────────────────────────────────────────────────


class TestCreditBudget:
    def test_check_budget_raises_when_exceeded(self):
        from agent_orchestrator import AgentOrchestrator, OrchestratorError
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                max_credits=2,
                force=True,
            )
            orch._credits_used = 2
            with pytest.raises(OrchestratorError, match="Credit budget exhausted"):
                orch._check_budget()

    def test_check_budget_passes_when_under(self):
        from agent_orchestrator import AgentOrchestrator
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                max_credits=5,
                force=True,
            )
            orch._credits_used = 3
            orch._check_budget()  # should not raise

    def test_check_budget_passes_when_no_limit(self):
        from agent_orchestrator import AgentOrchestrator
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                max_credits=None,
                force=True,
            )
            orch._credits_used = 999
            orch._check_budget()  # should not raise

    def test_record_credits_increments(self):
        from agent_orchestrator import AgentOrchestrator
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                force=True,
            )
            assert orch._credits_used == 0
            orch._record_credits()
            assert orch._credits_used == 1
            orch._record_credits(3)
            assert orch._credits_used == 4


# ── Parallel parameter ────────────────────────────────────────────────────────


class TestParallelParameter:
    def test_parallel_clamped_to_minimum_1(self):
        from agent_orchestrator import AgentOrchestrator
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                parallel=0,
                force=True,
            )
            assert orch.parallel == 1

    def test_parallel_stores_value(self):
        from agent_orchestrator import AgentOrchestrator
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / ".github-rules.json"
            rules.write_text(_MINIMAL_RULES_CONFIG)
            orch = AgentOrchestrator(
                rules_path=str(rules),
                parallel=4,
                force=True,
            )
            assert orch.parallel == 4
