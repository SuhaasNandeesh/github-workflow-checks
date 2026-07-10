"""PR 3 tests: New static rules, Tarjan SCC, bidirectional shell check, unresolved needs."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from static_analyzer import StaticAnalyzer
from agent_orchestrator import AgentOrchestrator
import json, copy


def _make_analyzer(**overrides) -> StaticAnalyzer:
    rules = overrides.pop("rules_config", None) or {"rules": {}, "suppressions": {"global": [], "by_repository": {}}}
    return StaticAnalyzer(rules_config=rules, **overrides)


# ─── Unresolved needs ─────────────────────────────────────────────────

def test_unresolved_needs_flags_missing_job() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "build": {"runs-on": "ubuntu-latest", "needs": "deploy", "steps": []},
        "test":  {"runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    unres = [f for f in findings if f["rule"] == "unresolved-needs"]
    assert len(unres) == 1
    assert "deploy" in unres[0]["message"]


def test_unresolved_needs_passes_when_all_jobs_exist() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "build": {"runs-on": "ubuntu-latest", "needs": "test", "steps": []},
        "test":  {"runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    unres = [f for f in findings if f["rule"] == "unresolved-needs"]
    assert len(unres) == 0


def test_unresolved_needs_handles_string_needs() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "build": {"runs-on": "ubuntu-latest", "needs": "nonexistent", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    unres = [f for f in findings if f["rule"] == "unresolved-needs"]
    assert len(unres) == 1


# ─── Job timeout missing ─────────────────────────────────────────────

def test_job_timeout_missing_flags_job() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo hi"}]}}}
    findings = a.analyze_workflow("/f.yml", data)
    timeout = [f for f in findings if f["rule"] == "job-timeout-missing"]
    assert len(timeout) == 1
    assert "build" in timeout[0]["location"]


def test_job_timeout_passes_when_present() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "timeout-minutes": 30, "steps": [{"run": "echo hi"}]}}}
    findings = a.analyze_workflow("/f.yml", data)
    timeout = [f for f in findings if f["rule"] == "job-timeout-missing"]
    assert len(timeout) == 0


# ─── Checkout persist credentials ────────────────────────────────────

def test_checkout_persist_credentials_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/checkout@v4"}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    cpc = [f for f in findings if f["rule"] == "checkout-persist-credentials"]
    assert len(cpc) == 1


def test_checkout_persist_credentials_not_flagged_when_false() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/checkout@v4", "with": {"persist-credentials": False}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    cpc = [f for f in findings if f["rule"] == "checkout-persist-credentials"]
    assert len(cpc) == 0


def test_checkout_persist_credentials_not_flagged_for_non_checkout() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/setup-node@v4"}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    cpc = [f for f in findings if f["rule"] == "checkout-persist-credentials"]
    assert len(cpc) == 0


# ─── Step timeout ────────────────────────────────────────────────────

def test_long_step_timeout_missing_flagged() -> None:
    a = _make_analyzer()
    long_script = "\n".join([f"echo line {i}" for i in range(20)])
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": long_script}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    st = [f for f in findings if f["rule"] == "step-timeout-missing"]
    assert len(st) == 1


def test_short_step_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": "echo hi\nnpm test"}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    st = [f for f in findings if f["rule"] == "step-timeout-missing"]
    assert len(st) == 0


# ─── Latest runtime version ──────────────────────────────────────────

def test_latest_runtime_version_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/setup-node@v4", "with": {"node-version": "latest"}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    lr = [f for f in findings if f["rule"] == "latest-runtime-version"]
    assert len(lr) == 1
    assert "node-version" in lr[0]["message"]


def test_latest_runtime_version_lts_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/setup-python@v5", "with": {"python-version": "lts/*"}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    lr = [f for f in findings if f["rule"] == "latest-runtime-version"]
    assert len(lr) == 1


def test_pinned_version_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/setup-node@v4", "with": {"node-version": "20"}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    lr = [f for f in findings if f["rule"] == "latest-runtime-version"]
    assert len(lr) == 0


# ─── Deprecated set-output ───────────────────────────────────────────

def test_deprecated_set_output_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "::set-output name=foo::bar"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    dso = [f for f in findings if f["rule"] == "deprecated-set-output"]
    assert len(dso) == 1
    assert "::set-output" in dso[0]["message"]


def test_deprecated_set_env_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "::set-env name=FOO::bar"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    dse = [f for f in findings if f["rule"] == "deprecated-set-output"]
    assert len(dse) == 1


def test_new_output_syntax_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "foo=bar" >> "$GITHUB_OUTPUT"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    dso = [f for f in findings if f["rule"] == "deprecated-set-output"]
    assert len(dso) == 0


# ─── Untrusted input injection ───────────────────────────────────────

def test_untrusted_input_to_env_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "title=${{ github.event.issue.title }}" >> "$GITHUB_ENV"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    uii = [f for f in findings if f["rule"] == "untrusted-input-injection"]
    assert len(uii) == 1


def test_untrusted_input_to_output_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "val=${{ github.head_ref }}" >> "$GITHUB_OUTPUT"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    uii = [f for f in findings if f["rule"] == "untrusted-input-injection"]
    assert len(uii) == 1


def test_safe_output_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"run": 'echo "result=ok" >> "$GITHUB_OUTPUT"'}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    uii = [f for f in findings if f["rule"] == "untrusted-input-injection"]
    assert len(uii) == 0


# ─── Submodule recursive ────────────────────────────────────────────

def test_submodule_recursive_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/checkout@v4", "with": {"submodules": True}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    sr = [f for f in findings if f["rule"] == "submodule-recursive"]
    assert len(sr) == 1


def test_submodule_recursive_string_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/checkout@v4", "with": {"submodules": "recursive"}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    sr = [f for f in findings if f["rule"] == "submodule-recursive"]
    assert len(sr) == 1


def test_submodules_false_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/checkout@v4", "with": {"submodules": False}}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    sr = [f for f in findings if f["rule"] == "submodule-recursive"]
    assert len(sr) == 0


# ─── Reusable workflow pinned ────────────────────────────────────────

def test_reusable_workflow_not_pinned_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"uses": "org/repo/.github/workflows/build.yml@v1"}}}
    findings = a.analyze_workflow("/f.yml", data)
    rwp = [f for f in findings if f["rule"] == "reusable-workflow-pinned"]
    assert len(rwp) == 1


def test_reusable_workflow_sha_pinned_not_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"uses": "org/repo/.github/workflows/build.yml@" + "a" * 40}}}
    findings = a.analyze_workflow("/f.yml", data)
    rwp = [f for f in findings if f["rule"] == "reusable-workflow-pinned"]
    assert len(rwp) == 0


# ─── OIDC cloud deploy ──────────────────────────────────────────────

def test_oidc_cloud_deploy_flagged_when_no_id_token() -> None:
    a = _make_analyzer()
    data = {"permissions": {"contents": "read"}, "jobs": {"deploy": {
        "runs-on": "ubuntu-latest",
        "permissions": {"contents": "read"},
        "steps": [
            {"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "arn:aws:iam::123456789012:role/my-role"}},
            {"run": "aws s3 sync . s3://bucket"},
        ],
    }}}
    findings = a.analyze_workflow("/f.yml", data)
    oc = [f for f in findings if f["rule"] == "oidc-cloud-deploy"]
    assert len(oc) == 1
    assert "id-token" in oc[0]["message"]


def test_oidc_cloud_deploy_not_flagged_when_id_token_write() -> None:
    a = _make_analyzer()
    data = {"permissions": {"contents": "read"}, "jobs": {"deploy": {
        "runs-on": "ubuntu-latest",
        "permissions": {"contents": "read", "id-token": "write"},
        "steps": [
            {"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "arn:aws:iam::123456789012:role/my-role"}},
        ],
    }}}
    findings = a.analyze_workflow("/f.yml", data)
    oc = [f for f in findings if f["rule"] == "oidc-cloud-deploy"]
    assert len(oc) == 0


# ─── Tarjan SCC cycle detection ─────────────────────────────────────

def test_cycle_detection_two_node_cycle() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "a": {"needs": "b", "runs-on": "ubuntu-latest", "steps": []},
        "b": {"needs": "a", "runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    cycles = [f for f in findings if f["rule"] == "job-dependency-cycle"]
    assert len(cycles) >= 1


def test_cycle_detection_self_loop() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "a": {"needs": "a", "runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    cycles = [f for f in findings if f["rule"] == "job-dependency-cycle"]
    assert len(cycles) >= 1


def test_cycle_detection_three_node_cycle() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "a": {"needs": "b", "runs-on": "ubuntu-latest", "steps": []},
        "b": {"needs": "c", "runs-on": "ubuntu-latest", "steps": []},
        "c": {"needs": "a", "runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    cycles = [f for f in findings if f["rule"] == "job-dependency-cycle"]
    assert len(cycles) >= 1


def test_no_cycle_dag() -> None:
    a = _make_analyzer()
    data = {"jobs": {
        "a": {"needs": [], "runs-on": "ubuntu-latest", "steps": []},
        "b": {"needs": "a", "runs-on": "ubuntu-latest", "steps": []},
        "c": {"needs": ["a", "b"], "runs-on": "ubuntu-latest", "steps": []},
    }}
    findings = a.analyze_workflow("/f.yml", data)
    cycles = [f for f in findings if f["rule"] == "job-dependency-cycle"]
    assert len(cycles) == 0


# ─── Generic pin helper: pin-setup-actions-sha ──────────────────────

def test_pin_setup_node_action_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/setup-node@v4"}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    pin = [f for f in findings if f["rule"] == "pin-action-sha"]
    assert len(pin) >= 1


# ─── Pin artifact actions ───────────────────────────────────────────

def test_pin_upload_artifact_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [
        {"uses": "actions/upload-artifact@v4"}
    ]}}}
    findings = a.analyze_workflow("/f.yml", data)
    pin = [f for f in findings if f["rule"] == "pin-action-sha"]
    assert len(pin) >= 1


# ─── Runner shell bidirectional ─────────────────────────────────────

def test_linux_commands_on_windows_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {
        "runs-on": "windows-latest",
        "steps": [{"run": "grep -r foo . && sed -i 's/x/y/' file.txt"}],
    }}}
    findings = a.analyze_workflow("/f.yml", data)
    shell = [f for f in findings if f["rule"] == "runner-shell-misalignment"]
    assert len(shell) >= 1


def test_powershell_on_linux_not_flagged_when_cross_platform() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {
        "runs-on": "ubuntu-latest",
        "steps": [{"run": "Get-ChildItem | Select-Object Name"}],
    }}}
    findings = a.analyze_workflow("/f.yml", data)
    shell = [f for f in findings if f["rule"] == "runner-shell-misalignment"]
    assert len(shell) == 0


def test_macos_shell_mismatch_flagged() -> None:
    a = _make_analyzer()
    data = {"jobs": {"build": {
        "runs-on": "macos-latest",
        "steps": [{"run": "Get-ChildItem -Recurse"}],
    }}}
    findings = a.analyze_workflow("/f.yml", data)
    shell = [f for f in findings if f["rule"] == "runner-shell-misalignment"]
    # PowerShell cmdlet on macOS runner without shell: pwsh → misalignment
    assert len(shell) >= 1


# ─── Global security gates: coverity missing ────────────────────────

def test_coverity_missing_on_non_build_workflow() -> None:
    """Non-build workflows should NOT require coverity scan."""
    a = _make_analyzer()
    data = {
        "name": "Lint",
        "jobs": {"lint": {"runs-on": "ubuntu-latest", "steps": [{"run": "npm run lint"}]}},
    }
    findings = a.analyze_workflow("/f.yml", data)
    cov = [f for f in findings if f["rule"] == "coverity-scan"]
    assert len(cov) == 0


# ─── GitLab var map completeness ────────────────────────────────────

def test_gitlab_var_map_has_common_entries() -> None:
    from agent_orchestrator import GITLAB_VAR_MAP
    for var in [
        "$CI_PROJECT_NAME", "$CI_COMMIT_SHA", "$CI_COMMIT_REF_NAME",
        "$CI_COMMIT_BRANCH", "$CI_COMMIT_TAG", "$CI_PIPELINE_ID",
        "$CI_PIPELINE_IID", "$CI_PROJECT_DIR", "$CI_JOB_NAME",
        "$CI_REGISTRY_USER", "$CI_DEFAULT_BRANCH",
    ]:
        assert var in GITLAB_VAR_MAP, f"Missing GitLab var: {var}"


def test_gitlab_var_map_dollar_and_brace_forms() -> None:
    from agent_orchestrator import GITLAB_VAR_MAP
    for var in ["$CI_PROJECT_NAME", "${CI_PROJECT_NAME}"]:
        assert var in GITLAB_VAR_MAP, f"Missing form: {var}"
        assert GITLAB_VAR_MAP[var].startswith("${{ github.")
