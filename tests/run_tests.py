"""Legacy smoke-test runner.

This file is kept for backward compatibility with the original
`python tests/run_tests.py` entrypoint. It is implemented as a thin
wrapper around pytest and runs the per-rule unit tests defined in
tests/test_*.py plus a small set of in-process sanity checks against the
mock repository.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MOCK_DIR = Path(__file__).resolve().parent / "mock_repo"


def _smoke_tests() -> bool:
    sys.path.insert(0, str(REPO_ROOT))
    from parser import WorkflowParser
    from static_analyzer import StaticAnalyzer
    from reporter import ReportGenerator

    print("=== In-process smoke tests against tests/mock_repo ===")
    parser = WorkflowParser()
    analyzer = StaticAnalyzer()
    ci_path = MOCK_DIR / ".github" / "workflows" / "ci.yml"
    deploy_path = MOCK_DIR / ".github" / "workflows" / "deploy.yml"

    try:
        ci_data = parser.load_workflow(ci_path)
        deploy_data = parser.load_workflow(deploy_path)
    except Exception as e:
        print(f"FAIL: Failed to parse YAML: {e}")
        return False
    print("PASS: Workflows parsed successfully.")

    summary = parser.extract_ast_summary(ci_data)
    assert summary["name"] == "Continuous Integration"
    assert "build" in summary["jobs"]
    print("PASS: AST extraction produced correct minimized summaries.")

    ci_violations = analyzer.analyze_workflow(ci_path, ci_data)
    deploy_violations = analyzer.analyze_workflow(deploy_path, deploy_data)

    pinned = [v for v in ci_violations if v["rule"] == "pin-action-sha"]
    gitlab = [v for v in ci_violations if v["rule"] == "residual-gitlab-vars"]
    assert len(pinned) == 1, f"Expected 1 pin-action-sha, got {len(pinned)}"
    assert len(gitlab) >= 1, f"Expected >= 1 residual-gitlab-vars, got {len(gitlab)}"
    print("PASS: Static analyzer flagged ci.yml violations.")

    cycle = [v for v in deploy_violations if v["rule"] == "job-dependency-cycle"]
    shell = [v for v in deploy_violations if v["rule"] == "runner-shell-misalignment"]
    secret = [v for v in deploy_violations if v["rule"] == "unbound-secrets"]
    assert len(cycle) == 1
    assert len(shell) == 1
    assert len(secret) == 1
    print("PASS: Static analyzer flagged deploy.yml violations.")

    # Tag severities so the static report generator sees them.
    for v in ci_violations + deploy_violations:
        if v.get("severity") is None:
            v["severity"] = "error" if v["rule"] in {
                "pin-action-sha", "least-privilege-token", "residual-gitlab-vars",
                "job-dependency-cycle", "runner-shell-misalignment",
            } else "warning"

    static_report = ReportGenerator.generate_static_report(
        "mock_repo", ci_violations + deploy_violations
    )
    assert "# Pipeline Migration Analysis: mock_repo" in static_report
    assert "## [Critical Errors] Action Required" in static_report
    print("PASS: Reporter generated correct markdown dashboard formatting.")

    return True


def main() -> int:
    smoke_ok = _smoke_tests()
    print("\n=== Running pytest suite ===")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(Path(__file__).parent), "-q"],
        cwd=str(REPO_ROOT),
    )
    pytest_ok = result.returncode == 0
    print(f"\nSmoke tests: {'PASS' if smoke_ok else 'FAIL'}")
    print(f"pytest suite: {'PASS' if pytest_ok else 'FAIL'}")
    return 0 if (smoke_ok and pytest_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
