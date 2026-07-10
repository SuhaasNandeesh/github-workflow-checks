import os
import sys

# Ensure parent directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from parser import WorkflowParser
from static_analyzer import StaticAnalyzer
from reporter import ReportGenerator

def run_tests():
    print("=== Executing Automated Verification Tests ===")
    
    parser = WorkflowParser()
    analyzer = StaticAnalyzer()
    
    mock_dir = os.path.dirname(__file__)
    ci_path = os.path.join(mock_dir, "mock_repo", ".github", "workflows", "ci.yml")
    deploy_path = os.path.join(mock_dir, "mock_repo", ".github", "workflows", "deploy.yml")
    
    # Test 1: Load files
    print("\nTest 1: Parsing YAML workflows...")
    try:
        ci_data = parser.load_workflow(ci_path)
        deploy_data = parser.load_workflow(deploy_path)
        print("PASS: Workflows parsed successfully.")
    except Exception as e:
        print(f"FAIL: Failed to parse YAML: {e}")
        return False
        
    # Test 2: AST Summarization
    print("\nTest 2: Validating token-minimized AST summaries...")
    ci_summary = parser.extract_ast_summary(ci_data)
    assert ci_summary["name"] == "Continuous Integration", "AST Summary Name mismatch"
    assert "build" in ci_summary["jobs"], "AST Summary Jobs list missing 'build'"
    print("PASS: AST extraction produced correct minimized summaries.")

    # Test 3: Static analyzer rules on ci.yml
    print("\nTest 3: Validating static analysis on ci.yml...")
    ci_violations = analyzer.analyze_workflow(ci_path, ci_data)
    
    # Assert specific rules are flagged
    pinned_flag = [v for v in ci_violations if v["rule"] == "pin-action-sha"]
    gitlab_flag = [v for v in ci_violations if v["rule"] == "residual-gitlab-vars"]
    
    assert len(pinned_flag) == 1, "Failed to flag unpinned actions/checkout@v4"
    assert len(gitlab_flag) == 1, "Failed to flag residual GitLab variable $CI_PROJECT_NAME"
    print("PASS: static_analyzer successfully flagged standard violations in ci.yml.")

    # Test 4: Static analyzer rules on deploy.yml
    print("\nTest 4: Validating static analysis on deploy.yml...")
    deploy_violations = analyzer.analyze_workflow(deploy_path, deploy_data)
    
    cycle_flag = [v for v in deploy_violations if v["rule"] == "job-dependency-cycle"]
    shell_flag = [v for v in deploy_violations if v["rule"] == "runner-shell-misalignment"]
    secret_flag = [v for v in deploy_violations if v["rule"] == "unbound-secrets"]
    
    assert len(cycle_flag) == 1, "Failed to flag job dependency circular loop"
    assert len(shell_flag) == 1, "Failed to flag runner shell misalignment for windows runner"
    assert len(secret_flag) == 1, "Failed to flag unbound secret variable $PROD_API_KEY"
    print("PASS: static_analyzer successfully flagged complex violations in deploy.yml.")

    # Test 5: Static Report Formatting
    print("\nTest 5: Testing offline report generator...")
    static_report = ReportGenerator.generate_static_report("mock_repo", ci_violations + deploy_violations)
    assert "# Pipeline Migration Analysis: mock_repo" in static_report, "Report title mismatch"
    assert "## [Critical Errors] Action Required" in static_report, "Critical error section missing"
    print("PASS: Reporter generated correct markdown dashboard formatting.")

    # Test 6: Resumption and state recovery
    print("\nTest 6: Testing state recovery and resumption logic...")
    from agent_orchestrator import AgentOrchestrator
    import json
    
    state_path = ".actions_audit_state.json"
    if os.path.exists(state_path):
        os.remove(state_path)
        
    orchestrator = AgentOrchestrator(mode="report", reset=False)
    orchestrator.run_on_directory(os.path.join(mock_dir, "mock_repo"))
    
    assert os.path.exists(state_path), "State database file was not created"
    with open(state_path, 'r', encoding='utf-8') as f:
        state_data = json.load(f)
    
    processed = state_data.get("processed_workflows", {})
    assert len(processed) == 2, "State database did not record both workflow files"
    
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    try:
        orchestrator2 = AgentOrchestrator(mode="report", reset=False)
        orchestrator2.run_on_directory(os.path.join(mock_dir, "mock_repo"))
    finally:
        sys.stdout = old_stdout
        
    captured = buffer.getvalue()
    assert "Skipping already processed workflow (resume mode)" in captured, "Orchestrator did not skip processed files in resume mode"
    print("PASS: Resumption logic successfully bypassed previously checked workflows.")
    
    # Clean up state file
    if os.path.exists(state_path):
        os.remove(state_path)

    print("\n=== All Automated Verification Tests Passed! ===")
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
