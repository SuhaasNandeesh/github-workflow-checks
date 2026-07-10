import argparse
import os
import sys
from agent_orchestrator import AgentOrchestrator

def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Multi-Agent GitHub Actions Pipeline Migration Analyzer & Fixer"
    )
    parser.add_argument(
        "--mode",
        choices=["report", "dry-run", "fix"],
        default="report",
        help="Execution target: 'report' to generate findings.md, 'dry-run' to print diffs, or 'fix' to edit files on disk."
    )
    parser.add_argument(
        "--dir",
        default=".",
        help="Path to the directory containing downloaded repositories."
    )
    parser.add_argument(
        "--config",
        default=".github-rules.json",
        help="Path to the .github-rules.json configuration file."
    )
    parser.add_argument(
        "--templates",
        default="templates",
        help="Path to the folder containing golden corporate workflow templates."
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help="Optional prompt string to override mode selection dynamically (e.g., 'fix all violations' will change mode to fix)."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Ignore saved audit state database and force a full re-scan from scratch."
    )

    args = parser.parse_args()

    # Determine mode dynamically if prompt is provided
    mode = args.mode
    if args.prompt:
        prompt_lower = args.prompt.lower()
        if "fix" in prompt_lower or "remediate" in prompt_lower or "apply" in prompt_lower:
            mode = "fix"
        elif "dry" in prompt_lower or "diff" in prompt_lower or "patch" in prompt_lower:
            mode = "dry-run"
        elif "report" in prompt_lower or "audit" in prompt_lower or "findings" in prompt_lower:
            mode = "report"

    # Instantiate orchestrator
    try:
        orchestrator = AgentOrchestrator(
            mode=mode,
            rules_path=args.config,
            templates_dir=args.templates,
            reset=args.reset
        )
        orchestrator.run_on_directory(args.dir)
    except Exception as e:
        print(f"Error: Analyzer failed to complete execution: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
