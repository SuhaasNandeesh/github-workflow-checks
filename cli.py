"""CLI entry point with explicit flags and exit codes.

Replaces the substring-matching `--prompt` mode override (A2) with explicit
flags and a structured exit code contract (D3).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from agent_orchestrator import (
    AgentOrchestrator,
    AuthenticationError,
    ConfigError,
    FixModeRequiresForceError,
    OrchestratorError,
    _EXIT_AUTH,
    _EXIT_BAD_CONFIG,
    _EXIT_BUDGET,
    _EXIT_INTERNAL,
    _EXIT_OK,
    _EXIT_VIOLATIONS,
)
from copilot_client import BudgetExhaustedError, SSLCertificateError
from logging_setup import configure_logging, get_logger

logger = get_logger()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="github-actions-checks",
        description=(
            "Autonomous Multi-Agent GitHub Actions Pipeline Migration "
            "Analyzer & Fixer"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["report", "dry-run", "fix"],
        default="report",
        help=(
            "Execution target: 'report' to generate findings.md, 'dry-run' to "
            "print diffs, or 'fix' to edit files on disk. 'fix' requires --force."
        ),
    )
    parser.add_argument(
        "--dir",
        default=".",
        help="Path to the directory containing downloaded repositories.",
    )
    parser.add_argument(
        "--config",
        default=".github-rules.json",
        help="Path to the .github-rules.json configuration file.",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help=(
            "Custom Copilot chat endpoint base URL (for GitHub Enterprise "
            "Server). Also used for action SHA resolution unless overridden "
            "by api_endpoint in the rules config."
        ),
    )
    parser.add_argument(
        "--audit-dir",
        default=None,
        help=(
            "Scratch directory for file-based inter-agent communication "
            "(.audit/<file>.static.json, .semantic.json, .verified.json, "
            ".fixer.json). Defaults to ./.actions_audit."
        ),
    )
    parser.add_argument(
        "--templates",
        default="templates",
        help="Path to the folder containing golden corporate workflow templates.",
    )
    parser.add_argument(
        "--state-db",
        default=".actions_audit_state.json",
        help="Path to the audit state database.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Discard saved audit state and force a full re-scan.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Required for --mode fix. Acknowledges destructive on-disk writes.",
    )
    parser.add_argument(
        "--max-credits",
        type=int,
        default=None,
        help="Abort the audit if estimated LLM credit cost exceeds this value.",
    )
    parser.add_argument(
        "--output-format",
        choices=["markdown", "sarif", "junit"],
        default="markdown",
        help="Output report format.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write reports to (defaults to the repo's .github/ folder).",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of workflow files to process concurrently (max 16).",
    )
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit with code 1 if any error-severity violation is found.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Suppress ANSI color codes in log output.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create .bak files before fix mode writes.",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Append logs to this file in addition to stderr.",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error log output.",
    )
    parser.add_argument(
        "--seed-sha-cache",
        action="store_true",
        help=(
            "Populate the offline action SHA cache (actions-sha-cache.json) "
            "from the GitHub API for a built-in list of common actions, so "
            "fix mode works air-gapped. Does not run an audit. Use with "
            "--endpoint for GHES. Network access required."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.max_credits is not None and args.max_credits <= 0:
        parser.error("--max-credits must be a positive integer.")
    if args.parallel < 1 or args.parallel > 16:
        parser.error("--parallel must be between 1 and 16.")

    log_file = args.log_file
    if log_file:
        try:
            open(log_file, "a").close()
        except OSError as e:
            parser.error(f"Cannot open log file {log_file}: {e}")

    configure_logging(
        level="ERROR" if args.quiet else "INFO",
        json_format=(args.log_format == "json"),
        log_file=log_file,
        no_color=args.no_color,
    )

    try:
        if args.seed_sha_cache:
            with AgentOrchestrator(
                rules_path=args.config,
                endpoint=args.endpoint,
            ) as orchestrator:
                return orchestrator.seed_sha_cache()
        with AgentOrchestrator(
            mode=args.mode,
            rules_path=args.config,
            templates_dir=args.templates,
            state_db_path=args.state_db,
            reset=args.reset,
            force=args.force,
            endpoint=args.endpoint,
            max_credits=args.max_credits,
            output_format=args.output_format,
            output_dir=args.output_dir,
            parallel=args.parallel,
            fail_on_violation=args.fail_on_violation,
            backup=not args.no_backup,
            audit_dir=args.audit_dir,
        ) as orchestrator:
            return orchestrator.run_on_directory(args.dir)
    except FixModeRequiresForceError as e:
        logger.error("%s", e)
        return _EXIT_BAD_CONFIG
    except ConfigError as e:
        logger.error("Configuration error: %s", e)
        return _EXIT_BAD_CONFIG
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return _EXIT_BAD_CONFIG
    except (SSLCertificateError, AuthenticationError) as e:
        logger.error("Authentication/TLS error: %s", e)
        return _EXIT_AUTH
    except BudgetExhaustedError as e:
        logger.error("Budget exhausted: %s", e)
        return _EXIT_BUDGET
    except OrchestratorError as e:
        logger.error("Analyzer failed: %s", e)
        return _EXIT_INTERNAL
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130
    except Exception as e:  # defensive last-resort
        logger.error("Unexpected error: %s", e)
        return _EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
