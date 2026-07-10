# GitHub Actions Pipeline Migration Analyzer

An autonomous, offline-first multi-agent framework designed to scan, analyze, document, and remediate GitHub Actions workflow pipelines across multiple repositories during a GitLab-to-GHES migration. 

The framework is optimized for high credit efficiency under VS Code / GitHub Copilot Enterprise subscriptions (consuming from your monthly 4,000 credit limit) by utilizing a **Static-First, Hybrid-Remediation Architecture**.

---

## Agentic Workflow Architecture

The system uses a sequential primary-to-subagent delegation pattern. Standard structural issues are handled programmatically to ensure 0-credit costs, while complex semantic reasoning is routed to LLM sub-agents:

```
[Target Workflows Directory]
             │
             ▼
 ┌───────────────────────┐
 │  Orchestrator Agent   │ ◄─── Loads rules from .github-rules.json
 └───────────┬───────────┘
             │ (Sequentially Audits Files)
             ▼
 ┌───────────────────────┐
 │ Static Auditor Agent  │ (0 Credit Cost: regex, syntax, dependency loops)
 └───────────┬───────────┘
             │ (If violations found, extracts minimized AST JSON)
             ▼
 ┌───────────────────────┐
 │ Semantic Auditor Agent│ (LLM: evaluates security gates, OIDC, logic flaws)
 └───────────┬───────────┘
             │
             ├─────────────── Mode: 'report' ──────────────┐
             │                                             │
             ▼                                             ▼
 ┌───────────────────────┐                    ┌───────────────────────┐
 │    Fixer Agent        │                    │   Documenter Agent    │
 └───────────┬───────────┘                    └────────────┬──────────┘
             │ (Remediates target block)                   │ (Generates markdown report)
             ▼                                             ▼
 ┌───────────────────────┐                    ┌───────────────────────┐
 │   ruamel.yaml writer  │                    │      findings.md      │
 └───────────────────────┘                    └───────────────────────┘
```

### The 5 Cooperating Agents:
1.  **Primary Orchestrator Agent (Programmatic)**: The main loop controller. Traverses directory workspaces, parses configurations, schedules sub-agent validations, and handles the self-correcting validation loop.
2.  **Static Auditor Agent (Programmatic)**: Performs regex rules and structural cycle checks locally (0 credit cost).
3.  **Semantic Auditor Agent (LLM)**: Analyzes the parsed AST JSON against security policies, runner alignments, and complex pipeline structures.
4.  **Documenter Agent (LLM)**: Compiles the final compliance markdown report detailing issue locations, severity logs, and copy-pasteable YAML fixes.
5.  **Fixer Agent (LLM)**: Rewrites complex shell steps, handles environment secrets binding, and validates formatting syntax round-trip.

---

## Project Structure

```
github-actions-checks/
├── .github-rules.json      # Central rules, severity profiles, and suppressions
├── README.md               # User onboarding and workflow documentation
├── requirements.txt        # Python dependency specifications
├── cli.py                  # CLI entry point
├── parser.py               # Round-trip ruamel.yaml parser and AST extractor
├── static_analyzer.py      # Programmatic regex and dependency validation rules
├── copilot_client.py       # Authentication wrapper and Copilot chat endpoint client
├── agent_orchestrator.py   # Multi-agent queue scheduler and correction controller
├── reporter.py             # Formatter layouts and offline report fallback generator
├── agents/                 # LLM System Prompts
│   ├── semantic_auditor_prompt.txt
│   ├── documenter_prompt.txt
│   └── fixer_prompt.txt
├── templates/              # (Optional) Golden corporate template workflows
└── tests/                  # Verification suites and mock repositories
```

---

## Getting Started in VS Code

### 1. Prerequisites
Ensure you have Python 3.8+ installed on your machine.

Open your VS Code terminal and install the round-trip YAML library:
```bash
pip install -r requirements.txt
```

> [!TIP]
> **macOS SSL Certificate Verification**: If you run the script on macOS and encounter an SSL certificate error (`[SSL: CERTIFICATE_VERIFY_FAILED]`), run the Python built-in command to install root certificates on your machine:
> ```bash
> /Applications/Python\ 3.x/Install\ Certificates.command
> ```
> *(Replace `3.x` with your specific installed Python directory name, e.g., `3.11`)*

### 2. Authenticate with GitHub Copilot
The LLM agents consume credits directly from your GitHub Copilot subscription. The framework automatically attempts to extract your active Copilot OAuth session credentials. 

To ensure authentication succeeds:
*   Make sure you are logged into the **GitHub Copilot** extension in your current VS Code instance.
*   *Alternatively*, install the [GitHub CLI](https://cli.github.com/) on your machine, open your terminal, and run:
    ```bash
    gh auth login
    ```
    This authenticates your command-line environment and allows the client to fetch your session token via `gh auth token`.

---

## Executing the Agents

You run the agentic workflow by calling `cli.py` in your VS Code terminal.

### A. Report Mode (Generate findings.md)
Scans the target workflows folder, runs static and semantic analysis, and creates a single **consolidated** `findings.md` file inside the repository's `.github/` folder (or root folder). This report aggregates all pipeline violations across all files, showing a structured occurrences matrix and copy-pasteable remediation blocks. No files are edited on disk.
```bash
python3 cli.py --mode report --dir /path/to/downloaded/repositories
```

### B. Dry-Run Mode (Preview Git Diff)
Performs all audit checks, runs the Fixer Agent to remediate issues in memory, and prints a Git-style unified diff patch to the console so you can inspect proposed changes.
```bash
python3 cli.py --mode dry-run --dir /path/to/downloaded/repositories
```

### C. Fix Mode (Apply Auto-Fixes)
Performs the analysis, applies programmatic patches, runs the Fixer Agent to resolve complex script issues, validates the syntax of the modified YAML files round-trip, and commits compliant files directly back to disk.
```bash
python3 cli.py --mode fix --dir /path/to/downloaded/repositories
```

### D. Custom Templates Injection (Optional)
To align the agents' recommendations with your corporate templates:
1.  Create a folder named `templates/` in the script directory.
2.  Add your golden standard workflow YAML configurations (e.g. `dotnet-pipeline.yml`, `node-build.yml`).
3.  Run the CLI tool. The agents will automatically read these configurations and format their remediation outputs to match them.

---

## Customizing Scan Rules (`.github-rules.json`)

You can edit [.github-rules.json](file:///Users/suhaasnandeesh/Code/scripts/github-actions-checks/.github-rules.json) to control severities or suppress warnings:

*   **Change Severity**: Set a rule to `error` (blocks and auto-fixes), `warning` (reports but does not block), or `ignore`.
*   **Built-in Fallbacks**: If the rules configuration JSON file is missing or fails to load, the analyzer automatically falls back onto built-in defaults (e.g., `pin-action-sha` and `least-privilege-token` are classified as errors, and BDBA/Coverity/JFrog image pushes are warnings) to guarantee correct report classifications.
*   **Suppress Warnings**:
    ```json
    "suppressions": {
      "global": ["concurrency-control"],
      "by_repository": {
        "legacy-repo-name": ["pin-action-sha"]
      }
    }
    ```

---

## State Recovery & Resumption

When running audits across dozens of repositories, runs can be interrupted by network drops, manual stops, or system reboots. To prevent starting from scratch, the Orchestrator implements automatic state saving:

1.  **State File (`.actions_audit_state.json`)**: Tracks processed files in real time. Progress metrics are saved immediately after each individual workflow file is parsed.
2.  **File Sync & Recheck**: On restart, the scanner compares the OS modification timestamp (`mtime`) of each workflow. If a file was not edited since the last successful audit, it is skipped. If it has changed, it is re-audited automatically.
3.  **Forcing a Fresh Run**: To clear the resume cache and run a full audit from scratch, pass the `--reset` flag:
    ```bash
    python3 cli.py --mode report --dir /path/to/repositories --reset
    ```
