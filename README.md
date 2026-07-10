# GitHub Actions Pipeline Migration Analyzer

An autonomous, offline-first multi-agent framework designed to scan, analyze, document, and remediate GitHub Actions workflow pipelines across multiple repositories during a GitLab-to-GitHub Enterprise Server (GHES) migration.

The framework is optimized for high credit efficiency under VS Code / GitHub Copilot Enterprise subscriptions (consuming from your monthly 4,000 credit limit) by utilizing a **Static-First, Hybrid-Remediation Architecture**.

---

## Agentic Workflow Architecture

The system uses a **file-based, to-and-fro multi-agent pipeline**. Agents
communicate through JSON scratch files written on disk (under `.actions_audit/`)
so context is saved across runs and never re-sent to the LLM in full. A
programmatic **Verifier** stage acts as a hallucination firewall between the
LLM semantic auditor and the rest of the pipeline. Standard structural issues
are handled programmatically (0-credit); only complex semantic reasoning and
non-structural fixes are routed to LLM sub-agents.

```
[Target Workflows Directory]
             |
             v
+-----------------------+
|  Orchestrator Agent   | <--- Loads rules from .github-rules.json
| (per-agent models)    |
+-----------+-----------+
             | (Stage 1, 0 credit)
             v
+-----------------------+   writes  .audit/<file>.static.json
|  Static Auditor Agent |   (regex, syntax, AST, 38+ rules)
+-----------+-----------+
             | (Stage 2, LLM, Haiku) reads static.json, writes .semantic.json
             v
+-----------------------+
| Semantic Auditor Agent|   (evaluates coverity/BDBA ordering, OIDC, logic)
+-----------+-----------+
             | (Stage 3, 0 credit) hallucination firewall
             v
+-----------------------+   writes  .audit/<file>.verified.json
|   Verifier (program.) |   (drops unknown rule IDs, bad locations, dups)
+-----------+-----------+
             |
   +---------+---------+ Mode: 'report'   +------------------+
   |                                      | Mode: dry-run    |
   v                                      v                  |
+-----------------------+   writes .audit/<file>.fixer.json   |
|  Fixer Agent (LLM)    |   (JSON Patch RFC 6902, to-and-fro  |
|  Haiku + retry loop   |    up to 3 attempts on parse fail) |
+-----------+-----------+   writes .audit/<file>.applied.patch
            |
            +-----------------+ Mode: 'report' +-----------+
                              |                      |
                              v                      v
                   +-----------------------+  +----------------------+
                   | Documenter Agent (LLM)|  | ruamel.yaml writer   |
                   | Sonnet -> markdown     |  | (fix mode on-disk)   |
                   +-----------+-----------+  +----------------------+
                              v
                       findings.md
```

### The cooperating agents & stages
1.  **Primary Orchestrator Agent (Programmatic)**: The main loop. Traverses
    repos, parses configs, schedules stages, enforces the credit budget,
    routes each stage to its configured per-agent model.
2.  **Static Auditor Agent (Programmatic, 0 credit)**: 38+ regex/structural/
    AST rules. Writes `.audit/<file>.static.json` with findings + the set of
    flagged step locations.
3.  **Semantic Auditor Agent (LLM, Haiku-class)**: Reads the static findings
    and the targeted AST (full `run:` content for flagged steps — no
    truncation). Writes raw `.audit/<file>.semantic.json`. Returns only
    findings for known rule IDs at real YAML paths.
4.  **Verifier (Programmatic, 0 credit)**: The hallucination firewall. Drops
    any LLM finding whose `rule` is unknown, whose `location` doesn't resolve
    in the YAML, or that duplicates a static finding. Survivors go to
    `.audit/<file>.verified.json`; rejections are kept under `_rejected` for
    auditability.
5.  **Fixer Agent (LLM, Haiku-class)**: For **error-severity** non-programmatic
    rules, emits JSON Patch (RFC 6902); the orchestrator applies it and
    re-parses. On parse failure it re-prompts the Fixer with the previous patch
    + the error (max 3 iterations — the to-and-fro loop). All attempts are
    logged to `.audit/<file>.fixer.json`. Warning/info non-programmatic
    violations are **not** sent to the LLM (credit conservation); they are
    written to `.audit/<file>.manual-review.json` for manual remediation.
6.  **Documenter Agent (LLM, Sonnet-class)**: Reads verified findings and emits
    a Markdown `findings.md` directly (not JSON).

### Per-agent model selection (credit optimization)
`.github-rules.json` declares a `models` map so cheap, structured work goes to
Haiku-class models and prose to Sonnet/Opus:

```json
"models": {
  "semantic":  "claude-haiku-4.5",
  "fixer":     "claude-haiku-4.5",
  "documenter":"claude-sonnet-5",
  "portfolio": "claude-opus-4.8"
}
```
Each agent falls back to the top-level `model` field, then the client default.
**Haiku 4.5 is sufficient** for the semantic/fixer stages because they are
strict JSON-in/JSON-out tasks validated by the Verifier and JSON Patch parser.
Sonnet is recommended only for the Documenter's prose.

---

## Project Structure

```
github-actions-checks/
├── .github-rules.json       # Central rules, severities, per-agent models, suppressions
├── actions-sha-cache.json   # Offline action SHA cache (air-gapped fix mode)
├── README.md                # User onboarding and workflow documentation
├── requirements.txt          # Python dependency specifications
├── cli.py                   # CLI entry point (argparse)
├── parser.py                # Round-trip ruamel.yaml parser + targeted AST extractor
├── static_analyzer.py       # Programmatic regex/structural validation (38+ rules)
├── copilot_client.py        # Auth + Copilot/GHES chat client, per-agent models, usage
├── agent_orchestrator.py     # Multi-agent scheduler, Verifier, fixer to-and-fro loop
├── reporter.py              # Markdown/SARIF/JUnit report generators
├── state_db.py              # Atomic file-locking state DB for resume support
├── rules_schema.py          # JSON Schema validation for .github-rules.json
├── logging_setup.py         # Structured logging configuration
├── agents/                  # LLM System Prompts
│   ├── semantic_auditor_prompt.txt
│   ├── documenter_prompt.txt
│   └── fixer_prompt.txt
├── templates/               # (Optional) Golden corporate template workflows
└── tests/                   # Verification suites and mock repositories
```

---

## Getting Started in VS Code

### 1. Prerequisites
Ensure you have Python 3.8+ installed on your machine.

Open your VS Code terminal and install dependencies:
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

### 3. GitHub Enterprise Server (GHES) Support
The framework supports self-hosted GHES endpoints for both LLM completions and
action SHA resolution. Configure via CLI or rules config:

```bash
# Via CLI flag (applies to LLM + SHA resolution)
python3 cli.py --mode report --dir ./repos --endpoint https://github.mycompany.com

# Via rules config (.github-rules.json)
{
  "endpoint": "https://github.mycompany.com",
  "api_endpoint": "https://github.mycompany.com/api/v3",
  ...
}
```
`endpoint` is used for the Copilot chat API. `api_endpoint` (optional, defaults
to `endpoint`) is used for action SHA resolution. For GHES, the client resolves
host-specific tokens via `gh auth token --hostname <host>`.

### 4. Offline / Air-gapped Fix Mode (Action SHA Cache)
Fix mode resolves action tags to immutable commit SHAs via the GitHub API. To
work fully offline (and avoid per-action 5s timeouts across 80+ repos), the
cache file `actions-sha-cache.json` is read first; on a miss it falls back to
the network and writes the result back for the next run. Override its location
with `sha_cache_path` in `.github-rules.json`.

The repository ships with a **pre-seeded** cache for common actions
(checkout, setup-node/python/go/java, upload/download-artifact, cache) pinned
to real commit SHAs. To refresh or extend the cache (e.g. after adding new
common actions), run:

```bash
# Seed/refresh the cache from the GitHub API (network required).
python3 cli.py --seed-sha-cache

# For GitHub Enterprise Server:
python3 cli.py --seed-sha-cache --endpoint https://github.mycompany.com
```
This resolves each seeded `action@tag` to its commit SHA and persists the
cache. It does not run an audit.

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

### D. Parallel Execution
Process multiple workflow files concurrently for faster audits across large repository sets:
```bash
python3 cli.py --mode report --dir /path/to/repositories --parallel 4
```

### E. Credit Budget Control
Abort the audit if LLM credit consumption exceeds a threshold to prevent unexpected costs:
```bash
python3 cli.py --mode report --dir /path/to/repositories --max-credits 50
```

### F. Custom Templates Injection (Optional)
To align the agents' recommendations with your corporate templates:
1.  Create a folder named `templates/` in the script directory.
2.  Add your golden standard workflow YAML configurations (e.g. `dotnet-pipeline.yml`, `node-build.yml`).
3.  Run the CLI tool. The agents will automatically read these configurations and format their remediation outputs to match them.

---

## Customizing Scan Rules (`.github-rules.json`)

You can edit [.github-rules.json](.github-rules.json) to control severities,
suppress warnings, select per-agent models, and scope global-gate rules:

*   **Change Severity**: Set a rule to `error` (blocks and auto-fixes),
    `warning` (reports but does not block), `info`, or `ignore`.
*   **Scope Gate Rules** (`applies_to`): Global-gate rules (coverity-scan,
    image-build-jfrog, image-signing, bdba-scan) only fire for the workflow
    scopes listed in `applies_to` — `["source","image"]` for coverity, `["image"]`
    for the image gates. Use `["all"]` to fire unconditionally.
*   **Built-in Fallbacks**: If the rules config is missing or fails to load, the
    analyzer falls back to built-in defaults.
*   **Suppress Warnings**:
    ```json
    "suppressions": {
      "global": ["concurrency-control"],
      "by_repository": {
        "legacy-repo-name": ["pin-action-sha"]
      }
    }
    ```
*   **Semantic Auditor Toggle**: Set `"semantic_audit": {"enabled": false}` to
    skip the LLM semantic auditor entirely (0 LLM credit cost — static-only run).

### Current rule set (38 rules)
Action pinning: `pin-action-sha`, `pin-setup-actions-sha`,
`pin-artifact-actions-sha`, `reusable-workflow-pinned`, `docker-action-digest-pin`.
Security: `least-privilege-token`, `job-permission-escalation`, `oidc-cloud-deploy`,
`checkout-persist-credentials`, `submodule-recursive`, `pull-request-target-danger`,
`self-hosted-runner-public-repo`, `secret-in-run-literal`, `secret-echoed-in-logs`,
`expression-in-run-injection`, `untrusted-input-injection`, `token-passed-to-third-party`,
`deprecated-set-output`, `environment-protection`, `concurrency-control`.
Quality/efficiency: `runner-shell-misalignment`, `multiline-block-scalar`,
`job-dependency-cycle`, `unresolved-needs`, `explicit-artifact-transfer`,
`unbound-secrets`, `residual-gitlab-vars`, `runner-version-pinned`,
`latest-runtime-version`, `job-timeout-missing`, `step-timeout-missing`,
`missing-set-x-pipefail`, `always-deploy-after-failure`, `matrix-fail-fast`.
Enterprise gates: `coverity-scan`, `image-build-jfrog`, `image-signing`,
`bdba-scan`.

## Exit Codes
| Code | Meaning |
| :--- | :--- |
| 0 | OK — no violations (or none when `--fail-on-violation` unset) |
| 1 | Violations found and `--fail-on-violation` is set |
| 2 | Bad configuration / missing target dir |
| 3 | Internal analyzer error |
| 4 | Authentication / TLS error |
| 5 | Credit budget exhausted (`--max-credits` reached) |

---

## Inter-Agent Scratch Directory (`.actions_audit/`)

The agents communicate through JSON scratch files written on disk so context
is saved and never re-sent to the LLM in full. For each workflow file the
orchestrator writes, under `.actions_audit/` (configurable via `--audit-dir`):

- `<file>.static.json` — Static Auditor findings + flagged step locations.
- `<file>.semantic.json` — raw Semantic Auditor findings (or error details).
- `<file>.verified.json` — Verifier-accepted findings + `_rejected` audit log.
- `<file>.fixer.json` — LLM Fixer attempt log (every to-and-fro iteration).
- `<file>.manual-review.json` — warning/info non-programmatic violations
  flagged for manual remediation (not sent to the LLM, to conserve credits).

These files are safe to delete; they are regenerated on the next run. Keep
them during a run for auditability and so the Documenter can summarize the
to-and-fro. The directory is gitignored by default.

## State Recovery & Resumption

When running audits across dozens of repositories, runs can be interrupted by network drops, manual stops, or system reboots. To prevent starting from scratch, the Orchestrator implements automatic state saving:

1.  **Atomic State DB (`.actions_audit_state.json`)**: Uses file-level locking for safe concurrent writes. Tracks processed files with content SHA-256 hashes and OS modification timestamps.
2.  **Resume Logic**: On restart, the scanner compares both the content hash and mtime of each workflow. Files unchanged since the last audit are automatically skipped.
3.  **Forcing a Fresh Run**: To clear the resume cache and run a full audit from scratch, pass the `--reset` flag:
    ```bash
    python3 cli.py --mode report --dir /path/to/repositories --reset
    ```

---

## Output Formats

The reporter supports multiple output formats:
- **Markdown** (default): Structured `findings.md` with severity dashboard, per-rule findings, and YAML fix snippets.
- **SARIF** (2.1.0): Machine-readable format for integration with GitHub Advanced Security, Dependabot, and IDE code scanners.
- **JUnit XML**: CI test reporter format for pipeline pass/fail gates.

Select the format via the `--output-format` flag:
```bash
python3 cli.py --mode report --dir ./repos --output-format sarif
```

---

## Testing

Run the full test suite:
```bash
python3 -m pytest tests/ -v
```

The suite covers: parser correctness, static analyzer rules, state DB atomic writes, reporter output formats, prompt schema validation, GHES endpoint support, parallel execution, and credit budget enforcement.
