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
+-----------------------+   writes  .actions_audit/<file>.static.json
|  Static Auditor Agent |   (regex, syntax, AST, 38 rules)
+-----------+-----------+
             | (Stage 2, LLM, Haiku) reads static.json, writes .semantic.json
             v
+-----------------------+
| Semantic Auditor Agent|   (evaluates coverity/BDBA ordering, OIDC, logic)
+-----------+-----------+
             | (Stage 3, 0 credit) hallucination firewall
             v
+-----------------------+   writes  .actions_audit/<file>.verified.json
|   Verifier (program.) |   (drops unknown rule IDs, bad locations, dups)
+-----------+-----------+
             |
   +---------+---------+ Mode: 'report'   +------------------+
   |                                      | Mode: dry-run    |
   v                                      v                  |
+-----------------------+   writes .actions_audit/<file>.fixer.json   |
|  Fixer Agent (LLM)    |   (JSON Patch RFC 6902, to-and-fro  |
|  Haiku + retry loop   |    up to 3 attempts on parse fail) |
+-----------+-----------+
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
2.  **Static Auditor Agent (Programmatic, 0 credit)**: 38 regex/structural/
    AST rules. Writes `.actions_audit/<file>.static.json` with findings + the set of
    flagged step locations.
3.  **Semantic Auditor Agent (LLM, Haiku-class)**: Reads the static findings
    and the targeted AST (full `run:` content for flagged steps — no
    truncation). Writes raw `.actions_audit/<file>.semantic.json`. Returns only
    findings for known rule IDs at real YAML paths.
4.  **Verifier (Programmatic, 0 credit)**: The hallucination firewall. Drops
    any LLM finding whose `rule` is unknown, whose `location` doesn't resolve
    in the YAML, or that duplicates a static finding. Survivors go to
    `.actions_audit/<file>.verified.json`; rejections are kept under `_rejected` for
    auditability.
5.  **Fixer Agent (LLM, Haiku-class)**: For **error-severity** non-programmatic
    rules, emits JSON Patch (RFC 6902); the orchestrator applies it and
    re-parses. On parse failure it re-prompts the Fixer with the previous patch
    + the error (max 3 iterations — the to-and-fro loop). All attempts are
    logged to `.actions_audit/<file>.fixer.json`. An empty patch (`[]`) is recorded as
    `failed`/`no_fix` rather than `applied`, so the audit log is honest and the
    violation is routed to manual review. Warning/info non-programmatic
    violations are **not** sent to the LLM (credit conservation); they are
    written to `.actions_audit/<file>.manual-review.json` for manual remediation.
    **Manual-review-only rules** (`pin-action-sha`,
    `pin-setup-actions-sha`, `pin-artifact-actions-sha`,
    `reusable-workflow-pinned`, `docker-action-digest-pin`) are **never**
    routed to the LLM Fixer — resolving a tag to a commit SHA requires the
    GitHub API, which the framework does not call (fully offline). Sending
    them to the LLM would produce a placeholder/hallucinated SHA written to
    disk, breaking the workflow. These rules always go to
    `.actions_audit/<file>.manual-review.json` so the owning team can pin manually.
    When the semantic auditor is **disabled**, any error-severity
    non-programmatic violations (that aren't manual-review-only) are also
    folded into `manual-review.json` rather than silently dropped.
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
├── README.md                # User onboarding and workflow documentation
├── requirements.txt         # Python dependency specifications
├── cli.py                   # CLI entry point (argparse)
├── parser.py                # Round-trip ruamel.yaml parser + targeted AST extractor
├── static_analyzer.py       # Programmatic regex/structural validation (38 rules)
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
├── templates/               # (Optional, user-created) Golden corporate template workflows
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
The LLM agents consume credits directly from your GitHub Copilot subscription
(via your VS Code business account). The framework automatically extracts your
active Copilot OAuth session credentials — **no separate login step is
required if you are already signed into the VS Code Copilot extension.**

The client resolves the token in this order:
1. `COPILOT_TOKEN` / `GITHUB_TOKEN` environment variables.
2. The VS Code Copilot session files — first `~/.config/github-copilot/apps.json`,
   then `~/.config/github-copilot/hosts.json` — this is what makes VS Code
   sign-in sufficient. For GHES deployments, `hosts.json` stores the OAuth
   session under the GHES hostname key (e.g. `github.mycompany.com`); the
   client tries the configured GHES hostname first, then falls back to the
   `github.com` key.
3. Fallback: the [GitHub CLI](https://cli.github.com/) via `gh auth token`
   (only if you prefer CLI auth over the extension).

### 3. Fully Offline Operation
The framework runs entirely against your locally downloaded/cloned repos. The only network call is to the Copilot LLM endpoint (for the semantic/documenter/fixer agents), authenticated via your VS Code session as described above. If the LLM is unreachable, the framework gracefully degrades to the 0-credit static analyzer + static markdown report. No GitHub API request is made in the default configuration; `api_endpoint`/`endpoint` in `.github-rules.json` is plumbed for future action-SHA resolution but is not called today.

All action-pinning rules (`pin-action-sha`, `pin-setup-actions-sha`,
`pin-artifact-actions-sha`, `reusable-workflow-pinned`,
`docker-action-digest-pin`) are reported as findings but **not** auto-fixed,
because resolving an action tag to a commit SHA would require the GitHub API.
Unpinned actions are listed in
`.actions_audit/<file>.manual-review.json` for the owning team
to pin manually.

### 4. GitHub Enterprise Server (GHES) Support (optional)
If your Copilot is hosted on a self-hosted GHES instance (rather than the
default `api.githubcopilot.com`), point the LLM client at it:

```bash
python3 cli.py --mode report --dir ./repos --endpoint https://github.mycompany.com
```
This is **not required** for a standard VS Code business-account Copilot setup
— only set `--endpoint` if your organization hosts Copilot on GHES.

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
> [!IMPORTANT]
> Fix mode requires `--force` to acknowledge destructive on-disk writes:
> ```bash
> python3 cli.py --mode fix --force --dir /path/to/downloaded/repositories
> ```
> **Safety guarantees**: writes are atomic (temp-file + `fsync` + `os.replace`,
> so a crash never leaves a truncated workflow); a `.bak` backup is created
> before each write (disable with `--no-backup`); a file is only rewritten
> when it has violations to remediate (compliant files are left untouched,
> preserving their mtime); and a failed write raises an `OrchestratorError`
> (exit code 3) instead of being silently recorded as "completed". Manual-
> review-only rules (action/SHA pinning) are never auto-fixed — they are
> written to `.actions_audit/<file>.manual-review.json`.

### D. Parallel Execution
Process multiple workflow files concurrently for faster audits across large repository sets:
```bash
python3 cli.py --mode report --dir /path/to/repositories --parallel 4
```
Each worker gets its own `StaticAnalyzer` and `ruamel.yaml` parser instance
so the shared instance state and the (non-thread-safe) ruamel engine are
never mutated concurrently. Dry-run diff output is serialized via an
internal lock so diffs from concurrent workers do not interleave.

### E. Credit Budget Control
Abort the audit if LLM credit consumption exceeds a threshold to prevent unexpected costs:
```bash
python3 cli.py --mode report --dir /path/to/repositories --max-credits 50
```

### F. Custom Templates Injection (Optional)
To align the agents' recommendations with your corporate templates:
1.  Create a folder named `templates/` in the script directory (or point `--templates` elsewhere).
2.  Add your golden standard workflow YAML configurations (e.g. `dotnet-pipeline.yml`, `node-build.yml`).
3.  Run the CLI tool. The agents will automatically read these configurations and format their remediation outputs to match them.

### G. CLI Flags Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--mode` | `report` | Audit mode: `report`, `dry-run`, or `fix`. |
| `--dir` | `.` | Path to the directory containing downloaded repositories. |
| `--config` | `.github-rules.json` | Path to the rules configuration file. |
| `--endpoint` | `None` | Custom Copilot chat endpoint base URL (for GHES). Also used for action SHA resolution unless overridden by `api_endpoint` in the rules config. |
| `--audit-dir` | `.actions_audit` | Scratch directory for inter-agent JSON files. |
| `--templates` | `templates` | Path to the folder containing golden corporate workflow templates. |
| `--state-db` | `.actions_audit_state.json` | Path to the audit state database for resume support. |
| `--reset` | off | Discard saved audit state and force a full re-scan. |
| `--force` | off | Required for `--mode fix`. Acknowledges destructive on-disk writes. |
| `--max-credits` | `None` | Abort the audit if estimated LLM credit cost exceeds this value. |
| `--output-format` | `markdown` | Output report format: `markdown`, `sarif`, or `junit`. |
| `--output-dir` | `None` | Directory to write reports to (defaults to the repo's `.github/` folder). Uses per-repo namespaced filenames when set. |
| `--parallel` | `1` | Number of workflow files to process concurrently (max 16). |
| `--fail-on-violation` | off | Exit with code 1 if any error-severity violation is found. |
| `--no-color` | off | Suppress ANSI color codes in log output. |
| `--no-backup` | off | Do not create `.bak` files before fix-mode writes. |
| `--log-file` | `None` | Append logs to this file in addition to stderr. |
| `--log-format` | `text` | Log output format: `text` or `json`. |
| `--quiet` | off | Suppress non-error log output. |

---

## Customizing Scan Rules (`.github-rules.json`)

You can edit [.github-rules.json](.github-rules.json) to control severities,
suppress warnings, select per-agent models, and scope global-gate rules:

*   **Change Severity**: Set a rule to `error` (blocks and auto-fixes),
    `warning` (reports but does not block), `info`, or `ignore`. Each rule may
    also carry a `description` (human-readable) and a `semantic` boolean
    (`true` marks the rule as requiring the LLM semantic auditor; defaults to
    `false`).
*   **Scope Gate Rules** (`applies_to`): Global-gate rules (coverity-scan,
    image-build-jfrog, image-signing, bdba-scan) only fire for the workflow
    scopes listed in `applies_to` — `["source","image"]` for coverity, `["image"]`
    for the image gates. Valid scopes are `source`, `image`, `deploy`, and `all`.
    Use `["all"]` to fire unconditionally.
*   **Top-Level Fields**:
    *   `model` — fallback LLM model identifier when no per-agent model is set.
    *   `models` — per-agent model identifiers (`semantic`, `fixer`,
        `documenter`, `portfolio`).
    *   `endpoint` — custom Copilot chat endpoint base URL for GHES. Also used
        for action SHA resolution unless `api_endpoint` is set.
    *   `api_endpoint` — GitHub API base URL for action SHA resolution
        (defaults to `endpoint` when set, otherwise `https://api.github.com`).
        Plumbed for future use; no API call is made today.
    *   `secret_keyword_pattern` — regex applied to variable names to detect
        probable secrets (used by the secret-detection rules).
    *   `semantic_audit.enabled` — toggle the LLM semantic auditor.
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
    Both `global` and `by_repository` are optional (a `suppressions` block with
    only `global`, or only `by_repository`, or omitted entirely is valid).
*   **Semantic Auditor Toggle**: Set `"semantic_audit": {"enabled": false}` to
    skip the LLM semantic auditor entirely (0 LLM credit cost — static-only run).

### Current rule set (38 rules)
Action pinning: `pin-action-sha`, `pin-setup-actions-sha`,
`pin-artifact-actions-sha`, `reusable-workflow-pinned`, `docker-action-digest-pin`.
The specialized `pin-setup-actions-sha` / `pin-artifact-actions-sha` rules fire
for `actions/setup-*` / `actions/{upload,download}-artifact,actions/cache`
actions respectively (when declared in the config); other unpinned actions
fall back to `pin-action-sha`. All pinning rules are manual-review-only in fix
mode (SHA resolution requires the GitHub API, which the framework does not
call).
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
| 130 | Interrupted by user (Ctrl+C / SIGINT) |

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

`<file>` is the repository-relative path with separators replaced by `__`
and the `.yml`/`.yaml` extension stripped, so files from different repos and
subdirectories don't collide (e.g. `repo__.github__workflows__ci.static.json`).

These files are safe to delete; they are regenerated on the next run. Keep
them during a run for auditability and so the Documenter can summarize the
to-and-fro. The directory is gitignored by default.

## State Recovery & Resumption

When running audits across dozens of repositories, runs can be interrupted by network drops, manual stops, or system reboots. To prevent starting from scratch, the Orchestrator implements automatic state saving:

1.  **Atomic State DB (`.actions_audit_state.json`)**: Uses file-level locking for safe concurrent writes. Tracks processed files with content SHA-256 hashes and OS modification timestamps.
2.  **Mode-Scoped Resume Logic**: Resume state is namespaced by mode (`report::`,
    `dry-run::`, `fix::`), so a completed `report` run does **not** cause a
    subsequent `fix` run to skip the same files. On restart, the scanner compares
    both the content hash and mtime of each workflow; files unchanged since the
    last audit **in the same mode** are automatically skipped.
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

By default each repository's report is written into that repo's `.github/`
folder (no collision, since each repo has its own directory). When
`--output-dir` is set, reports are written to that directory using **per-repo
namespaced filenames** (e.g. `<repo>-findings.md`, `<repo>-findings.sarif.json`)
so that multi-repo runs do not overwrite each other's reports.

---

## Testing

Run the full test suite:
```bash
python3 -m pytest tests/ -v
```

A legacy smoke-test runner is also available (wraps pytest + in-process sanity
checks against `tests/mock_repo`):
```bash
python3 tests/run_tests.py
```

The suite covers: parser correctness, static analyzer rules, state DB atomic writes, reporter output formats, prompt schema validation, GHES endpoint support, parallel execution, and credit budget enforcement.
