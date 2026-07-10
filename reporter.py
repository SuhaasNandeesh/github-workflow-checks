"""Report generators: Markdown (LLM/Static), SARIF, JUnit."""
from __future__ import annotations

import html
import json
import re
from typing import Any


# SARIF 2.1.0 schema (minimal). https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_RULE_SUMMARIES: dict[str, str] = {
    "pin-action-sha": "Action must be pinned to a full-length commit SHA.",
    "pin-setup-actions-sha": "Setup action (node/python/go/java/...) must be pinned to a commit SHA.",
    "pin-artifact-actions-sha": "Artifact/cache action must be pinned to a commit SHA.",
    "least-privilege-token": "Workflow should declare explicit GITHUB_TOKEN permissions.",
    "residual-gitlab-vars": "Shell step contains a residual GitLab CI variable.",
    "runner-shell-misalignment": "Shell script does not match the runner OS (e.g. bash on Windows).",
    "multiline-block-scalar": "Multi-line run: command should use literal (|) block scalar.",
    "job-dependency-cycle": "Job dependency graph contains a cycle.",
    "unresolved-needs": "needs: references an unknown job.",
    "unbound-secrets": "Credentials variable is referenced but not bound in env:.",
    "explicit-artifact-transfer": "Job depends on an artifact-producing job but never downloads the artifact.",
    "coverity-scan": "Coverity/Black Duck SAST scan is not configured.",
    "image-build-jfrog": "Docker build & JFrog Artifactory push is not configured.",
    "image-signing": "Pushed images are not signed with Cosign.",
    "bdba-scan": "BDBA vulnerability scan is not configured on built images.",
    "oidc-cloud-deploy": "Cloud deploy step should use OIDC (id-token: write).",
    "checkout-persist-credentials": "actions/checkout should set persist-credentials: false.",
    "job-timeout-missing": "Job is missing timeout-minutes.",
    "step-timeout-missing": "Long-running step is missing timeout-minutes.",
    "latest-runtime-version": "Runtime version is set to 'latest' (non-reproducible).",
    "runner-version-pinned": "runs-on uses 'latest' instead of a pinned version.",
    "deprecated-set-output": "Deprecated ::set-output/::set-env/::add-path workflow command used.",
    "untrusted-input-injection": "Untrusted input is written to $GITHUB_ENV/$GITHUB_OUTPUT.",
    "submodule-recursive": "actions/checkout uses submodules: recursive (security risk).",
    "reusable-workflow-pinned": "Reusable workflow call is not pinned to a commit SHA.",
    "job-permission-escalation": "Job re-widens permissions beyond the workflow default.",
    "concurrency-control": "State-modifying workflow should declare a concurrency group.",
    "pull-request-target-danger": "pull_request_target with PR-head checkout executes untrusted code with base secrets.",
    "self-hosted-runner-public-repo": "runs-on: self-hosted without a label risks untrusted code execution.",
    "secret-in-run-literal": "Hardcoded credential literal in run: script.",
    "secret-echoed-in-logs": "Secret interpolated directly in run: is echoed in logs.",
    "expression-in-run-injection": "Untrusted ${{ github.event.* }} expression interpolated in run:.",
    "environment-protection": "Deployment job lacks an environment: with required reviewers.",
    "docker-action-digest-pin": "Docker image/action pinned by tag, not digest.",
    "missing-set-x-pipefail": "Multi-line bash run: lacks 'set -e -o pipefail'.",
    "token-passed-to-third-party": "Token/secret passed via env to a third-party action.",
    "always-deploy-after-failure": "Deploy job uses if: always() and deploys on upstream failure.",
    "matrix-fail-fast": "Matrix has fail-fast: true, hiding later failures.",
}


class ReportGenerator:
    @staticmethod
    def generate_static_report(repo_name: str, violations: list[dict[str, Any]]) -> str:
        """Programmatic markdown fallback (B14: severity is the single source of truth)."""
        errors = [v for v in violations if v.get("severity") == "error"]
        warnings = [v for v in violations if v.get("severity") == "warning"]
        infos = [v for v in violations if v.get("severity") == "info"]
        uncategorized = [
            v for v in violations
            if v.get("severity") not in ("error", "warning", "info")
        ]

        md: list[str] = []
        md.append(f"# Pipeline Migration Analysis: {repo_name}\n")
        md.append(
            "This report summarizes the compliance, security, and standard violations "
            "detected in the migrated GitHub Actions workflows.\n"
        )

        md.append("## Executive Compliance Dashboard")
        md.append("| Metric | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| **Critical Errors** | {len(errors)} |")
        md.append(f"| **Standard Warnings** | {len(warnings)} |")
        md.append(f"| **Info Notices** | {len(infos)} |")
        md.append(f"| **Uncategorized** | {len(uncategorized)} |")
        md.append(f"| **Total Violations** | {len(violations)} |\n")

        if not violations:
            md.append(
                "> [!NOTE]\n> **Status: COMPLIANT**. No violations or policy breaches "
                "were detected in this repository's workflows.\n"
            )
            return "\n".join(md)

        for label, group in (
            ("[Critical Errors] Action Required", errors),
            ("[Standard Warnings] Policy Guidelines", warnings),
            ("[Info Notices]", infos),
            ("[Other Findings]", uncategorized),
        ):
            if not group:
                continue
            md.append(f"## {label}\n")
            for idx, v in enumerate(group):
                rule = v.get("rule") or "unknown"
                file_path = v.get("file", "")
                loc = v.get("location") or "unknown"
                msg = v.get("message") or rule
                orig = v.get("original")
                md.append(f"### {idx+1}. Rule: `{rule}`")
                if file_path:
                    md.append(f"- **File**: `{file_path}`")
                md.append(f"- **Location**: `{loc}`")
                md.append(f"- **Issue**: {msg}")
                if orig:
                    md.append(f"- **Original Source**: `{orig}`")
                md.append("")
                suggestion = ReportGenerator._get_suggestion(rule, orig, v)
                if suggestion:
                    md.append("- **Recommended Remediated Snippet**:")
                    md.append(f"```yaml\n{suggestion}\n```")
                md.append("\n---\n")
        return "\n".join(md)

    @staticmethod
    def _get_suggestion(
        rule: str | None,
        original: Any,
        violation: dict[str, Any] | None = None,
    ) -> str | None:
        if not rule:
            return None
        action_ref = (original or "").split("@", 1)
        action_name = action_ref[0] if action_ref else "owner/action"
        tag = action_ref[1] if len(action_ref) > 1 else "v1"
        suggestions: dict[str, str] = {
            "pin-action-sha": (
                f"# Pin action to immutable SHA\nuses: {action_name}@<latest-commit-sha>  # {tag}"
            ),
            "pin-setup-actions-sha": (
                f"# Pin setup action to immutable SHA\nuses: {action_name}@<latest-commit-sha>  # {tag}"
            ),
            "pin-artifact-actions-sha": (
                f"# Pin artifact action to immutable SHA\nuses: {action_name}@<latest-commit-sha>  # {tag}"
            ),
            "reusable-workflow-pinned": (
                f"# Pin reusable workflow to immutable SHA\nuses: {action_name}/.github/workflows/x.yml@<latest-commit-sha>  # {tag}"
            ),
            "coverity-scan": (
                "- name: Black Duck Coverity Scan\n"
                "  uses: blackduck-inc/black-duck-security-scan@v2\n"
                "  with:\n"
                "    api_token: ${{ secrets.BD_TOKEN }}\n"
                "    server_url: ${{ secrets.BD_URL }}\n"
                "    coverity_url: ${{ secrets.COVERITY_URL }}\n"
                "    coverity_user: ${{ secrets.COVERITY_USER }}\n"
                "    coverity_pass: ${{ secrets.COVERITY_PASS }}"
            ),
            "image-build-jfrog": (
                "- name: Build and Push to JFrog\n"
                "  run: |\n"
                "    IMAGE=${{ env.JF_REGISTRY }}/${{ github.event.repository.name }}:${{ github.sha }}\n"
                "    docker build -t \"$IMAGE\" .\n"
                "    jf docker push \"$IMAGE\" --build-name=\"${{ github.run_id }}\" --build-number=\"${{ github.run_number }}\""
            ),
            "image-signing": (
                "- name: Sign image with Cosign (digest-pinned)\n"
                "  run: cosign sign --yes \"${{ env.JF_REGISTRY }}/${{ github.event.repository.name }}@${{ steps.build.outputs.digest }}\"\n"
                "  env:\n"
                "    COSIGN_EXPERIMENTAL: 'true'"
            ),
            "bdba-scan": (
                "- name: Run BDBA Scan on Image\n"
                "  uses: blackduck-inc/black-duck-security-scan@v2\n"
                "  with:\n"
                "    api_token: ${{ secrets.BD_TOKEN }}\n"
                "    server_url: ${{ secrets.BD_URL }}\n"
                "    image_name: ${{ env.JF_REGISTRY }}/${{ github.event.repository.name }}:${{ github.sha }}"
            ),
            "concurrency-control": (
                "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true"
            ),
            "least-privilege-token": "permissions:\n  contents: read",
            "oidc-cloud-deploy": (
                "permissions:\n  id-token: write   # required for OIDC\n  contents: read"
            ),
            "checkout-persist-credentials": (
                "- uses: actions/checkout@v4\n  with:\n    persist-credentials: false"
            ),
            "job-timeout-missing": "timeout-minutes: 30",
            "step-timeout-missing": "timeout-minutes: 10",
            "runner-version-pinned": "runs-on: ubuntu-22.04",
            "deprecated-set-output": (
                "# Replace deprecated workflow commands with env files.\n"
                "echo \"KEY=value\" >> \"$GITHUB_OUTPUT\""
            ),
            "untrusted-input-injection": (
                "# Sanitize untrusted input before assigning to GITHUB_ENV / GITHUB_OUTPUT.\n"
                "echo \"value=${SANITIZED_VALUE}\" >> \"$GITHUB_OUTPUT\""
            ),
            "submodule-recursive": (
                "- uses: actions/checkout@v4\n  with:\n    submodules: false   # or 'true' if explicit review is required"
            ),
            "job-permission-escalation": (
                "# Job-level permissions must not exceed workflow-level permissions."
            ),
            "pull-request-target-danger": (
                "# Do not check out PR head under pull_request_target.\n"
                "on: [pull_request]   # use pull_request, NOT pull_request_target, for builds\n"
                "  - uses: actions/checkout@v4  # checks out the PR head safely (no base secrets)"
            ),
            "self-hosted-runner-public-repo": (
                "# Use GitHub-hosted runners or label-gated self-hosted runners.\n"
                "runs-on: ubuntu-latest   # or [self-hosted, corp-only]"
            ),
            "secret-in-run-literal": (
                "# Bind credentials via env, never inline.\n"
                "env:\n  API_KEY: ${{ secrets.API_KEY }}\nrun: curl -H \"Authorization: Bearer $API_KEY\" ..."
            ),
            "secret-echoed-in-logs": (
                "# Bind secrets through env, not directly in run:.\n"
                "env:\n  TOKEN: ${{ secrets.TOKEN }}\nrun: curl -H \"Authorization: Bearer $TOKEN\" ..."
            ),
            "expression-in-run-injection": (
                "# Assign untrusted expressions to env first, then use $VAR.\n"
                "env:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"sanitized: $TITLE\""
            ),
            "environment-protection": (
                "environment:\n  name: production\n  url: ${{ steps.deploy.outputs.url }}"
            ),
            "docker-action-digest-pin": (
                "# Pin by immutable digest, not tag.\n"
                "container:\n  image: registry/app@sha256:<digest>"
            ),
            "missing-set-x-pipefail": (
                "run: |\n  set -e -o pipefail\n  # rest of script"
            ),
            "token-passed-to-third-party": (
                "# Audit the action's trust level before passing tokens.\n"
                "# Prefer first-party actions, or pass a minimally-scoped PAT."
            ),
            "always-deploy-after-failure": (
                "# Gate deploys on upstream success.\n"
                "if: ${{ success() }}   # or: needs.<job>.result == 'success'"
            ),
            "matrix-fail-fast": (
                "strategy:\n  fail-fast: false\n  matrix:\n    os: [ubuntu-22.04, ubuntu-latest]"
            ),
        }
        if rule in suggestions:
            return suggestions[rule]
        # Consume remediation_hint from the violation dict if present
        hint = (violation or {}).get("remediation_hint")
        if hint:
            return str(hint)
        # Generic GitLab var swap suggestion
        if rule == "residual-gitlab-vars" and isinstance(original, str):
            return f"# Replace with GitHub context\necho \"...${{{{ github.sha }}}}...\"   # was: {original}"
        if rule == "runner-shell-misalignment":
            return "- name: Force bash on Windows\n  shell: bash\n  run: <your-commands>"
        if rule == "explicit-artifact-transfer":
            return "- uses: actions/download-artifact@v4\n  with:\n    name: <artifact-name>"
        if rule == "unbound-secrets":
            if isinstance(original, str):
                return f"env:\n  {original}: ${{{{ secrets.{original} }}}}"
        if rule == "multiline-block-scalar":
            return "run: |\n  # use literal block scalar (|) for multi-line scripts"
        if rule == "job-dependency-cycle":
            return "# Break the cycle by removing one of the 'needs' edges."
        if rule == "unresolved-needs":
            return "needs:\n  - <existing-job-id>   # fix the reference"
        if rule == "latest-runtime-version":
            return "with:\n  node-version: '20'   # pin a specific major/minor"
        return None

    @staticmethod
    def generate_sarif(repo_name: str, violations: list[dict[str, Any]]) -> str:
        """Emit a SARIF 2.1.0 document for integration with GHAS / Dependabot / IDEs."""
        rules_index: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for v in violations:
            rule_id = v.get("rule") or "unknown"
            if rule_id not in rules_index:
                rules_index[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": _RULE_SUMMARIES.get(rule_id, rule_id)
                    },
                    "helpUri": (
                        f"https://github.com/anomalyco/opencode/blob/main/docs/rules/{rule_id}.md"
                    ),
                }
            level_map = {"error": "error", "warning": "warning", "info": "note"}
            level = level_map.get(v.get("severity", "warning"), "warning")
            message = v.get("message") or rule_id
            file_uri = v.get("file") or ""
            region: dict[str, Any] = {}
            line = _parse_location_line(v.get("location", ""))
            if line:
                region["startLine"] = line
                region["endLine"] = line
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri},
                        **({"region": region} if region else {}),
                    }
                }],
            }
            if v.get("original"):
                result["properties"] = {"original": v["original"]}
            results.append(result)

        sarif = {
            "version": "2.1.0",
            "$schema": _SARIF_SCHEMA,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "github-actions-checks",
                        "version": "1.0.0",
                        "informationUri": (
                            "https://github.com/anomalyco/opencode"
                        ),
                        "rules": list(rules_index.values()),
                    }
                },
                "invocations": [{
                    "executionSuccessful": True,
                    "properties": {"repository": repo_name},
                }],
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_junit(repo_name: str, violations: list[dict[str, Any]]) -> str:
        """Emit a JUnit XML report for CI test reporters."""
        cases: list[str] = []
        for v in violations:
            rule = v.get("rule") or "unknown"
            name = html.escape(rule)
            file_uri = html.escape(v.get("file", ""))
            loc = html.escape(v.get("location", ""))
            message = html.escape(v.get("message", ""))
            severity = html.escape(v.get("severity", "warning"))
            classname = f"github-actions-checks.{severity}"
            case = (
                f'  <testcase classname="{classname}" '
                f'name="{name}" file="{file_uri}">'
            )
            if severity == "error":
                case += f'<failure type="{name}" message="{message}">{loc}</failure>'
            elif severity == "warning":
                case += f'<skipped message="{message}"/>'
            else:
                case += f'<system-out>{message}</system-out>'
            case += '</testcase>'
            cases.append(case)
        body = "\n".join(cases)
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="{html.escape(repo_name)}" tests="{len(cases)}">\n'
            f"{body}\n"
            f"</testsuite>\n"
        )


def _parse_location_line(location: str) -> int | None:
    """Extract the step index from a location string like 'jobs.build.steps[3]'.

    Returns the 1-based line number hint (index + 1) or None if not parseable.
    """
    if not location:
        return None
    # Match patterns like: jobs.X.steps[N]
    m = re.search(r"\.steps\[(\d+)\]", location)
    if m:
        return int(m.group(1)) + 1  # 1-based for SARIF startLine
    return None
