import os

class ReportGenerator:
    @staticmethod
    def generate_static_report(repo_name, violations):
        """Compiles a programmatic markdown findings report as an offline backup

        or structure generator when LLM documentation is not requested.
        """
        # Identify errors: check severity key, or fallback to default error rule list (in case of cached state loads)
        errors = [
            v for v in violations 
            if v.get("severity") == "error" or v.get("rule") in ["pin-action-sha", "least-privilege-token", "residual-gitlab-vars", "job-dependency-cycle", "runner-shell-misalignment"]
        ]
        warnings = [v for v in violations if v not in errors]


        md = []
        md.append(f"# Pipeline Migration Analysis: {repo_name}\n")
        md.append("This report summarizes the compliance, security, and standard violations detected in the migrated GitHub Actions workflows.\n")
        
        md.append("## Executive Compliance Dashboard")
        md.append("| Metric | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| **Critical Errors** | {len(errors)} |")
        md.append(f"| **Standard Warnings** | {len(warnings)} |")
        md.append(f"| **Total Violations** | {len(violations)} |\n")

        if not violations:
            md.append("> [!NOTE]\n> **Status: COMPLIANT**. No violations or policy breaches were detected in this repository's workflows.\n")
            return "\n".join(md)

        if errors:
            md.append("## [Critical Errors] Action Required\n")
            for idx, err in enumerate(errors):
                rule = err.get("rule")
                file_path = err.get("file", "")
                loc = err.get("location")
                msg = err.get("message")
                orig = err.get("original")
                
                md.append(f"### {idx+1}. Rule: `{rule}`")
                if file_path:
                    md.append(f"- **File**: `{file_path}`")
                md.append(f"- **Location**: `{loc}`")
                md.append(f"- **Issue**: {msg}")
                if orig:
                    md.append(f"- **Original Source**: `{orig}`")
                md.append("")
                
                # Provide static suggestions
                suggestion = ReportGenerator._get_suggestion(rule, orig)
                if suggestion:
                    md.append("- **Recommended Remediated Snippet**:")
                    md.append(f"```yaml\n{suggestion}\n```")
                md.append("\n---\n")

        if warnings:
            md.append("## [Standard Warnings] Policy Guidelines\n")
            for idx, wrn in enumerate(warnings):
                rule = wrn.get("rule")
                file_path = wrn.get("file", "")
                loc = wrn.get("location")
                msg = wrn.get("message")
                orig = wrn.get("original")
                
                md.append(f"### {idx+1}. Rule: `{rule}`")
                if file_path:
                    md.append(f"- **File**: `{file_path}`")
                md.append(f"- **Location**: `{loc}`")
                md.append(f"- **Warning Details**: {msg}")
                if orig:
                    md.append(f"- **Original Source**: `{orig}`")
                md.append("")
                
                suggestion = ReportGenerator._get_suggestion(rule, orig)
                if suggestion:
                    md.append("- **Recommended Remediated Snippet**:")
                    md.append(f"```yaml\n{suggestion}\n```")
                md.append("\n---\n")

        return "\n".join(md)

    @staticmethod
    def _get_suggestion(rule, original):
        suggestions = {
            "pin-action-sha": f"# Pin action to immutable SHA\nuses: {original.split('@')[0]}@<latest-commit-sha> # {original.split('@')[1] if '@' in original else 'v1'}",
            "coverity-scan": "- name: Black Duck Security Scan\n  uses: blackduck-inc/black-duck-security-scan@v2\n  with:\n    api_token: ${{ secrets.BD_TOKEN }}\n    server_url: ${{ secrets.BD_URL }}",
            "image-build-jfrog": "- name: Build and Push Docker Image\n  run: |\n    docker build -t $JF_REGISTRY/my-image:$SHA .\n    jf docker push $JF_REGISTRY/my-image:$SHA\n    jf rt build-publish",
            "image-signing": "- name: Sign image with Cosign\n  run: cosign sign --yes $JF_REGISTRY/my-image@$IMAGE_DIGEST\n  env:\n    COSIGN_EXPERIMENTAL: 'true'",
            "bdba-scan": "- name: Run BDBA Scan\n  uses: blackduck-inc/black-duck-security-scan@v2\n  with:\n    api_token: ${{ secrets.BD_TOKEN }}\n    server_url: ${{ secrets.BD_URL }}\n    # Additional scanning triggers for docker image",
            "concurrency-control": "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true",
            "least-privilege-token": "permissions:\n  contents: read"
        }
        return suggestions.get(rule)
