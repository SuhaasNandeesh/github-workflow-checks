# Pipeline Migration Analysis: .github

This report summarizes the compliance, security, and standard violations detected in the migrated GitHub Actions workflows.

## Executive Compliance Dashboard
| Metric | Count |
| :--- | :--- |
| **Critical Errors** | 8 |
| **Standard Warnings** | 9 |
| **Info Notices** | 4 |
| **Uncategorized** | 0 |
| **Total Violations** | 21 |

## [Critical Errors] Action Required

### 1. Rule: `least-privilege-token`
- **File**: `.github/workflows/ci.yml`
- **Location**: `workflow.permissions`
- **Issue**: Workflow does not declare explicit GITHUB_TOKEN permissions. Set default to read-only or empty 'permissions: {}' at the top-level.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
permissions:
  contents: read
```

---

### 2. Rule: `pin-action-sha`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build.steps[0]`
- **Issue**: Action 'actions/checkout' is pinned to tag/branch 'v4' instead of an immutable commit SHA.
- **Original Source**: `actions/checkout@v4`

- **Recommended Remediated Snippet**:
```yaml
# Pin action to immutable SHA
uses: actions/checkout@<latest-commit-sha>  # v4
```

---

### 3. Rule: `residual-gitlab-vars`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build.steps[1]`
- **Issue**: Shell step contains residual GitLab CI variable reference '$CI_PROJECT_NAME'.
- **Original Source**: `$CI_PROJECT_NAME`

- **Recommended Remediated Snippet**:
```yaml
# Replace with GitHub context
echo "...${{ github.sha }}..."   # was: $CI_PROJECT_NAME
```

---

### 4. Rule: `residual-gitlab-vars`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build.steps[1]`
- **Issue**: Shell step contains residual GitLab CI variable reference '$CI_PROJECT_NAME'.
- **Original Source**: `$CI_PROJECT_NAME`

- **Recommended Remediated Snippet**:
```yaml
# Replace with GitHub context
echo "...${{ github.sha }}..."   # was: $CI_PROJECT_NAME
```

---

### 5. Rule: `job-dependency-cycle`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `workflow.jobs`
- **Issue**: Circular dependency deadlock detected between jobs 'publish' and 'validate'.
- **Original Source**: `publish -> validate`

- **Recommended Remediated Snippet**:
```yaml
# Break the cycle by removing one of the 'needs' edges.
```

---

### 6. Rule: `least-privilege-token`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `workflow.permissions`
- **Issue**: Workflow does not declare explicit GITHUB_TOKEN permissions. Set default to read-only or empty 'permissions: {}' at the top-level.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
permissions:
  contents: read
```

---

### 7. Rule: `runner-shell-misalignment`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.validate.steps[0]`
- **Issue**: Job runs on Windows, but step uses Linux commands ['mkdir -p', 'tar'] without setting 'shell: bash'.
- **Original Source**: `mkdir -p build/logs # Violates runner-shell-misalignment on Windows
echo "Validating target..."
`

- **Recommended Remediated Snippet**:
```yaml
- name: Force bash on Windows
  shell: bash
  run: <your-commands>
```

---

### 8. Rule: `pin-action-sha`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.publish.steps[0]`
- **Issue**: Action 'actions/checkout' is pinned to tag/branch 'v4' instead of an immutable commit SHA.
- **Original Source**: `actions/checkout@v4`

- **Recommended Remediated Snippet**:
```yaml
# Pin action to immutable SHA
uses: actions/checkout@<latest-commit-sha>  # v4
```

---

## [Standard Warnings] Policy Guidelines

### 1. Rule: `job-timeout-missing`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build`
- **Issue**: Job 'build' does not declare 'timeout-minutes'. Hung builds may consume runner resources indefinitely.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
timeout-minutes: 30
```

---

### 2. Rule: `checkout-persist-credentials`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build.steps[0]`
- **Issue**: actions/checkout should set 'persist-credentials: false' to prevent the token from persisting in post-checkout steps.
- **Original Source**: `actions/checkout@v4`

- **Recommended Remediated Snippet**:
```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

---

### 3. Rule: `coverity-scan`
- **File**: `.github/workflows/ci.yml`
- **Location**: `workflow`
- **Issue**: Coverity scan (SAST / secrets checking) is not configured in this workflow.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
- name: Black Duck Coverity Scan
  uses: blackduck-inc/black-duck-security-scan@v2
  with:
    api_token: ${{ secrets.BD_TOKEN }}
    server_url: ${{ secrets.BD_URL }}
    coverity_url: ${{ secrets.COVERITY_URL }}
    coverity_user: ${{ secrets.COVERITY_USER }}
    coverity_pass: ${{ secrets.COVERITY_PASS }}
```

---

### 4. Rule: `concurrency-control`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `workflow.concurrency`
- **Issue**: State-modifying workflow (deployment/release) should configure 'concurrency' to prevent execution collisions.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

---

### 5. Rule: `job-timeout-missing`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.validate`
- **Issue**: Job 'validate' does not declare 'timeout-minutes'. Hung builds may consume runner resources indefinitely.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
timeout-minutes: 30
```

---

### 6. Rule: `job-timeout-missing`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.publish`
- **Issue**: Job 'publish' does not declare 'timeout-minutes'. Hung builds may consume runner resources indefinitely.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
timeout-minutes: 30
```

---

### 7. Rule: `checkout-persist-credentials`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.publish.steps[0]`
- **Issue**: actions/checkout should set 'persist-credentials: false' to prevent the token from persisting in post-checkout steps.
- **Original Source**: `actions/checkout@v4`

- **Recommended Remediated Snippet**:
```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

---

### 8. Rule: `environment-protection`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.publish`
- **Issue**: Deployment job 'publish' does not declare an 'environment:'. Use a protected environment with required reviewers for production.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
environment:
  name: production
  url: ${{ steps.deploy.outputs.url }}
```

---

### 9. Rule: `coverity-scan`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `workflow`
- **Issue**: Coverity scan (SAST / secrets checking) is not configured in this workflow.
- **Original Source**: `missing`

- **Recommended Remediated Snippet**:
```yaml
- name: Black Duck Coverity Scan
  uses: blackduck-inc/black-duck-security-scan@v2
  with:
    api_token: ${{ secrets.BD_TOKEN }}
    server_url: ${{ secrets.BD_URL }}
    coverity_url: ${{ secrets.COVERITY_URL }}
    coverity_user: ${{ secrets.COVERITY_USER }}
    coverity_pass: ${{ secrets.COVERITY_PASS }}
```

---

## [Info Notices]

### 1. Rule: `runner-version-pinned`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build`
- **Issue**: Job 'build' uses 'runs-on: latest' which is non-reproducible. Pin to a specific version.
- **Original Source**: `ubuntu-latest`

- **Recommended Remediated Snippet**:
```yaml
runs-on: ubuntu-22.04
```

---

### 2. Rule: `missing-set-x-pipefail`
- **File**: `.github/workflows/ci.yml`
- **Location**: `jobs.build.steps[1]`
- **Issue**: Multi-line bash run: script lacks 'set -e -o pipefail'; failures may be masked. Add it at the top of the script.
- **Original Source**: `3 lines`

- **Recommended Remediated Snippet**:
```yaml
run: |
  set -e -o pipefail
  # rest of script
```

---

### 3. Rule: `runner-version-pinned`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.validate`
- **Issue**: Job 'validate' uses 'runs-on: latest' which is non-reproducible. Pin to a specific version.
- **Original Source**: `windows-latest`

- **Recommended Remediated Snippet**:
```yaml
runs-on: ubuntu-22.04
```

---

### 4. Rule: `runner-version-pinned`
- **File**: `.github/workflows/deploy.yml`
- **Location**: `jobs.publish`
- **Issue**: Job 'publish' uses 'runs-on: latest' which is non-reproducible. Pin to a specific version.
- **Original Source**: `ubuntu-latest`

- **Recommended Remediated Snippet**:
```yaml
runs-on: ubuntu-22.04
```

---
