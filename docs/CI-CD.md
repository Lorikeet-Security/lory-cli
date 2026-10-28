# CI/CD Integration & Headless Automation

`lory` is built for automated security gates across continuous integration pipelines, preventing high and critical vulnerabilities from entering production codebases.

---

## 1. Exit Codes & Gate Behavior

`lory` signals audit outcomes via standard process exit codes:

| Exit Code | Meaning | CI Impact |
| :---: | :--- | :--- |
| **`0`** | Clean scan (No findings exceeding threshold) | Pipeline proceeds |
| **`1`** | Security Gate Failure (Critical or High vulnerabilities detected) | Pipeline halts |
| **`2`** | CLI or Network Error (Invalid arguments, endpoint timeout) | Pipeline error |

---

## 2. GitHub Actions Integration

### Automated Pull Request Security Review
Create `.github/workflows/lorikeet-security.yml`:

```yaml
name: Lorikeet Security AI Review

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for GitHub Code Scanning SARIF upload

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history for accurate git diff review

      - name: Install Lorikeet CLI
        run: |
          curl -fsSL https://lorikeetsecurity.com/install.sh | bash

      - name: Run Lory AI Code Review
        env:
          LORIKEET_TOKEN: ${{ secrets.LORIKEET_TOKEN }}
        run: |
          lory review . --min-severity=high

      - name: Export SARIF Report
        if: always()
        env:
          LORIKEET_TOKEN: ${{ secrets.LORIKEET_TOKEN }}
        run: |
          lory export --format=sarif --out=lorikeet-results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: lorikeet-results.sarif
```

---

## 3. GitLab CI/CD Pipeline

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - security

lorikeet-code-review:
  stage: security
  image: golang:1.24-alpine
  before_script:
    - apk add --no-cache curl bash git
    - curl -fsSL https://lorikeetsecurity.com/install.sh | bash
  script:
    - lory review . --min-severity=medium
  variables:
    LORIKEET_TOKEN: $LORIKEET_TOKEN
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## 4. Headless API Key & Token Management

In non-interactive environments (CI runners, containers), interactive browser login is disabled. Configure authentication using one of the following methods:

### Method A: Environment Variable (Recommended)
Set `LORIKEET_TOKEN` or `LORIKEET_API_KEY` in your CI repository secrets:
```bash
export LORIKEET_TOKEN="talon_sec_live_..."
lory review .
```

### Method B: Command-Line Flag
```bash
lory review . --token="${{ secrets.LORIKEET_TOKEN }}"
```

### Method C: Headless Login Command
```bash
lory login --api-key="${{ secrets.LORIKEET_API_KEY }}"
lory review .
```

---

## 5. Pre-Commit Hooks (`.pre-commit-config.yaml`)

Integrate `lory diff` into your local git hook workflow using [pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: local
    hooks:
      - id: lory-diff
        name: Lorikeet Security Pre-Commit Review
        entry: lory diff --cached --min-severity=high
        language: system
        stages: [pre-commit]
        pass_filenames: false
```

Or as a lightweight shell hook in `.git/hooks/pre-commit`:
```bash
#!/usr/bin/env bash
echo "Running Lorikeet Security pre-commit check..."
if ! lory diff --cached --min-severity=high; then
  echo "Commit blocked: High or Critical security vulnerabilities detected."
  echo "Run 'lory fix' to automatically remediate them."
  exit 1
fi
```
