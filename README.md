<p align="center">
  <a href="https://lorikeetsecurity.com">
    <img src="assets/brand/lorikeet-logo-banner.png" alt="Lorikeet Security Banner" width="360" />
  </a>
</p>

<p align="center">
  <strong>Autonomous AI Security Analyst & Continuous PTaaS Verification Platform</strong>
</p>

<p align="center">
  <em>Real-time AST code auditing, vulnerability auto-remediation, active PTaaS verification, and native Model Context Protocol (MCP) server.</em>
</p>

<p align="center">
  <a href="https://github.com/Lorikeet-Security/lory-cli/releases"><img src="https://img.shields.io/badge/release-v1.2.1-db6574?style=for-the-badge&logo=github&logoColor=white" alt="Release v1.2.1"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.22+"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Compatible-ba5663?style=for-the-badge&logo=anthropic&logoColor=white" alt="MCP Compatible"></a>
  <a href="https://github.com/oasis-tcs/sarif-spec"><img src="https://img.shields.io/badge/SARIF-2.1.0-4caf50?style=for-the-badge" alt="SARIF 2.1.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-2b4c7e?style=for-the-badge" alt="Apache 2.0"></a>
</p>

---

## Overview

Lory is the command-line security analyst for the **Lorikeet Security** platform. Built in Go with Cobra and Bubbletea, `lory` pairs static AST code analysis with active penetration testing (PTaaS) verification.

Whether run in your terminal, embedded into **Claude Code** and **Cursor** via the Model Context Protocol (MCP), or gating pull requests in CI/CD, `lory` delivers deterministic, actionable security intelligence without false-positive noise.

---

## Key Capabilities

<table align="center" width="100%">
  <tr>
    <td width="33%" align="center">
      <img src="assets/brand/lory-coding.png" width="100" alt="Lory Sitting"/><br/><br/>
      <strong>Talon OAuth SSO</strong><br/>
      RFC 7636 PKCE loopback authentication linking local CLI sessions to your Lorikeet enterprise organization.
    </td>
    <td width="33%" align="center">
      <img src="assets/brand/lory-coding.png" width="100" alt="Lory Sitting"/><br/><br/>
      <strong>AI Review & Auto-Fix</strong><br/>
      Streaming AST semantic review across 25+ languages with verified in-place vulnerability remediation.
    </td>
    <td width="33%" align="center">
      <img src="assets/brand/lory-coding.png" width="100" alt="Lory Sitting"/><br/><br/>
      <strong>PTaaS & Trust Seals</strong><br/>
      Live web target audits, 1-click exploit retesting, and cryptographic SVG trust badges for public verification.
    </td>
  </tr>
</table>

---

## Terminal Review Session

```text
$ lory review .

  LORIKEET SECURITY : Lory Code Reviewer v1.2.1
  Target: /workspace/api (Go, TypeScript, Python)
  Rule Pack: OWASP Top 10 + ASVS 4.0.3 (1,969 rules loaded)

  [CRITICAL] SQL Injection via raw query concatenation
  File:     src/db/queries.ts:42
  CWE:      CWE-89: Improper Neutralization of Special Elements in SQL Command
  Snippet:  const res = await db.query(`SELECT * FROM users WHERE id = '${id}'`);
  Fix:      Use parameterized prepared statements:
            const res = await db.query('SELECT * FROM users WHERE id = $1', [id]);

  [HIGH] Missing Authentication Gate on Export Endpoint
  File:     routes/export.py:18
  CWE:      CWE-306: Missing Authentication for Critical Function
  Snippet:  @app.route('/api/v1/export', methods=['POST'])
  Fix:      Add @require_auth decorator to protect sensitive telemetry exports.

  Summary: 2 findings (1 Critical, 1 High, 0 Medium, 0 Low) in 1.4s
  Run `lory fix` to apply verified patches automatically.
```

---

## Installation & Quickstart

### Method 1: Instant Install Script (Linux & macOS)

```bash
curl -fsSL https://lorikeetsecurity.com/install.sh | bash
```

### Method 2: Go Toolchain

```bash
go install github.com/Lorikeet-Security/lory-cli@latest
```

### Method 3: Pre-compiled Standalone Binaries (v1.2.1)

Zero external dependencies. Download and run:

| Platform | Architecture | Binary Link | Checksum (SHA-256) |
|---|---|---|---|
| **Linux** | AMD64 (x86_64) | [`lory-linux-amd64`](https://github.com/Lorikeet-Security/lory-cli/releases/download/v1.2.1/lory-linux-amd64) | [checksums.txt](checksums.txt) |
| **Linux** | ARM64 (aarch64) | [`lory-linux-arm64`](https://github.com/Lorikeet-Security/lory-cli/releases/download/v1.2.1/lory-linux-arm64) | [checksums.txt](checksums.txt) |
| **macOS** | Apple Silicon (M-series) | [`lory-darwin-arm64`](https://github.com/Lorikeet-Security/lory-cli/releases/download/v1.2.1/lory-darwin-arm64) | [checksums.txt](checksums.txt) |
| **macOS** | Intel (x86_64) | [`lory-darwin-amd64`](https://github.com/Lorikeet-Security/lory-cli/releases/download/v1.2.1/lory-darwin-amd64) | [checksums.txt](checksums.txt) |
| **Windows** | x86_64 | [`lory-windows-amd64.exe`](https://github.com/Lorikeet-Security/lory-cli/releases/download/v1.2.1/lory-windows-amd64.exe) | [checksums.txt](checksums.txt) |

### Verification

```bash
lory version
# Output: lory version 1.2.1 (Lorikeet Security AI Reviewer)
```

---

## Quickstart Guide

### 1. Authenticate with Talon OAuth SSO
Launch secure browser authentication with cryptographic PKCE (S256) loopback:

```bash
# Interactive Talon OAuth login
lory login

# Check active session identity and permissions
lory whoami
```

### 2. Autonomous Code Review & Instant Auto-Fix
Audit your source code for critical security weaknesses and apply verified fixes in place:

```bash
# Review entire workspace with live streaming findings
lory review .

# Filter by minimum severity
lory review --min-severity=high src/

# Automatically apply verified patches directly to your files
lory fix src/db/queries.ts
```

### 3. PTaaS Endpoint Scanning & Security Verification
Audit web applications against modern security standards, TLS posture, headers, and cookie policies:

```bash
# Run comprehensive PTaaS audit on a live target
lory scan https://api.yourcompany.com

# Export audit findings to JSON
lory scan --format=json https://api.yourcompany.com
```

### 4. Git Pre-Commit Security Guard
Audit only modified or staged files before pushing to remote:

```bash
# Audit unstaged changes in working tree
lory diff

# Audit staged changes before committing
lory diff --cached
```

### 5. Compliance Evidence Packs (SARIF 2.1.0, SOC 2, PDF)
Generate compliance deliverables for auditors or CI security tabs:

```bash
# Export standard SARIF for GitHub Code Scanning
lory export --format sarif --out results.sarif

# Export audit-ready SOC 2 Type II / ISO 27001 evidence report
lory export --format soc2 --out compliance-evidence.md

# Export executive PDF report
lory export --format pdf --out executive-security-report.pdf
```

### 6. Website Trust Seals & Badges
Generate cryptographic SVG trust seals to showcase your security attestation:

```bash
# Generate footer HTML & SVG embed snippet
lory badge https://yourcompany.com

# Export dark-mode pill badge SVG
lory badge --style pill --theme dark --format svg --out lorikeet-badge.svg
```

---

## Model Context Protocol (MCP) Setup

Arm your AI pair programmers with direct access to Lorikeet Security intelligence.

### Claude Code Configuration (`~/.claude.json`)

```json
{
  "mcpServers": {
    "lory": {
      "command": "lory",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Cursor IDE Configuration (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "lorikeet-security": {
      "command": "lory",
      "args": ["mcp", "serve"]
    }
  }
}
```

#### Available MCP Tools:
- `lory_review_file`: Real-time source file security evaluation with line-accurate CWE citations.
- `lory_scan_target`: Automated passive web application PTaaS security scan.
- `lory_explain_finding`: Detailed remediation playbooks and exploit mitigation guidance.

---

## Complete CLI Command Reference

| Command | Subcommands / Flags | Description |
|---|---|---|
| `login` | `--port`, `--api-key` | Authenticate via Talon OAuth 2.0 PKCE loopback or API key |
| `whoami` | - | Inspect current Talon identity, organization, and token scopes |
| `logout` | - | Securely clear credentials and terminate active session |
| `review` | `[path]`, `--stream`, `--min-severity` | Run streaming AST AI code analysis on files or directories |
| `fix` | `[path]`, `--dry-run` | Automatically apply verified vulnerability remediations |
| `scan` | `[target]`, `--format=json\|text` | Dual-mode command: PTaaS audit on URLs or SAST on directories |
| `diff` | `--cached`, `[commit..commit]` | Scan git delta working tree changes before commit |
| `findings` | `--status=open\|verified` | Stream and filter discovered security vulnerabilities |
| `retest` | `[finding-id]` | 1-click exploit replay to verify vulnerability remediation |
| `export` | `--format=sarif\|soc2\|pdf` | Export compliance evidence packs and audit reports |
| `badge` | `--style=pill\|shield`, `--theme` | Generate embeddable cryptographic trust seal badges |
| `mcp` | `serve` | Launch high-performance stdio Model Context Protocol server |
| `token` | `set`, `show`, `clear` | Manage Lorikeet Security platform API access tokens |
| `version` | - | Display CLI build version and engine runtime information |

---

## Inline Suppression Directives

Silencing intentional design choices or false positives is simple with inline comments:

```typescript
// lory-ignore  Sanitized upstream by API gateway middleware
const query = `SELECT * FROM accounts WHERE id = '${userId}'`;
```

- `lory-ignore`: Silences alerts on the current line or subsequent line.
- `lory-ignore-next-line`: Silences alerts specifically on the next line.
- `lory-ignore-file`: Place in the first 20 lines to exclude the entire file from analysis.

---

## CI/CD Pipeline Automation

### GitHub Actions Workflow (`.github/workflows/security.yml`)

```yaml
name: Lorikeet Security Gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-audit:
    name: Lory Code & Dependency Review
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Lory CLI
        run: curl -fsSL https://lorikeetsecurity.com/install.sh | bash

      - name: Review Git Changes
        env:
          LORIKEET_TOKEN: ${{ secrets.LORIKEET_TOKEN }}
        run: lory diff --cached

      - name: Generate SARIF Security Report
        run: lory export --format sarif --out lory-results.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: lory-results.sarif
```

---

## Privacy & Architecture Guarantees

Lorikeet Security is designed from the ground up for strict enterprise privacy:

1. **Ephemeral Processing**: Code snippets evaluated via the cloud AI engine are processed ephemerally in-memory and are **never** logged, retained, or utilized for LLM training.
2. **Path Anonymization**: Full local paths and workspace metadata are stripped before transmission; only base filenames (e.g. `auth.ts`) are sent for language syntax context.
3. **Local SAST Offline Fallback**: When working in air-gapped environments or without network connectivity, `lory` automatically degrades to local deterministic rule engines.
4. **Zero Telemetry**: We collect zero background telemetry, user activity metrics, or environmental identifiers.

---

## Technical Documentation

Explore deep architectural breakdowns and platform specifications in the [`docs/`](./docs/) directory:

- [**Architecture & Engine Pipeline**](./docs/Architecture.md)
- [**Talon OAuth PKCE Deep Dive**](./docs/Authentication.md)
- [**AI Code Review & AST Grammar Engine**](./docs/AI-Code-Review.md)
- [**PTaaS Security Auditing Protocol**](./docs/PTaaS-Web-Scanning.md)
- [**Trust Seal Verification & Cryptography**](./docs/Trust-Badges.md)
- [**MCP Server Specification & Tool Schemas**](./docs/MCP-Integration.md)
- [**CI/CD Headless Deployments**](./docs/CI-CD.md)

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/Lorikeet-Security/lory-cli.git
cd lory-cli

# Build standalone binary
make build

# Run test suite
go test -v ./...

# Install to system PATH
sudo make install
```

---

<p align="center">
  <strong>Engineered with precision by <a href="https://lorikeetsecurity.com">Lorikeet Security</a></strong><br/>
  <em>Securing modern codebases with hybrid AI intelligence.</em>
</p>
