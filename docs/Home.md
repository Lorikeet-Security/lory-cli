# Lorikeet Security CLI (`lory`) Documentation

Welcome to the comprehensive technical documentation for **`lory`**, the official command-line interface and security engineering workstation for [Lorikeet Security](https://lorikeetsecurity.com).

`lory` combines developer-first **White-Box AI Code Review** with active **PTaaS (Penetration Testing as a Service) Web Security Scanning**, live **Trust Badge generation**, and **Model Context Protocol (MCP)** server integration.

---

## Documentation Index

Explore each technical domain in detail:

| Document | Description |
| :--- | :--- |
| [**Architecture**](Architecture.md) | Architectural layout, engine pipelines, dual-mode analysis, and Mermaid sequence flows. |
| [**Authentication**](Authentication.md) | Talon OAuth 2.0 PKCE loopback login, session lifecycle, token refresh, and credentials security. |
| [**AI Code Review**](AI-Code-Review.md) | Real-time streaming SSE code reviews, AST parsing, CWE mapping, and in-place `--fix` auto-remediation. |
| [**PTaaS Web Scanning**](PTaaS-Web-Scanning.md) | Active & passive web scanning via `/ptaas/tools/scan-api.php`, security score computation, and audit checks. |
| [**Trust Badges**](Trust-Badges.md) | Cryptographic trust seals, dual-tone shield, SaaS dark/light pills, and SVG/HTML/Markdown exports. |
| [**MCP Integration**](MCP-Integration.md) | Model Context Protocol (`lory mcp serve`) stdio server for Claude Code, Cursor, and agent sidecars. |
| [**CI/CD Integration**](CI-CD.md) | Headless automation, GitHub Actions, GitLab CI, and SARIF 2.1.0 security reporting. |

---

## Quickstart

### 1. Installation

#### Standalone Binary (Linux & macOS)
```bash
curl -fsSL https://lorikeetsecurity.com/install.sh | bash
```

#### Via Go Compiler
```bash
go install github.com/Lorikeet-Security/lory-cli@latest
```

#### Verification
```bash
lory version
# Output: lory version 1.1.1 (Lorikeet Security AI Reviewer)
```

---

### 2. Five-Minute Workflow

```bash
# 1. Authenticate with Talon SSO
lory login

# 2. Verify identity & organization context
lory whoami

# 3. Review local repository with streaming findings
lory review .

# 4. Automatically apply suggested vulnerability fixes
lory fix .

# 5. Run live PTaaS Web Audit on your staging or production endpoint
lory scan https://staging.example.com

# 6. Generate a verified footer trust badge
lory badge staging.example.com --style=shield --theme=dark
```

---

## Feature Matrix

| Feature | Local Engine (Air-Gapped) | Lorikeet Platform Connected |
| :--- | :---: | :---: |
| **AST & Pattern Matching** | ✅ Yes | ✅ Yes |
| **CWE Classification** | ✅ Yes | ✅ Yes |
| **Real-Time SSE Streaming** | Offline buffer | ✅ Real-time SSE |
| **In-Place Code Auto-Fixes** | ✅ Built-in templates | ✅ Lory AI Synthesized Patches |
| **PTaaS Web Audit** | ❌ Requires network | ✅ Full audit via `/ptaas/tools/scan-api.php` |
| **Trust Badge Attestation** | Local SVG generation | ✅ Cryptographically verified attestation |
| **MCP Server Mode** | ✅ Yes | ✅ Yes |
| **SARIF 2.1.0 Export** | ✅ Yes | ✅ Yes |

---

## Command Reference Summary

```text
USAGE:
  lory <command> [arguments] [flags]

COMMANDS:
  login                    Authenticate interactively via Talon SSO or with API key
  logout                   Clear active session credentials
  whoami                   Inspect current Talon session and organization context
  review [path...]         Run Lory AI code review on files or directories
  scan <path|url>          Review code or run PTaaS web security scan against URL
  fix [path...]            Review code and automatically apply suggested fixes
  diff [git-args...]       Review only changed files in current git diff
  chat                     Start interactive security REPL session
  retest <finding-id>      1-click replay test to verify if a patch resolved a finding
  findings [list]          Stream active, verified vulnerabilities and triage state
  export                   Generate SARIF 2.1.0 or SOC 2 / ISO 27001 evidence packs
  badge [target]           Generate 'Secured by Lorikeet Security' badge for footers
  token [set|clear|show]   Manage Lorikeet/Lory access token for higher rate limits
  mcp serve                Launch Model Context Protocol stdio server for Claude Code & Cursor
  request-review <id>      Escalate finding to Lorikeet's human assessment team
  version                  Show CLI version information

FLAGS:
  --api-key <key>          Lorikeet API Key for headless/automated authentication
  --port <port>            Local callback port for Talon SSO flow (default: 54321)
  --fix                    Automatically apply suggested fixes to source files
  --stream                 Stream findings in real-time as they arrive (default: true)
  --base-url <url>         Lorikeet Security platform base URL (default: https://lorikeetsecurity.com)
  --token <token>          Lory access token (or set LORIKEET_TOKEN env var)
  --format <table|json>    Output format (default: table)
  --help, -h               Show help screen
```
