# Lory CLI (`lory`)

> Lorikeet Security's AI security analyst & PTaaS scanner directly in your terminal.

`lory` is the official command-line interface for [Lorikeet Security](https://lorikeetsecurity.com). It brings Lory's real-time AI code reviewer and the Lorikeet PTaaS web security scanner straight to your terminal, pre-commit hooks, and CI/CD pipelines.

```
 _        ___   ____  __   __
| |      / _ \ |  _ \ \ \ / /  LORIKEET SECURITY
| |     | | | || |_) | \ V /   AI Security Analyst & PTaaS Platform
| |___  | |_| ||  _ <   | |    Lory Review & Web Security Scanner
|_____|  \___/ |_| \_\  |_|    v1.1.0
```

---

## 1. What It Does

1. **Lory AI Code Review (`lory review`, `lory scan <path>`)**:
   - Analyzes source code files across 25+ programming languages.
   - Evaluates code against Lorikeet's real-time AI engine (`/ptaas/ajax/lory-code-review.php`) with streaming SSE findings.
   - Identifies injection sinks (SQL, command, template, path traversal), broken auth, hardcoded secrets, SSRF, permissive CORS, and insecure framework configs.
   - Generates exact line-anchored quick fixes with explanations.

2. **Auto-Remediation (`lory fix <path>`, `lory review --fix`)**:
   - Automatically applies Lory's suggested quick fixes to source files in-place.

3. **Git Diff & Pre-Commit (`lory diff`)**:
   - Reviews only modified files or staged commits, ideal for pre-commit hooks and PR checks.

4. **Web Security Scanner (`lory scan <url>`)**:
   - Performs non-intrusive PTaaS web security scans against target endpoints (matching `scan-api.php`).
   - Audits Security Headers (HSTS, CSP, X-Frame-Options, etc.), SSL/TLS certificates, Cookie security flags, Server info leaks, and `security.txt`.
   - Computes an overall security posture score (0 - 100).

5. **AI IDE Integration (`lory mcp serve`)**:
   - Full Model Context Protocol (MCP) stdio server for **Claude Code**, **Cursor**, and any MCP client.

---

## 2. Quickstart

### Installation

```bash
# Build standalone binary from source
make build

# Optional: Install to system PATH
sudo make install
```

### Review Code

```bash
# Review current repository or directory
lory review .

# Review a specific file with real-time streaming
lory review src/server.js

# Review and automatically apply suggested fixes
lory fix src/server.js
```

### Scan a Live Target URL

```bash
# Audits headers, SSL/TLS, cookies, server leaks, and calculates score
lory scan https://example.com
```

### Review Git Changes

```bash
# Review only modified files in current branch / diff
lory diff

# Review staged changes
lory diff --cached
```

---

## 3. Ignoring Findings

Lory respects the same suppression comments as the official VS Code extension:

```javascript
// lory-ignore  the id is an internal enum, not user input
db.query(`SELECT * FROM t WHERE kind='${KIND}'`);
```

- `lory-ignore`: Silences findings on the current line or the following line.
- `lory-ignore-next-line`: Silences findings on the next line.
- `lory-ignore-file`: Place anywhere in the first 20 lines to skip reviewing the entire file.

---

## 4. Rate Limits & Access Tokens

By default, Lory runs on the anonymous tier (30 requests/min, keyed to IP). To use your Lorikeet access token:

```bash
# Set your Lorikeet token (e.g. from portal MCP page)
lory token set lkmcp_xxxxxxxxxxxxxxxx

# Inspect active token status
lory token show

# Clear token and return to anonymous tier
lory token clear
```

Alternatively, set the environment variable:
```bash
export LORIKEET_TOKEN="lkmcp_xxxxxxxxxxxxxxxx"
```

---

## 5. Model Context Protocol (MCP) Configuration

Configure `lory` in Claude Code (`~/.claude.json`) or Cursor:

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

Exposed MCP Tools:
- `lory_review_file`: Review a source file for security vulnerabilities using Lory AI.
- `lory_scan_target`: Run PTaaS web security scan against a live URL.
- `lory_explain_finding`: Detailed remediation guidance for CWEs and vulnerabilities.

---

## 6. Command Reference

| Command | Usage | Description |
| :--- | :--- | :--- |
| `review` | `lory review [path...]` | Runs Lory AI code review on files or directories. |
| `scan` | `lory scan <path\|url>` | Reviews code or runs PTaaS web security scan against URL. |
| `fix` | `lory fix [path...]` | Reviews code and automatically applies suggested fixes. |
| `diff` | `lory diff [git-args]` | Reviews only modified files from `git diff`. |
| `token` | `lory token [set\|clear\|show]` | Configures Lorikeet access token for higher rate limits. |
| `mcp` | `lory mcp serve` | Launches MCP stdio server for Claude Code and Cursor. |
| `version` | `lory version` | Shows version information. |
