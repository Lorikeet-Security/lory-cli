# AI Code Review & Auto-Remediation

`lory review` and `lory fix` provide deep static and dynamic security analysis of application source code using Lorikeet Security's real-time AI security analyst.

---

## 1. Running an AI Code Review (`lory review`)

Analyze single files, folders, or entire repositories:

```bash
# Review current directory
lory review .

# Review specific directory or file
lory review src/auth/login.ts

# Review multiple targets
lory review cmd/ api/ pkg/
```

### Flags & Options
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--fix` | Automatically apply suggested code fixes to files | `false` |
| `--stream` | Stream findings in real-time as they are synthesized | `true` |
| `--min-severity` | Minimum severity threshold: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--max-lines` | Maximum line count for a file before skipping | `1500` |
| `--format` | Output format: `table` or `json` | `table` |
| `--base-url` | Lorikeet platform endpoint | `https://lorikeetsecurity.com` |
| `--token` | Lorikeet token override | Stored session |

---

## 2. Real-Time Streaming Server-Sent Events (SSE)

When connected to the Lorikeet Security platform, `lory review` connects to:
```text
POST /ptaas/ajax/lory-code-review.php
Accept: text/event-stream
```

### Protocol Mechanics
1. Code chunks are submitted with language and line context metadata.
2. The server processes code through the Lory ReAct multi-agent security orchestrator.
3. As vulnerabilities are synthesized, findings are pushed down the SSE connection as `data: {...}` events.
4. The CLI TUI immediately renders each finding in real time with an animated spinner, preventing long wait times on large files.

### Finding Schema
```json
{
  "id": "LOR-SQLI-001",
  "title": "SQL Injection in User Query Handler",
  "severity": "CRITICAL",
  "cwe": "CWE-89",
  "confidence": 0.98,
  "filename": "src/db/users.py",
  "line": 42,
  "code_snippet": "query = f\"SELECT * FROM users WHERE email = '{user_input}'\"",
  "recommendation": "Use parameterized queries with prepared statements.",
  "patch": "query = \"SELECT * FROM users WHERE email = %s\"\ncursor.execute(query, (user_input,))"
}
```

---

## 3. In-Place Code Auto-Fixes (`lory fix`)

The `lory fix` command executes an AI code review and automatically applies verified remediation patches directly to the source files on disk:

```bash
# Automatically fix vulnerabilities across the project
lory fix .

# Fix a specific file
lory fix src/handlers/auth.go
```

`lory fix` is equivalent to running `lory review --fix`.

### How Auto-Fixes Work
1. `lory` extracts the line range containing the vulnerability.
2. It verifies that the existing snippet matches the expected AST node.
3. Performs atomic replacement of the vulnerable snippet with the synthesized patch.
4. Preserves surrounding indentation, line breaks, and unrelated comments.
5. Prints a unified diff summary of all applied modifications.

---

## 4. Git Diff Reviews (`lory diff`)

Evaluate only files and lines modified in your local working tree or between git commits:

```bash
# Review uncommitted working tree changes
lory diff

# Review staged changes
lory diff --cached

# Review changes against main branch
lory diff origin/main...HEAD
```

This is ideal for pre-commit hooks, pull request validation, and rapid local iteration.

---

## 5. Supported Languages & Frameworks

`lory` natively understands 25+ programming languages and frameworks:

- **Web & Backend**: Go, TypeScript, JavaScript, Python, Rust, Java, C#, PHP, Ruby, Kotlin, Swift
- **Systems**: C, C++, Zig
- **Frontend Frameworks**: React, Vue, Next.js, Svelte, Angular
- **Infrastructure & Config**: Terraform, Dockerfile, Kubernetes YAML, GitHub Actions YAML, CloudFormation, Helm

---

## 6. Inline Vulnerability Suppressions

If a specific finding is an accepted risk or known false positive, you can suppress it directly in source code using comments:

### Single Line Suppression
```python
# lory:ignore CWE-89 User input is sanitized by custom WAF middleware
query = f"SELECT * FROM logs WHERE tag = '{tag}'"
```

### Block Suppression
```javascript
// lory:suppress-start LOR-XSS-002 Internal admin dashboard with trusted HTML
element.innerHTML = sanitizedMarkup;
// lory:suppress-end
```

### Global Ignore File (`.loryignore`)
Create a `.loryignore` file in the root of your repository:
```text
# Ignore generated code and vendor libraries
vendor/
node_modules/
dist/
*.min.js

# Ignore specific test suites
test/fixtures/vulnerable_samples/
```
