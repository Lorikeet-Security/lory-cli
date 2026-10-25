# Lory CLI (`lory`)

> Autonomous, hybrid-intelligence security testing directly from your terminal.

`lory` is the official local command-line interface for [Lorikeet Security](https://lorikeetsecurity.com/lory). Modeled after the developer-first workflow of Keygraph Shannon, `lory` bridges local white-box static code analysis with live runtime verification while keeping full state synchronized with the **Talon** compliance and attestation platform.

[![Release](https://github.com/lorikeetsecurity/lory/actions/workflows/release.yml/badge.svg)](https://github.com/lorikeetsecurity/lory/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-brightgreen.svg)](https://sarifweb.azurewebsites.net/)
[![SOC 2 / ISO 27001](https://img.shields.io/badge/Compliance-SOC_2_%7C_ISO_27001-blueviolet.svg)](https://lorikeetsecurity.com/talon)

---

## 1. Overview & Distribution

`lory` runs as a zero-dependency standalone binary or via Node's `npx` runner for instant adoption.

### Installation Channels

```bash
# Instant zero-install run (Node / npx)
npx @lorikeetsecurity/lory@latest scan

# Homebrew (macOS / Linux)
brew install lorikeetsecurity/tap/lory

# Shell script installer
curl -fsSL https://lorikeet.security/install.sh | bash

# Ephemeral Docker Execution Worker
docker pull ghcr.io/lorikeetsecurity/lory-worker:latest
```

### Local Build from Source

```bash
git clone https://github.com/lorikeetsecurity/lory-cli.git
cd lory-cli
make build
./lory --help
```

---

## 2. Authentication Architecture

`lory` supports both interactive desktop developer sessions and headless automated environments (CI/CD).

```text
                 ┌──────────────────────────────────────────────┐
                 │                  lory auth                   │
                 └───────────────────────┬──────────────────────┘
                                         │
                 ┌───────────────────────┴──────────────────────┐
                 ▼                                              ▼
       [ Talon SSO Browser Flow ]                     [ Headless API Key ]
  1. CLI starts local callback server            1. Flags: --api-key / env var:
     http://localhost:54321/callback                LORIKEET_API_KEY
  2. Opens browser:                              2. Direct exchange with
     https://talon.lorikeetsecurity.com/cli/auth    https://api.lorikeetsecurity.com
  3. User completes Talon SSO                    3. Validates org permissions,
  4. Redirect returns short-lived code              active seats, and credits
  5. CLI exchanges code for:
     • Bearer Access Token (JWT)
     • Refresh Token
                 │                                              │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                 ┌──────────────────────────────────────────────┐
                 │ Secure Token Storage:                        │
                 │ Linux: Secret Service / Keyring              │
                 │ macOS: Keychain Access                       │
                 │ Fallback: ~/.lorikeet/credentials.json (0600)│
                 └──────────────────────────────────────────────┘
```

### Usage

```bash
# Interactive Talon SSO
lory login
# > Opening browser to authenticate via Talon SSO...
# > Logged in as developer@lorikeetsecurity.com (Lorikeet Corp)

# Headless / CI/CD pipeline
export LORIKEET_API_KEY="lory_live_xxxxxxxx"
lory scan --repo . --target http://localhost:3000
```

---

## 3. System Architecture

`lory` blends local source-code AST mapping (white-box) with active runtime validation (black-box verification).

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Local CLI (lory)                                │
│                                                                             │
│  ┌─────────────────────────┐  ┌───────────────────────┐  ┌────────────────┐ │
│  │ Interactive TUI         │  │ White-Box Code Mapper │  │ Local Docker / │ │
│  │ (Bubbletea / Ink)       │  │ (AST, routes, auth,   │  │ Tool Sandbox   │ │
│  │ Real-time PoC streaming │  │  sinks, sensitive IDs)│  │ (nmap, ffuf,   │ │
│  └───────────┬─────────────┘  └───────────┬───────────┘  │  nuclei, curl) │ │
│              │                            │              └────────┬───────┘ │
│              └──────────────────┬─────────┴───────────────────────┘         │
│                                 │ WebSocket / gRPC Streaming                │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Lorikeet Platform & Talon Backend                        │
│                                                                             │
│  ┌──────────────────────────────┐       ┌────────────────────────────────┐  │
│  │ Lory ReAct Orchestrator      │       │ Talon Cloud Engine             │  │
│  │ • Threat Modeling & Vectors  │◄─────►│ • Compliance Attestation Engine│  │
│  │ • Exploit Synthesis Loop     │       │ • SOC 2 / ISO 27001 Evidence   │  │
│  │ • Dual validation (No bogus) │       │ • 1-Click Retest Graph         │  │
│  └──────────────────────────────┘       │ • Human-Assisted Review Queue  │  │
│                                         └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Sandbox Execution Modes
To isolate execution workloads and verify vulnerabilities safely:
1. **Local Container Sandbox:** Launches `docker run --rm -v $(pwd):/workspace ghcr.io/lorikeetsecurity/lory-worker` to test endpoints and run local tools without polluting host dependencies.
2. **Hybrid Cloud Egress:** CLI streams AST metadata to the Lory brain, which runs external checks from Lorikeet cloud egress points back against exposed environments.

---

## 4. CLI Capabilities & Command Reference

Every feature on the web dashboard corresponds directly to a CLI command:

| Web Feature | CLI Command | Description |
| :--- | :--- | :--- |
| **New Pentest Project** | `lory scan --repo . --target <url>` | Runs white-box code mapping paired with live verification. |
| **Interactive Terminal Chat** | `lory chat` | REPL session where Lory inspects files, re-tests issues, and answers triage queries. |
| **1-Click Retest** | `lory retest <finding-id>` | Fetches the exact replay test from Talon to confirm if a fix works. |
| **Vulnerability Triage** | `lory findings list --status open` | Streams active, verified vulnerabilities with reproducible verification details. |
| **Compliance Export** | `lory export --format pdf,sarif --soc2` | Generates audit-ready evidence packs, SARIF 2.1.0, and attestation artifacts. |
| **IDE / Editor Integration** | `lory mcp serve` | Launches a Model Context Protocol stdio server for Claude Code and Cursor. |
| **Escalate to Human Review** | `lory request-review <finding-id>` | Dispatches complex findings directly to Lorikeet's human assessment team. |

---

## 5. Repository Layout

```text
lory/
├── apps/
│   ├── cli/                      # Terminal application (Go standalone + TS/Ink)
│   │   ├── cmd/                  # Core Go command implementations
│   │   ├── src/                  # TypeScript CLI source
│   │   │   ├── commands/         # Subcommand handlers (auth, scan, retest, chat, mcp)
│   │   │   ├── auth/             # Loopback SSO callback & keychain
│   │   │   └── ui/               # Terminal spinners, live tables, color cards
│   │   ├── main.go               # Go entrypoint compiling to standalone binary
│   │   └── package.json
│   │
│   └── worker/                   # Ephemeral container runtime
│       ├── Dockerfile            # Tooling bundle (ffuf, nuclei, headless browser)
│       └── runner/               # Execution sandboxing scripts
│
├── packages/
│   ├── sdk/                      # Talon & Lory API Client
│   ├── analyzer/                 # AST & endpoint route extraction
│   └── protocol/                 # Shared JSON/Protobuf schemas
│
├── pkg/                          # Go internal packages
│   ├── analyzer/                 # AST parsing & sink detection engine
│   ├── auth/                     # OAuth SSO loopback server & credentials
│   ├── export/                   # SARIF 2.1.0 & SOC 2 evidence generators
│   ├── mcp/                      # Model Context Protocol stdio server
│   ├── retest/                   # 1-click PoC replay verification
│   ├── scanner/                  # Dual-validation orchestration engine
│   ├── tui/                      # ANSI terminal UI & progress spinners
│   └── types/                    # Core vulnerability & route data structures
│
├── .github/workflows/
│   └── release.yml               # Binaries, Docker image, and npm publish pipelines
├── Makefile                      # Build automation
├── install.sh                    # One-line installer script
└── README.md
```

---

## 6. Model Context Protocol (MCP) Integration

To use `lory` inside **Claude Code**, **Cursor**, or any MCP-compatible AI IDE, configure:

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
- `lory_scan`: White-box AST mapping and live exploit verification.
- `lory_get_findings`: Retrieve confirmed vulnerabilities and triage states.
- `lory_retest`: 1-click PoC verification to validate remediation code.
- `lory_analyze_routes`: Source code inspection and HTTP endpoint extraction.
