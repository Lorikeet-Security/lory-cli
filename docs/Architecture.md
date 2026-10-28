# Lorikeet CLI Architecture

`lory` is built as a zero-dependency, standalone Go binary designed for high performance, portability across developer workstations and CI/CD pipelines, and seamless interaction with the **Lorikeet Security Talon Platform**.

---

## 1. High-Level System Architecture

The following diagram illustrates the interaction between `lory`, the developer workspace, and the Lorikeet Security cloud platform:

```mermaid
flowchart TD
    subgraph DeveloperWorkspace["Developer Local Workspace"]
        CLI["lory CLI Binary<br/>(Zero-dependency Go executable)"]
        FS["Source Code Files / Git Repo"]
        Creds["~/.lorikeet/credentials.json<br/>(0600 Permissions)"]
        IDE["AI IDEs & Editors<br/>(Claude Code, Cursor, VS Code)"]
    end

    subgraph CLIInternal["CLI Internal Subsystems"]
        AuthModule["pkg/auth<br/>• PKCE Generator<br/>• Loopback Callback Server<br/>• Token Manager"]
        ReviewerModule["pkg/reviewer<br/>• File Walker & Filters<br/>• Diff Evaluator<br/>• AST Analyzer"]
        WebScanModule["pkg/webscan<br/>• URL Target Auditor<br/>• Result Parser"]
        BadgeModule["pkg/badge<br/>• Trust Seal Generator<br/>• SVG & HTML Formatter"]
        MCPModule["pkg/mcp<br/>• JSON-RPC 2.0 Server<br/>• Tool Dispatcher"]
        ClientModule["pkg/client<br/>• SSE Stream Client<br/>• HTTP Transport"]
        AnalyzerEngine["pkg/analyzer<br/>• Local Static Rules Engine<br/>• Air-Gapped Fallback"]
    end

    subgraph Platform["Lorikeet Security Talon Cloud"]
        TalonOAuth["Talon OAuth 2.0 Provider<br/>/talon/mcp/oauth/*"]
        LoryAIReview["Lory AI Review Endpoint<br/>/ptaas/ajax/lory-code-review.php"]
        PTaaSScanAPI["PTaaS Scan API<br/>/ptaas/tools/scan-api.php"]
        AttestationAPI["Attestation & Badges Engine<br/>lorikeetsecurity.com/verify"]
    end

    CLI --> AuthModule
    CLI --> ReviewerModule
    CLI --> WebScanModule
    CLI --> BadgeModule
    CLI --> MCPModule

    IDE <-->|"Stdio (JSON-RPC 2.0)"| MCPModule
    ReviewerModule --> FS
    AuthModule <--> Creds
    ReviewerModule --> ClientModule
    ReviewerModule -.->|"Fallback if offline"| AnalyzerEngine
    WebScanModule --> ClientModule

    ClientModule -->|"POST /ptaas/ajax/lory-code-review.php (SSE)"| LoryAIReview
    ClientModule -->|"POST /ptaas/tools/scan-api.php"| PTaaSScanAPI
    AuthModule -->|"OAuth 2.0 + PKCE"| TalonOAuth
    BadgeModule -.->|"Attestation Link"| AttestationAPI
```

---

## 2. Talon OAuth 2.0 PKCE Loopback Flow

To securely authenticate developer terminals without exposing API secrets or requiring manual token copying, `lory` implements an **RFC 7636 PKCE (Proof Key for Code Exchange)** loopback authorization flow using SHA-256 (`S256`):

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant CLI as lory CLI
    participant Server as Ephemeral Loopback Server<br/>(127.0.0.1:54321)
    participant Browser as System Web Browser
    participant Talon as Talon OAuth Provider<br/>(lorikeetsecurity.com)

    Dev->>CLI: Executes `lory login`
    CLI->>CLI: Generate code_verifier (32-byte cryptographically secure random)
    CLI->>CLI: Compute code_challenge = Base64URL(SHA256(code_verifier))
    CLI->>CLI: Generate random CSRF state (16 bytes hex)
    CLI->>Server: Start HTTP listener on 127.0.0.1:54321 (or ephemeral port)
    CLI->>Browser: Open https://lorikeetsecurity.com/talon/mcp/oauth/authorize<br/>?client_id=...&code_challenge=...&code_challenge_method=S256&state=...
    Browser->>Talon: Present Talon SSO login prompt to user
    Talon->>Browser: User authenticates (SSO / MFA / Passkey)
    Talon->>Browser: HTTP 302 Redirect to http://127.0.0.1:54321/callback?code=AUTH_CODE&state=CSRF_STATE
    Browser->>Server: GET /callback?code=AUTH_CODE&state=CSRF_STATE
    Server->>Server: Verify state matches CSRF state token
    Server-->>Browser: Render Dual-Tone Talon Claw Shield "Authentication Successful" page
    Server->>CLI: Transmit authorization code via internal channel
    Server->>Server: Gracefully shutdown HTTP server
    CLI->>Talon: POST /talon/mcp/oauth/token<br/>(code, client_id, code_verifier, redirect_uri)
    Talon->>Talon: Validate code_verifier matches code_challenge
    Talon-->>CLI: Return access_token, refresh_token, user_email, company_name, company_id
    CLI->>CLI: If profile missing, query /talon/api/whoami or /talon/mcp/oauth/userinfo
    CLI->>CLI: Persist to ~/.lorikeet/credentials.json (mode 0600)
    CLI-->>Dev: Print authenticated user & organization banner
```

---

## 3. Dual-Mode Review Execution Pipeline

`lory review` and `lory fix` are engineered with continuous operational availability in mind:

```mermaid
flowchart TD
    Start["Developer runs `lory review <path>`"] --> AuthCheck{"Is session authenticated<br/>or LORIKEET_TOKEN set?"}

    AuthCheck -- Yes --> PlatformRequest["Prepare LoryReviewRequest<br/>(Code, Language, Filename, Stream=true)"]
    AuthCheck -- No / Token Missing --> PromptLogin["Prompt `lory login` or fallback to Local SAST"]

    PlatformRequest --> ConnectPlatform{"Attempt connection to<br/>https://lorikeetsecurity.com/ptaas/ajax/lory-code-review.php"}

    ConnectPlatform -- HTTP 200 (SSE Connected) --> StreamSSE["Read Real-Time SSE Event Stream<br/>• Parse finding objects<br/>• Render live progress in TUI"]
    ConnectPlatform -- Offline / Network Error --> FallbackLocal["Activate Local Offline Analyzer Engine<br/>(pkg/analyzer/local_engine.go)"]

    StreamSSE --> CollectFindings["Collect & deduplicate findings"]
    FallbackLocal --> CollectFindings

    CollectFindings --> RenderTUI["Render Terminal Findings Table<br/>• Severity Badge<br/>• CWE Classification<br/>• Line Reference<br/>• Remediation Recommendation"]

    RenderTUI --> CheckFix{"Was `--fix` flag<br/>or `lory fix` invoked?"}
    CheckFix -- Yes --> ApplyPatches["Apply in-place code replacements to source files<br/>with AST-verified patch blocks"]
    CheckFix -- No --> ExitClean["Exit with status code (0 if clean, 1 if critical/high)"]
    ApplyPatches --> ExitClean
```

---

## 4. Component Layout

The codebase is organized into modular packages:

```text
lory-cli/
├── apps/
│   └── cli/
│       ├── cmd/               # CLI Command implementations (review, scan, badge, etc.)
│       └── main.go            # Entrypoint and flag parsing
├── pkg/
│   ├── analyzer/              # Offline AST static analysis and fallback engine
│   ├── auth/                  # PKCE OAuth 2.0 loopback server and token storage
│   ├── badge/                 # Trust badge generation and SVG/HTML template rendering
│   ├── client/                # Platform HTTP client and SSE event-stream parser
│   ├── export/                # SARIF 2.1.0 and compliance export formats
│   ├── mcp/                   # Model Context Protocol stdio server
│   ├── retest/                # 1-click regression verification harness
│   ├── reviewer/              # File walker, language detector, and code extractor
│   ├── scanner/               # Local repository scanner utilities
│   ├── tui/                   # ANSI colored formatting, spinners, and badges
│   ├── types/                 # Universal domain models and request/response payloads
│   └── webscan/               # PTaaS web auditing client and score calculator
└── docs/                      # Comprehensive documentation and architecture guides
```
