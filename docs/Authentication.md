# Authentication & Session Management

`lory` offers seamless authentication designed for both interactive developer workstations and automated headless CI/CD systems.

---

## 1. Authentication Mechanisms

`lory` supports three primary authentication paths:

| Mode | Command / Environment | Use Case |
| :--- | :--- | :--- |
| **Talon OAuth 2.0 PKCE** | `lory login` | Interactive terminal sessions on local developer machines |
| **API Key Flag** | `lory login --api-key <key>` | Standalone API key login without opening a browser |
| **Environment Variable** | `LORIKEET_API_KEY` or `LORIKEET_TOKEN` | CI/CD pipelines, Docker containers, headless agents |

---

## 2. Interactive Talon OAuth Login (`lory login`)

To log in interactively:

```bash
lory login
```

### Options & Flags
- `--port <port>`: Specify a custom port for the local callback listener (default: `54321`). If port 54321 is occupied, `lory` automatically falls back to an ephemeral OS-assigned port.
- `--api-key <key>`: Pass an API key directly without launching the browser.
- `--base-url <url>`: Override the Lorikeet Security platform base URL (default: `https://lorikeetsecurity.com`).

### Authentication Flow
1. `lory` starts an HTTP loopback server listening on `127.0.0.1:54321`.
2. Generates an RFC 7636 PKCE `code_verifier` (32 bytes entropy) and SHA-256 `code_challenge`.
3. Opens the system default browser to:
   ```text
   https://lorikeetsecurity.com/talon/mcp/oauth/authorize?response_type=code&client_id=...&redirect_uri=http://127.0.0.1:54321/callback&code_challenge=...&code_challenge_method=S256&state=...
   ```
4. Upon successful login in the browser, Talon redirects back to the loopback callback.
5. The loopback server renders the **Lorikeet Security Talon Claw Dual-Tone Shield** page with confirmation of your identity.
6. The CLI exchanges the authorization code and `code_verifier` at:
   ```text
   POST https://lorikeetsecurity.com/talon/mcp/oauth/token
   ```
7. Extracts the user profile (user email, company name, company ID). If the token endpoint omits these, `lory` automatically resolves identity via `/talon/api/whoami` or `/talon/mcp/oauth/userinfo`.
8. Saves credentials to disk and sets the active token.

---

## 3. Credentials File Security

Credentials are saved in:
```text
~/.lorikeet/credentials.json
```

On systems conforming to XDG standards, `$XDG_CONFIG_HOME/lorikeet/credentials.json` is respected if `$HOME/.lorikeet` is unavailable.

### File Permissions
The credentials directory and file are created with strict **`0700`** directory permissions and **`0600`** (`-rw-------`) file permissions to ensure that only the owning operating system user can read or write tokens.

### File Schema (`credentials.json`)
```json
{
  "access_token": "talon_token_94a8e...",
  "refresh_token": "talon_refresh_b32c1...",
  "user_email": "engineer@acme.com",
  "org_name": "Acme Security",
  "org_id": "org_acme_prod",
  "auth_method": "talon-oauth",
  "expires_at": "2026-11-28T19:30:00Z"
}
```

---

## 4. Identity Inspection (`lory whoami`)

Inspect your currently active Talon session, token expiration, and organization context:

```bash
lory whoami
```

### Example Output
```text
  User:         engineer@acme.com
  Organization: Acme Security (ID: org_acme_prod)
  Auth Method:  talon-oauth
  Session:      Active (Expires: 2026-11-28 19:30:00)
  Token:        talon_token_94a8... [VALID]
```

To output machine-readable JSON (useful for scripts):
```bash
lory whoami --format=json
```

---

## 5. Session Logout (`lory logout`)

To clear stored session tokens and revoke active credentials:

```bash
lory logout
```

This immediately deletes `~/.lorikeet/credentials.json` and purges any in-memory cached tokens.

---

## 6. Access Token Management (`lory token`)

Developers who possess a direct Talon Access Token can configure it directly:

```bash
# Set an access token
lory token set talon_token_abc12345

# View the active token
lory token show

# Clear the token
lory token clear
```

Alternatively, set the environment variable:
```bash
export LORIKEET_TOKEN="talon_token_abc12345"
```
