# Model Context Protocol (MCP) Integration

`lory mcp serve` transforms the `lory` CLI into a standards-compliant **Model Context Protocol (MCP)** server operating over standard input/output (`stdio`).

This allows AI coding agents—including **Claude Code**, **Cursor**, **Windsurf**, and IDE sidecars—to invoke Lorikeet's security analysis tools directly within their agentic loops.

---

## 1. Launching the MCP Server

```bash
lory mcp serve
```

When started, `lory` listens for JSON-RPC 2.0 messages over `stdin` and writes responses to `stdout`.

Protocol specifications:
- **Protocol Version**: `2024-11-05`
- **Transport**: `stdio`
- **Server Name**: `lorikeet-lory-mcp`
- **Server Version**: `1.1.1`

---

## 2. Tools Exposed by the MCP Server

The server registers three primary security tools:

### 1. `lory_review_file`
Reviews a source code file for security vulnerabilities using Lorikeet Security's Lory AI analyst.
- **Input Parameters**:
  - `file_path` (string, required): Absolute or workspace-relative path to the file to review.
- **Returns**: A structured list of security findings, CWE mappings, exact line numbers, code snippets, and synthesized remediation patches.

### 2. `lory_scan_target`
Performs an active/passive PTaaS web security scan against a live endpoint.
- **Input Parameters**:
  - `url` (string, required): Target URL (e.g., `https://staging.acme.com`).
- **Returns**: Live audit findings, security score (0-100), TLS/SSL validity, security headers, and cookie policy posture.

### 3. `lory_explain_finding`
Provides detailed remediation guidance, attack playbooks, and mitigation examples for a specific CWE or vulnerability title.
- **Input Parameters**:
  - `cwe` (string, optional): CWE identifier (e.g., `CWE-89`, `CWE-79`).
  - `title` (string, optional): Vulnerability title (e.g., `SQL Injection`, `Path Traversal`).
- **Returns**: Remediation walk-through, safe API alternatives, and defense-in-depth recommendations.

---

## 3. Configuring Claude Desktop & Claude Code

Add `lory` to your Claude Desktop configuration file:

### On macOS
`~/Library/Application Support/Claude/claude_desktop_config.json`

### On Linux
`~/.config/Claude/claude_desktop_config.json`

### On Windows
`%APPDATA%\Claude\claude_desktop_config.json`

### Configuration Snippet
```json
{
  "mcpServers": {
    "lorikeet-lory": {
      "command": "lory",
      "args": ["mcp", "serve"],
      "env": {
        "LORIKEET_TOKEN": "your_talon_access_token"
      }
    }
  }
}
```

If you installed `lory` to a custom path (e.g., `/usr/local/bin/lory` or `C:\tools\lory.exe`), specify the full path in the `command` field.

---

## 4. Configuring Cursor IDE

To enable Lorikeet MCP tools in Cursor:
1. Open Cursor Settings -> **Features** -> **MCP**.
2. Click **Add New MCP Server**.
3. Set:
   - **Name**: `Lorikeet Security`
   - **Type**: `command`
   - **Command**: `lory mcp serve`
4. Alternatively, configure in `.cursor/mcp.json` in your project root:
   ```json
   {
     "mcpServers": {
       "lorikeet": {
         "command": "lory",
         "args": ["mcp", "serve"]
       }
     }
   }
   ```

---

## 5. Testing the MCP Server Interactively

You can test the MCP server by piping JSON-RPC 2.0 requests:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}' | lory mcp serve
```

Expected response:
```json
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{"listChanged":false}},"protocolVersion":"2024-11-05","serverInfo":{"name":"lorikeet-lory-mcp","version":"1.1.1"}}}
```

List tools:
```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | lory mcp serve
```
