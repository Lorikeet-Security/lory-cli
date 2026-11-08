package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/Lorikeet-Security/lory-cli/pkg/auth"
	"github.com/Lorikeet-Security/lory-cli/pkg/client"
	"github.com/Lorikeet-Security/lory-cli/pkg/reviewer"
	"github.com/Lorikeet-Security/lory-cli/pkg/types"
	"github.com/Lorikeet-Security/lory-cli/pkg/webscan"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

func ServeMCP() error {
	scannerInput := bufio.NewScanner(os.Stdin)

	for scannerInput.Scan() {
		line := scannerInput.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(req.ID, -32700, "Parse error")
			continue
		}

		handleRequest(&req)
	}

	return scannerInput.Err()
}

var (
	outWriterLock sync.Mutex
	outWriter     io.Writer = os.Stdout
)

// SetOutput sets the output destination for MCP responses (useful for testing).
func SetOutput(w io.Writer) {
	outWriterLock.Lock()
	defer outWriterLock.Unlock()
	outWriter = w
}

func sendResponse(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	outWriterLock.Lock()
	defer outWriterLock.Unlock()
	fmt.Fprintf(outWriter, "%s\n", data)
}

func sendError(id interface{}, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	outWriterLock.Lock()
	defer outWriterLock.Unlock()
	fmt.Fprintf(outWriter, "%s\n", data)
}

// HandleRequest processes an incoming JSON-RPC request.
func HandleRequest(req *JSONRPCRequest) {
	handleRequest(req)
}

func handleRequest(req *JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		sendResponse(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "lorikeet-lory-mcp",
				"version": "1.2.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{
					"listChanged": false,
				},
			},
		})

	case "notifications/initialized":
		// No response required for notifications

	case "tools/list":
		sendResponse(req.ID, map[string]interface{}{
			"tools": []map[string]interface{}{
				{
					"name":        "lory_review_file",
					"description": "Reviews a source code file for security vulnerabilities using Lorikeet Security's Lory AI analyst",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"file_path": map[string]string{"type": "string", "description": "Path to file to review"},
						},
						"required": []string{"file_path"},
					},
				},
				{
					"name":        "lory_scan_target",
					"description": "Performs passive PTaaS web security scan against target URL (headers, SSL/TLS, cookies, server info leaks)",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"url": map[string]string{"type": "string", "description": "Target application URL (e.g. https://example.com)"},
						},
						"required": []string{"url"},
					},
				},
				{
					"name":        "lory_explain_finding",
					"description": "Provides in-depth remediation advice for a specific vulnerability or CWE",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"cwe":   map[string]string{"type": "string", "description": "CWE identifier (e.g. CWE-89)"},
							"title": map[string]string{"type": "string", "description": "Vulnerability title"},
						},
					},
				},
			},
		})

	case "tools/call":
		var callParams struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			sendError(req.ID, -32602, "Invalid params")
			return
		}

		token := auth.GetToken()
		loryCli := client.NewLoryClient(client.DefaultBaseURL, token)

		switch callParams.Name {
		case "lory_review_file":
			filePath, _ := callParams.Arguments["file_path"].(string)
			if filePath == "" {
				sendError(req.ID, -32602, "file_path is required")
				return
			}

			res, err := reviewer.ReviewFile(context.Background(), filePath, types.ReviewConfig{Stream: false}, loryCli, nil)
			if err != nil {
				sendError(req.ID, -32000, err.Error())
				return
			}

			data, _ := json.MarshalIndent(res.Findings, "", "  ")
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Lory review for %s (%d lines):\n\n%s", res.FilePath, res.Lines, string(data))},
				},
			})

		case "lory_scan_target":
			rawURL, _ := callParams.Arguments["url"].(string)
			if rawURL == "" {
				sendError(req.ID, -32602, "url is required")
				return
			}

			parsedURL, err := url.ParseRequestURI(rawURL)
			if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
				sendError(req.ID, -32602, "invalid url: must be a valid http or https URL")
				return
			}

			scanRes, err := webscan.ScanTargetURLWithClient(context.Background(), loryCli, rawURL)
			if err != nil {
				sendError(req.ID, -32000, err.Error())
				return
			}

			data, _ := json.MarshalIndent(scanRes, "", "  ")
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			})

		case "lory_explain_finding":
			cwe, _ := callParams.Arguments["cwe"].(string)
			title, _ := callParams.Arguments["title"].(string)

			if strings.TrimSpace(cwe) == "" && strings.TrimSpace(title) == "" {
				sendError(req.ID, -32602, "at least one of 'cwe' or 'title' is required")
				return
			}

			explanation := FormatExplanation(cwe, title)
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": explanation},
				},
			})

		default:
			sendError(req.ID, -32601, fmt.Sprintf("Unknown tool: %s", callParams.Name))
		}

	default:
		sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func hasCWE(cweText, target string) bool {
	idx := strings.Index(cweText, target)
	if idx == -1 {
		return false
	}
	end := idx + len(target)
	if end < len(cweText) {
		nextByte := cweText[end]
		if nextByte >= '0' && nextByte <= '9' {
			return false
		}
	}
	return true
}

// ExplainFinding returns contextual remediation advice for a given CWE or vulnerability title.
func ExplainFinding(cwe, title string) string {
	cweUpper := strings.ToUpper(strings.TrimSpace(cwe))
	titleLower := strings.ToLower(strings.TrimSpace(title))

	switch {
	case hasCWE(cweUpper, "CWE-89") || strings.Contains(titleLower, "sql"):
		return "Remediation guidance: Use parameterized queries or prepared statements. Never concatenate untrusted user input directly into SQL queries. Utilize ORM frameworks with parameter binding."
	case hasCWE(cweUpper, "CWE-78") || strings.Contains(titleLower, "command"):
		return "Remediation guidance: Avoid passing unsanitized user input to system shell execution functions. Use APIs that execute binaries with discrete argument slices, or validate input against strict allowlists."
	case hasCWE(cweUpper, "CWE-798") || strings.Contains(titleLower, "hard-coded") || strings.Contains(titleLower, "secret") || strings.Contains(titleLower, "credential"):
		return "Remediation guidance: Store credentials, API keys, and sensitive tokens in environment variables or dedicated secret managers (e.g. HashiCorp Vault, AWS Secrets Manager). Never hardcode secrets in source code."
	case hasCWE(cweUpper, "CWE-79") || strings.Contains(titleLower, "xss") || strings.Contains(titleLower, "cross-site scripting"):
		return "Remediation guidance: Apply context-aware output encoding before rendering user input in HTML, JavaScript, or attribute contexts. Implement Content Security Policy (CSP) and use modern templating engines with automatic contextual escaping."
	case hasCWE(cweUpper, "CWE-918") || strings.Contains(titleLower, "ssrf"):
		return "Remediation guidance: Validate and strictly allowlist destination hostnames and IP addresses. Disallow requests to private RFC 1918 subnets, loopback addresses (127.0.0.1), and cloud metadata services (169.254.169.254)."
	case hasCWE(cweUpper, "CWE-942") || strings.Contains(titleLower, "cors"):
		return "Remediation guidance: Configure Access-Control-Allow-Origin headers with explicit, trusted origin whitelists. Do not reflect arbitrary Origin headers or use wildcard '*' when credentials are included."
	case hasCWE(cweUpper, "CWE-311") || hasCWE(cweUpper, "CWE-312") || hasCWE(cweUpper, "CWE-319") || strings.Contains(titleLower, "encrypt") || strings.Contains(titleLower, "cleartext"):
		return "Remediation guidance: Encrypt sensitive data in transit using TLS/HTTPS with modern cipher suites. Encrypt sensitive data at rest using authenticated cryptography (e.g., AES-256-GCM) with secure key management."
	case hasCWE(cweUpper, "CWE-352") || strings.Contains(titleLower, "csrf"):
		return "Remediation guidance: Implement Anti-CSRF tokens using the Synchronizer Token Pattern or Double Submit Cookies, and ensure session cookies configure SameSite=Lax or SameSite=Strict."
	case hasCWE(cweUpper, "CWE-22") || hasCWE(cweUpper, "CWE-23") || strings.Contains(titleLower, "path traversal") || strings.Contains(titleLower, "directory traversal"):
		return "Remediation guidance: Canonicalize file paths and verify that the resolved path resides strictly within the intended base directory. Reject path traversal sequences such as '../'."
	case hasCWE(cweUpper, "CWE-639") || hasCWE(cweUpper, "CWE-862") || hasCWE(cweUpper, "CWE-285") || strings.Contains(titleLower, "idor") || strings.Contains(titleLower, "authorization"):
		return "Remediation guidance: Enforce server-side object-level access control checks on every request. Validate that the authenticated session is authorized to access the requested record or resource identifier."
	case hasCWE(cweUpper, "CWE-693") || hasCWE(cweUpper, "CWE-1021") || strings.Contains(titleLower, "header") || strings.Contains(titleLower, "clickjacking"):
		return "Remediation guidance: Configure HTTP security headers including Content-Security-Policy, X-Frame-Options, Strict-Transport-Security (HSTS), and X-Content-Type-Options: nosniff."
	case hasCWE(cweUpper, "CWE-384") || hasCWE(cweUpper, "CWE-614") || strings.Contains(titleLower, "cookie") || strings.Contains(titleLower, "session"):
		return "Remediation guidance: Set Secure, HttpOnly, and SameSite attributes on sensitive cookies. Regenerate session identifiers upon user privilege changes or login."
	default:
		return "Remediation guidance: Follow least-privilege principles, validate input against strict whitelists, use parameterized queries, and avoid direct shell execution."
	}
}

// FormatExplanation formats a structured explanation string for a finding.
func FormatExplanation(cwe, title string) string {
	cwe = strings.TrimSpace(cwe)
	title = strings.TrimSpace(title)

	var heading string
	if title != "" && cwe != "" {
		heading = fmt.Sprintf("Vulnerability: %s (%s)", title, cwe)
	} else if title != "" {
		heading = fmt.Sprintf("Vulnerability: %s", title)
	} else {
		heading = fmt.Sprintf("Vulnerability: %s", cwe)
	}

	advice := ExplainFinding(cwe, title)
	return fmt.Sprintf("%s\n\n%s", heading, advice)
}
