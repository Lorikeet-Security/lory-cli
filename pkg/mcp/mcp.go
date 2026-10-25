package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/reviewer"
	"github.com/lorikeetsecurity/lory/pkg/types"
	"github.com/lorikeetsecurity/lory/pkg/webscan"
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

func sendResponse(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stdout, "%s\n", data)
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
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func handleRequest(req *JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		sendResponse(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "lorikeet-lory-mcp",
				"version": "1.1.0",
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

			scanRes, err := webscan.ScanTargetURL(rawURL)
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

			explanation := fmt.Sprintf("Vulnerability: %s (%s)\n\nRemediation guidance: Follow least-privilege principles, validate input against strict whitelists, use parameterized queries, and avoid direct shell execution.", title, cwe)
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
