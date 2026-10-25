package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
	"github.com/lorikeetsecurity/lory/pkg/retest"
	"github.com/lorikeetsecurity/lory/pkg/scanner"
	"github.com/lorikeetsecurity/lory/pkg/types"
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

// ServeMCP runs the Model Context Protocol stdio server
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
				"version": "1.0.0",
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
					"name":        "lory_scan",
					"description": "Runs white-box code mapping paired with live verification against target endpoint",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"repo_path":  map[string]string{"type": "string", "description": "Local repository directory"},
							"target_url": map[string]string{"type": "string", "description": "Live target application URL"},
						},
						"required": []string{"repo_path"},
					},
				},
				{
					"name":        "lory_get_findings",
					"description": "Lists verified vulnerabilities and security posture from current workspace",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"repo_path": map[string]string{"type": "string", "description": "Path to workspace repository"},
						},
					},
				},
				{
					"name":        "lory_retest",
					"description": "Replays Talon 1-click verification PoC to test if a security fix was effective",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"finding_id": map[string]string{"type": "string", "description": "Finding ID e.g. LOR-0001"},
							"target_url": map[string]string{"type": "string", "description": "Target base URL"},
						},
						"required": []string{"finding_id"},
					},
				},
				{
					"name":        "lory_analyze_routes",
					"description": "Extracts HTTP endpoint routes and sensitive sinks from source files",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"repo_path": map[string]string{"type": "string", "description": "Repository path"},
						},
						"required": []string{"repo_path"},
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

		switch callParams.Name {
		case "lory_scan":
			repoPath, _ := callParams.Arguments["repo_path"].(string)
			if repoPath == "" {
				repoPath = "."
			}
			targetURL, _ := callParams.Arguments["target_url"].(string)

			findings, analysis, err := scanner.RunScan(types.ScanConfig{
				RepoPath:  repoPath,
				TargetURL: targetURL,
			}, nil)
			if err != nil {
				sendError(req.ID, -32000, err.Error())
				return
			}

			summary := fmt.Sprintf("Scan complete! Found %d verified findings across %d routes (%d files).", len(findings), len(analysis.Routes), analysis.TotalFiles)
			findingsJSON, _ := json.MarshalIndent(findings, "", "  ")

			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("%s\n\n%s", summary, string(findingsJSON))},
				},
			})

		case "lory_get_findings":
			repoPath, _ := callParams.Arguments["repo_path"].(string)
			if repoPath == "" {
				repoPath = "."
			}
			findings, _, _ := scanner.RunScan(types.ScanConfig{RepoPath: repoPath}, nil)
			data, _ := json.MarshalIndent(findings, "", "  ")
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			})

		case "lory_retest":
			findingID, _ := callParams.Arguments["finding_id"].(string)
			targetURL, _ := callParams.Arguments["target_url"].(string)
			result, err := retest.ExecuteRetest(findingID, targetURL)
			if err != nil {
				sendError(req.ID, -32000, err.Error())
				return
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			})

		case "lory_analyze_routes":
			repoPath, _ := callParams.Arguments["repo_path"].(string)
			if repoPath == "" {
				repoPath = "."
			}
			result, err := analyzer.AnalyzeRepository(repoPath)
			if err != nil {
				sendError(req.ID, -32000, err.Error())
				return
			}
			data, _ := json.MarshalIndent(result.Routes, "", "  ")
			sendResponse(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": string(data)},
				},
			})

		default:
			sendError(req.ID, -32601, fmt.Sprintf("Unknown tool: %s", callParams.Name))
		}

	default:
		sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}
