package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lorikeet-Security/lory-cli/pkg/client"
	"github.com/Lorikeet-Security/lory-cli/pkg/mcp"
	"github.com/Lorikeet-Security/lory-cli/pkg/webscan"
)

func TestWebScan_AuthenticatedClientRetainsToken(t *testing.T) {
	var capturedAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"score": 95, "target": "http://example.com"}`))
	}))
	defer server.Close()

	cli := client.NewLoryClient(server.URL, "test_token_12345")
	_, err := webscan.ScanTargetURLWithClient(context.Background(), cli, "http://example.com")
	if err != nil {
		t.Fatalf("ScanTargetURLWithClient failed: %v", err)
	}

	if capturedAuthHeader != "Bearer test_token_12345" {
		t.Errorf("expected Authorization header 'Bearer test_token_12345', got '%s'", capturedAuthHeader)
	}
}

func executeMCPRequest(req *mcp.JSONRPCRequest) (*mcp.JSONRPCResponse, error) {
	var buf bytes.Buffer
	mcp.SetOutput(&buf)

	mcp.HandleRequest(req)

	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func TestMCP_ScanTarget_URLValidation(t *testing.T) {
	invalidURLs := []string{
		"ftp://example.com/payload",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"not-a-valid-url",
		"",
	}

	for _, invalidURL := range invalidURLs {
		t.Run("invalid_url_"+invalidURL, func(t *testing.T) {
			paramsBytes, _ := json.Marshal(map[string]interface{}{
				"name": "lory_scan_target",
				"arguments": map[string]interface{}{
					"url": invalidURL,
				},
			})

			req := &mcp.JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params:  paramsBytes,
			}

			resp, err := executeMCPRequest(req)
			if err != nil {
				t.Fatalf("executeMCPRequest failed: %v", err)
			}

			if resp.Error == nil {
				t.Fatalf("expected error for invalid URL %q, got success", invalidURL)
			}

			errMap, ok := resp.Error.(map[string]interface{})
			if !ok {
				t.Fatalf("expected error object, got %v", resp.Error)
			}

			code, _ := errMap["code"].(float64)
			if int(code) != -32602 {
				t.Errorf("expected error code -32602, got %v", code)
			}
		})
	}
}

func TestMCP_ExplainFinding_ContextualAdvice(t *testing.T) {
	tests := []struct {
		name          string
		cwe           string
		title         string
		expectedTerms []string
		rejectedTerms []string
	}{
		{
			name:          "CWE-311 Missing Encryption",
			cwe:           "CWE-311",
			title:         "Missing Encryption of Sensitive Data",
			expectedTerms: []string{"Encrypt", "TLS", "AES-256-GCM"},
			rejectedTerms: []string{"parameterized queries", "direct shell execution"},
		},
		{
			name:          "CWE-89 SQL Injection",
			cwe:           "CWE-89",
			title:         "SQL Injection (Concatenated query)",
			expectedTerms: []string{"parameterized queries", "prepared statements"},
			rejectedTerms: []string{"shell execution", "SameSite"},
		},
		{
			name:          "CWE-78 Command Injection",
			cwe:           "CWE-78",
			title:         "OS Command Injection",
			expectedTerms: []string{"shell execution", "discrete argument"},
			rejectedTerms: []string{"SQL", "parameterized queries"},
		},
		{
			name:          "CWE-798 Hard-coded Credentials",
			cwe:           "CWE-798",
			title:         "Hard-coded Secrets",
			expectedTerms: []string{"secret manager", "environment variables"},
			rejectedTerms: []string{"parameterized queries"},
		},
		{
			name:          "CWE-918 SSRF",
			cwe:           "CWE-918",
			title:         "Server-Side Request Forgery",
			expectedTerms: []string{"RFC 1918", "metadata"},
			rejectedTerms: []string{"SQL queries"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paramsBytes, _ := json.Marshal(map[string]interface{}{
				"name": "lory_explain_finding",
				"arguments": map[string]interface{}{
					"cwe":   tc.cwe,
					"title": tc.title,
				},
			})

			req := &mcp.JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      42,
				Method:  "tools/call",
				Params:  paramsBytes,
			}

			resp, err := executeMCPRequest(req)
			if err != nil {
				t.Fatalf("executeMCPRequest failed: %v", err)
			}

			if resp.Error != nil {
				t.Fatalf("unexpected error response: %v", resp.Error)
			}

			resultMap, ok := resp.Result.(map[string]interface{})
			if !ok {
				t.Fatalf("expected result object, got %v", resp.Result)
			}

			content, ok := resultMap["content"].([]interface{})
			if !ok || len(content) == 0 {
				t.Fatalf("expected non-empty content array, got %v", resultMap)
			}

			item := content[0].(map[string]interface{})
			text := item["text"].(string)

			for _, term := range tc.expectedTerms {
				if !strings.Contains(strings.ToLower(text), strings.ToLower(term)) {
					t.Errorf("expected explanation to contain %q, but got:\n%s", term, text)
				}
			}

			for _, term := range tc.rejectedTerms {
				if strings.Contains(strings.ToLower(text), strings.ToLower(term)) {
					t.Errorf("expected explanation NOT to contain %q, but got:\n%s", term, text)
				}
			}
		})
	}
}

func TestMCP_ExplainFinding_ValidationEmptyArgs(t *testing.T) {
	paramsBytes, _ := json.Marshal(map[string]interface{}{
		"name": "lory_explain_finding",
		"arguments": map[string]interface{}{
			"cwe":   "",
			"title": "",
		},
	})

	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      99,
		Method:  "tools/call",
		Params:  paramsBytes,
	}

	resp, err := executeMCPRequest(req)
	if err != nil {
		t.Fatalf("executeMCPRequest failed: %v", err)
	}

	if resp.Error == nil {
		t.Fatalf("expected error for empty cwe/title, got success")
	}

	errMap, ok := resp.Error.(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object, got %v", resp.Error)
	}

	code, _ := errMap["code"].(float64)
	if int(code) != -32602 {
		t.Errorf("expected error code -32602, got %v", code)
	}
}
