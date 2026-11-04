package mcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/webscan"
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
