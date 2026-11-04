package retest_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/retest"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func TestExecuteRetestResolved(t *testing.T) {
	// Mock server that returns 403 Forbidden (patched)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"Forbidden"}`))
	}))
	defer server.Close()

	result, err := retest.ExecuteRetest("LOR-0001", server.URL)
	if err != nil {
		t.Fatalf("ExecuteRetest failed: %v", err)
	}

	if !result.Resolved {
		t.Errorf("expected retest to pass (resolved), but got false")
	}

	if result.NewStatus != types.StatusResolved {
		t.Errorf("expected status RESOLVED, got %s", result.NewStatus)
	}
}

func TestExecuteRetestStillVulnerable(t *testing.T) {
	// Mock server that returns 200 OK with leaked data (still vulnerable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"balance": 10000}`))
	}))
	defer server.Close()

	result, err := retest.ExecuteRetest("LOR-0001", server.URL)
	if err != nil {
		t.Fatalf("ExecuteRetest failed: %v", err)
	}

	if result.Resolved {
		t.Errorf("expected retest to fail (still vulnerable), but got resolved=true")
	}

	if result.NewStatus != types.StatusVerified {
		t.Errorf("expected status VERIFIED, got %s", result.NewStatus)
	}
}

func TestExecuteRetestServerUnreachable(t *testing.T) {
	// Port 59999 is inactive; connection will be refused
	result, err := retest.ExecuteRetest("LOR-0001", "http://127.0.0.1:59999")
	if err == nil && result.Resolved {
		t.Errorf("expected retest to fail or be unverified on unreachable host, but got resolved=true")
	}
}

func TestExecuteRetest_DynamicReplayVector(t *testing.T) {
	var capturedMethod, capturedPath, capturedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		bodyBytes := make([]byte, 1024)
		n, _ := r.Body.Read(bodyBytes)
		capturedBody = string(bodyBytes[:n])
		w.WriteHeader(http.StatusForbidden) // Patched
	}))
	defer server.Close()

	customFinding := types.VulnerabilityFinding{
		ID:         "LOR-SQLI-001",
		Route:      "/api/v1/search",
		Method:     "POST",
		PoCPayload: `{"query":"' OR 1=1--"}`,
	}
	retest.RegisterFinding(customFinding)

	result, err := retest.ExecuteRetest("LOR-SQLI-001", server.URL)
	if err != nil {
		t.Fatalf("ExecuteRetest failed: %v", err)
	}

	if capturedMethod != "POST" {
		t.Errorf("expected method POST, got %s", capturedMethod)
	}
	if capturedPath != "/api/v1/search" {
		t.Errorf("expected path /api/v1/search, got %s", capturedPath)
	}
	if capturedBody != `{"query":"' OR 1=1--"}` {
		t.Errorf("expected body %s, got %s", `{"query":"' OR 1=1--"}`, capturedBody)
	}
	if !result.Resolved {
		t.Errorf("expected resolved=true on 403 Forbidden")
	}
}

func TestExecuteRetest_NonexistentFinding(t *testing.T) {
	_, err := retest.ExecuteRetest("LOR-DOES-NOT-EXIST", "http://localhost:3000")
	if err == nil {
		t.Errorf("expected error for nonexistent finding ID, got nil")
	}
}
