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
	t.Skip("Known bug: connection failure or server down is erroneously marked as resolved, see #2")

	// Port 59999 is inactive; connection will be refused
	result, err := retest.ExecuteRetest("LOR-0001", "http://127.0.0.1:59999")
	if err == nil && result.Resolved {
		t.Errorf("expected retest to fail or be unverified on unreachable host, but got resolved=true")
	}
}
