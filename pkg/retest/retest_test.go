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
