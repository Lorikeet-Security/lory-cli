package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/scanner"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func TestRunScan_CleanRepoHasNoFindings(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-clean-repo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := types.ScanConfig{
		RepoPath:  tempDir,
		TargetURL: "",
	}

	findings, _, err := scanner.RunScan(cfg, nil)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean repository without synthetic baseline, got %d", len(findings))
	}
}

func TestRunScan_RouteAttribution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-routes-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// File 1: health route
	healthCode := `app.get('/health', (req, res) => { res.send('ok'); });`
	if err := os.WriteFile(filepath.Join(tempDir, "health.js"), []byte(healthCode), 0644); err != nil {
		t.Fatal(err)
	}

	// File 2: users route with vulnerability sink
	userCode := `app.post('/api/users', (req, res) => {
	const sql = "SELECT * FROM users WHERE name = " + req.query.name;
});`
	if err := os.WriteFile(filepath.Join(tempDir, "users.js"), []byte(userCode), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := types.ScanConfig{
		RepoPath:  tempDir,
		TargetURL: "",
	}

	findings, _, err := scanner.RunScan(cfg, nil)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected at least 1 finding for users.js")
	}

	sqliFinding := findings[0]
	if sqliFinding.Route != "/api/users" {
		t.Errorf("expected route /api/users, got %s", sqliFinding.Route)
	}
	if sqliFinding.Method != "POST" {
		t.Errorf("expected method POST, got %s", sqliFinding.Method)
	}
}
