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

func TestRunScan_ClosestEnclosingRouteAttribution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-multi-routes-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	multiRouteCode := `app.get('/api/ping', (req, res) => {
	res.send('pong');
});

app.post('/api/search', (req, res) => {
	const sql = "SELECT * FROM items WHERE query = " + req.body.q;
});`
	if err := os.WriteFile(filepath.Join(tempDir, "api.js"), []byte(multiRouteCode), 0644); err != nil {
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

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Route != "/api/search" {
		t.Errorf("expected closest enclosing route /api/search, got %s", findings[0].Route)
	}
	if findings[0].Method != "POST" {
		t.Errorf("expected method POST, got %s", findings[0].Method)
	}
}

func TestRunScan_SinkWithoutRouteDoesNotInheritRouteZero(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-no-route-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// File 1 has a route
	routeCode := `app.get('/api/status', (req, res) => { res.send('ok'); });`
	if err := os.WriteFile(filepath.Join(tempDir, "routes.js"), []byte(routeCode), 0644); err != nil {
		t.Fatal(err)
	}

	// File 2 has a backend SQL injection sink with no routes
	dbCode := `function query(params) {
	const sql = "SELECT * FROM secrets WHERE name = " + params.name;
}`
	if err := os.WriteFile(filepath.Join(tempDir, "db.js"), []byte(dbCode), 0644); err != nil {
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

	var dbFinding *types.VulnerabilityFinding
	for _, f := range findings {
		if filepath.Base(f.SourceFile) == "db.js" {
			dbFinding = &f
			break
		}
	}

	if dbFinding == nil {
		t.Fatalf("expected finding for db.js")
	}

	if dbFinding.Route != "N/A" {
		t.Errorf("expected Route 'N/A' for sink outside route handlers, got %s", dbFinding.Route)
	}
	if dbFinding.Method != "N/A" {
		t.Errorf("expected Method 'N/A' for sink outside route handlers, got %s", dbFinding.Method)
	}
}
