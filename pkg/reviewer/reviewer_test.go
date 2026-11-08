package reviewer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lorikeet-Security/lory-cli/pkg/reviewer"
	"github.com/Lorikeet-Security/lory-cli/pkg/types"
)

func TestReviewFile_MinSeverityFilter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-reviewer-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Code with a High secret and Critical SQLi
	code := `
const apiKey = "api_key = 'abcdef1234567890abcdef'";
const sql = "SELECT * FROM users WHERE name = " + req.query.name;
`
	filePath := filepath.Join(tempDir, "sample.js")
	if err := os.WriteFile(filePath, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. MinSeverity Critical: should only return Critical SQLi (suppress High)
	res, err := reviewer.ReviewFile(context.Background(), filePath, types.ReviewConfig{
		MinSeverity: types.SeverityCritical,
	}, nil, nil)
	if err != nil {
		t.Fatalf("ReviewFile failed: %v", err)
	}

	for _, f := range res.Findings {
		if f.Severity != types.SeverityCritical {
			t.Errorf("expected only critical findings with MinSeverity=critical, got %s", f.Severity)
		}
	}

	// 2. MinSeverity Low: should include both High and Critical
	resLow, err := reviewer.ReviewFile(context.Background(), filePath, types.ReviewConfig{
		MinSeverity: types.SeverityLow,
	}, nil, nil)
	if err != nil {
		t.Fatalf("ReviewFile with low minSeverity failed: %v", err)
	}

	if len(resLow.Findings) < len(res.Findings) {
		t.Errorf("expected more or equal findings with low minSeverity")
	}
}

func TestReviewPath_LoryIgnore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-reviewer-ignore-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Subdir ignored via .loryignore
	ignoredDir := filepath.Join(tempDir, "legacy")
	os.MkdirAll(ignoredDir, 0755)
	vulnCode := `const sql = "SELECT * FROM legacy WHERE id = " + req.query.id;`
	if err := os.WriteFile(filepath.Join(ignoredDir, "old.js"), []byte(vulnCode), 0644); err != nil {
		t.Fatal(err)
	}

	// Normal file
	normalCode := `const port = 8080;`
	if err := os.WriteFile(filepath.Join(tempDir, "server.js"), []byte(normalCode), 0644); err != nil {
		t.Fatal(err)
	}

	// Write .loryignore
	if err := os.WriteFile(filepath.Join(tempDir, ".loryignore"), []byte("legacy/\n"), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := reviewer.ReviewPath(context.Background(), tempDir, types.ReviewConfig{
		MinSeverity: types.SeverityLow,
	}, nil, nil)
	if err != nil {
		t.Fatalf("ReviewPath failed: %v", err)
	}

	for _, res := range results {
		if filepath.Base(filepath.Dir(res.FilePath)) == "legacy" {
			t.Errorf("expected legacy/ directory to be skipped due to .loryignore, but reviewed %s", res.FilePath)
		}
	}
}
