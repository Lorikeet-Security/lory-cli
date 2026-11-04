package reviewer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/reviewer"
	"github.com/lorikeetsecurity/lory/pkg/types"
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
