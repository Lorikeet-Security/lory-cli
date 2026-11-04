package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunFindings_StatusFilter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-findings-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sampleCode := `app.post('/api/users', (req, res) => {
	const sql = "SELECT * FROM users WHERE id = " + req.query.id;
});`
	if err := os.WriteFile(filepath.Join(tempDir, "users.js"), []byte(sampleCode), 0644); err != nil {
		t.Fatal(err)
	}

	// Should succeed without error
	err = RunFindings([]string{"--repo", tempDir, "--status", "open"})
	if err != nil {
		t.Fatalf("RunFindings with --status open failed: %v", err)
	}

	err = RunFindings([]string{"--repo", tempDir, "--status", "verified"})
	if err != nil {
		t.Fatalf("RunFindings with --status verified failed: %v", err)
	}

	err = RunFindings([]string{"--repo", tempDir, "--status", "all"})
	if err != nil {
		t.Fatalf("RunFindings with --status all failed: %v", err)
	}
}
