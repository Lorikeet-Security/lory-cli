package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunScan_LocalFileWithFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-scan-flags-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "sample.js")
	if err := os.WriteFile(testFile, []byte("console.log('hello');\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Should not fail with stat error for flags
	err = RunScan([]string{"--format", "json", testFile})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}
}
