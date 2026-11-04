package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunReview_FormatJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-review-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sampleFile := filepath.Join(tempDir, "sample.js")
	if err := os.WriteFile(sampleFile, []byte("const x = 1;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err = RunReview([]string{"--format", "json", sampleFile})
	if err != nil {
		t.Fatalf("RunReview with --format json failed: %v", err)
	}
}
