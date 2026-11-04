package cmd

import (
	"os"
	"testing"
)

func TestRunBadge_Flags(t *testing.T) {
	// Test basic execution
	err := RunBadge([]string{"--format", "svg", "--target", "example.com"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Test output to file
	tmpFile := "/tmp/test_badge.svg"
	defer os.Remove(tmpFile)

	err = RunBadge([]string{"--format", "svg", "--out", tmpFile, "--target", "test.com"})
	if err != nil {
		t.Fatalf("expected nil error on write file, got %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected non-empty badge file")
	}

	// Test positional target preceding flags
	tmpFile2 := "/tmp/test_badge_pos.svg"
	defer os.Remove(tmpFile2)

	err = RunBadge([]string{"myapp.com", "--format", "svg", "--out", tmpFile2})
	if err != nil {
		t.Fatalf("expected nil error when target precedes flags, got %v", err)
	}

	data2, err := os.ReadFile(tmpFile2)
	if err != nil || len(data2) == 0 {
		t.Fatalf("expected non-empty badge file when target precedes flags")
	}
}
