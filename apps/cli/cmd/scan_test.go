package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsWebTarget(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-scan-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Existing file with .com in name
	comFile := filepath.Join(tempDir, "test.com.js")
	if err := os.WriteFile(comFile, []byte("console.log(1);"), 0644); err != nil {
		t.Fatal(err)
	}

	if IsWebTarget(comFile) {
		t.Errorf("expected %s to be recognized as file review, not web target", comFile)
	}

	if !IsWebTarget("http://localhost:8080") {
		t.Errorf("expected http://localhost:8080 to be web target")
	}

	if !IsWebTarget("https://app.lorikeetsecurity.com") {
		t.Errorf("expected https://app.lorikeetsecurity.com to be web target")
	}

	if !IsWebTarget("https://example.com/api/v1") {
		t.Errorf("expected https://example.com/api/v1 to be web target")
	}

	if !IsWebTarget("localhost:8080") {
		t.Errorf("expected localhost:8080 to be web target")
	}

	if !IsWebTarget("127.0.0.1:3000") {
		t.Errorf("expected 127.0.0.1:3000 to be web target")
	}

	if !IsWebTarget("example.com") {
		t.Errorf("expected example.com to be web target")
	}

	if IsWebTarget("./local/file.go") {
		t.Errorf("expected ./local/file.go to be recognized as file path")
	}
}

func TestRunScan_LocalFileWithFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-scan-flags-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "sample.com.js")
	if err := os.WriteFile(testFile, []byte("console.log('hello');\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err = RunScan([]string{"--format", "json", testFile})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}
}
