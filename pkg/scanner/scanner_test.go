package scanner_test

import (
	"os"
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
