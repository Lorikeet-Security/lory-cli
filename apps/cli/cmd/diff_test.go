package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunDiff_SkipsDeletedFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-diff-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Init git repo
	exec.Command("git", "-C", tempDir, "init").Run()
	exec.Command("git", "-C", tempDir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", tempDir, "config", "user.name", "Test").Run()

	file1 := filepath.Join(tempDir, "file1.js")
	file2 := filepath.Join(tempDir, "file2.js")
	os.WriteFile(file1, []byte("console.log(1);"), 0644)
	os.WriteFile(file2, []byte("console.log(2);"), 0644)

	exec.Command("git", "-C", tempDir, "add", ".").Run()
	exec.Command("git", "-C", tempDir, "commit", "-m", "init").Run()

	// Delete file2 and modify file1
	os.Remove(file2)
	os.WriteFile(file1, []byte("console.log(3);"), 0644)

	// Change dir to tempDir to test RunDiff
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	err = RunDiff([]string{})
	if err != nil {
		t.Fatalf("RunDiff failed on git diff with deleted file: %v", err)
	}
}
