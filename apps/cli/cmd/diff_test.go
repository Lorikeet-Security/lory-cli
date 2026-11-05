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

func TestRunDiff_FlagsForwarding(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-diff-flags-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	exec.Command("git", "-C", tempDir, "init").Run()
	exec.Command("git", "-C", tempDir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", tempDir, "config", "user.name", "Test").Run()

	file1 := filepath.Join(tempDir, "sample.js")
	os.WriteFile(file1, []byte("console.log(1);"), 0644)
	exec.Command("git", "-C", tempDir, "add", ".").Run()
	exec.Command("git", "-C", tempDir, "commit", "-m", "init").Run()

	// Modify file
	os.WriteFile(file1, []byte("console.log(2);"), 0644)

	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Passing --fix should not exit with status 129
	err = RunDiff([]string{"--fix"})
	if err != nil {
		t.Fatalf("RunDiff with --fix failed: %v", err)
	}

	// Passing --format json should not fail
	err = RunDiff([]string{"--format", "json"})
	if err != nil {
		t.Fatalf("RunDiff with --format json failed: %v", err)
	}

	// Git ref preceding flag should not fail with exit status 129
	err = RunDiff([]string{"HEAD", "--fix"})
	if err != nil {
		t.Fatalf("RunDiff with git ref preceding --fix failed: %v", err)
	}

	// Git ref preceding --format json should work
	err = RunDiff([]string{"HEAD", "--format", "json"})
	if err != nil {
		t.Fatalf("RunDiff with git ref preceding --format json failed: %v", err)
	}
}

func TestRunDiff_CachedAndStagedFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lory-diff-cached-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	exec.Command("git", "-C", tempDir, "init").Run()
	exec.Command("git", "-C", tempDir, "config", "user.email", "test@example.com").Run()
	exec.Command("git", "-C", tempDir, "config", "user.name", "Test").Run()

	file1 := filepath.Join(tempDir, "sample.js")
	os.WriteFile(file1, []byte("console.log(1);"), 0644)
	exec.Command("git", "-C", tempDir, "add", ".").Run()
	exec.Command("git", "-C", tempDir, "commit", "-m", "init").Run()

	// Modify and stage file
	os.WriteFile(file1, []byte("console.log(2);"), 0644)
	exec.Command("git", "-C", tempDir, "add", ".").Run()

	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// --cached should parse and work
	err = RunDiff([]string{"--cached"})
	if err != nil {
		t.Fatalf("RunDiff with --cached failed: %v", err)
	}

	// --staged with other flags should work
	err = RunDiff([]string{"--staged", "--format", "json"})
	if err != nil {
		t.Fatalf("RunDiff with --staged --format json failed: %v", err)
	}
}
