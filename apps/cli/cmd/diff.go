package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
)

func RunDiff(args []string) error {
	cmdArgs := []string{"diff", "--name-only"}
	if len(args) > 0 {
		cmdArgs = append(cmdArgs, args...)
	}

	out, err := exec.Command("git", cmdArgs...).Output()
	if err != nil {
		return fmt.Errorf("git diff failed: %w", err)
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	validFiles := make([]string, 0)
	for _, f := range files {
		f = strings.TrimSpace(f)
		if f != "" && analyzer.DetectLanguage(f) != "" {
			validFiles = append(validFiles, f)
		}
	}

	if len(validFiles) == 0 {
		fmt.Println("No modified files detected in git diff.")
		return nil
	}

	fmt.Printf("Reviewing %d modified file(s) from git diff...\n\n", len(validFiles))
	return RunReview(validFiles)
}
