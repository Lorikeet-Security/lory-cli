package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
	"github.com/lorikeetsecurity/lory/pkg/client"
)

func RunDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	baseURLFlag := fs.String("base-url", client.DefaultBaseURL, "Base URL of Lorikeet Security platform")
	tokenFlag := fs.String("token", "", "Lory access token")
	fixFlag := fs.Bool("fix", false, "Automatically apply suggested Lory quick fixes")
	minSevFlag := fs.String("min-severity", "low", "Minimum severity to report")
	formatFlag := fs.String("format", "table", "Output format: table, json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	gitRefs := fs.Args()
	cmdArgs := []string{"diff", "--name-only"}
	if len(gitRefs) > 0 {
		cmdArgs = append(cmdArgs, gitRefs...)
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
			// Skip deleted files that no longer exist on disk
			if _, err := os.Stat(f); err == nil {
				validFiles = append(validFiles, f)
			}
		}
	}

	if len(validFiles) == 0 {
		if *formatFlag != "json" {
			fmt.Println("No modified files detected in git diff.")
		}
		return nil
	}

	if *formatFlag != "json" {
		fmt.Printf("Reviewing %d modified file(s) from git diff...\n\n", len(validFiles))
	}

	reviewArgs := []string{
		fmt.Sprintf("--format=%s", *formatFlag),
		fmt.Sprintf("--base-url=%s", *baseURLFlag),
		fmt.Sprintf("--min-severity=%s", *minSevFlag),
	}
	if *tokenFlag != "" {
		reviewArgs = append(reviewArgs, fmt.Sprintf("--token=%s", *tokenFlag))
	}
	if *fixFlag {
		reviewArgs = append(reviewArgs, "--fix")
	}
	reviewArgs = append(reviewArgs, validFiles...)
	return RunReview(reviewArgs)
}
