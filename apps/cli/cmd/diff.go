package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Lorikeet-Security/lory-cli/pkg/analyzer"
	"github.com/Lorikeet-Security/lory-cli/pkg/client"
)

func RunDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	baseURLFlag := fs.String("base-url", client.DefaultBaseURL, "Base URL of Lorikeet Security platform")
	tokenFlag := fs.String("token", "", "Lory access token")
	fixFlag := fs.Bool("fix", false, "Automatically apply suggested Lory quick fixes")
	minSevFlag := fs.String("min-severity", "low", "Minimum severity to report")
	formatFlag := fs.String("format", "table", "Output format: table, json")
	cachedFlag := fs.Bool("cached", false, "Review staged changes in the git index")
	stagedFlag := fs.Bool("staged", false, "Review staged changes in the git index")

	// Partition arguments so flags are parsed even if git refs precede them
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "base-url", "token", "min-severity", "format":
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	reordered := append(flagArgs, posArgs...)

	if err := fs.Parse(reordered); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	gitRefs := fs.Args()
	cmdArgs := []string{"diff", "--name-only"}
	if *cachedFlag || *stagedFlag {
		cmdArgs = append(cmdArgs, "--cached")
	}
	if len(gitRefs) > 0 {
		cmdArgs = append(cmdArgs, gitRefs...)
	}

	out, err := exec.Command("git", cmdArgs...).Output()
	if err != nil {
		return fmt.Errorf("git diff failed: %w", err)
	}

	customIgnore := analyzer.LoadIgnorePatterns(".")
	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	validFiles := make([]string, 0)
	for _, f := range files {
		f = strings.TrimSpace(f)
		if f != "" && analyzer.DetectLanguage(f) != "" {
			if analyzer.IsPathIgnored(filepath.ToSlash(f), false, customIgnore) {
				continue
			}
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
