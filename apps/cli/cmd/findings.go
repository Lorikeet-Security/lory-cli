package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/scanner"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func RunFindings(args []string) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	statusFlag := fs.String("status", "open", "Filter by status: open, verified, resolved, all")
	sevFlag := fs.String("severity", "", "Filter by severity: critical, high, medium, low")
	repoFlag := fs.String("repo", ".", "Repository path to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tui.PrintBanner()
	fmt.Printf("%sVerified Vulnerability Triage%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("Filter: status=%s%s%s", tui.ColorCyan, *statusFlag, tui.ColorReset)
	if *sevFlag != "" {
		fmt.Printf(" severity=%s%s%s", tui.ColorYellow, *sevFlag, tui.ColorReset)
	}
	fmt.Printf("\n\n")

	findings, _, err := scanner.RunScan(types.ScanConfig{RepoPath: *repoFlag}, nil)
	if err != nil {
		return err
	}

	// Filter
	filtered := make([]types.VulnerabilityFinding, 0)
	for _, f := range findings {
		if *sevFlag != "" && !strings.EqualFold(string(f.Severity), *sevFlag) {
			continue
		}
		if *statusFlag != "all" && *statusFlag != "open" && !strings.EqualFold(string(f.Status), *statusFlag) {
			continue
		}
		filtered = append(filtered, f)
	}

	if len(filtered) == 0 {
		fmt.Printf("%s✔ No vulnerabilities matching filter.%s\n\n", tui.ColorGreen, tui.ColorReset)
		return nil
	}

	// Print table header
	fmt.Printf("%-10s %-12s %-8s %-12s %-22s %-20s\n", "ID", "SEVERITY", "CVSS", "CWE", "STATUS", "ENDPOINT")
	fmt.Println(strings.Repeat("─", 88))

	for _, f := range filtered {
		fmt.Printf("%-10s %-21s %-8.1f %-12s %-31s %-20s\n",
			f.ID,
			tui.SeverityBadge(f.Severity),
			f.CVSS,
			f.CWE,
			tui.StatusBadge(f.Status),
			f.Method+" "+f.Route,
		)
	}

	fmt.Printf("\nUse %slory retest <id>%s to replay verification on any finding.\n\n", tui.ColorCyan, tui.ColorReset)
	return nil
}
