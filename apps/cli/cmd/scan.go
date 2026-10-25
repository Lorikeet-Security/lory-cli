package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/export"
	"github.com/lorikeetsecurity/lory/pkg/scanner"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	repoFlag := fs.String("repo", ".", "Path to repository or code folder to analyze")
	targetFlag := fs.String("target", "", "Live target endpoint URL (e.g. http://localhost:3000)")
	formatFlag := fs.String("format", "table", "Output format: table, json, sarif")
	dryRunFlag := fs.Bool("dry-run", false, "Execute white-box analysis without sending active network probes")
	dockerFlag := fs.Bool("docker", false, "Run execution worker sandbox in Docker container")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Quiet banner for machine-readable output formats
	if *formatFlag == "table" {
		tui.PrintBanner()
	}

	creds, _ := auth.LoadCredentials()
	if *formatFlag == "table" {
		if creds != nil {
			fmt.Printf("%s[Session]%s Authenticated as %s%s%s (%s)\n", tui.ColorDim, tui.ColorReset, tui.ColorCyan, creds.UserEmail, tui.ColorReset, creds.OrgName)
		} else {
			fmt.Printf("%s[Session]%s Running in local unauthenticated mode (Run 'lory login' to sync with Talon)\n", tui.ColorDim, tui.ColorReset)
		}
	}

	config := types.ScanConfig{
		RepoPath:  *repoFlag,
		TargetURL: *targetFlag,
		Format:    *formatFlag,
		DryRun:    *dryRunFlag,
		UseDocker: *dockerFlag,
	}

	if *formatFlag == "table" {
		fmt.Printf("\n%sStarting Autonomous Dual-Validation Pentest%s\n", tui.ColorBold, tui.ColorReset)
		fmt.Printf("• Source Repo:   %s%s%s\n", tui.ColorWhite, config.RepoPath, tui.ColorReset)
		if config.TargetURL != "" {
			fmt.Printf("• Target URL:    %s%s%s\n", tui.ColorWhite, config.TargetURL, tui.ColorReset)
		} else {
			fmt.Printf("• Target URL:    %sNone specified (white-box mode)%s\n", tui.ColorDim, tui.ColorReset)
		}
		fmt.Println()
	}

	progressFn := func(stage string, detail string, finding *types.VulnerabilityFinding) {
		if *formatFlag != "table" {
			return
		}
		switch stage {
		case "ast":
			fmt.Printf("  %s•%s %s\n", tui.ColorCyan, tui.ColorReset, detail)
		case "runtime_verification":
			fmt.Printf("  %s⚡%s %s\n", tui.ColorYellow, tui.ColorReset, detail)
		case "whitebox_sink", "runtime_finding":
			if finding != nil {
				fmt.Printf("  %s!%s %s: %s%s%s (%s)\n", tui.ColorRed, tui.ColorReset, tui.SeverityBadge(finding.Severity), tui.ColorBold, finding.Title, tui.ColorReset, finding.ID)
			}
		}
	}

	findings, analysis, err := scanner.RunScan(config, progressFn)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if *formatFlag == "json" {
		out, _ := json.MarshalIndent(map[string]interface{}{
			"scan_timestamp": time.Now().UTC(),
			"repo":           config.RepoPath,
			"target":         config.TargetURL,
			"frameworks":     analysis.Frameworks,
			"routes_count":   len(analysis.Routes),
			"findings":       findings,
		}, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	if *formatFlag == "sarif" {
		sarifData, err := export.GenerateSARIF(findings)
		if err != nil {
			return err
		}
		fmt.Println(string(sarifData))
		return nil
	}

	// Render Detailed Finding Cards in Table mode
	fmt.Printf("\n%s=== Dual-Validated Findings (%d) ===%s\n", tui.ColorBold, len(findings), tui.ColorReset)
	for _, f := range findings {
		tui.RenderFindingCard(f)
	}

	// Summary stats
	critCount, highCount, medCount, lowCount := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			critCount++
		case types.SeverityHigh:
			highCount++
		case types.SeverityMedium:
			medCount++
		case types.SeverityLow:
			lowCount++
		}
	}

	fmt.Printf("\n%sPentest Summary:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("  Total Endpoints:   %d\n", len(analysis.Routes))
	fmt.Printf("  Files Analyzed:    %d\n", analysis.TotalFiles)
	fmt.Printf("  Confirmed Issues:  %s%d Critical%s | %s%d High%s | %s%d Medium%s | %s%d Low%s\n",
		tui.ColorRed, critCount, tui.ColorReset,
		tui.ColorRed, highCount, tui.ColorReset,
		tui.ColorYellow, medCount, tui.ColorReset,
		tui.ColorBlue, lowCount, tui.ColorReset,
	)

	if creds != nil {
		fmt.Printf("\n%s✔ State synchronized with Talon Compliance Attestation Engine.%s\n", tui.ColorGreen, tui.ColorReset)
	} else {
		fmt.Printf("\n%sTip: Run 'lory login' to push these findings to Talon for SOC 2 tracking and 1-click retest.%s\n", tui.ColorDim, tui.ColorReset)
	}

	// In CI, exit with code 1 if criticals found
	if os.Getenv("CI") != "" && critCount > 0 {
		return fmt.Errorf("pipeline failed: %d critical vulnerabilities discovered", critCount)
	}

	return nil
}
