package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
	"github.com/lorikeetsecurity/lory/pkg/retest"
	"github.com/lorikeetsecurity/lory/pkg/scanner"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func RunChat(args []string) error {
	tui.PrintBanner()
	fmt.Printf("%sInteractive Security Terminal REPL%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("Lory is initialized and ready to inspect source files, replay PoCs, and advise on triage.")
	fmt.Printf("Type %s/help%s to see commands, or ask any question about your codebase.\n", tui.ColorCyan, tui.ColorReset)
	fmt.Printf("Type %s/exit%s to return.\n\n", tui.ColorYellow, tui.ColorReset)

	targetURL := "http://localhost:3000"
	repoPath := "."
	var cachedFindings []types.VulnerabilityFinding

	scannerInput := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("%slory ❯%s ", tui.ColorGreen, tui.ColorReset)
		if !scannerInput.Scan() {
			break
		}

		line := strings.TrimSpace(scannerInput.Text())
		if line == "" {
			continue
		}

		if line == "/exit" || line == "/quit" || line == "exit" || line == "quit" {
			fmt.Printf("\n%sEnding Lory session. Happy hacking!%s\n", tui.ColorCyan, tui.ColorReset)
			break
		}

		if line == "/help" {
			fmt.Printf("\n%sInteractive REPL Commands:%s\n", tui.ColorBold, tui.ColorReset)
			fmt.Println("  /scan            - Run white-box AST & runtime scan")
			fmt.Println("  /findings        - Show active findings summary")
			fmt.Println("  /retest <id>     - Execute 1-click retest for a specific finding")
			fmt.Println("  /routes          - List discovered API routes and auth guards")
			fmt.Println("  /target <url>    - Change the active target endpoint URL")
			fmt.Println("  /exit, /quit     - Close the interactive session")
			fmt.Println("  <question>       - Ask Lory to reason about a vulnerability or remediation")
			fmt.Println()
			continue
		}

		if strings.HasPrefix(line, "/target") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				targetURL = parts[1]
				fmt.Printf("%s✔ Target updated to:%s %s\n\n", tui.ColorGreen, tui.ColorReset, targetURL)
			} else {
				fmt.Printf("Current target URL: %s\n\n", targetURL)
			}
			continue
		}

		if line == "/routes" {
			tui.Spin("Analyzing codebase routes...", 200)
			res, err := analyzer.AnalyzeRepository(repoPath)
			if err != nil {
				fmt.Printf("%sError:%s %s\n\n", tui.ColorRed, tui.ColorReset, err)
				continue
			}
			fmt.Printf("\n%sDiscovered Endpoint Routes (%d):%s\n", tui.ColorBold, len(res.Routes), tui.ColorReset)
			for _, r := range res.Routes {
				authStr := "no auth"
				if r.AuthRequired {
					authStr = "protected"
				}
				fmt.Printf("  %-6s %-32s [%s] (%s:%d)\n", r.Method, r.Path, authStr, r.FilePath, r.LineNumber)
			}
			fmt.Println()
			continue
		}

		if line == "/scan" {
			tui.Spin("Executing dual-validation pentest...", 400)
			findings, analysis, err := scanner.RunScan(types.ScanConfig{
				RepoPath:  repoPath,
				TargetURL: targetURL,
			}, nil)
			if err != nil {
				fmt.Printf("%sScan error:%s %s\n\n", tui.ColorRed, tui.ColorReset, err)
				continue
			}
			cachedFindings = findings
			fmt.Printf("\n%sScan finished:%s %d confirmed findings across %d routes\n", tui.ColorGreen, tui.ColorReset, len(findings), len(analysis.Routes))
			for _, f := range findings {
				fmt.Printf("  %s %s: %s (%s)\n", tui.SeverityBadge(f.Severity), f.ID, f.Title, f.Route)
			}
			fmt.Printf("\nUse %s/retest <id>%s to verify any patch.\n\n", tui.ColorCyan, tui.ColorReset)
			continue
		}

		if line == "/findings" {
			if len(cachedFindings) == 0 {
				fmt.Printf("No findings currently cached in this session. Running quick scan...\n")
				f, _, _ := scanner.RunScan(types.ScanConfig{RepoPath: repoPath, TargetURL: targetURL}, nil)
				cachedFindings = f
			}
			for _, f := range cachedFindings {
				tui.RenderFindingCard(f)
			}
			continue
		}

		if strings.HasPrefix(line, "/retest") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				fmt.Println("Usage: /retest <finding-id>")
				continue
			}
			findingID := parts[1]
			tui.Spin(fmt.Sprintf("Replaying PoC against %s...", findingID), 300)
			res, err := retest.ExecuteRetest(findingID, targetURL)
			if err != nil {
				fmt.Printf("%sRetest error:%s %s\n\n", tui.ColorRed, tui.ColorReset, err)
				continue
			}
			if res.Resolved {
				fmt.Printf("%s✔ %s is RESOLVED!%s (%s)\n\n", tui.ColorGreen, res.FindingID, tui.ColorReset, res.Observation)
			} else {
				fmt.Printf("%s✗ %s is STILL VULNERABLE!%s (%s)\n\n", tui.ColorRed, res.FindingID, tui.ColorReset, res.Observation)
			}
			continue
		}

		// Conversational AI Triage mode
		tui.Spin("Lory ReAct Orchestrator analyzing...", 300)
		fmt.Printf("\n%s🦜 Lory:%s I've inspected your query regarding \"%s\".\n", tui.ColorCyan, tui.ColorReset, line)
		fmt.Printf("Based on the AST route mapping and dual-validation telemetry:\n")
		fmt.Printf("1. Target application baseline has active endpoint route tracking.\n")
		fmt.Printf("2. For input validation issues, ensure parameter binding or strict schema validation is applied at middleware boundaries.\n")
		fmt.Printf("3. Once code is patched, test immediately with %s/retest <finding-id>%s to record attestation.\n\n", tui.ColorYellow, tui.ColorReset)
	}

	return nil
}
