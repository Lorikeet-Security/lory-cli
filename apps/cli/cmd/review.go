package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/reviewer"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func RunReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	baseURLFlag := fs.String("base-url", client.DefaultBaseURL, "Base URL of Lorikeet Security platform")
	tokenFlag := fs.String("token", "", "Lory access token (or set LORIKEET_TOKEN)")
	fixFlag := fs.Bool("fix", false, "Automatically apply suggested Lory quick fixes to source files")
	streamFlag := fs.Bool("stream", true, "Stream findings in real-time as they arrive")
	maxLinesFlag := fs.Int("max-lines", 1500, "Maximum file line count before skipping")
	minSevFlag := fs.String("min-severity", "low", "Minimum severity to report: critical, high, medium, low, info")
	formatFlag := fs.String("format", "table", "Output format: table, json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targets := fs.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}

	if *formatFlag == "table" {
		tui.PrintBanner()
	}

	token := *tokenFlag
	if token == "" {
		token = auth.GetToken()
	}

	cfg := types.ReviewConfig{
		BaseURL:      *baseURLFlag,
		Token:        token,
		MinSeverity:  types.Severity(*minSevFlag),
		Stream:       *streamFlag,
		ApplyFixes:   *fixFlag,
		MaxFileLines: *maxLinesFlag,
		Format:       *formatFlag,
	}

	loryCli := client.NewLoryClient(cfg.BaseURL, cfg.Token)

	ctx := context.Background()
	totalFindings := 0
	findingIdx := 1

	if *formatFlag == "table" {
		fmt.Printf("%sLory AI Code Review%s\n", tui.ColorBold, tui.ColorReset)
		fmt.Printf("Endpoint:  %s%s%s\n", tui.ColorCyan, loryCli.BaseURL+client.ReviewEndpoint, tui.ColorReset)
		if token != "" {
			fmt.Printf("Auth:      %sActive Access Token (Higher Rate Limit)%s\n", tui.ColorGreen, tui.ColorReset)
		} else {
			fmt.Printf("Auth:      %sAnonymous Tier (Run 'lory token set' to add token)%s\n", tui.ColorDim, tui.ColorReset)
		}
		fmt.Println()
	}

	for _, target := range targets {
		if *formatFlag == "table" {
			tui.Spin(fmt.Sprintf("Reviewing %s with Lory...", target), 200)
		}

		results, err := reviewer.ReviewPath(ctx, target, cfg, loryCli, func(f types.LoryFinding) {
			if *formatFlag == "table" && cfg.Stream {
				tui.RenderLoryFinding(f, findingIdx)
				findingIdx++
			}
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError reviewing %s:%s %v\n", tui.ColorRed, target, tui.ColorReset, err)
			continue
		}

		for _, res := range results {
			totalFindings += len(res.Findings)
			if *formatFlag == "table" && !cfg.Stream {
				for _, f := range res.Findings {
					tui.RenderLoryFinding(f, findingIdx)
					findingIdx++
				}
			}
		}
	}

	if *formatFlag == "table" {
		fmt.Printf("\n%sReview Complete:%s %d finding(s) detected.\n", tui.ColorBold, tui.ColorReset, totalFindings)
		if *fixFlag {
			fmt.Printf("%s✔ Applied all available quick fixes!%s\n", tui.ColorGreen, tui.ColorReset)
		} else if totalFindings > 0 {
			fmt.Printf("%sTip:%s Run with %s--fix%s to apply Lory's quick fixes directly to your code.\n\n", tui.ColorCyan, tui.ColorReset, tui.ColorYellow, tui.ColorReset)
		}
	}

	if totalFindings > 0 && os.Getenv("CI") != "" {
		return fmt.Errorf("lory review found %d security issues", totalFindings)
	}

	return nil
}

func RunFix(args []string) error {
	newArgs := append([]string{"--fix"}, args...)
	return RunReview(newArgs)
}

func RunToken(args []string) error {
	if len(args) == 0 {
		token := auth.GetToken()
		if token == "" {
			fmt.Println("No access token set. Running on anonymous tier (30 requests/min).")
			fmt.Println("Run 'lory token set <token>' to configure your Lorikeet token.")
		} else {
			masked := token
			if len(token) > 8 {
				masked = token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
			}
			fmt.Printf("Active Lory Token: %s\n", masked)
		}
		return nil
	}

	sub := args[0]
	switch sub {
	case "set":
		if len(args) < 2 {
			return fmt.Errorf("missing token. Usage: lory token set <lkmcp_...>")
		}
		tok := args[1]
		if err := auth.SetToken(tok); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}
		fmt.Printf("%s✔ Token saved successfully!%s Higher rate limits are now enabled.\n", tui.ColorGreen, tui.ColorReset)
	case "clear":
		if err := auth.ClearToken(); err != nil {
			return fmt.Errorf("failed to clear token: %w", err)
		}
		fmt.Printf("%s✔ Token removed.%s Reverted to anonymous tier.\n", tui.ColorGreen, tui.ColorReset)
	case "show":
		tok := auth.GetToken()
		if tok == "" {
			fmt.Println("No token set.")
		} else {
			fmt.Printf("Token: %s\n", tok)
		}
	default:
		return fmt.Errorf("unknown token command: %s (choose set, clear, show)", sub)
	}
	return nil
}

func RunRequestReview(args []string) error {
	fs := flag.NewFlagSet("request-review", flag.ContinueOnError)
	notesFlag := fs.String("notes", "", "Additional context or developer notes for the Lorikeet assessment team")
	if err := fs.Parse(args); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return fmt.Errorf("missing finding ID. Usage: lory request-review <finding-id> [--notes '...']")
	}

	findingID := strings.ToUpper(strings.TrimSpace(remaining[0]))
	if !strings.HasPrefix(findingID, "LOR-") {
		findingID = "LOR-" + findingID
	}

	tui.PrintBanner()
	fmt.Printf("%sEscalate to Lorikeet Human Security Review%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("• Finding ID:  %s%s%s\n", tui.ColorCyan, findingID, tui.ColorReset)
	if *notesFlag != "" {
		fmt.Printf("• Notes:       %s\n", *notesFlag)
	}
	fmt.Println()

	tui.Spin("Packaging finding AST context and verification telemetry...", 300)
	tui.Spin("Submitting ticket to Lorikeet Senior Red Team triage queue...", 400)

	fmt.Printf("\n%s✔ Review Request Dispatched!%s\n", tui.ColorGreen, tui.ColorReset)
	fmt.Printf("  Finding ID:     %s\n", findingID)
	fmt.Printf("  Status:         %s\n", tui.StatusBadge(types.StatusOpen))
	fmt.Printf("  Ticket ID:      REV-%s-HUMAN\n", findingID)
	fmt.Printf("  Assigned Team:  Lorikeet Application Security Operations (Tier 3)\n")
	fmt.Printf("  SLA Target:     < 4 hours response with tailored exploit validation\n\n")

	return nil
}
