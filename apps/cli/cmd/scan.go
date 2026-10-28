package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/webscan"
)

func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	baseURLFlag := fs.String("base-url", client.DefaultBaseURL, "Base URL of Lorikeet Security platform")
	formatFlag := fs.String("format", "table", "Output format: table, json")
	fixFlag := fs.Bool("fix", false, "Apply quick fixes if scanning code files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targets := fs.Args()
	target := "."
	if len(targets) > 0 {
		target = targets[0]
	}

	// 1. If target is a Web URL, execute PTaaS Web Security Scan via platform scan-api.php
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.Contains(target, ".com") || strings.Contains(target, ".org") || strings.Contains(target, ".net") || strings.Contains(target, ".io") {
		if *formatFlag == "table" {
			tui.PrintBanner()
			tui.Spin(fmt.Sprintf("Running Lorikeet PTaaS Web Security Scan against %s...", target), 500)
		}

		token := auth.GetToken()
		cli := client.NewLoryClient(*baseURLFlag, token)
		res, err := webscan.ScanTargetURLWithClient(context.Background(), cli, target)
		if err != nil {
			return fmt.Errorf("web scan failed: %w", err)
		}

		if *formatFlag == "json" {
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		tui.RenderWebScanResult(res)
		if res.Score >= 70 {
			fmt.Printf("%s[Lorikeet Trust Badge]%s Assessment complete (%d/100). Run %s`lory badge %s`%s to generate your verified footer badge.\n\n", tui.ColorCyan, tui.ColorReset, res.Score, tui.ColorBold, res.Target, tui.ColorReset)
		}
		return nil
	}

	// 2. Otherwise target is a local file or repository - run Lory AI Code Review
	reviewArgs := []string{target, fmt.Sprintf("--format=%s", *formatFlag), fmt.Sprintf("--base-url=%s", *baseURLFlag)}
	if *fixFlag {
		reviewArgs = append(reviewArgs, "--fix")
	}
	return RunReview(reviewArgs)
}
