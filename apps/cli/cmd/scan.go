package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/webscan"
)

func IsWebTarget(target string) bool {
	// 1. Explicit web schemes are always web targets
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return true
	}

	// 2. Existing local file or directory paths are always code review targets
	if _, err := os.Stat(target); err == nil {
		return false
	}

	// 3. Slashes without scheme indicate a local relative or absolute filesystem path
	if strings.Contains(target, "/") || strings.Contains(target, "\\") {
		return false
	}

	// 4. Localhost or loopback endpoints
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "localhost") || strings.HasPrefix(lower, "127.0.0.1") || strings.HasPrefix(lower, "0.0.0.0") {
		return true
	}

	// 5. Hostname or host:port combinations
	u, err := url.Parse("http://" + target)
	if err == nil && u.Host != "" && (strings.Contains(u.Host, ".") || strings.Contains(u.Host, ":")) {
		return true
	}

	return false
}

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
	if IsWebTarget(target) {
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
	reviewArgs := []string{fmt.Sprintf("--format=%s", *formatFlag), fmt.Sprintf("--base-url=%s", *baseURLFlag)}
	if *fixFlag {
		reviewArgs = append(reviewArgs, "--fix")
	}
	reviewArgs = append(reviewArgs, target)
	return RunReview(reviewArgs)
}
