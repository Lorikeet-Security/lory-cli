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
	formatFlag := fs.String("format", "table", "Output format: table, json, mcp")
	outputMCPFlag := fs.Bool("output-mcp", false, "Output scan findings in spec-compliant MCP resource format")
	fixFlag := fs.Bool("fix", false, "Apply quick fixes if scanning code files")

	// Partition arguments so flags are parsed even if target precedes them (e.g. `lory scan <target> [flags]`)
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "base-url", "format":
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

		if *outputMCPFlag || *formatFlag == "mcp" {
			mcpPayload := map[string]interface{}{
				"uri":      fmt.Sprintf("lorikeet://web-scan/%s", target),
				"name":     "Lory Web Security Scan Results",
				"mimeType": "application/json",
				"text":     res,
			}
			data, _ := json.MarshalIndent(mcpPayload, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if *formatFlag == "json" {
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		tui.RenderWebScanResult(res)
		if res.Score >= 70 {
			fmt.Printf("%s[Lorikeet Trust Badge]%s Assessment complete (%d/100). Run %s`lory badge %s`%s to generate your verified footer badge.\n", tui.ColorCyan, tui.ColorReset, res.Score, tui.ColorBold, res.Target, tui.ColorReset)
		}

		findingCount := 0
		for _, cat := range res.Categories {
			for _, chk := range cat.Checks {
				if chk.Status == "fail" || chk.Status == "warn" {
					findingCount++
				}
			}
		}
		tui.RenderPLGUpsell(findingCount, token != "", target)
		return nil
	}

	// 2. Otherwise target is a local file or repository - run Lory AI Code Review
	reviewArgs := []string{fmt.Sprintf("--format=%s", *formatFlag), fmt.Sprintf("--base-url=%s", *baseURLFlag)}
	if *fixFlag {
		reviewArgs = append(reviewArgs, "--fix")
	}
	if *outputMCPFlag {
		reviewArgs = append(reviewArgs, "--output-mcp")
	}
	reviewArgs = append(reviewArgs, target)
	return RunReview(reviewArgs)
}
