package main

import (
	"fmt"
	"os"

	"github.com/lorikeetsecurity/lory/apps/cli/cmd"
	"github.com/lorikeetsecurity/lory/pkg/mcp"
	"github.com/lorikeetsecurity/lory/pkg/tui"
)

const Version = "1.1.0"

func printHelp() {
	tui.PrintBanner()
	fmt.Printf("%sUSAGE:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  lory <command> [arguments] [flags]")
	fmt.Println()
	fmt.Printf("%sCOMMANDS:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("  %-24s %s\n", "review [path...]", "Run Lory AI code review on files or directories")
	fmt.Printf("  %-24s %s\n", "scan <path|url>", "Review code or run PTaaS web security scan against URL")
	fmt.Printf("  %-24s %s\n", "fix [path...]", "Review code and automatically apply suggested fixes")
	fmt.Printf("  %-24s %s\n", "diff [git-args...]", "Review only changed files in current git diff")
	fmt.Printf("  %-24s %s\n", "token [set|clear|show]", "Manage Lorikeet/Lory access token for higher rate limits")
	fmt.Printf("  %-24s %s\n", "mcp serve", "Launch Model Context Protocol stdio server for Claude Code & Cursor")
	fmt.Printf("  %-24s %s\n", "version", "Show CLI version information")
	fmt.Println()
	fmt.Printf("%sFLAGS:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  --fix                  Automatically apply suggested fixes to source files")
	fmt.Println("  --stream               Stream findings in real-time as they arrive (default: true)")
	fmt.Println("  --base-url <url>       Lorikeet Security platform base URL (default: https://lorikeetsecurity.com)")
	fmt.Println("  --token <token>        Lory access token (or set LORIKEET_TOKEN env var)")
	fmt.Println("  --format <table|json>  Output format (default: table)")
	fmt.Println("  --help, -h             Show this help screen")
	fmt.Println()
	fmt.Printf("%sLEARN MORE:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  Lorikeet Security: https://lorikeetsecurity.com")
	fmt.Println()
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "review":
		err = cmd.RunReview(args)
	case "scan":
		err = cmd.RunScan(args)
	case "fix":
		err = cmd.RunFix(args)
	case "diff":
		err = cmd.RunDiff(args)
	case "token":
		err = cmd.RunToken(args)
	case "mcp":
		err = mcp.ServeMCP()
	case "version", "-v", "--version":
		fmt.Printf("lory version %s (Lorikeet Security AI Reviewer)\n", Version)
	case "help", "--help", "-h":
		printHelp()
	default:
		// If first arg looks like a file, directory or URL, treat as `lory scan <arg>`
		if _, statErr := os.Stat(command); statErr == nil || os.Args[1] == "." {
			err = cmd.RunScan(os.Args[1:])
		} else {
			fmt.Printf("%sError: unknown command '%s'%s\n\n", tui.ColorRed, command, tui.ColorReset)
			printHelp()
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sError:%s %v\n", tui.ColorRed, tui.ColorReset, err)
		os.Exit(1)
	}
}
