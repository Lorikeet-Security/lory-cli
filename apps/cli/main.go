package main

import (
	"fmt"
	"os"

	"github.com/lorikeetsecurity/lory/apps/cli/cmd"
	"github.com/lorikeetsecurity/lory/pkg/mcp"
	"github.com/lorikeetsecurity/lory/pkg/tui"
)

const Version = "1.0.0"

func printHelp() {
	tui.PrintBanner()
	fmt.Printf("%sUSAGE:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  lory <command> [flags]")
	fmt.Println()
	fmt.Printf("%sCOMMANDS:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("  %-24s %s\n", "scan", "Run white-box AST mapping and live exploit verification")
	fmt.Printf("  %-24s %s\n", "chat", "Start interactive security REPL session")
	fmt.Printf("  %-24s %s\n", "retest <finding-id>", "1-click replay test to verify if a patch resolved a finding")
	fmt.Printf("  %-24s %s\n", "findings [list]", "Stream active, verified vulnerabilities and triage state")
	fmt.Printf("  %-24s %s\n", "export", "Generate SARIF 2.1.0 or SOC 2 / ISO 27001 evidence packs")
	fmt.Printf("  %-24s %s\n", "mcp serve", "Launch Model Context Protocol stdio server for Claude & Cursor")
	fmt.Printf("  %-24s %s\n", "request-review <id>", "Escalate finding to Lorikeet's human assessment team")
	fmt.Printf("  %-24s %s\n", "login", "Authenticate interactively via Talon SSO or with API key")
	fmt.Printf("  %-24s %s\n", "logout", "Clear active session credentials")
	fmt.Printf("  %-24s %s\n", "whoami", "Inspect current Talon session and organization context")
	fmt.Printf("  %-24s %s\n", "version", "Show CLI version information")
	fmt.Println()
	fmt.Printf("%sFLAGS:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  --help, -h             Show this help screen")
	fmt.Println()
	fmt.Printf("%sLEARN MORE:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Println("  Visit https://lorikeetsecurity.com/lory for complete documentation.")
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
	case "scan":
		err = cmd.RunScan(args)
	case "chat":
		err = cmd.RunChat(args)
	case "retest":
		err = cmd.RunRetest(args)
	case "findings":
		err = cmd.RunFindings(args)
	case "export":
		err = cmd.RunExport(args)
	case "mcp":
		if len(args) > 0 && args[0] == "serve" {
			err = mcp.ServeMCP()
		} else {
			err = mcp.ServeMCP()
		}
	case "request-review":
		err = cmd.RunRequestReview(args)
	case "auth":
		err = cmd.RunAuth(args)
	case "login":
		err = cmd.RunLogin(args)
	case "logout":
		err = cmd.RunLogout(args)
	case "whoami", "status":
		err = cmd.RunWhoami(args)
	case "version", "-v", "--version":
		fmt.Printf("lory version %s (Lorikeet Talon Engine)\n", Version)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Printf("%sError: unknown command '%s'%s\n\n", tui.ColorRed, command, tui.ColorReset)
		printHelp()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sError:%s %v\n", tui.ColorRed, tui.ColorReset, err)
		os.Exit(1)
	}
}
