package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/lorikeetsecurity/lory/pkg/retest"
	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func RunRetest(args []string) error {
	fs := flag.NewFlagSet("retest", flag.ContinueOnError)
	targetFlag := fs.String("target", "http://localhost:3000", "Live target base URL to replay against")
	if err := fs.Parse(args); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return fmt.Errorf("missing finding ID. Usage: lory retest <finding-id> [--target <url>]")
	}

	findingID := remaining[0]

	tui.PrintBanner()
	fmt.Printf("%s1-Click Retest Replay%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("• Finding ID:  %s%s%s\n", tui.ColorCyan, findingID, tui.ColorReset)
	fmt.Printf("• Target URL:  %s%s%s\n\n", tui.ColorWhite, *targetFlag, tui.ColorReset)

	tui.Spin(fmt.Sprintf("Fetching exact replay test vector for %s from Talon...", findingID), 300)
	tui.Spin("Replaying exploit payload against target endpoint...", 500)

	result, err := retest.ExecuteRetest(findingID, *targetFlag)
	if err != nil {
		return fmt.Errorf("retest execution failed: %w", err)
	}

	fmt.Println()
	if result.Resolved {
		fmt.Printf("%s✔ RETEST PASSED: %s is RESOLVED!%s\n", tui.ColorGreen, result.FindingID, tui.ColorReset)
		fmt.Printf("  Observation: %s\n", result.Observation)
		fmt.Printf("  Duration:    %dms\n", result.DurationMs)
		fmt.Printf("  Talon State: %s -> %s\n", tui.StatusBadge(result.OriginalStatus), tui.StatusBadge(types.StatusResolved))
		fmt.Printf("\n%s✔ Updated Talon compliance attestation graph.%s\n\n", tui.ColorGreen, tui.ColorReset)
	} else {
		fmt.Printf("%s✗ RETEST FAILED: %s is STILL VULNERABLE%s\n", tui.ColorRed, result.FindingID, tui.ColorReset)
		fmt.Printf("  Observation: %s\n", result.Observation)
		fmt.Printf("  Duration:    %dms\n", result.DurationMs)
		fmt.Printf("  Talon State: %s\n", tui.StatusBadge(types.StatusVerified))
		fmt.Printf("\n%sRemediation fix was not detected by live replay.%s\n\n", tui.ColorYellow, tui.ColorReset)
		os.Exit(1)
	}

	return nil
}
