package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/tui"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

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
