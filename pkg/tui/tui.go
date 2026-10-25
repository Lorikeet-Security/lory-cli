package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorGray    = "\033[90m"

	BgRed        = "\033[41m"
	BgYellow     = "\033[43m"
	BgBlue       = "\033[44m"
	BgGreen      = "\033[42m"
)

func PrintBanner() {
	banner := `
  ___  ____  _   _ 
 / _ \|  _ \| | | |  ` + ColorCyan + ColorBold + `LORIKEET SECURITY` + ColorReset + `
| | | | |_) | |_| |  ` + ColorDim + `Autonomous Hybrid-Intelligence Security Testing` + ColorReset + `
| |_| |  _ < \__, |  ` + ColorGreen + `Talon Synchronization Active` + ColorReset + `
 \___/|_| \_\ ___/   ` + ColorGray + `v1.0.0` + ColorReset + `
`
	fmt.Println(banner)
}

func SeverityBadge(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return fmt.Sprintf("%s%s[CRITICAL]%s", ColorRed, ColorBold, ColorReset)
	case types.SeverityHigh:
		return fmt.Sprintf("%s%s[ HIGH ]%s", ColorRed, ColorBold, ColorReset)
	case types.SeverityMedium:
		return fmt.Sprintf("%s%s[MEDIUM]%s", ColorYellow, ColorBold, ColorReset)
	case types.SeverityLow:
		return fmt.Sprintf("%s%s[ LOW  ]%s", ColorBlue, ColorBold, ColorReset)
	default:
		return fmt.Sprintf("%s%s[ INFO ]%s", ColorGray, ColorBold, ColorReset)
	}
}

func StatusBadge(s types.FindingStatus) string {
	switch s {
	case types.StatusVerified:
		return fmt.Sprintf("%s%s● VERIFIED%s", ColorRed, ColorBold, ColorReset)
	case types.StatusResolved:
		return fmt.Sprintf("%s%s✔ RESOLVED%s", ColorGreen, ColorBold, ColorReset)
	case types.StatusRetesting:
		return fmt.Sprintf("%s%s↻ RETESTING%s", ColorYellow, ColorBold, ColorReset)
	case types.StatusReviewReq:
		return fmt.Sprintf("%s%s⚑ REVIEW REQUESTED%s", ColorMagenta, ColorBold, ColorReset)
	default:
		return fmt.Sprintf("%s%s○ OPEN%s", ColorCyan, ColorBold, ColorReset)
	}
}

func RenderFindingCard(f types.VulnerabilityFinding) {
	width := 76
	divider := strings.Repeat("─", width)

	fmt.Printf("\n%s%s%s\n", ColorCyan, divider, ColorReset)
	fmt.Printf(" %s  %s%s%s (%s)\n", SeverityBadge(f.Severity), ColorBold, f.Title, ColorReset, f.ID)
	fmt.Printf(" Status:     %s   CVSS: %s%.1f%s   CWE: %s%s%s\n", 
		StatusBadge(f.Status), ColorYellow, f.CVSS, ColorReset, ColorCyan, f.CWE, ColorReset)
	fmt.Printf(" Location:   %s%s %s%s (Line %d)\n", ColorWhite, f.Method, f.Route, ColorReset, f.SourceLine)
	fmt.Printf(" Source:     %s%s%s\n", ColorDim, f.SourceFile, ColorReset)
	fmt.Printf(" Compliance: %s%s%s\n", ColorGray, strings.Join(f.ComplianceTags, ", "), ColorReset)
	
	fmt.Printf("\n %sExploit Synthesis PoC:%s\n", ColorBold, ColorReset)
	fmt.Printf("   %s%s%s\n", ColorYellow, f.PoCCommand, ColorReset)

	if f.PoCResponse != "" {
		fmt.Printf("\n %sVerified Target Output:%s\n", ColorBold, ColorReset)
		fmt.Printf("   %s%s%s\n", ColorDim, f.PoCResponse, ColorReset)
	}

	fmt.Printf("\n %sRemediation Guidance:%s\n", ColorGreen, ColorReset)
	fmt.Printf("   %s\n", f.Remediation)
	fmt.Printf("%s%s%s\n", ColorCyan, divider, ColorReset)
}

func Spin(msg string, duration time.Duration) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	end := time.Now().Add(duration)
	i := 0
	for time.Now().Before(end) {
		fmt.Printf("\r%s%s%s %s", ColorCyan, frames[i%len(frames)], ColorReset, msg)
		time.Sleep(80 * time.Millisecond)
		i++
	}
	fmt.Printf("\r%s✔%s %s\n", ColorGreen, ColorReset, msg)
}
