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
)

func PrintBanner() {
	banner := `
 _        ___   ____  __   __
| |      / _ \ |  _ \ \ \ / /  ` + ColorCyan + ColorBold + `LORIKEET SECURITY` + ColorReset + `
| |     | | | || |_) | \ V /   ` + ColorDim + `AI Security Analyst & PTaaS Platform` + ColorReset + `
| |___  | |_| ||  _ <   | |    ` + ColorGreen + `Lory Review & Web Security Scanner` + ColorReset + `
|_____|  \___/ |_| \_\  |_|    ` + ColorGray + `v1.1.0` + ColorReset + `
`
	fmt.Println(banner)
}

func SeverityBadge(s types.Severity) string {
	switch strings.ToLower(string(s)) {
	case "critical":
		return fmt.Sprintf("%s%s[CRITICAL]%s", ColorRed, ColorBold, ColorReset)
	case "high":
		return fmt.Sprintf("%s%s[ HIGH ]%s", ColorRed, ColorBold, ColorReset)
	case "medium":
		return fmt.Sprintf("%s%s[MEDIUM]%s", ColorYellow, ColorBold, ColorReset)
	case "low":
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
	fmt.Printf("\n %sExploit Synthesis PoC:%s\n", ColorBold, ColorReset)
	fmt.Printf("   %s%s%s\n", ColorYellow, f.PoCCommand, ColorReset)
	fmt.Printf("\n %sRemediation Guidance:%s\n", ColorGreen, ColorReset)
	fmt.Printf("   %s\n", f.Remediation)
	fmt.Printf("%s%s%s\n", ColorCyan, divider, ColorReset)
}

func RenderLoryFinding(f types.LoryFinding, index int) {
	fmt.Printf("\n%s#%d  %s %s%s%s", ColorCyan, index, SeverityBadge(f.Severity), ColorBold, f.Title, ColorReset)
	if f.CWE != "" {
		fmt.Printf(" (%s%s%s)", ColorCyan, f.CWE, ColorReset)
	}
	fmt.Println()

	loc := fmt.Sprintf("%s:%d", f.FilePath, f.Line)
	if f.EndLine > f.Line {
		loc = fmt.Sprintf("%s:%d-%d", f.FilePath, f.Line, f.EndLine)
	}
	fmt.Printf("    %sLocation:%s   %s%s%s (confidence: %s)\n", ColorDim, ColorReset, ColorWhite, loc, ColorReset, f.Confidence)

	if f.Detail != "" {
		fmt.Printf("    %sDetail:%s     %s\n", ColorDim, ColorReset, f.Detail)
	}

	if f.Fix != "" {
		fmt.Printf("    %sQuick Fix:%s  %s%s%s\n", ColorGreen, ColorReset, ColorYellow, strings.TrimSpace(f.Fix), ColorReset)
		if f.FixNote != "" {
			fmt.Printf("    %sNote:%s       %s\n", ColorDim, ColorReset, f.FixNote)
		}
	}
}

func RenderWebScanResult(res *types.WebScanResult) {
	fmt.Printf("\n%s=== Web Security Scan Results ===%s\n", ColorBold, ColorReset)
	fmt.Printf("Target:     %s%s%s\n", ColorCyan, res.Target, ColorReset)
	fmt.Printf("Scanned At: %s\n", res.ScannedAt)

	// Score badge
	scoreColor := ColorRed
	if res.Score >= 80 {
		scoreColor = ColorGreen
	} else if res.Score >= 50 {
		scoreColor = ColorYellow
	}
	fmt.Printf("Security Score: %s%s%d / 100%s\n\n", scoreColor, ColorBold, res.Score, ColorReset)

	for _, cat := range res.Categories {
		fmt.Printf("%s%s%s\n", ColorBold, cat.Name, ColorReset)
		for _, chk := range cat.Checks {
			icon := fmt.Sprintf("%s✔%s", ColorGreen, ColorReset)
			if chk.Status == "fail" {
				icon = fmt.Sprintf("%s✗%s", ColorRed, ColorReset)
			} else if chk.Status == "warn" {
				icon = fmt.Sprintf("%s!%s", ColorYellow, ColorReset)
			} else if chk.Status == "info" {
				icon = fmt.Sprintf("%si%s", ColorBlue, ColorReset)
			}
			fmt.Printf("  %s %-32s %s%s%s\n", icon, chk.Name, ColorDim, chk.Detail, ColorReset)
		}
		fmt.Println()
	}
}

func Spin(msg string, duration time.Duration) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	end := time.Now().Add(duration)
	i := 0
	for time.Now().Before(end) {
		fmt.Printf("\r%s%s%s %s", ColorCyan, frames[i%len(frames)], ColorReset, msg)
		time.Sleep(70 * time.Millisecond)
		i++
	}
	fmt.Printf("\r%s✔%s %s\n", ColorGreen, ColorReset, msg)
}
