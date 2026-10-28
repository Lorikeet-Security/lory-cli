package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/badge"
	"github.com/lorikeetsecurity/lory/pkg/tui"
)

// RunBadge handles the `lory badge` command
func RunBadge(args []string) error {
	fs := flag.NewFlagSet("badge", flag.ContinueOnError)
	styleFlag := fs.String("style", "pill", "Badge style: pill, shield, seal, minimal")
	themeFlag := fs.String("theme", "dark", "Color theme: dark, light")
	formatFlag := fs.String("format", "all", "Output format: all, html, markdown, svg")
	scoreFlag := fs.Int("score", 100, "Security assessment score (0-100)")
	statusFlag := fs.String("status", "VERIFIED", "Status label: VERIFIED, PASSED, AUDITED")
	targetFlag := fs.String("target", "", "Target hostname or repository (e.g. acme.com)")
	outFlag := fs.String("out", "", "Write output to file (e.g. badge.svg or badge.html)")
	verifyURLFlag := fs.String("verify-url", "", "Custom attestation verification link")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	target := *targetFlag
	if target == "" && len(fs.Args()) > 0 {
		target = fs.Args()[0]
	}
	if target == "" {
		target = "example.com"
	}

	creds, _ := auth.LoadCredentials()
	orgName := "Lorikeet Security"
	if creds != nil && creds.OrgName != "" {
		orgName = creds.OrgName
	}

	opts := badge.BadgeOptions{
		Style:     badge.BadgeStyle(strings.ToLower(*styleFlag)),
		Theme:     badge.BadgeTheme(strings.ToLower(*themeFlag)),
		Target:    target,
		Score:     *scoreFlag,
		Status:    strings.ToUpper(*statusFlag),
		VerifyURL: *verifyURLFlag,
		OrgName:   orgName,
	}
	opts.Normalize()

	// Direct raw export format when piping or targeting a specific file format
	if *formatFlag == "svg" {
		svgContent := badge.GenerateSVG(opts)
		if *outFlag != "" {
			return os.WriteFile(*outFlag, []byte(svgContent), 0644)
		}
		fmt.Print(svgContent)
		return nil
	}

	if *formatFlag == "html" {
		htmlContent := badge.GenerateHTMLEmbed(opts)
		if *outFlag != "" {
			return os.WriteFile(*outFlag, []byte(htmlContent), 0644)
		}
		fmt.Print(htmlContent)
		return nil
	}

	if *formatFlag == "markdown" {
		mdContent := badge.GenerateMarkdown(opts)
		if *outFlag != "" {
			return os.WriteFile(*outFlag, []byte(mdContent), 0644)
		}
		fmt.Println(mdContent)
		return nil
	}

	// Default: "all" - display beautiful terminal summary with copy-paste snippets
	tui.PrintBanner()

	fmt.Printf("%s[+] LORIKEET SECURITY ASSESSMENT TRUST BADGE%s\n", tui.ColorCyan, tui.ColorReset)
	fmt.Printf("    Target:       %s%s%s\n", tui.ColorBold, opts.Target, tui.ColorReset)
	fmt.Printf("    Status:       %s%s (Score: %d/100)%s\n", tui.ColorGreen, opts.Status, opts.Score, tui.ColorReset)
	fmt.Printf("    Style/Theme:  %s%s / %s%s\n", tui.ColorBold, opts.Style, opts.Theme, tui.ColorReset)
	fmt.Printf("    Attestation:  %s%s%s\n\n", tui.ColorDim, opts.VerifyURL, tui.ColorReset)

	fmt.Printf("%s=== HTML FOOTER SNIPPET (Copy & paste into your website footer) ===%s\n\n", tui.ColorBold, tui.ColorReset)
	htmlSnippet := badge.GenerateHTMLEmbed(opts)
	fmt.Printf("%s%s%s\n\n", tui.ColorCyan, htmlSnippet, tui.ColorReset)

	fmt.Printf("%s=== MARKDOWN SNIPPET (For README or Docs) ===%s\n\n", tui.ColorBold, tui.ColorReset)
	mdSnippet := badge.GenerateMarkdown(opts)
	fmt.Printf("%s%s%s\n\n", tui.ColorGreen, mdSnippet, tui.ColorReset)

	if *outFlag != "" {
		var content []byte
		if strings.HasSuffix(*outFlag, ".html") {
			content = []byte(htmlSnippet)
		} else {
			content = []byte(badge.GenerateSVG(opts))
		}
		if err := os.WriteFile(*outFlag, content, 0644); err != nil {
			return fmt.Errorf("failed to write badge file: %w", err)
		}
		fmt.Printf("%s✔ Saved badge asset to %s%s\n\n", tui.ColorGreen, *outFlag, tui.ColorReset)
	} else {
		fmt.Printf("%sTip: Save as standalone SVG with:%s\n", tui.ColorDim, tui.ColorReset)
		fmt.Printf("  lory badge --format svg --out lorikeet-badge.svg\n\n")
	}

	return nil
}
