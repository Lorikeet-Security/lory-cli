package badge

import (
	"strings"
	"testing"
)

func TestGenerateSVG_DefaultPill(t *testing.T) {
	opts := DefaultOptions()
	svg := GenerateSVG(opts)

	if !strings.Contains(svg, "<svg") {
		t.Errorf("expected SVG root tag, got %s", svg)
	}
	if !strings.Contains(svg, "Lorikeet Security") {
		t.Errorf("expected brand text, got %s", svg)
	}
	if !strings.Contains(svg, "SECURED BY") {
		t.Errorf("expected 'SECURED BY' label, got %s", svg)
	}
	if !strings.Contains(svg, "VERIFIED") {
		t.Errorf("expected status 'VERIFIED', got %s", svg)
	}
}

func TestGenerateSVG_Styles(t *testing.T) {
	styles := []BadgeStyle{StylePill, StyleShield, StyleSeal, StyleMinimal}

	for _, style := range styles {
		opts := BadgeOptions{
			Style:  style,
			Target: "example.com",
			Score:  95,
		}
		svg := GenerateSVG(opts)
		if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
			t.Errorf("style %s did not generate valid svg", style)
		}
	}
}

func TestGenerateSVG_Themes(t *testing.T) {
	darkOpts := BadgeOptions{Theme: ThemeDark}
	darkSVG := GenerateSVG(darkOpts)
	if !strings.Contains(darkSVG, "#0A1628") {
		t.Errorf("expected dark theme background")
	}

	lightOpts := BadgeOptions{Theme: ThemeLight}
	lightSVG := GenerateSVG(lightOpts)
	if !strings.Contains(strings.ToUpper(lightSVG), "#FFFFFF") {
		t.Errorf("expected light theme background")
	}
}

func TestGenerateHTMLEmbed(t *testing.T) {
	opts := BadgeOptions{
		Target: "acme-corp.com",
	}
	html := GenerateHTMLEmbed(opts)

	if !strings.Contains(html, "<a href=") {
		t.Errorf("expected anchor tag in html embed")
	}
	if !strings.Contains(html, "data:image/svg+xml;base64,") {
		t.Errorf("expected base64 data uri in html embed")
	}
	if !strings.Contains(html, "https://lorikeetsecurity.com/trust-center") {
		t.Errorf("expected normalized verification URL in html embed")
	}
}

func TestGenerateMarkdown(t *testing.T) {
	opts := BadgeOptions{
		Theme: ThemeDark,
	}
	md := GenerateMarkdown(opts)
	if !strings.Contains(md, "[![Secured by Lorikeet Security]") {
		t.Errorf("expected markdown image link format, got %s", md)
	}
}
