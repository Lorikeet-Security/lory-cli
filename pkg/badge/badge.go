package badge

import (
	"encoding/base64"
	"fmt"
	"time"
)

// BadgeStyle defines the visual format of the badge
type BadgeStyle string

const (
	StylePill    BadgeStyle = "pill"    // Modern SaaS footer badge (default)
	StyleShield  BadgeStyle = "shield"  // Classic shields.io style dual-tone badge
	StyleSeal    BadgeStyle = "seal"    // Detailed enterprise security attestation seal
	StyleMinimal BadgeStyle = "minimal" // Clean inline badge
)

// BadgeTheme defines the color scheme
type BadgeTheme string

const (
	ThemeDark  BadgeTheme = "dark"
	ThemeLight BadgeTheme = "light"
)

// BadgeOptions configures the badge generation
type BadgeOptions struct {
	Style        BadgeStyle
	Theme        BadgeTheme
	Target       string
	Score        int
	Status       string
	VerifiedAt   string
	VerifyURL    string
	OrgName      string
	AssessmentID string
}

// DefaultOptions returns standard configuration for a Lorikeet badge
func DefaultOptions() BadgeOptions {
	return BadgeOptions{
		Style:        StylePill,
		Theme:        ThemeDark,
		Target:       "Target Endpoint",
		Score:        100,
		Status:       "VERIFIED",
		VerifiedAt:   time.Now().UTC().Format("2006-01-02"),
		VerifyURL:    "https://lorikeetsecurity.com/trust-center?target=YOUR_DOMAIN",
		OrgName:      "Lorikeet Security",
		AssessmentID: fmt.Sprintf("LS-%d", time.Now().Unix()),
	}
}

// Normalize validates and applies defaults to options
func (o *BadgeOptions) Normalize() {
	if o.Style == "" {
		o.Style = StylePill
	}
	if o.Theme == "" {
		o.Theme = ThemeDark
	}
	if o.Status == "" {
		o.Status = "VERIFIED"
	}
	if o.VerifiedAt == "" {
		o.VerifiedAt = time.Now().UTC().Format("2006-01-02")
	}
	if o.VerifyURL == "" {
		if o.Target != "" && o.Target != "example.com" && o.Target != "Target Endpoint" {
			o.VerifyURL = fmt.Sprintf("https://lorikeetsecurity.com/trust-center?target=%s", o.Target)
		} else {
			o.VerifyURL = "https://lorikeetsecurity.com/trust-center?target=YOUR_DOMAIN"
		}
	}
	if o.AssessmentID == "" {
		o.AssessmentID = fmt.Sprintf("LS-%d", time.Now().Unix())
	}
}

// GenerateSVG produces the standalone SVG graphic for the specified badge
func GenerateSVG(opts BadgeOptions) string {
	opts.Normalize()

	switch opts.Style {
	case StyleShield:
		return renderShieldSVG(opts)
	case StyleSeal:
		return renderSealSVG(opts)
	case StyleMinimal:
		return renderMinimalSVG(opts)
	case StylePill:
		fallthrough
	default:
		return renderPillSVG(opts)
	}
}

// renderPillSVG creates the official Lorikeet SaaS footer pill badge (240x44)
func renderPillSVG(opts BadgeOptions) string {
	isDark := opts.Theme != ThemeLight

	// Colors matching official Lorikeet Brand Guidelines
	bgColor := "#0A1628"      // Deep Canvas Navy
	bgEnd := "#142B49"        // Slate Navy
	borderColor := "#1A375D"  // Elevated Slate
	labelColor := "#DB6574"   // Lorikeet Rose Light
	titleColor := "#FFFFFF"   // Primary Text
	badgeBg := "#064E3B"      // Emerald Dark
	badgeBorder := "#059669"  // Emerald
	badgeText := "#34D399"    // Emerald Light
	glowOpacity := "0.35"
	shieldB64 := talonShieldDarkB64

	if !isDark {
		bgColor = "#FFFFFF"
		bgEnd = "#F8FAFC"
		borderColor = "#E2E8F0"
		labelColor = "#BA5663" // Lorikeet Rose Primary
		titleColor = "#0A1628" // Deep Canvas Navy Text
		badgeBg = "#ECFDF5"
		badgeBorder = "#A7F3D0"
		badgeText = "#059669"
		glowOpacity = "0.12"
		shieldB64 = talonShieldLightB64
	}

	statusText := opts.Status
	if opts.Score > 0 && opts.Score < 100 {
		statusText = fmt.Sprintf("%d/100", opts.Score)
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 240 44" width="240" height="44" role="img" aria-label="Secured by Lorikeet Security - %s">
  <defs>
    <linearGradient id="lsBgGrad" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
      <stop offset="0%%" stop-color="%s"/>
      <stop offset="100%%" stop-color="%s"/>
    </linearGradient>
    <filter id="lsGlow" x="-10%%" y="-10%%" width="120%%" height="120%%">
      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#BA5663" flood-opacity="%s"/>
    </filter>
  </defs>

  <!-- Container Pill -->
  <rect x="1" y="1" width="238" height="42" rx="21" fill="url(#lsBgGrad)" stroke="%s" stroke-width="1.2" filter="url(#lsGlow)"/>

  <!-- Official Talon PTaaS Shield & Claw Mark -->
  <image href="data:image/png;base64,%s" xlink:href="data:image/png;base64,%s" x="11" y="7" width="26" height="30" preserveAspectRatio="xMidYMid meet"/>

  <!-- Brand Typography -->
  <g transform="translate(44, 0)">
    <text x="0" y="17" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="700" letter-spacing="0.14em">SECURED BY</text>
    <text x="0" y="31" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11.5" font-weight="800" letter-spacing="-0.01em">Lorikeet Security</text>
  </g>

  <!-- Status / Verification Pill -->
  <g transform="translate(162, 11)">
    <rect x="0" y="0" width="68" height="22" rx="11" fill="%s" stroke="%s" stroke-width="1"/>
    <!-- Shield Check Icon -->
    <path d="M8.5 5.5L12 4L15.5 5.5V9C15.5 11.5 13.8 13.8 12 14.5C10.2 13.8 8.5 11.5 8.5 9V5.5Z" fill="none" stroke="%s" stroke-width="1.2" stroke-linejoin="round"/>
    <path d="M10.5 9L11.5 10L13.8 7.8" fill="none" stroke="%s" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="19" y="14.5" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="800" letter-spacing="0.06em">%s</text>
  </g>
</svg>`,
		opts.Status,
		bgColor, bgEnd,
		glowOpacity,
		borderColor,
		shieldB64, shieldB64,
		labelColor,
		titleColor,
		badgeBg, badgeBorder,
		badgeText,
		badgeText,
		badgeText,
		statusText,
	)
}

// renderShieldSVG creates the classic dual-tone badge with balanced proportions (296x28)
func renderShieldSVG(opts BadgeOptions) string {
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 296 28" width="296" height="28" role="img" aria-label="Secured by Lorikeet Security">
  <defs>
    <clipPath id="shieldRound">
      <rect width="296" height="28" rx="5"/>
    </clipPath>
  </defs>

  <g clip-path="url(#shieldRound)">
    <!-- Left Plate: Deep Navy -->
    <rect width="208" height="28" fill="#0A1628"/>
    <!-- Right Plate: Verified Emerald -->
    <rect x="208" width="88" height="28" fill="#059669"/>

    <!-- Official Talon PTaaS Shield & Claw Mark -->
    <image href="data:image/png;base64,%s" xlink:href="data:image/png;base64,%s" x="8" y="4" width="18" height="20" preserveAspectRatio="xMidYMid meet"/>

    <!-- Left Plate Typography -->
    <text x="33" y="18" fill="#DB6574" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="700" letter-spacing="0.08em">SECURED BY</text>
    <text x="96" y="18" fill="#FFFFFF" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8.5" font-weight="800" letter-spacing="0.04em">LORIKEET SECURITY</text>

    <!-- Right Plate Verification -->
    <path d="M218 8L223.5 6L229 8V13.5C229 17 226.5 19.8 223.5 21C220.5 19.8 218 17 218 13.5V8Z" fill="none" stroke="#FFFFFF" stroke-width="1.3" stroke-linejoin="round"/>
    <path d="M221 13.5L223 15.5L226.5 11.5" fill="none" stroke="#FFFFFF" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="235" y="18" fill="#FFFFFF" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8.5" font-weight="800" letter-spacing="0.06em">%s</text>
  </g>
  <rect width="296" height="28" rx="5" fill="none" stroke="#1A375D" stroke-width="1"/>
</svg>`, talonShieldDarkB64, talonShieldDarkB64, opts.Status)
}

// renderSealSVG creates the enterprise attestation seal with spacious layout (360x72)
func renderSealSVG(opts BadgeOptions) string {
	isDark := opts.Theme != ThemeLight
	bgColor := "#0A1628"     // Deep Canvas Navy
	borderColor := "#1A375D" // Elevated Slate
	textColor := "#FFFFFF"
	subColor := "#94A3B8"    // Secondary Slate
	kickerColor := "#DB6574" // Lorikeet Rose Light
	fullB64 := talonFullDarkB64

	if !isDark {
		bgColor = "#FFFFFF"
		borderColor = "#CBD5E1"
		textColor = "#0A1628"
		subColor = "#64748B"
		kickerColor = "#BA5663" // Lorikeet Rose Primary
		fullB64 = talonFullLightB64
	}

	scoreBadge := fmt.Sprintf("%d/100", opts.Score)
	if opts.Score >= 90 {
		scoreBadge = "GRADE A+"
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 360 72" width="360" height="72" role="img" aria-label="Lorikeet Security Continuous Verification Seal">
  <rect x="1" y="1" width="358" height="70" rx="10" fill="%s" stroke="%s" stroke-width="1.5"/>

  <!-- Official Talon Full Brand Emblem -->
  <image href="data:image/png;base64,%s" xlink:href="data:image/png;base64,%s" x="14" y="10" width="42" height="52" preserveAspectRatio="xMidYMid meet"/>

  <!-- Attestation Headers with spacious layout and zero collision -->
  <text x="66" y="24" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8.5" font-weight="700" letter-spacing="0.12em">SECURED BY LORIKEET SECURITY</text>
  <text x="66" y="42" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12.5" font-weight="800" letter-spacing="-0.01em">Continuous PTaaS Verification</text>
  <text x="66" y="58" fill="%s" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8.5" font-weight="500">Last Verified: %s</text>

  <!-- Pass Chip with plenty of clearance (x=276) -->
  <g transform="translate(276, 14)">
    <rect width="68" height="22" rx="11" fill="#064E3B" stroke="#059669" stroke-width="1"/>
    <circle cx="10" cy="11" r="3" fill="#10B981"/>
    <text x="18" y="14.5" fill="#34D399" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="800" letter-spacing="0.04em">%s</text>
  </g>
</svg>`,
		bgColor, borderColor,
		fullB64, fullB64,
		kickerColor,
		textColor,
		subColor, opts.VerifiedAt,
		scoreBadge,
	)
}

// renderMinimalSVG creates a subtle inline badge (170x32)
func renderMinimalSVG(opts BadgeOptions) string {
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 170 32" width="170" height="32" role="img" aria-label="Secured by Lorikeet Security">
  <rect x="0.5" y="0.5" width="169" height="31" rx="6" fill="#0A1628" stroke="#1A375D" stroke-width="1"/>
  <image href="data:image/png;base64,%s" xlink:href="data:image/png;base64,%s" x="7" y="5.5" width="18" height="21" preserveAspectRatio="xMidYMid meet"/>
  <text x="32" y="14" fill="#DB6574" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="7" font-weight="700" letter-spacing="0.12em">SECURED BY</text>
  <text x="32" y="24" fill="#FFFFFF" font-family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9.5" font-weight="700">Lorikeet Security</text>
  <circle cx="154" cy="16" r="3.5" fill="#10B981"/>
</svg>`, talonShieldDarkB64, talonShieldDarkB64)
}

// GenerateHTMLEmbed produces an embeddable responsive HTML/CSS snippet ready to paste into any footer
func GenerateHTMLEmbed(opts BadgeOptions) string {
	opts.Normalize()
	svgContent := GenerateSVG(opts)

	svgB64 := base64.StdEncoding.EncodeToString([]byte(svgContent))

	return fmt.Sprintf(`<!-- Lorikeet Security Verified Badge -->
<a href="%s" target="_blank" rel="noopener noreferrer" class="lorikeet-security-badge" title="Verified by Lorikeet Security Continuous PTaaS Assessment" aria-label="Secured by Lorikeet Security">
  <img src="data:image/svg+xml;base64,%s" alt="Secured by Lorikeet Security" width="240" height="44" style="height: 44px; width: auto; max-width: 100%%; display: inline-block; vertical-align: middle; transition: transform 0.2s ease, filter 0.2s ease;" onmouseover="this.style.transform='translateY(-2px)';this.style.filter='drop-shadow(0 4px 12px rgba(186,86,99,0.35))'" onmouseout="this.style.transform='none';this.style.filter='none'" />
</a>`, opts.VerifyURL, svgB64)
}

// GenerateInlineHTML produces an inline SVG version without data-uri
func GenerateInlineHTML(opts BadgeOptions) string {
	opts.Normalize()
	svgContent := GenerateSVG(opts)

	return fmt.Sprintf(`<!-- Lorikeet Security Verified Badge (Inline SVG) -->
<a href="%s" target="_blank" rel="noopener noreferrer" class="lorikeet-badge-link" title="Verified by Lorikeet Security Continuous PTaaS Assessment" style="display: inline-block; text-decoration: none; transition: transform 0.2s ease;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
%s
</a>`, opts.VerifyURL, svgContent)
}

// GenerateMarkdown produces Markdown syntax for README footers or documentation
func GenerateMarkdown(opts BadgeOptions) string {
	opts.Normalize()
	badgeFileName := fmt.Sprintf("lorikeet-secured-%s.svg", opts.Theme)
	if opts.Style == StyleShield {
		badgeFileName = "lorikeet-secured-shield.svg"
	}
	return fmt.Sprintf("[![Secured by Lorikeet Security](https://lorikeetsecurity.com/badges/%s)](%s)", badgeFileName, opts.VerifyURL)
}

// GenerateAllSnippets returns all formats for developer convenience
func GenerateAllSnippets(opts BadgeOptions) map[string]string {
	opts.Normalize()
	return map[string]string{
		"svg":         GenerateSVG(opts),
		"html":        GenerateHTMLEmbed(opts),
		"html_inline": GenerateInlineHTML(opts),
		"markdown":    GenerateMarkdown(opts),
		"verify_url":  opts.VerifyURL,
	}
}
