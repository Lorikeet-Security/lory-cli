package analyzer

import (
	"regexp"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

type RulePattern struct {
	Regex       *regexp.Regexp
	CWE         string
	Severity    types.Severity
	Confidence  types.Confidence
	Title       string
	Detail      string
	FixTemplate func(match string, fullLine string) (string, string)
}

var localRules = []RulePattern{
	{
		Regex:      regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:req\.query|req\.body|params|request\.)`),
		CWE:        "CWE-89",
		Severity:   types.SeverityCritical,
		Confidence: types.ConfidenceHigh,
		Title:      "SQL Injection (Concatenated query)",
		Detail:     "Direct user input is concatenated into a SQL statement without parameterized query binding, allowing attackers to manipulate query logic.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return "// Fix: use parameterized query\n" + strings.Replace(fullLine, "+", "/* $1 */", 1), "Bind dynamic user input via SQL query parameters."
		},
	},
	{
		Regex:      regexp.MustCompile(`(?i)(?:exec|execSync|spawn|child_process\.exec|os\.system|subprocess\.Popen)\s*\(\s*[^)]*(?:req\.|params|args|input)`),
		CWE:        "CWE-78",
		Severity:   types.SeverityCritical,
		Confidence: types.ConfidenceHigh,
		Title:      "Remote OS Command Injection",
		Detail:     "Arbitrary shell execution spawned with unvalidated incoming request arguments, allowing remote code execution.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return "// Fix: avoid shell interpolation and use fixed binary path\n" + fullLine, "Validate arguments against a strict whitelist without invoking system shell."
		},
	},
	{
		Regex:      regexp.MustCompile(`(?i)(?:api[_-]?key|secret|password|jwt_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]`),
		CWE:        "CWE-798",
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceHigh,
		Title:      "Hardcoded Sensitive Credential",
		Detail:     "High-entropy secret or API key committed in cleartext source file, risking credential leak.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return strings.Replace(fullLine, match, "process.env.API_KEY", 1), "Store credentials in environment variables or a managed secret store."
		},
	},
	{
		Regex:      regexp.MustCompile(`(?i)(?:axios\.get|fetch|http\.get|requests\.get)\s*\(\s*(?:req\.query|req\.body|url_param|target)`),
		CWE:        "CWE-918",
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceMedium,
		Title:      "Server-Side Request Forgery (SSRF)",
		Detail:     "Outbound network request performed to client-controlled URL parameter without IP egress restrictions or scheme validation.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return "// Fix: validate URL against strict domain allowlist\n" + fullLine, "Restrict destination URLs to an approved allowlist and block internal IP ranges."
		},
	},
	{
		Regex:      regexp.MustCompile(`(?i)Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]`),
		CWE:        "CWE-942",
		Severity:   types.SeverityMedium,
		Confidence: types.ConfidenceHigh,
		Title:      "Permissive Cross-Origin Resource Sharing (CORS)",
		Detail:     "Wildcard Access-Control-Allow-Origin allows arbitrary cross-domain web pages to read authenticated API responses.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return strings.Replace(fullLine, "*", "https://app.yourdomain.com", 1), "Specify explicit trusted origins instead of wildcard *."
		},
	},
	{
		Regex:      regexp.MustCompile(`(?i)dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(?:req\.|props\.|input|content)`),
		CWE:        "CWE-79",
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceHigh,
		Title:      "Cross-Site Scripting (XSS) via Unsanitized DOM Sink",
		Detail:     "Raw HTML injected directly into DOM via dangerouslySetInnerHTML without DOMPurify sanitization.",
		FixTemplate: func(match string, fullLine string) (string, string) {
			return strings.Replace(fullLine, "__html:", "__html: DOMPurify.sanitize(", 1) + ")", "Sanitize HTML using DOMPurify before rendering."
		},
	},
}

// AnalyzeCodeLocally runs local SAST rules on code content
func AnalyzeCodeLocally(content, filePath string) []types.LoryFinding {
	lines := strings.Split(content, "\n")
	findings := make([]types.LoryFinding, 0)

	if IsFileIgnored(content) {
		return findings
	}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		if IsLineIgnored(lines, lineNum) {
			continue
		}

		for _, rule := range localRules {
			if match := rule.Regex.FindString(line); match != "" {
				fix, fixNote := "", ""
				if rule.FixTemplate != nil {
					fix, fixNote = rule.FixTemplate(match, line)
				}

				findings = append(findings, types.LoryFinding{
					Line:       lineNum,
					Severity:   rule.Severity,
					Confidence: rule.Confidence,
					Title:      rule.Title,
					Detail:     rule.Detail,
					CWE:        rule.CWE,
					Fix:        fix,
					FixNote:    fixNote,
					FilePath:   filePath,
				})
			}
		}
	}

	return findings
}
