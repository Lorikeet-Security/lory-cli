package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

var (
	// Route regexes for common web frameworks
	expressRouteRegex = regexp.MustCompile(`(?:app|router)\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]`)
	fastapiRouteRegex = regexp.MustCompile(`@app\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]`)
	ginRouteRegex     = regexp.MustCompile(`(?:r|router|api|v1)\.(GET|POST|PUT|DELETE|PATCH)\(\s*['"]([^'"]+)['"]`)
	nextRouteRegex    = regexp.MustCompile(`export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)`)

	// Security Sink regexes
	sqliRegex       = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:req\.query|req\.body|params|request\.)`)
	cmdExecRegex    = regexp.MustCompile(`(?i)(?:exec|execSync|spawn|child_process\.exec|os\.system|subprocess\.Popen)\s*\(\s*[^)]*(?:req\.|params|args|input)`)
	hardcodedSecret = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|password|jwt_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]`)
	ssrfRegex       = regexp.MustCompile(`(?i)(?:axios\.get|fetch|http\.get|requests\.get)\s*\(\s*(?:req\.query|req\.body|url_param|target)`)
	corsWildcard    = regexp.MustCompile(`(?i)Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]`)
)

type AnalysisResult struct {
	RepoPath   string
	Routes     []types.EndpointRoute
	WhiteBoxPoCs []WhiteBoxFinding
	TotalFiles int
	Frameworks []string
}

type WhiteBoxFinding struct {
	Category    string
	Description string
	FilePath    string
	LineNumber  int
	Snippet     string
	Severity    types.Severity
	CWE         string
}

// AnalyzeRepository parses source code files to build AST and route maps
func AnalyzeRepository(repoPath string) (*AnalysisResult, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}

	result := &AnalysisResult{
		RepoPath:     absPath,
		Routes:       make([]types.EndpointRoute, 0),
		WhiteBoxPoCs: make([]WhiteBoxFinding, 0),
	}

	frameworkSet := make(map[string]bool)

	ignoredDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
		"dist":         true,
		"build":        true,
		".next":        true,
		".cache":       true,
		"venv":         true,
		".venv":        true,
	}

	validExts := map[string]bool{
		".js":   true,
		".ts":   true,
		".jsx":  true,
		".tsx":  true,
		".py":   true,
		".go":   true,
		".rb":   true,
		".php":  true,
		".java": true,
	}

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if info.IsDir() {
			if ignoredDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !validExts[ext] {
			return nil
		}

		result.TotalFiles++
		relPath, _ := filepath.Rel(absPath, path)

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Route extraction: Express / Node
			if matches := expressRouteRegex.FindStringSubmatch(line); len(matches) > 2 {
				frameworkSet["Express.js"] = true
				result.Routes = append(result.Routes, types.EndpointRoute{
					Method:       strings.ToUpper(matches[1]),
					Path:         matches[2],
					FilePath:     relPath,
					LineNumber:   lineNum,
					Framework:    "Express.js",
					AuthRequired: strings.Contains(line, "auth") || strings.Contains(line, "protect"),
				})
			}

			// Route extraction: FastAPI
			if matches := fastapiRouteRegex.FindStringSubmatch(line); len(matches) > 2 {
				frameworkSet["FastAPI"] = true
				result.Routes = append(result.Routes, types.EndpointRoute{
					Method:       strings.ToUpper(matches[1]),
					Path:         matches[2],
					FilePath:     relPath,
					LineNumber:   lineNum,
					Framework:    "FastAPI",
					AuthRequired: strings.Contains(line, "Depends(get_current_user)"),
				})
			}

			// Route extraction: Go Gin
			if matches := ginRouteRegex.FindStringSubmatch(line); len(matches) > 2 {
				frameworkSet["Gin (Go)"] = true
				result.Routes = append(result.Routes, types.EndpointRoute{
					Method:       strings.ToUpper(matches[1]),
					Path:         matches[2],
					FilePath:     relPath,
					LineNumber:   lineNum,
					Framework:    "Gin",
					AuthRequired: strings.Contains(line, "AuthMiddleware"),
				})
			}

			// Route extraction: Next.js App Router (route.ts / route.js)
			if strings.Contains(path, "app") && (strings.HasSuffix(path, "route.ts") || strings.HasSuffix(path, "route.js")) {
				if matches := nextRouteRegex.FindStringSubmatch(line); len(matches) > 1 {
					frameworkSet["Next.js"] = true
					// Infer route path from directory
					dir := filepath.Dir(relPath)
					webRoute := "/" + strings.ReplaceAll(strings.TrimPrefix(dir, "app/"), "api/", "api/")
					result.Routes = append(result.Routes, types.EndpointRoute{
						Method:       matches[1],
						Path:         webRoute,
						FilePath:     relPath,
						LineNumber:   lineNum,
						Framework:    "Next.js App Router",
						AuthRequired: false,
					})
				}
			}

			// Vulnerability Sink: SQL Injection
			if sqliRegex.MatchString(line) {
				result.WhiteBoxPoCs = append(result.WhiteBoxPoCs, WhiteBoxFinding{
					Category:    "SQL Injection (Concatenated query)",
					Description: "Direct user input interpolated into dynamic SQL statement without parameterized query binding",
					FilePath:    relPath,
					LineNumber:  lineNum,
					Snippet:     strings.TrimSpace(line),
					Severity:    types.SeverityCritical,
					CWE:         "CWE-89",
				})
			}

			// Vulnerability Sink: Command Injection
			if cmdExecRegex.MatchString(line) {
				result.WhiteBoxPoCs = append(result.WhiteBoxPoCs, WhiteBoxFinding{
					Category:    "Remote OS Command Injection",
					Description: "Arbitrary shell execution spawned with unvalidated incoming request arguments",
					FilePath:    relPath,
					LineNumber:  lineNum,
					Snippet:     strings.TrimSpace(line),
					Severity:    types.SeverityCritical,
					CWE:         "CWE-78",
				})
			}

			// Vulnerability Sink: Hardcoded Credential
			if hardcodedSecret.MatchString(line) && !strings.Contains(strings.ToLower(path), "test") {
				result.WhiteBoxPoCs = append(result.WhiteBoxPoCs, WhiteBoxFinding{
					Category:    "Hardcoded Sensitive Credential",
					Description: "High-entropy secret or API key committed in cleartext source file",
					FilePath:    relPath,
					LineNumber:  lineNum,
					Snippet:     strings.TrimSpace(line),
					Severity:    types.SeverityHigh,
					CWE:         "CWE-798",
				})
			}

			// Vulnerability Sink: SSRF
			if ssrfRegex.MatchString(line) {
				result.WhiteBoxPoCs = append(result.WhiteBoxPoCs, WhiteBoxFinding{
					Category:    "Server-Side Request Forgery (SSRF)",
					Description: "Server performs outbound network requests to client-controlled URL parameter without IP egress restrictions",
					FilePath:    relPath,
					LineNumber:  lineNum,
					Snippet:     strings.TrimSpace(line),
					Severity:    types.SeverityHigh,
					CWE:         "CWE-918",
				})
			}

			// Vulnerability Sink: Permissive CORS
			if corsWildcard.MatchString(line) {
				result.WhiteBoxPoCs = append(result.WhiteBoxPoCs, WhiteBoxFinding{
					Category:    "Permissive Cross-Origin Resource Sharing (CORS)",
					Description: "Wildcard Access-Control-Allow-Origin configured allowing cross-domain data exfiltration",
					FilePath:    relPath,
					LineNumber:  lineNum,
					Snippet:     strings.TrimSpace(line),
					Severity:    types.SeverityMedium,
					CWE:         "CWE-942",
				})
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("scan walk error: %w", err)
	}

	for f := range frameworkSet {
		result.Frameworks = append(result.Frameworks, f)
	}

	return result, nil
}
