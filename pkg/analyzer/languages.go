package analyzer

import (
	"path/filepath"
	"regexp"
	"strings"
)

var extToLanguage = map[string]string{
	".js":          "javascript",
	".mjs":         "javascript",
	".cjs":         "javascript",
	".jsx":         "javascriptreact",
	".ts":          "typescript",
	".mts":         "typescript",
	".cts":         "typescript",
	".tsx":         "typescriptreact",
	".py":          "python",
	".php":         "php",
	".go":          "go",
	".java":        "java",
	".cs":          "csharp",
	".rb":          "ruby",
	".rs":          "rust",
	".c":           "c",
	".h":           "c",
	".cpp":         "cpp",
	".cc":          "cpp",
	".cxx":         "cpp",
	".hpp":         "cpp",
	".kt":          "kotlin",
	".kts":         "kotlin",
	".swift":       "swift",
	".scala":       "scala",
	".sh":          "shellscript",
	".bash":        "shellscript",
	".zsh":         "shellscript",
	".ps1":         "powershell",
	".sql":         "sql",
	".yml":         "yaml",
	".yaml":        "yaml",
	".tf":          "terraform",
	"Dockerfile":   "dockerfile",
	".dockerfile":  "dockerfile",
	".html":        "html",
	".htm":         "html",
	".vue":         "vue",
	".svelte":      "svelte",
}

var (
	ignoreFileRegex = regexp.MustCompile(`(?i)(?://|#|/\*|<!--)\s*lory-ignore-file`)
	ignoreLineRegex = regexp.MustCompile(`(?i)(?://|#|/\*|<!--)\s*(?:lory-ignore|lory-ignore-next-line)`)
)

// DetectLanguage returns the Lory language identifier for a file path
func DetectLanguage(filePath string) string {
	base := filepath.Base(filePath)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return "dockerfile"
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extToLanguage[ext]; ok {
		return lang
	}
	return ""
}

// IsFileIgnored checks if the file has lory-ignore-file in its first 20 lines
func IsFileIgnored(content string) bool {
	lines := strings.Split(content, "\n")
	limit := 20
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 0; i < limit; i++ {
		if ignoreFileRegex.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// IsLineIgnored checks if finding on line is suppressed by lory-ignore comments
func IsLineIgnored(lines []string, lineNum int) bool {
	idx := lineNum - 1
	if idx < 0 || idx >= len(lines) {
		return false
	}

	// Check current line for inline ignore
	if ignoreLineRegex.MatchString(lines[idx]) {
		return true
	}

	// Check previous line for lory-ignore or lory-ignore-next-line
	if idx > 0 && ignoreLineRegex.MatchString(lines[idx-1]) {
		return true
	}

	return false
}
