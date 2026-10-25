package reviewer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".cache":       true,
	"out":          true,
	"coverage":     true,
	".venv":        true,
	"venv":         true,
}

type FileReviewResult struct {
	FilePath string
	Language string
	Lines    int
	Findings []types.LoryFinding
	Summary  string
	FromAPI  bool
}

// ReviewFile reviews a single source code file
func ReviewFile(ctx context.Context, filePath string, cfg types.ReviewConfig, loryCli *client.LoryClient, onFinding client.FindingCallback) (*FileReviewResult, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	content := string(contentBytes)
	lines := strings.Split(content, "\n")
	lineCount := len(lines)

	if cfg.MaxFileLines > 0 && lineCount > cfg.MaxFileLines {
		return nil, fmt.Errorf("file has %d lines (exceeds max %d)", lineCount, cfg.MaxFileLines)
	}

	lang := analyzer.DetectLanguage(filePath)
	if lang == "" {
		return nil, fmt.Errorf("unsupported language for %s", filePath)
	}

	if analyzer.IsFileIgnored(content) {
		return &FileReviewResult{
			FilePath: filePath,
			Language: lang,
			Lines:    lineCount,
			Findings: []types.LoryFinding{},
			Summary:  "Skipped (lory-ignore-file)",
		}, nil
	}

	// 1. Try remote Lory API
	var apiFindings []types.LoryFinding
	var summary string
	fromAPI := false

	if loryCli != nil && !cfg.DryRun {
		req := types.LoryReviewRequest{
			Code:      content,
			Language:  lang,
			Filename:  filepath.Base(filePath),
			StartLine: 1,
			Stream:    cfg.Stream,
		}

		resp, err := loryCli.ReviewCode(ctx, req, onFinding)
		if err == nil && resp != nil {
			fromAPI = true
			apiFindings = resp.Findings
			summary = resp.Summary
		}
	}

	// 2. If API is unreachable (e.g. offline or sandboxed), use local analysis engine
	if !fromAPI {
		localFindings := analyzer.AnalyzeCodeLocally(content, filePath)
		apiFindings = localFindings
		summary = fmt.Sprintf("Locally reviewed %s (%s)", filepath.Base(filePath), lang)
		if onFinding != nil {
			for _, f := range localFindings {
				onFinding(f)
			}
		}
	}

	// Filter findings according to ignore comments and thresholds
	filtered := make([]types.LoryFinding, 0)
	for _, f := range apiFindings {
		if analyzer.IsLineIgnored(lines, f.Line) {
			continue
		}
		f.FilePath = filePath
		filtered = append(filtered, f)
	}

	// Apply fixes if requested
	if cfg.ApplyFixes && len(filtered) > 0 {
		_ = ApplyFixesToFile(filePath, content, filtered)
	}

	return &FileReviewResult{
		FilePath: filePath,
		Language: lang,
		Lines:    lineCount,
		Findings: filtered,
		Summary:  summary,
		FromAPI:  fromAPI,
	}, nil
}

// ReviewPath reviews a file or recursively reviews all supported files in a directory
func ReviewPath(ctx context.Context, targetPath string, cfg types.ReviewConfig, loryCli *client.LoryClient, onFinding client.FindingCallback) ([]FileReviewResult, error) {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		res, err := ReviewFile(ctx, targetPath, cfg, loryCli, onFinding)
		if err != nil {
			return nil, err
		}
		return []FileReviewResult{*res}, nil
	}

	results := make([]FileReviewResult, 0)
	err = filepath.Walk(targetPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if info.IsDir() {
			if ignoredDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if analyzer.DetectLanguage(path) == "" {
			return nil
		}

		res, err := ReviewFile(ctx, path, cfg, loryCli, onFinding)
		if err == nil && res != nil {
			results = append(results, *res)
		}
		return nil
	})

	return results, err
}

// ApplyFixesToFile applies suggested code fixes to the file
func ApplyFixesToFile(filePath string, originalContent string, findings []types.LoryFinding) error {
	lines := strings.Split(originalContent, "\n")
	modified := false

	// Apply fixes from bottom to top so line indices remain stable
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		if f.Fix == "" {
			continue
		}
		startLine := f.Line - 1
		endLine := startLine
		if f.EndLine > f.Line {
			endLine = f.EndLine - 1
		}

		if startLine >= 0 && endLine < len(lines) {
			fixLines := strings.Split(f.Fix, "\n")
			newLines := append(lines[:startLine], append(fixLines, lines[endLine+1:]...)...)
			lines = newLines
			modified = true
		}
	}

	if modified {
		return os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
	}
	return nil
}
