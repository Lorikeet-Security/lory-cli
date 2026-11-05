package analyzer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/analyzer"
)

func TestAnalyzeRepository(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lorikeet-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create dummy express file with a route and SQLi sink
	sampleCode := `
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    const q = "SELECT * FROM users WHERE id = " + req.query.id;
    res.send(q);
});

app.post('/api/admin/login', (req, res) => {
    res.json({ status: 'ok' });
});
`
	if err := os.WriteFile(filepath.Join(tempDir, "server.js"), []byte(sampleCode), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzer.AnalyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("AnalyzeRepository failed: %v", err)
	}

	if len(result.Routes) != 2 {
		t.Errorf("expected 2 routes, found %d", len(result.Routes))
	}

	if len(result.WhiteBoxPoCs) != 1 {
		t.Errorf("expected 1 SQLi sink, found %d", len(result.WhiteBoxPoCs))
	}

	if result.WhiteBoxPoCs[0].CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", result.WhiteBoxPoCs[0].CWE)
	}
}

func TestAnalyze_DoesNotSelfMatchRegex(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lorikeet-selfmatch-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// File defining a regex pattern containing SQL keywords
	sampleCode := `package sample
import "regexp"
var myRegex = regexp.MustCompile("(?i)(?:SELECT|INSERT|UPDATE|DELETE).*\\+.*(?:req\\.query|req\\.body|params|request\\.)")
`
	if err := os.WriteFile(filepath.Join(tempDir, "regex.go"), []byte(sampleCode), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzer.AnalyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("AnalyzeRepository failed: %v", err)
	}

	if len(result.WhiteBoxPoCs) > 0 {
		t.Errorf("expected 0 findings for regex definition, found %d", len(result.WhiteBoxPoCs))
	}
}

func TestAnalyze_ModernExtensions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lorikeet-mjs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mjsCode := `app.get('/api/esm', (req, res) => res.json({ ok: true }));`
	if err := os.WriteFile(filepath.Join(tempDir, "server.mjs"), []byte(mjsCode), 0644); err != nil {
		t.Fatal(err)
	}

	mtsCode := `app.post('/api/ts', (req, res) => res.json({ ok: true }));`
	if err := os.WriteFile(filepath.Join(tempDir, "service.mts"), []byte(mtsCode), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzer.AnalyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("AnalyzeRepository failed: %v", err)
	}

	if result.TotalFiles != 2 {
		t.Errorf("expected 2 files analyzed for .mjs and .mts, got %d", result.TotalFiles)
	}
	if len(result.Routes) != 2 {
		t.Errorf("expected 2 routes discovered, got %d", len(result.Routes))
	}
}

func TestAnalyze_LoryIgnoreDirectivesAndFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lorikeet-ignore-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// File with lory:ignore
	ignoredLineCode := `// lory:ignore CWE-89
const sql = "SELECT * FROM users WHERE name = " + req.query.name;`
	if err := os.WriteFile(filepath.Join(tempDir, "ignored_line.js"), []byte(ignoredLineCode), 0644); err != nil {
		t.Fatal(err)
	}

	// File with lory-ignore-file
	ignoredFileCode := `// lory-ignore-file
const sql = "SELECT * FROM secrets WHERE id = " + req.body.id;`
	if err := os.WriteFile(filepath.Join(tempDir, "ignored_file.js"), []byte(ignoredFileCode), 0644); err != nil {
		t.Fatal(err)
	}

	// File covered by .loryignore
	os.MkdirAll(filepath.Join(tempDir, "vendor"), 0755)
	vendorCode := `const sql = "SELECT * FROM vendor WHERE id = " + req.query.id;`
	if err := os.WriteFile(filepath.Join(tempDir, "vendor", "lib.js"), []byte(vendorCode), 0644); err != nil {
		t.Fatal(err)
	}

	// File covered by wildcard in .loryignore
	minCode := `const sql = "SELECT * FROM minified WHERE id = " + req.query.id;`
	if err := os.WriteFile(filepath.Join(tempDir, "bundle.min.js"), []byte(minCode), 0644); err != nil {
		t.Fatal(err)
	}

	// Create .loryignore with directory and wildcard patterns
	if err := os.WriteFile(filepath.Join(tempDir, ".loryignore"), []byte("vendor/\n*.min.js\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzer.AnalyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("AnalyzeRepository failed: %v", err)
	}

	if len(result.WhiteBoxPoCs) != 0 {
		t.Errorf("expected 0 findings due to suppressions and .loryignore, got %d", len(result.WhiteBoxPoCs))
	}
}
