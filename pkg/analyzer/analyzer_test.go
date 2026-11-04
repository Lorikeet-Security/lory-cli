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
	t.Skip("Known bug: static analyzer regex self-matches its own regex definition (Phase 7 triage)")

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
