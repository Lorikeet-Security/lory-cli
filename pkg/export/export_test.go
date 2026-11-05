package export_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/export"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

func TestSARIF_NoDuplicateRuleIDs(t *testing.T) {
	findings := []types.VulnerabilityFinding{
		{
			ID:          "LOR-0001",
			Title:       "SQL Injection (Concatenated query)",
			Severity:    types.SeverityCritical,
			CWE:         "CWE-89",
			SourceFile:  "app.js",
			SourceLine:  10,
			Description: "Test finding 1",
		},
		{
			ID:          "LOR-0001",
			Title:       "SQL Injection (Concatenated query)",
			Severity:    types.SeverityCritical,
			CWE:         "CWE-89",
			SourceFile:  "db.js",
			SourceLine:  25,
			Description: "Test finding 2",
		},
	}

	data, err := export.GenerateSARIF(findings)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(data), &sarif); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})

	if v, ok := driver["version"].(string); !ok || v != "1.2.0" {
		t.Errorf("expected driver version 1.2.0, got %v", driver["version"])
	}

	seen := make(map[string]bool)
	for _, r := range rules {
		ruleObj := r.(map[string]interface{})
		id := ruleObj["id"].(string)
		if seen[id] {
			t.Errorf("SARIF contains duplicate rule ID: %s", id)
		}
		seen[id] = true
	}
	if len(rules) != 1 {
		t.Errorf("expected exactly 1 deduplicated rule, got %d", len(rules))
	}
}

func TestGeneratePDFEvidence_ValidPDF(t *testing.T) {
	findings := []types.VulnerabilityFinding{
		{
			ID:             "LOR-0001",
			Title:          "SQL Injection in login handler",
			Severity:       types.SeverityCritical,
			CVSS:           9.8,
			Status:         "OPEN",
			CWE:            "CWE-89",
			Method:         "POST",
			Route:          "/api/v1/auth/login",
			SourceFile:     "server/auth.js",
			SourceLine:     42,
			PoCCommand:     "curl -X POST https://example.com/api/v1/auth/login -d \"user=' OR 1=1--\"",
			Remediation:    "Use parameterized queries via pg-promise.",
			ComplianceTags: []string{"SOC2:CC6.1", "ISO27001:A.12.6"},
		},
	}
	orgName := "Acme Security Corp"

	pdfBytes := export.GeneratePDFEvidence(findings, orgName)

	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) {
		t.Errorf("expected PDF to start with %%PDF-1.4 header")
	}

	if !bytes.Contains(pdfBytes, []byte("stream\n")) {
		t.Errorf("expected PDF to contain stream data")
	}

	if !bytes.HasSuffix(pdfBytes, []byte("%%EOF\n")) {
		t.Errorf("expected PDF to end with %%%%EOF\\n")
	}

	// Write to temporary file for external tool validation
	tmpFile, err := os.CreateTemp("", "evidence-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(pdfBytes); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	if pdfinfoPath, err := exec.LookPath("pdfinfo"); err == nil {
		cmd := exec.Command(pdfinfoPath, tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pdfinfo validation failed: %v\nOutput: %s", err, string(out))
		}
	}

	if pdftotextPath, err := exec.LookPath("pdftotext"); err == nil {
		cmd := exec.Command(pdftotextPath, tmpFile.Name(), "-")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pdftotext extraction failed: %v\nOutput: %s", err, string(out))
		}
		extracted := string(out)
		if !strings.Contains(extracted, orgName) {
			t.Errorf("expected pdftotext output to contain %q", orgName)
		}
		if !strings.Contains(extracted, "LOR-0001") {
			t.Errorf("expected pdftotext output to contain 'LOR-0001'")
		}
	}
}

func TestGeneratePDF_EmptyAndMultiPage(t *testing.T) {
	// Empty text test
	emptyPDF := export.GeneratePDF("")
	if !bytes.HasPrefix(emptyPDF, []byte("%PDF-1.4")) || !bytes.HasSuffix(emptyPDF, []byte("%%EOF\n")) {
		t.Errorf("GeneratePDF(\"\") produced invalid PDF header/trailer")
	}

	// Multi-page text test (> 45 lines)
	var sb strings.Builder
	for i := 1; i <= 100; i++ {
		sb.WriteString(fmt.Sprintf("Compliance finding item line %d with additional text to test pagination\n", i))
	}
	multiPDF := export.GeneratePDF(sb.String())
	if !bytes.HasPrefix(multiPDF, []byte("%PDF-1.4")) || !bytes.HasSuffix(multiPDF, []byte("%%EOF\n")) {
		t.Errorf("GeneratePDF multi-page produced invalid PDF header/trailer")
	}

	tmpFile, err := os.CreateTemp("", "multipage-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = os.WriteFile(tmpFile.Name(), multiPDF, 0644)

	if pdfinfoPath, err := exec.LookPath("pdfinfo"); err == nil {
		cmd := exec.Command(pdfinfoPath, tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pdfinfo validation failed for multi-page PDF: %v\nOutput: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Pages:           3") {
			t.Errorf("expected 3 pages, output was: %s", string(out))
		}
	}
}
