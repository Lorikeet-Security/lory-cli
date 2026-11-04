package export_test

import (
	"encoding/json"
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

	if v, ok := driver["version"].(string); !ok || v != "1.1.1" {
		t.Errorf("expected driver version 1.1.1, got %v", driver["version"])
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
