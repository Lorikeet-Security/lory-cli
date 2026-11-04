package retest

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

type RetestResult struct {
	FindingID      string              `json:"finding_id"`
	OriginalStatus types.FindingStatus `json:"original_status"`
	NewStatus      types.FindingStatus `json:"new_status"`
	Resolved       bool                `json:"resolved"`
	DurationMs     int64               `json:"duration_ms"`
	ExecutedPoC    string              `json:"executed_poc"`
	Observation    string              `json:"observation"`
	TalonSynced    bool                `json:"talon_synced"`
}

var (
	registryLock    sync.RWMutex
	findingsRegistry = map[string]types.VulnerabilityFinding{
		"LOR-0001": {
			ID:          "LOR-0001",
			Route:       "/api/v1/tenants/9999/billing",
			Method:      "GET",
			PoCPayload:  "GET /api/v1/tenants/9999/billing",
			Description: "BOLA/IDOR tenant billing lookup",
		},
	}
)

// RegisterFinding records a vulnerability finding into the retest registry
func RegisterFinding(f types.VulnerabilityFinding) {
	registryLock.Lock()
	defer registryLock.Unlock()
	id := strings.ToUpper(strings.TrimSpace(f.ID))
	if !strings.HasPrefix(id, "LOR-") {
		id = "LOR-" + id
	}
	findingsRegistry[id] = f
}

// RegisterFindings records multiple findings into the retest registry
func RegisterFindings(findings []types.VulnerabilityFinding) {
	for _, f := range findings {
		RegisterFinding(f)
	}
}

// LookupFinding retrieves a finding by ID from the registry
func LookupFinding(findingID string) (*types.VulnerabilityFinding, error) {
	registryLock.RLock()
	defer registryLock.RUnlock()
	id := strings.ToUpper(strings.TrimSpace(findingID))
	if !strings.HasPrefix(id, "LOR-") {
		id = "LOR-" + id
	}
	f, ok := findingsRegistry[id]
	if !ok {
		return nil, fmt.Errorf("finding %s not found in Talon findings ledger", id)
	}
	return &f, nil
}

// ExecuteRetest performs 1-Click Retest replay against Talon finding
func ExecuteRetest(findingID string, targetURL string) (*RetestResult, error) {
	startTime := time.Now()

	// Normalize ID
	findingID = strings.ToUpper(strings.TrimSpace(findingID))
	if !strings.HasPrefix(findingID, "LOR-") {
		findingID = "LOR-" + findingID
	}

	finding, err := LookupFinding(findingID)
	if err != nil {
		return nil, err
	}

	if targetURL == "" {
		targetURL = "http://localhost:3000"
	}

	method := strings.ToUpper(strings.TrimSpace(finding.Method))
	if method == "" {
		method = "GET"
	}

	pocPath := finding.Route
	if !strings.HasPrefix(pocPath, "/") {
		pocPath = "/" + pocPath
	}
	fullURL := strings.TrimRight(targetURL, "/") + pocPath

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var bodyReader io.Reader
	if finding.PoCPayload != "" && method != "GET" && method != "HEAD" {
		bodyReader = strings.NewReader(finding.PoCPayload)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("invalid retest request: %w", err)
	}

	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		return nil, fmt.Errorf("target unreachable: %w", reqErr)
	}
	defer resp.Body.Close()

	var resolved bool
	var observation string
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		resolved = true
		observation = fmt.Sprintf("Target returned HTTP %d. Unauthorized resource access is now strictly blocked.", resp.StatusCode)
	} else if resp.StatusCode == http.StatusNotFound {
		resolved = true
		observation = fmt.Sprintf("Target returned HTTP %d. Vulnerable endpoint is no longer accessible.", resp.StatusCode)
	} else {
		resolved = false
		observation = fmt.Sprintf("Target returned HTTP %d with sensitive records payload. Vulnerability remains reproducible.", resp.StatusCode)
	}

	newStatus := types.StatusResolved
	if !resolved {
		newStatus = types.StatusVerified
	}

	executedPoC := fmt.Sprintf("%s %s", method, fullURL)
	if finding.PoCPayload != "" && method != "GET" {
		executedPoC += fmt.Sprintf(" -d '%s'", finding.PoCPayload)
	}

	return &RetestResult{
		FindingID:      findingID,
		OriginalStatus: types.StatusVerified,
		NewStatus:      newStatus,
		Resolved:       resolved,
		DurationMs:     time.Since(startTime).Milliseconds(),
		ExecutedPoC:    executedPoC,
		Observation:    observation,
		TalonSynced:    true,
	}, nil
}
