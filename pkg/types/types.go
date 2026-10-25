package types

import "time"

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence levels
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// FindingStatus indicates vulnerability status
type FindingStatus string

const (
	StatusOpen      FindingStatus = "OPEN"
	StatusVerified  FindingStatus = "VERIFIED"
	StatusRetesting FindingStatus = "RETESTING"
	StatusResolved  FindingStatus = "RESOLVED"
	StatusIgnored   FindingStatus = "IGNORED"
)

// LoryFinding represents an authentic Lory AI finding
type LoryFinding struct {
	ID         string     `json:"id,omitempty"`
	Line       int        `json:"line"`
	EndLine    int        `json:"end_line,omitempty"`
	Severity   Severity   `json:"severity"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Confidence Confidence `json:"confidence"`
	CWE        string     `json:"cwe,omitempty"`
	Fix        string     `json:"fix,omitempty"`
	FixNote    string     `json:"fix_note,omitempty"`
	FilePath   string     `json:"file_path,omitempty"`
}

// EndpointRoute represents an AST-discovered HTTP route
type EndpointRoute struct {
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	FilePath     string   `json:"file_path"`
	LineNumber   int      `json:"line_number"`
	Handler      string   `json:"handler,omitempty"`
	AuthRequired bool     `json:"auth_required"`
	Middleware   []string `json:"middleware,omitempty"`
	Framework    string   `json:"framework"`
}

// VulnerabilityFinding represents a security finding
type VulnerabilityFinding struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Severity       Severity      `json:"severity"`
	Status         FindingStatus `json:"status"`
	CWE            string        `json:"cwe"`
	CVSS           float64       `json:"cvss"`
	Description    string        `json:"description"`
	Route          string        `json:"route"`
	Method         string        `json:"method"`
	SourceFile     string        `json:"source_file"`
	SourceLine     int           `json:"source_line"`
	PoCPayload     string        `json:"poc_payload"`
	PoCCommand     string        `json:"poc_command"`
	PoCResponse    string        `json:"poc_response"`
	Remediation    string        `json:"remediation"`
	VerifiedAt     time.Time     `json:"verified_at"`
	ComplianceTags []string      `json:"compliance_tags"`
}

// AuthCredentials holds session information
type AuthCredentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserEmail    string    `json:"user_email"`
	OrgName      string    `json:"org_name"`
	OrgID        string    `json:"org_id"`
	AuthMethod   string    `json:"auth_method"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// LoryReviewRequest is the payload sent to /ptaas/ajax/lory-code-review.php
type LoryReviewRequest struct {
	Code      string `json:"code"`
	Language  string `json:"language"`
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	Stream    bool   `json:"stream"`
}

// LoryReviewResponse is the response returned from the Lory review endpoint
type LoryReviewResponse struct {
	Success  bool                   `json:"success,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Findings []LoryFinding          `json:"findings"`
	Summary  string                 `json:"summary,omitempty"`
	Meta     map[string]interface{} `json:"meta,omitempty"`
}

// WebScanCheck represents an individual check from scan-api.php
type WebScanCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "warn", "fail", "info"
	Detail string `json:"detail"`
}

// WebScanCategory represents a category of checks from scan-api.php
type WebScanCategory struct {
	Name   string         `json:"name"`
	Icon   string         `json:"icon"`
	Checks []WebScanCheck `json:"checks"`
}

// WebScanResult represents the result from scan-api.php
type WebScanResult struct {
	Score          int               `json:"score"`
	Target         string            `json:"target"`
	ScannedAt      string            `json:"scanned_at"`
	ScansRemaining int               `json:"scans_remaining"`
	Categories     []WebScanCategory `json:"categories"`
}

// ScanConfig holds parameters for a security scan
type ScanConfig struct {
	RepoPath   string `json:"repo_path"`
	TargetURL  string `json:"target_url"`
	Format     string `json:"format"`
	DryRun     bool   `json:"dry_run"`
	UseDocker  bool   `json:"use_docker"`
	WorkerTag  string `json:"worker_tag"`
	Verbose    bool   `json:"verbose"`
}

// ReviewConfig controls review behavior
type ReviewConfig struct {
	BaseURL       string
	Token         string
	MinSeverity   Severity
	MinConfidence Confidence
	Stream        bool
	ApplyFixes    bool
	MaxFileLines  int
	ExcludeGlobs  []string
	Timeout       time.Duration
	DryRun        bool
	Verbose       bool
	Format        string
}
