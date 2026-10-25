package types

import "time"

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingStatus indicates vulnerability status
type FindingStatus string

const (
	StatusOpen       FindingStatus = "OPEN"
	StatusVerified   FindingStatus = "VERIFIED"
	StatusRetesting  FindingStatus = "RETESTING"
	StatusResolved   FindingStatus = "RESOLVED"
	StatusReviewReq  FindingStatus = "REVIEW_REQUESTED"
)

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

// VulnerabilityFinding represents a security finding with dual-validation details
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
	ComplianceTags []string      `json:"compliance_tags"` // e.g. ["SOC2-CC6.1", "ISO27001-A.12.6"]
}

// AuthCredentials holds cached Talon session information
type AuthCredentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserEmail    string    `json:"user_email"`
	OrgName      string    `json:"org_name"`
	OrgID        string    `json:"org_id"`
	AuthMethod   string    `json:"auth_method"` // "sso" or "api_key"
	ExpiresAt    time.Time `json:"expires_at"`
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
