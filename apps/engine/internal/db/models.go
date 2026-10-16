package db

import (
	"time"

	"github.com/google/uuid"
)

// Organization represents a multi-tenant workspace account.
type Organization struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	PlanTier     string    `json:"plan_tier"`
	PRQuotaLimit int       `json:"pr_quota_limit"`
	PRQuotaUsed  int       `json:"pr_quota_used"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Repository represents a GitHub repository monitored by Quell.
type Repository struct {
	ID             uuid.UUID `json:"id"`
	OrgID          uuid.UUID `json:"org_id"`
	GithubRepoID   int64     `json:"github_repo_id"`
	FullName       string    `json:"full_name"`
	DefaultBranch  string    `json:"default_branch"`
	InstallationID int64     `json:"installation_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Scan records an automated static scan run on a commit.
type Scan struct {
	ID                 uuid.UUID  `json:"id"`
	RepoID             uuid.UUID  `json:"repo_id"`
	CommitSHA          string     `json:"commit_sha"`
	Status             string     `json:"status"` // queued, running, completed, failed
	StartedAt          *time.Time `json:"started_at,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	SuspectCount       int        `json:"suspect_count"`
	VulnerabilityCount int        `json:"vulnerability_count"`
	CreatedAt          time.Time  `json:"created_at"`
}

// ScanWithRepo enriches a Scan with its parent Repository info for dashboard feeds.
type ScanWithRepo struct {
	Scan
	RepoFullName string `json:"repo_full_name"`
}

// Vulnerability stores security triage findings.
type Vulnerability struct {
	ID                 uuid.UUID `json:"id"`
	ScanID             uuid.UUID `json:"scan_id"`
	CWEID              string    `json:"cwe_id"`
	Severity           string    `json:"severity"`
	FilePath           string    `json:"file_path"`
	LineStart          int       `json:"line_start"`
	LineEnd            int       `json:"line_end"`
	IsFalsePositive    bool      `json:"is_false_positive"`
	AIReasoning        string    `json:"ai_reasoning"`
	AttackVector       string    `json:"attack_vector"`
	RemediationSummary string    `json:"remediation_summary"`
	CreatedAt          time.Time `json:"created_at"`
}

// RemediationPR tracks automated pull requests opened by quell-bot.
type RemediationPR struct {
	ID             uuid.UUID `json:"id"`
	VulnID         uuid.UUID `json:"vuln_id"`
	GithubPRNumber int       `json:"github_pr_number"`
	GithubPRURL    string    `json:"github_pr_url"`
	PatchDiff      string    `json:"patch_diff"`
	Status         string    `json:"status"` // opened, merged, closed
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SystemStats summarizes system metrics for dashboard reporting.
type SystemStats struct {
	TotalOrganizations int   `json:"total_organizations"`
	TotalRepositories  int   `json:"total_repositories"`
	TotalScans         int   `json:"total_scans"`
	TotalVulnsFound    int   `json:"total_vulns_found"`
	TotalPRsOpened     int   `json:"total_prs_opened"`
	FalsePositivesRate float64 `json:"false_positives_rate"`
}
