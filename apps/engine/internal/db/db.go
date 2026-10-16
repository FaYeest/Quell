package db

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Client wraps pgxpool.Pool and exposes persistence operations.
type Client struct {
	Pool *pgxpool.Pool
}

// NewClient establishes a connection pool to PostgreSQL.
func NewClient(ctx context.Context, databaseURL string) (*Client, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid database URL: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &Client{Pool: pool}, nil
}

// Close closes the database connection pool.
func (c *Client) Close() {
	if c.Pool != nil {
		c.Pool.Close()
	}
}

// RunMigrations executes initial database migrations.
func (c *Client) RunMigrations(ctx context.Context) error {
	_, err := c.Pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	return nil
}

// GetOrCreateOrganization finds an organization by name or creates it if not found.
func (c *Client) GetOrCreateOrganization(ctx context.Context, name, planTier string) (*Organization, error) {
	if planTier == "" {
		planTier = "starter"
	}

	var org Organization
	query := `
		INSERT INTO organizations (name, plan_tier, pr_quota_limit, pr_quota_used)
		VALUES ($1, $2, 20, 0)
		ON CONFLICT DO NOTHING
		RETURNING id, name, plan_tier, pr_quota_limit, pr_quota_used, created_at, updated_at;
	`
	err := c.Pool.QueryRow(ctx, query, name, planTier).Scan(
		&org.ID, &org.Name, &org.PlanTier, &org.PRQuotaLimit, &org.PRQuotaUsed, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == nil {
		return &org, nil
	}

	// Fallback to select if already existed
	selectQuery := `
		SELECT id, name, plan_tier, pr_quota_limit, pr_quota_used, created_at, updated_at
		FROM organizations
		WHERE name = $1
		ORDER BY created_at ASC LIMIT 1;
	`
	err = c.Pool.QueryRow(ctx, selectQuery, name).Scan(
		&org.ID, &org.Name, &org.PlanTier, &org.PRQuotaLimit, &org.PRQuotaUsed, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create organization %s: %w", name, err)
	}
	return &org, nil
}

// CheckAndIncrementPRQuota atomically checks if an org has quota left and increments pr_quota_used.
// Returns (true, nil) if quota was available and successfully consumed.
func (c *Client) CheckAndIncrementPRQuota(ctx context.Context, orgID uuid.UUID) (bool, error) {
	query := `
		UPDATE organizations
		SET pr_quota_used = pr_quota_used + 1, updated_at = NOW()
		WHERE id = $1 AND pr_quota_used < pr_quota_limit
		RETURNING pr_quota_used, pr_quota_limit;
	`
	var used, limit int
	err := c.Pool.QueryRow(ctx, query, orgID).Scan(&used, &limit)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil // Quota reached limit
		}
		return false, fmt.Errorf("failed to check/increment PR quota: %w", err)
	}
	return true, nil
}

// UpsertRepository creates or updates a tracked repository record.
func (c *Client) UpsertRepository(ctx context.Context, orgID uuid.UUID, githubRepoID int64, fullName, defaultBranch string, installationID int64) (*Repository, error) {
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	query := `
		INSERT INTO repositories (org_id, github_repo_id, full_name, default_branch, installation_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (github_repo_id) DO UPDATE
		SET full_name = EXCLUDED.full_name,
		    default_branch = EXCLUDED.default_branch,
		    installation_id = EXCLUDED.installation_id,
		    updated_at = NOW()
		RETURNING id, org_id, github_repo_id, full_name, default_branch, installation_id, created_at, updated_at;
	`
	var repo Repository
	err := c.Pool.QueryRow(ctx, query, orgID, githubRepoID, fullName, defaultBranch, installationID).Scan(
		&repo.ID, &repo.OrgID, &repo.GithubRepoID, &repo.FullName, &repo.DefaultBranch, &repo.InstallationID, &repo.CreatedAt, &repo.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert repository: %w", err)
	}
	return &repo, nil
}

// GetRepositoryByFullName retrieves a repository by full name (owner/repo).
func (c *Client) GetRepositoryByFullName(ctx context.Context, fullName string) (*Repository, error) {
	query := `
		SELECT id, org_id, github_repo_id, full_name, default_branch, installation_id, created_at, updated_at
		FROM repositories
		WHERE full_name = $1
		LIMIT 1;
	`
	var repo Repository
	err := c.Pool.QueryRow(ctx, query, fullName).Scan(
		&repo.ID, &repo.OrgID, &repo.GithubRepoID, &repo.FullName, &repo.DefaultBranch, &repo.InstallationID, &repo.CreatedAt, &repo.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

// CreateScan initializes a new scan record in queued state.
func (c *Client) CreateScan(ctx context.Context, repoID uuid.UUID, commitSHA string) (*Scan, error) {
	query := `
		INSERT INTO scans (repo_id, commit_sha, status, started_at)
		VALUES ($1, $2, 'running', NOW())
		RETURNING id, repo_id, commit_sha, status, started_at, completed_at, suspect_count, vulnerability_count, created_at;
	`
	var scan Scan
	err := c.Pool.QueryRow(ctx, query, repoID, commitSHA).Scan(
		&scan.ID, &scan.RepoID, &scan.CommitSHA, &scan.Status, &scan.StartedAt, &scan.CompletedAt, &scan.SuspectCount, &scan.VulnerabilityCount, &scan.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	return &scan, nil
}

// CompleteScan finalizes a scan record with results count and status.
func (c *Client) CompleteScan(ctx context.Context, scanID uuid.UUID, status string, suspectCount, vulnCount int) error {
	query := `
		UPDATE scans
		SET status = $2, suspect_count = $3, vulnerability_count = $4, completed_at = NOW()
		WHERE id = $1;
	`
	_, err := c.Pool.Exec(ctx, query, scanID, status, suspectCount, vulnCount)
	if err != nil {
		return fmt.Errorf("failed to complete scan: %w", err)
	}
	return nil
}

// CreateVulnerability inserts a detected vulnerability record.
func (c *Client) CreateVulnerability(ctx context.Context, v *Vulnerability) (*Vulnerability, error) {
	query := `
		INSERT INTO vulnerabilities (
			scan_id, cwe_id, severity, file_path, line_start, line_end,
			is_false_positive, ai_reasoning, attack_vector, remediation_summary
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at;
	`
	err := c.Pool.QueryRow(ctx, query,
		v.ScanID, v.CWEID, v.Severity, v.FilePath, v.LineStart, v.LineEnd,
		v.IsFalsePositive, v.AIReasoning, v.AttackVector, v.RemediationSummary,
	).Scan(&v.ID, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert vulnerability: %w", err)
	}
	return v, nil
}

// CreateRemediationPR inserts a record of an auto-remediation PR.
func (c *Client) CreateRemediationPR(ctx context.Context, pr *RemediationPR) (*RemediationPR, error) {
	query := `
		INSERT INTO remediation_prs (vuln_id, github_pr_number, github_pr_url, patch_diff, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at;
	`
	err := c.Pool.QueryRow(ctx, query,
		pr.VulnID, pr.GithubPRNumber, pr.GithubPRURL, pr.PatchDiff, pr.Status,
	).Scan(&pr.ID, &pr.CreatedAt, &pr.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert remediation PR: %w", err)
	}
	return pr, nil
}

// ListRecentScans retrieves recent scans for dashboard display.
func (c *Client) ListRecentScans(ctx context.Context, limit, offset int) ([]ScanWithRepo, error) {
	if limit <= 0 {
		limit = 20
	}

	query := `
		SELECT s.id, s.repo_id, s.commit_sha, s.status, s.started_at, s.completed_at,
		       s.suspect_count, s.vulnerability_count, s.created_at, r.full_name
		FROM scans s
		JOIN repositories r ON s.repo_id = r.id
		ORDER BY s.created_at DESC
		LIMIT $1 OFFSET $2;
	`
	rows, err := c.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list scans: %w", err)
	}
	defer rows.Close()

	var results []ScanWithRepo
	for rows.Next() {
		var item ScanWithRepo
		if err := rows.Scan(
			&item.ID, &item.RepoID, &item.CommitSHA, &item.Status, &item.StartedAt, &item.CompletedAt,
			&item.SuspectCount, &item.VulnerabilityCount, &item.CreatedAt, &item.RepoFullName,
		); err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	return results, nil
}

// GetStats compiles aggregate metrics for the dashboard summary.
func (c *Client) GetStats(ctx context.Context) (*SystemStats, error) {
	var stats SystemStats

	query := `
		SELECT 
			(SELECT COUNT(*) FROM organizations) AS total_orgs,
			(SELECT COUNT(*) FROM repositories) AS total_repos,
			(SELECT COUNT(*) FROM scans) AS total_scans,
			(SELECT COUNT(*) FROM vulnerabilities WHERE is_false_positive = false) AS total_vulns,
			(SELECT COUNT(*) FROM remediation_prs) AS total_prs,
			(SELECT COALESCE(
				ROUND(
					(COUNT(*) FILTER (WHERE is_false_positive = true)::numeric / NULLIF(COUNT(*), 0)::numeric) * 100, 
					2
				), 0)
			 FROM vulnerabilities) AS fp_rate;
	`
	err := c.Pool.QueryRow(ctx, query).Scan(
		&stats.TotalOrganizations,
		&stats.TotalRepositories,
		&stats.TotalScans,
		&stats.TotalVulnsFound,
		&stats.TotalPRsOpened,
		&stats.FalsePositivesRate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query stats: %w", err)
	}
	return &stats, nil
}
