-- Quell Security Engine Initial Schema
-- Multi-tenant schema with pgvector support

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan_tier VARCHAR(50) NOT NULL DEFAULT 'starter', -- starter, growth, scale
    pr_quota_limit INT NOT NULL DEFAULT 20,
    pr_quota_used INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Repositories
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_repo_id BIGINT NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL, -- e.g. "acme/backend-api"
    default_branch VARCHAR(100) NOT NULL DEFAULT 'main',
    installation_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_repositories_installation_id ON repositories(installation_id);
CREATE INDEX IF NOT EXISTS idx_repositories_full_name ON repositories(full_name);

-- 3. Scans
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha VARCHAR(64) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'queued', -- queued, running, completed, failed
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    suspect_count INT NOT NULL DEFAULT 0,
    vulnerability_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_repo_id ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

-- 4. Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cwe_id VARCHAR(100),
    severity VARCHAR(50) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path TEXT NOT NULL,
    line_start INT NOT NULL,
    line_end INT NOT NULL,
    is_false_positive BOOLEAN NOT NULL DEFAULT false,
    ai_reasoning TEXT,
    attack_vector TEXT,
    remediation_summary TEXT,
    embedding vector(1536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);

-- 5. Remediation PRs
CREATE TABLE IF NOT EXISTS remediation_prs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    github_pr_number INT NOT NULL,
    github_pr_url TEXT NOT NULL,
    patch_diff TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'opened', -- opened, merged, closed
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_prs_vuln_id ON remediation_prs(vuln_id);
