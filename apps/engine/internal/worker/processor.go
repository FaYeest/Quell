package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/quell-dev/quell/apps/engine/internal/ast"
	"github.com/quell-dev/quell/apps/engine/internal/db"
	gh "github.com/quell-dev/quell/apps/engine/internal/github"
	"github.com/quell-dev/quell/apps/engine/internal/patcher"
	"github.com/quell-dev/quell/apps/engine/internal/scanner"
	"github.com/quell-dev/quell/apps/engine/internal/triage"
)

// Processor orchestrates the scan queue consumption and pipeline execution.
type Processor struct {
	dbClient    *db.Client
	ghClient    *gh.Client
	triageAgent *triage.Agent
	chunker     *ast.Chunker
}

// NewProcessor constructs a new worker Processor instance.
func NewProcessor(dbClient *db.Client, ghClient *gh.Client, triageAgent *triage.Agent) *Processor {
	return &Processor{
		dbClient:    dbClient,
		ghClient:    ghClient,
		triageAgent: triageAgent,
		chunker:     ast.NewChunker(),
	}
}

// HandleScanRepository processes an autonomous repository scan job.
func (p *Processor) HandleScanRepository(ctx context.Context, t *asynq.Task) error {
	var payload ScanPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal scan payload: %w", err)
	}

	log.Printf("📥 [Worker] Starting scan for repo: %s (Commit: %s)", payload.RepoFullName, payload.CommitSHA)

	// 1. Create scan entry in database
	var scanID uuid.UUID
	if p.dbClient != nil {
		scan, err := p.dbClient.CreateScan(ctx, payload.RepoID, payload.CommitSHA)
		if err != nil {
			log.Printf("❌ Failed to create scan record in DB: %v", err)
			return err
		}
		scanID = scan.ID
	}

	// 2. Clone repo ephemerally or use local path
	var scanDir string
	var cleanup func()

	if payload.LocalPath != "" {
		scanDir = payload.LocalPath
		cleanup = func() {} // No cleanup for local test folder
	} else {
		clonedDir, cleanFn, err := p.ghClient.CloneRepoEphemeral(ctx, payload.InstallationID, payload.RepoFullName, payload.CommitSHA)
		if err != nil {
			if p.dbClient != nil {
				_ = p.dbClient.CompleteScan(ctx, scanID, "failed", 0, 0)
			}
			return fmt.Errorf("ephemeral clone failed: %w", err)
		}
		scanDir = clonedDir
		cleanup = cleanFn
	}
	defer cleanup()

	// 3. Deterministic Static Scan (Semgrep)
	scanOpts := scanner.ScanOptions{
		TargetDir: scanDir,
	}

	startTime := time.Now()
	findings, err := scanner.RunScan(ctx, scanOpts)
	if err != nil {
		if p.dbClient != nil {
			_ = p.dbClient.CompleteScan(ctx, scanID, "failed", 0, 0)
		}
		return fmt.Errorf("semgrep scan failed: %w", err)
	}
	log.Printf("🔍 [Worker] Semgrep identified %d suspect findings in %v", len(findings), time.Since(startTime))

	vulnCount := 0

	// 4. Process each finding through AST Chunker & Contextual Triage
	for _, f := range findings {
		astCtx, err := p.chunker.ExtractContext(f.FilePath, f.StartLine, f.EndLine, scanDir)
		if err != nil {
			astCtx = &ast.ASTContext{
				TargetFile:        f.FilePath,
				EnclosingFunction: "unknown",
				FunctionSource:    f.Lines,
			}
		}

		triageRes, err := p.triageAgent.Triage(ctx, f, astCtx)
		if err != nil {
			log.Printf("⚠️ Triage failed for finding %s: %v", f.RuleID, err)
			continue
		}

		// Insert vulnerability into DB
		var savedVuln *db.Vulnerability
		if p.dbClient != nil {
			vulnRecord := &db.Vulnerability{
				ScanID:             scanID,
				CWEID:              f.CWE,
				Severity:           triageRes.Severity,
				FilePath:           f.FilePath,
				LineStart:          f.StartLine,
				LineEnd:            f.EndLine,
				IsFalsePositive:    !triageRes.IsExploitable,
				AIReasoning:        triageRes.TriageReason,
				AttackVector:       triageRes.AttackVector,
				RemediationSummary: triageRes.RemediationSummary,
			}

			var err error
			savedVuln, err = p.dbClient.CreateVulnerability(ctx, vulnRecord)
			if err != nil {
				log.Printf("⚠️ Failed to persist vulnerability record: %v", err)
				continue
			}
		}

		// If real exploitable vulnerability -> check quota & open PR
		if triageRes.IsExploitable {
			vulnCount++

			if p.dbClient != nil {
				hasQuota, err := p.dbClient.CheckAndIncrementPRQuota(ctx, payload.OrgID)
				if err != nil {
					log.Printf("⚠️ Error checking PR quota: %v", err)
					continue
				}

				if !hasQuota {
					log.Printf("⛔ Quota limit reached for organization %s. Auto-PR skipped.", payload.OrgID)
					continue
				}
			}

			// Generate patch diff
			patchOut, err := patcher.GenerateDiff(f.FilePath, astCtx.FullFileSource, triageRes.OriginalCodeBlock, triageRes.PatchedCodeBlock)
			if err != nil {
				log.Printf("⚠️ Failed to generate patch diff: %v", err)
				continue
			}

			// Parse owner/repo
			parts := strings.Split(payload.RepoFullName, "/")
			if len(parts) == 2 {
				owner := parts[0]
				repoName := parts[1]

				prInfo := gh.VulnerabilityPRInfo{
					CWEID:              f.CWE,
					Severity:           triageRes.Severity,
					VulnerabilityType:  triageRes.VulnerabilityType,
					FilePath:           f.FilePath,
					LineStart:          f.StartLine,
					LineEnd:            f.EndLine,
					AIReasoning:        triageRes.TriageReason,
					AttackVector:       triageRes.AttackVector,
					RemediationSummary: triageRes.RemediationSummary,
					UnifiedDiff:        patchOut.UnifiedDiff,
				}

				// Relative file path inside repo
				relPath := f.FilePath
				if filepath.IsAbs(relPath) {
					if rel, err := filepath.Rel(scanDir, relPath); err == nil {
						relPath = rel
					}
				}

				prNum, prURL, err := p.ghClient.CreateRemediationPR(
					ctx,
					payload.InstallationID,
					owner,
					repoName,
					payload.DefaultBranch,
					prInfo,
					relPath,
					patchOut.NewFileContent,
				)

				if err != nil {
					log.Printf("❌ Failed to create remediation PR: %v", err)
				} else {
					log.Printf("🚀 [Worker] Remediation PR created: #%d (%s)", prNum, prURL)

					// Persist remediation PR
					if p.dbClient != nil && savedVuln != nil {
						prRecord := &db.RemediationPR{
							VulnID:         savedVuln.ID,
							GithubPRNumber: prNum,
							GithubPRURL:    prURL,
							PatchDiff:      patchOut.UnifiedDiff,
							Status:         "opened",
						}
						_, _ = p.dbClient.CreateRemediationPR(ctx, prRecord)
					}
				}
			}
		}
	}

	// 5. Complete scan record
	if p.dbClient != nil {
		if err := p.dbClient.CompleteScan(ctx, scanID, "completed", len(findings), vulnCount); err != nil {
			log.Printf("⚠️ Failed to mark scan as completed: %v", err)
		}
	}

	log.Printf("✅ [Worker] Finished scan: %d suspects, %d exploitable vulns remediated.", len(findings), vulnCount)
	return nil
}

// RegisterServerHandlers registers the task worker handlers to an Asynq ServeMux.
func (p *Processor) RegisterServerHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeScanRepository, p.HandleScanRepository)
}
