package worker

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

const (
	TypeScanRepository = "scan:repository"
)

// ScanPayload carries the metadata needed to run an autonomous scan.
type ScanPayload struct {
	OrgID          uuid.UUID `json:"org_id"`
	RepoID         uuid.UUID `json:"repo_id"`
	InstallationID int64     `json:"installation_id"`
	RepoFullName   string    `json:"repo_full_name"` // e.g. "acme/backend"
	CommitSHA      string    `json:"commit_sha"`
	DefaultBranch  string    `json:"default_branch"`
	IsManual       bool      `json:"is_manual"`
	LocalPath      string    `json:"local_path,omitempty"` // For local dev/testing
}

// NewScanTask creates an Asynq task for scanning a repository.
func NewScanTask(payload ScanPayload) (*asynq.Task, error) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeScanRepository, bytes, asynq.MaxRetry(3)), nil
}
