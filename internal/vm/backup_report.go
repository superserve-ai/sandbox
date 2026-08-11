package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// BackupReporter delivers verified-generation reports to the control
// plane, closing the loop between the uploader's durable outbox and the
// backup_generation coverage table. Deliver is the uploader's OnVerified
// callback: a non-nil return keeps the signal outboxed, so this only
// returns nil once the control plane accepted the report (any 2xx).
// Redelivery after a crash means duplicates; the endpoint is idempotent
// on (owner, bucket, generation).
type BackupReporter struct {
	// ControlPlaneURL is the base URL of the control plane API; reports
	// POST to {ControlPlaneURL}/internal/hosts/{HostID}/backups with the
	// same bearer token as the heartbeat.
	ControlPlaneURL string
	HostID          string
	Token           string
	// Bucket names the store the generation was verified in: coverage is
	// per bucket, and the control plane records which cell bucket holds
	// the bytes.
	Bucket string
	Client *http.Client
	Log    zerolog.Logger
}

// backupReportFile mirrors the control plane's manifest entry shape.
// Host paths deliberately do not travel: they name staging locations
// that stop existing once the upload acks.
type backupReportFile struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	BaseSHA256 string `json:"base_sha256,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

type backupReportBody struct {
	SandboxID   string             `json:"sandbox_id,omitempty"`
	TemplateID  string             `json:"template_id,omitempty"`
	BuildID     string             `json:"build_id,omitempty"`
	Generation  string             `json:"generation"`
	Bucket      string             `json:"bucket"`
	CompletedAt time.Time          `json:"completed_at"`
	Files       []backupReportFile `json:"files"`
}

// Deliver reports one verified generation. CompletedAt is stamped at
// delivery time: the outbox entry does not carry the verification
// instant, so a crash-redelivered report skews later by the outage,
// which coverage queries tolerate (a backup can only be reported after
// it completed).
func (r *BackupReporter) Deliver(task backup.Task) error {
	body := backupReportBody{
		SandboxID:   task.SandboxID,
		TemplateID:  task.TemplateID,
		BuildID:     task.BuildID,
		Generation:  task.Generation,
		Bucket:      r.Bucket,
		CompletedAt: time.Now().UTC(),
		Files:       make([]backupReportFile, 0, len(task.Files)),
	}
	for _, f := range task.Files {
		body.Files = append(body.Files, backupReportFile{
			Name:       f.Name,
			SizeBytes:  f.Size,
			SHA256:     f.SHA256,
			BaseSHA256: f.BaseSHA256,
			Shared:     f.Shared,
		})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal backup report: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/internal/hosts/%s/backups", r.ControlPlaneURL, r.HostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build backup report request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver backup report: %w", err)
	}
	defer resp.Body.Close()
	// Any 2xx clears the outbox entry, including accepted-but-orphaned
	// reports: only the control plane knows whether an owner row exists,
	// and redelivering an unacceptable report forever helps nobody.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("backup report rejected: %s: %s", resp.Status, string(msg))
	}
	return nil
}
