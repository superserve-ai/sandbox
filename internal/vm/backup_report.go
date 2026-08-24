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
// that stop existing once the upload acks. Object is the exact bucket
// object path the upload wrote (fingerprint-suffixed, full bases/ path
// for shared entries), empty on entries outboxed before the field
// existed; the control plane stores it so a future GC can name a
// generation's objects without listing the bucket.
type backupReportFile struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	BaseSHA256 string `json:"base_sha256,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	Object     string `json:"object,omitempty"`
}

type backupReportBody struct {
	SandboxID   string    `json:"sandbox_id,omitempty"`
	TemplateID  string    `json:"template_id,omitempty"`
	BuildID     string    `json:"build_id,omitempty"`
	Generation  string    `json:"generation"`
	Bucket      string    `json:"bucket"`
	CompletedAt time.Time `json:"completed_at"`
	// PauseToken names the exact pause this generation captured, echoed
	// from the pause RPC through the journal; empty for pre-token entries
	// and backfill mints, which fall back to content matching.
	PauseToken string             `json:"pause_token,omitempty"`
	Files      []backupReportFile `json:"files"`
}

// Deliver reports one verified generation. CompletedAt is the ack-time
// verification instant pinned on the outbox entry; only entries written
// before that field existed fall back to delivery time, whose skew
// coverage queries tolerate in one direction (a backup can only be
// reported after it completed).
func (r *BackupReporter) Deliver(task backup.Task) error {
	// Finalized manifests travel verbatim; only legacy outbox entries
	// (pre-finalization) re-synthesize shared entries, accepting the
	// zero-size fallback when staging cleanup won the race.
	files := task.Files
	if !task.FilesFinal {
		files = task.ReportedFiles()
	}
	// The outbox pinned the bucket the upload verified against; trust it
	// over the current configuration, which can differ after a restart
	// that repointed BACKUP_BUCKET while notifications were outboxed.
	// Empty means a pre-pinning outbox entry: the current bucket is the
	// only available answer, as before.
	bucket := task.VerifiedBucket
	if bucket == "" {
		bucket = r.Bucket
	}
	completedAt := task.VerifiedAt
	if completedAt.IsZero() {
		completedAt = time.Now()
	}
	body := backupReportBody{
		SandboxID:   task.SandboxID,
		TemplateID:  task.TemplateID,
		BuildID:     task.BuildID,
		Generation:  task.Generation,
		Bucket:      bucket,
		CompletedAt: completedAt.UTC(),
		PauseToken:  task.PauseToken,
		Files:       make([]backupReportFile, 0, len(files)),
	}
	for _, f := range files {
		body.Files = append(body.Files, backupReportFile{
			Name:       f.Name,
			SizeBytes:  f.Size,
			SHA256:     f.SHA256,
			BaseSHA256: f.BaseSHA256,
			Shared:     f.Shared,
			Object:     f.Object,
		})
	}
	status, statusLine, msg, err := r.post(body)
	if err != nil {
		return err
	}
	// Any 2xx clears the outbox entry, including accepted-but-orphaned
	// reports: only the control plane knows whether an owner row exists,
	// and redelivering an unacceptable report forever helps nobody.
	if status >= 200 && status < 300 {
		return nil
	}
	// A control plane from before a field binds report bodies strictly
	// and 400s the unknown field, which the permanent-rejection drop
	// below would turn into a lost coverage row on every report this
	// host sends during the rollout (or rollback) window. Degrade to the
	// pre-field payload: the report then lands exactly as an old vmd's
	// would, and the acceptance clears the outbox entry. Degraded
	// generations keep their coverage row but lose the stripped field's
	// value permanently — pathless rows keep their bucket manifests as
	// the path authority (the control plane's enrichment arm upgrades
	// the row if a rich report is ever redelivered), and a stripped
	// pause token leaves the generation unlinked until the next pause
	// re-verifies coverage token-bound (the count reads unbacked
	// meanwhile: over-reported risk, never a false zero). Deliberately
	// NOT retained for a rich redelivery: holding the entry would
	// re-deliver it every flush against the old control plane and
	// head-of-line block every signal behind it.
	// Gated on the binder's own unknown-field message so a rejection a
	// NEW control plane issues (a value failing validation) is never
	// stripped past the check it failed. Bounded loop: the decoder stops
	// at the FIRST unknown field, so a control plane predating both
	// fields rejects them one at a time.
	for range [2]struct{}{} {
		if !permanentReject(status) {
			break
		}
		var downgraded string
		switch {
		case isUnknownPauseTokenField(msg) && body.PauseToken != "":
			body.PauseToken = ""
			downgraded = "pause token"
		case isUnknownObjectField(msg) && stripObjectPaths(&body):
			downgraded = "object paths"
		}
		if downgraded == "" {
			break
		}
		r.Log.Warn().Str("generation", task.Generation).
			Str("status", statusLine).Str("response", string(msg)).
			Msgf("backup report rejected; retrying without %s for an older control plane", downgraded)
		status, statusLine, msg, err = r.post(body)
		if err != nil {
			return err
		}
		if status >= 200 && status < 300 {
			return nil
		}
	}
	// A permanent rejection can never succeed on retry, and the flush
	// stops at the first failure, so returning an error here would wedge
	// every later report on this host behind one poisoned entry forever.
	// Drop it loudly instead: the generation stays durable in the bucket,
	// only its coverage row is lost.
	if permanentReject(status) {
		r.Log.Error().Str("generation", task.Generation).
			Str("sandbox_id", task.SandboxID).Str("template_id", task.TemplateID).
			Str("status", statusLine).Str("response", string(msg)).
			Msg("backup report permanently rejected; dropping its coverage row")
		return nil
	}
	return fmt.Errorf("backup report rejected: %s: %s", statusLine, msg)
}

// permanentReject reports whether a status can never succeed on
// redelivery. Auth and pressure statuses stay retryable, since a rotated
// token or a throttled control plane would otherwise silently drain the
// whole outbox; 404 means the control plane has not deployed the route
// yet (vmd can roll out first), so the report becomes deliverable when
// the rollout completes and must survive in the outbox.
func permanentReject(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusNotFound:
		return false
	}
	return status >= 400 && status < 500
}

// isUnknownObjectField matches a pre-field control plane's strict-binder
// rejection, which names the field it refused (encoding/json's
// DisallowUnknownFields error, quoted or JSON-escaped in the response
// body). Anything else is a genuine rejection of the report's content
// and must not be retried stripped.
func isUnknownPauseTokenField(msg []byte) bool {
	return bytes.Contains(msg, []byte(`unknown field "pause_token"`)) ||
		bytes.Contains(msg, []byte(`unknown field \"pause_token\"`))
}

func isUnknownObjectField(msg []byte) bool {
	return bytes.Contains(msg, []byte(`unknown field "object"`)) ||
		bytes.Contains(msg, []byte(`unknown field \"object\"`))
}

// stripObjectPaths clears every per-file object path in place, reporting
// whether any were present.
func stripObjectPaths(body *backupReportBody) bool {
	stripped := false
	for i := range body.Files {
		if body.Files[i].Object != "" {
			body.Files[i].Object = ""
			stripped = true
		}
	}
	return stripped
}

// post performs one delivery attempt, returning the response status and
// up to 512 bytes of a non-2xx body. err is transport-level only; HTTP
// rejections are the caller's to classify.
func (r *BackupReporter) post(body backupReportBody) (status int, statusLine string, msg []byte, err error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, "", nil, fmt.Errorf("marshal backup report: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/internal/hosts/%s/backups", r.ControlPlaneURL, r.HostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, "", nil, fmt.Errorf("build backup report request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("deliver backup report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, resp.Status, nil, nil
	}
	msg, _ = io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, resp.Status, msg, nil
}
