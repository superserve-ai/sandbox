package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// errFinalizeInFlight rolls a report's transaction back when the
// sandbox is mid-finalize: coverage re-records idempotently on
// redelivery, and the size sync lands once the snapshot row exists.
var errFinalizeInFlight = errors.New("pause finalization in flight")

// maxBackupReportFiles bounds a report's manifest jsonb. Sandbox
// generations carry a handful of files, but template builds ship every
// regular artifact in the build's snapshot directory with no bound of
// their own, so this must sit far above anything a real build produces;
// a report rejected here is rejected forever and the reporter drops it
// as poisoned, losing that generation's coverage row.
const maxBackupReportFiles = 512

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// backupFileReport is one artifact in a verified generation, as recorded
// in the generation's bucket manifest. Host paths deliberately do not
// appear: they name staging locations that stop existing after the
// upload acks, and restore derives object names from the generation key.
type backupFileReport struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	BaseSHA256 string `json:"base_sha256,omitempty"`
	// Shared marks an artifact stored bucket-wide under bases/ rather
	// than inside the generation prefix.
	Shared bool `json:"shared,omitempty"`
}

// backupReport is a host's notice that one generation is fully uploaded
// and digest-verified in its cell bucket. Delivery is at least once from
// the host's durable outbox; the insert is idempotent on
// (owner, bucket, generation).
type backupReport struct {
	SandboxID   string             `json:"sandbox_id,omitempty"`
	TemplateID  string             `json:"template_id,omitempty"`
	BuildID     string             `json:"build_id,omitempty"`
	Generation  string             `json:"generation"`
	Bucket      string             `json:"bucket"`
	CompletedAt time.Time          `json:"completed_at"`
	Files       []backupFileReport `json:"files"`
}

// ReportHostBackup handles POST /internal/hosts/:host_id/backups.
//
// Records the generation in backup_generation (coverage becomes a DB
// query), and when the report's vmstate digest matches the sandbox's
// newest snapshot row, syncs snapshot.size_bytes from the verified
// manifest, since pause-time manifests stopped carrying disk sizes when
// hashing moved off the pause path. Every terminal outcome that is not
// a transport or server fault returns 200: the host redelivers on
// anything else, and a report the control plane can never accept (an
// unknown sandbox, a malformed row) must not wedge the outbox forever.
func (h *Handlers) ReportHostBackup(c *gin.Context) {
	if c.Param("host_id") == "" {
		respondErrorMsg(c, "bad_request", "host_id is required", http.StatusBadRequest)
		return
	}
	var req backupReport
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !sha256Hex.MatchString(req.Generation) {
		respondErrorMsg(c, "bad_request", "generation must be a sha256 hex key", http.StatusBadRequest)
		return
	}
	if req.Bucket == "" || req.CompletedAt.IsZero() {
		respondErrorMsg(c, "bad_request", "bucket and completed_at are required", http.StatusBadRequest)
		return
	}
	// Zero files is a coverage-only report: hosts seed historical
	// completions whose task rows (and manifests) are long gone, and the
	// bucket's manifest object remains the file-set authority for them.
	// Rejecting those would poison the seed, since the reporter treats a
	// 400 as permanent.
	if len(req.Files) > maxBackupReportFiles {
		respondErrorMsg(c, "bad_request", "files must carry the generation manifest", http.StatusBadRequest)
		return
	}
	for _, f := range req.Files {
		if f.Name == "" || f.SizeBytes < 0 || !sha256Hex.MatchString(f.SHA256) {
			respondErrorMsg(c, "bad_request", "each file needs a name, size, and sha256", http.StatusBadRequest)
			return
		}
		if f.BaseSHA256 != "" && !sha256Hex.MatchString(f.BaseSHA256) {
			respondErrorMsg(c, "bad_request", "base_sha256 must be sha256 hex when present", http.StatusBadRequest)
			return
		}
	}
	if (req.SandboxID == "") == (req.TemplateID == "") {
		respondErrorMsg(c, "bad_request", "exactly one of sandbox_id or template_id is required", http.StatusBadRequest)
		return
	}
	if req.TemplateID != "" && req.BuildID == "" {
		respondErrorMsg(c, "bad_request", "template reports require build_id", http.StatusBadRequest)
		return
	}

	var sandboxID, templateID uuid.UUID
	if req.SandboxID != "" {
		id, err := uuid.Parse(req.SandboxID)
		if err != nil {
			respondErrorMsg(c, "bad_request", "sandbox_id must be a uuid", http.StatusBadRequest)
			return
		}
		sandboxID = id
	} else {
		id, err := uuid.Parse(req.TemplateID)
		if err != nil {
			respondErrorMsg(c, "bad_request", "template_id must be a uuid", http.StatusBadRequest)
			return
		}
		templateID = id
	}
	files, err := json.Marshal(req.Files)
	if err != nil {
		respondErrorMsg(c, "bad_request", "files not serializable", http.StatusBadRequest)
		return
	}

	ctx := c.Request.Context()
	recorded := false
	sizeSynced := false
	apply := func(q *db.Queries) error {
		var rows int64
		var err error
		if req.SandboxID != "" {
			rows, err = q.RecordSandboxBackupGeneration(ctx, db.RecordSandboxBackupGenerationParams{
				SandboxID:   pgtype.UUID{Bytes: sandboxID, Valid: true},
				Generation:  req.Generation,
				Bucket:      req.Bucket,
				CompletedAt: req.CompletedAt.UTC(),
				Files:       files,
			})
		} else {
			rows, err = q.RecordTemplateBackupGeneration(ctx, db.RecordTemplateBackupGenerationParams{
				TemplateID:  pgtype.UUID{Bytes: templateID, Valid: true},
				BuildID:     &req.BuildID,
				Generation:  req.Generation,
				Bucket:      req.Bucket,
				CompletedAt: req.CompletedAt.UTC(),
				Files:       files,
			})
		}
		if err != nil {
			return err
		}
		recorded = rows > 0
		if req.SandboxID == "" {
			return nil
		}
		// Size sync under the sandbox row lock FinalizePause also takes,
		// so the vmstate match below cannot go stale mid-transaction: a
		// concurrent pause either commits first (the match fails, its own
		// finalize owns sizes) or waits for this commit.
		row, err := q.LockSandboxRow(ctx, sandboxID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		// 'pausing' means FinalizePause has not committed this pause's
		// snapshot row yet (it takes the same row lock we now hold): a
		// fast upload's report arriving in that window would match the
		// PREVIOUS snapshot's vmstate and silently skip the new one's
		// size sync forever, since a 200 clears the host's outbox. Roll
		// the whole transaction back as retryable instead; redelivery
		// re-records coverage idempotently and the sync lands once the
		// finalize has committed.
		// Time-bounded: a finalize that failed permanently leaves the
		// sandbox stranded in 'pausing' with no retry scheduled, and an
		// unconditional 503 would head-of-line-block the host's outbox
		// forever. A fresh 'pausing' retries; a stale one proceeds, and
		// the vmstate match below skips the sync exactly as for any
		// other settled mismatch.
		if row.Status == "pausing" && time.Since(row.UpdatedAt) < 10*time.Minute {
			return errFinalizeInFlight
		}
		snap, err := q.LatestSnapshotVMState(ctx, sandboxID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		var vmstate string
		var total int64
		for _, f := range req.Files {
			if f.Name == "vmstate.snap" {
				vmstate = f.SHA256
			}
			if !f.Shared {
				total += f.SizeBytes
			}
		}
		if vmstate == "" || snap.VmstateSha256 != vmstate {
			// The report describes an older pause (or one whose manifest
			// hash was skipped): coverage is recorded above, but this
			// snapshot row's sizes belong to its own pause's report.
			return nil
		}
		if err := q.SetSnapshotSizeBytes(ctx, db.SetSnapshotSizeBytesParams{
			ID: snap.SnapshotID, SizeBytes: total,
		}); err != nil {
			return err
		}
		sizeSynced = true
		return nil
	}

	if h.Pool == nil {
		err = apply(h.DB)
	} else {
		var tx pgx.Tx
		if tx, err = h.Pool.Begin(ctx); err == nil {
			defer tx.Rollback(ctx)
			if err = apply(h.DB.WithTx(tx)); err == nil {
				err = tx.Commit(ctx)
			}
		}
	}
	if err != nil {
		if errors.Is(err, errFinalizeInFlight) {
			// Retryable by contract: 503 keeps the entry outboxed and the
			// host redelivers after the finalize commits.
			respondErrorMsg(c, "finalize_in_flight", "pause finalization in progress; retry", http.StatusServiceUnavailable)
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			// The owner row does not exist here (a sandbox this control
			// plane never knew, or one hard-removed out of band). The
			// host's bucket object is real either way; log it and accept
			// so the outbox clears instead of redelivering forever.
			log.Warn().Str("host_id", c.Param("host_id")).
				Str("generation", req.Generation).
				Str("sandbox_id", req.SandboxID).Str("template_id", req.TemplateID).
				Msg("backup report for unknown owner; recorded nothing")
			c.JSON(http.StatusOK, gin.H{"recorded": false, "orphaned": true})
			return
		}
		log.Error().Err(err).Str("host_id", c.Param("host_id")).
			Str("generation", req.Generation).Msg("backup report failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recorded": recorded, "size_synced": sizeSynced})
}
