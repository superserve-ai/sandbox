package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/backup"
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

// fingerprintHex bounds a reported packing fingerprint to the hex the
// uploader emits. Charset over exact length on purpose: today's
// fingerprints are 12 hex chars, but pinning the width here would make
// any future widening a silent coverage-dropping incompatibility, while
// the charset is what keeps arbitrary bytes out of a field that will
// become deletion authority.
var fingerprintHex = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

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
	// Object is the exact bucket object path the host wrote for this
	// entry (the packing-fingerprint-suffixed name under the generation
	// prefix, or the full bases/ path for shared entries). Persisted
	// verbatim into the files jsonb so lifecycle GC can name a
	// generation's objects from the DB without listing the bucket.
	// Optional: reports from hosts predating the field omit it, and
	// those generations' bucket manifests remain their path authority.
	Object string `json:"object,omitempty"`
}

// backupReport is a host's notice that one generation is fully uploaded
// and digest-verified in its cell bucket. Delivery is at least once from
// the host's durable outbox; the insert is idempotent on
// (owner, bucket, generation).
type backupReport struct {
	SandboxID   string    `json:"sandbox_id,omitempty"`
	TemplateID  string    `json:"template_id,omitempty"`
	BuildID     string    `json:"build_id,omitempty"`
	Generation  string    `json:"generation"`
	Bucket      string    `json:"bucket"`
	CompletedAt time.Time `json:"completed_at"`
	// PauseToken echoes the identity this control plane minted for the
	// pause that produced the generation (threaded through the pause RPC
	// and the host's journal). Empty from older hosts and pre-token
	// outbox entries.
	PauseToken string             `json:"pause_token,omitempty"`
	Files      []backupFileReport `json:"files"`
}

// validateReportedObject pins an optional per-file object path to the
// layout the uploader can actually write: shared entries under their
// content-addressed bases/ name, everything else under the report
// owner's generation prefix bound to the entry's own file name, with a
// non-empty single-segment packing-fingerprint suffix either way. The
// expected prefix comes from the same layout helpers the uploader
// names objects with, so this check cannot drift from the write side.
// It matters because these paths are meant to become deletion authority
// for a lifecycle GC: a buggy host must not be able to park another
// owner's object (or a generation's manifest) in this ledger entry.
func validateReportedObject(req backupReport, f backupFileReport) error {
	var prefix string
	if f.Shared {
		prefix = backup.SharedBaseObject(f.SHA256, "")
	} else {
		var err error
		if req.SandboxID != "" {
			prefix, err = backup.SandboxObject(req.SandboxID, req.Generation, f.Name)
		} else {
			prefix, err = backup.TemplateObject(req.TemplateID, req.BuildID, req.Generation, f.Name)
		}
		if err != nil {
			return fmt.Errorf("object for %q: %w", f.Name, err)
		}
		prefix += ".p"
	}
	fp, ok := strings.CutPrefix(f.Object, prefix)
	if !ok || !fingerprintHex.MatchString(fp) {
		return fmt.Errorf("object for %q must name this entry under its own prefix with a hex packing fingerprint", f.Name)
	}
	return nil
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
	withObjects := 0
	for _, f := range req.Files {
		if f.Name == "" || f.SizeBytes < 0 || !sha256Hex.MatchString(f.SHA256) {
			respondErrorMsg(c, "bad_request", "each file needs a name, size, and sha256", http.StatusBadRequest)
			return
		}
		if f.BaseSHA256 != "" && !sha256Hex.MatchString(f.BaseSHA256) {
			respondErrorMsg(c, "bad_request", "base_sha256 must be sha256 hex when present", http.StatusBadRequest)
			return
		}
		if f.Object != "" {
			if err := validateReportedObject(req, f); err != nil {
				respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
				return
			}
			withObjects++
		}
	}
	// Paths land all-or-none: a conforming host finalizes a report with
	// every path or (a deduped manifest, a legacy entry) none, and the
	// upsert's demotion guard treats ANY path as a path-bearing manifest,
	// so accepting a mixed set would let it replace a complete ledger
	// entry with a partial one.
	if withObjects != 0 && withObjects != len(req.Files) {
		respondErrorMsg(c, "bad_request", "object paths must cover every file or none", http.StatusBadRequest)
		return
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
		var sbRow db.LockSandboxRowRow
		haveSandbox := false
		if req.SandboxID != "" {
			// Lock order matches FinalizePause: sandbox row first, then
			// dependent writes. Inserting the FK-backed coverage row
			// before the lock took a share lock on the sandbox row and
			// upgraded it under FOR UPDATE, inviting deadlock against
			// the lifecycle path.
			sbRow, err = q.LockSandboxRow(ctx, sandboxID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			haveSandbox = err == nil
			if haveSandbox && sbRow.Status == "pausing" && time.Since(sbRow.UpdatedAt) < 10*time.Minute {
				return errFinalizeInFlight
			}
		}
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
		manifest, err := q.LatestSnapshotManifest(ctx, sandboxID)
		if err != nil {
			return err
		}
		if len(manifest) == 0 {
			return nil
		}
		byName := map[string]string{}
		for _, f := range req.Files {
			byName[f.Name] = f.SHA256
		}
		var total int64
		var hasDisk, hasVMState bool
		for _, f := range req.Files {
			if f.Name == "rootfs.ext4" {
				hasDisk = true
			}
			if f.Name == "vmstate.snap" {
				hasVMState = true
			}
			if !f.Shared {
				total += f.SizeBytes
			}
		}
		// The report must carry the complete restorable pair AND match
		// every digest the pause-time manifest recorded: vmstate alone
		// is not a unique pause identity, and any recorded row the
		// report contradicts (or lacks) means it describes a different
		// pause. Rows are vmstate-only today and tighten the match
		// automatically as richer manifests appear.
		contentMatch := hasDisk && hasVMState
		if contentMatch {
			for _, row := range manifest {
				if byName[row.FileName] != row.Sha256 {
					contentMatch = false
					break
				}
			}
		}
		snapshotID := manifest[0].SnapshotID
		// Coverage links — the operator's retirement gate — require a
		// VERIFIED pause identity: content match plus STRICT token
		// equality, both sides non-empty. There is deliberately no
		// tokenless fallback: pause-time manifests are vmstate-only, and
		// vmstate digest coincidence across pauses is exactly the
		// evidence the migration refused to backfill links from —
		// accepting it live while refusing it historically would be
		// incoherent. A pause finalized without a token (older daemon, or
		// an old control-plane replica that minted none) therefore stays
		// unlinked and reads unbacked until the sandbox next pauses
		// through the token path: over-reported risk, never a false zero,
		// converging as the fleet does. A STALE token — an old replica's
		// legacy one-row upsert preserving the column it does not mention
		// — cannot reach this predicate: the migration's trigger clears a
		// token whose value did not move across a generation advance, so
		// the row reads honestly tokenless (unlinked) rather than
		// mislinkable when the old pause's delayed report carries a
		// colliding vmstate digest.
		linkable := contentMatch && req.PauseToken != "" &&
			req.PauseToken == manifest[0].PauseToken
		if linkable {
			// Persist the verdict as the generation's coverage identity
			// (snapshot row + its per-pause generation counter) so
			// coverage reads never re-derive it from timestamps or
			// content.
			if err := q.MarkSandboxBackupCovered(ctx, db.MarkSandboxBackupCoveredParams{
				SandboxID:          pgtype.UUID{Bytes: sandboxID, Valid: true},
				Bucket:             req.Bucket,
				Generation:         req.Generation,
				SnapshotID:         pgtype.UUID{Bytes: snapshotID, Valid: true},
				SnapshotGeneration: &manifest[0].SnapshotGeneration,
			}); err != nil {
				return err
			}
		}
		// Size sync is a SEPARATE, lower-stakes concern (display sizes,
		// not the retirement gate) and predates tokens: it keeps its
		// original content gate for token-free pairs so old-daemon fleets
		// don't regress, refusing only a definite token disagreement —
		// that report provably describes another pause's artifacts.
		if !contentMatch || req.PauseToken != manifest[0].PauseToken {
			return nil
		}
		if err := q.SetSnapshotSizeBytes(ctx, db.SetSnapshotSizeBytesParams{
			ID: snapshotID, SizeBytes: total,
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
