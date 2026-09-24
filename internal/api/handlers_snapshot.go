package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// A saved snapshot is a customer capture of a sandbox that new sandboxes can
// be created from. Its row exists as creating before the host is asked, under
// the id the host's capture is keyed by, so an answer lost on the way back is
// settled later by asking the host again (see the sweep). The host serializes
// captures and deletes of one id, refuses a capture for an id it has deleted,
// and a fork takes private copies before it uses anything, so a delete is
// unconditional once a row is ready or failed, and final.
const (
	snapshotKindFS    = "fs"
	snapshotKindMemFS = "mem+fs"
	// The host bounds its own work by the guest's memory and answers before
	// this; the request is detached from the caller so a client that hangs
	// up does not abandon a capture that is already stalling the guest.
	snapshotCaptureTimeout = 10 * time.Minute
	snapshotDeleteTimeout  = 30 * time.Second
	// SQLSTATEs raised by the sandbox_snapshot quota trigger: the team's or
	// sandbox's snapshot limit, and the team's limit on captures in flight.
	snapshotQuotaErrCode    = "SS002"
	snapshotInFlightErrCode = "SS003"

	snapshotSweepInterval = time.Minute
	// A row still creating this long after its insert has lost its answer
	// and is due for the sweep; a capture's own budget is minutes.
	snapshotSweepCreatingAge = 15 * time.Minute
	// A claimed row is due again after this, whether or not the host answered.
	snapshotSweepRetry = time.Minute
	// A capture unsettled this long has a host that stopped answering: it
	// no longer counts against its team, and it is reported as an error so
	// an operator retires the host's rows along with the host.
	snapshotSweepStuckAge       = time.Hour
	snapshotSweepBatch    int64 = 50
)

type createSnapshotRequest struct {
	Kind           string  `json:"kind"`
	Name           *string `json:"name"`
	IdempotencyKey *string `json:"idempotency_key"`
}

type snapshotPatchRequest struct {
	Name *string `json:"name"`
}

type snapshotResources struct {
	VCPUCount int32 `json:"vcpu_count"`
	MemoryMiB int32 `json:"memory_mib"`
	DiskMiB   int32 `json:"disk_mib"`
}

type snapshotResponse struct {
	ID         uuid.UUID         `json:"id"`
	SandboxID  uuid.UUID         `json:"sandbox_id"`
	TemplateID *uuid.UUID        `json:"template_id"`
	Kind       string            `json:"kind"`
	Status     string            `json:"status"`
	Name       *string           `json:"name"`
	SizeBytes  int64             `json:"size_bytes"`
	Resources  snapshotResources `json:"resources"`
	CreatedAt  time.Time         `json:"created_at"`
	ReadyAt    *time.Time        `json:"ready_at"`
}

func snapshotJSON(s db.SandboxSnapshot) snapshotResponse {
	out := snapshotResponse{
		ID:        s.ID,
		SandboxID: s.SandboxID,
		Kind:      s.Kind,
		Status:    s.Status,
		Name:      s.Name,
		SizeBytes: s.SizeBytes,
		Resources: snapshotResources{VCPUCount: s.VcpuCount, MemoryMiB: s.MemoryMib, DiskMiB: s.DiskMib},
		CreatedAt: s.CreatedAt,
	}
	if s.TemplateID.Valid {
		id := uuid.UUID(s.TemplateID.Bytes)
		out.TemplateID = &id
	}
	if s.ReadyAt.Valid {
		t := s.ReadyAt.Time
		out.ReadyAt = &t
	}
	return out
}

func parseSnapshotID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("snapshot_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Invalid snapshot_id: %q is not a valid snapshot ID", raw), http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func isSnapshotLimitErr(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// CreateSandboxSnapshot captures a sandbox into a saved snapshot and answers
// once the host holds it.
func (h *Handlers) CreateSandboxSnapshot(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	body := createSnapshotRequest{Kind: snapshotKindMemFS}
	if c.Request.Body != nil && c.Request.ContentLength != 0 {
		if err := bindJSONStrict(c, &body); err != nil {
			respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if body.Kind == "" {
		body.Kind = snapshotKindMemFS
	}
	if body.Kind != snapshotKindFS && body.Kind != snapshotKindMemFS {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("kind must be %q or %q", snapshotKindFS, snapshotKindMemFS), http.StatusBadRequest)
		return
	}
	if body.Name != nil && (len(*body.Name) < 1 || len(*body.Name) > 64) {
		respondErrorMsg(c, "bad_request", "name must be 1 to 64 characters", http.StatusBadRequest)
		return
	}
	if body.IdempotencyKey != nil && (len(*body.IdempotencyKey) < 1 || len(*body.IdempotencyKey) > 255) {
		respondErrorMsg(c, "bad_request", "idempotency_key must be 1 to 255 characters", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()

	// A key already on file is answered with what it made, whatever became
	// of it or its source since; only a new key is checked for eligibility.
	if body.IdempotencyKey != nil {
		existing, err := h.DB.GetSandboxSnapshotByIdempotencyKey(ctx, db.GetSandboxSnapshotByIdempotencyKeyParams{TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: body.IdempotencyKey})
		if err == nil {
			respondSnapshotReplay(c, existing)
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Msg("snapshot: idempotent lookup")
			respondError(c, ErrInternal)
			return
		}
	}

	sb, err := h.DB.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("snapshot: load sandbox")
		respondError(c, ErrInternal)
		return
	}
	if (sb.Status != db.SandboxStatusActive && sb.Status != db.SandboxStatusPaused) || sb.HostID == "" {
		respondErrorMsg(c, "conflict", fmt.Sprintf("sandbox must be active or paused to snapshot; it is %s", sb.Status), http.StatusConflict)
		return
	}
	if sb.BasePath == nil {
		respondErrorMsg(c, "conflict", "sandbox predates overlay disks and cannot be snapshotted; create a new one from its template", http.StatusConflict)
		return
	}
	bindings, err := h.snapshotSecretBindings(ctx, sandboxID)
	if err != nil {
		log.Error().Err(err).Msg("snapshot: list secret bindings")
		respondError(c, ErrInternal)
		return
	}
	netCfg := sb.NetworkConfig
	if len(netCfg) == 0 {
		netCfg = []byte("{}")
	}
	row, err := h.DB.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
		ID:             uuid.New(),
		TeamID:         teamID,
		SandboxID:      sandboxID,
		TemplateID:     sb.TemplateID,
		Kind:           body.Kind,
		Name:           body.Name,
		IdempotencyKey: body.IdempotencyKey,
		HostID:         sb.HostID,
		VcpuCount:      sb.VcpuCount,
		MemoryMib:      sb.MemoryMib,
		DiskMib:        sb.DiskMib,
		BasePath:       *sb.BasePath,
		TimeoutSeconds: sb.TimeoutSeconds,
		NetworkConfig:  netCfg,
		SecretBindings: bindings,
		SweepAfter:     pgtype.Timestamptz{Time: time.Now().Add(snapshotSweepCreatingAge), Valid: true},
	})
	if err != nil {
		switch {
		case body.IdempotencyKey != nil && isUniqueViolation(err):
			// Another request with the same key got in first.
			existing, gerr := h.DB.GetSandboxSnapshotByIdempotencyKey(ctx, db.GetSandboxSnapshotByIdempotencyKeyParams{TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: body.IdempotencyKey})
			if gerr != nil {
				log.Error().Err(gerr).Msg("snapshot: idempotent re-read")
				respondError(c, ErrInternal)
				return
			}
			respondSnapshotReplay(c, existing)
		case isSnapshotLimitErr(err, snapshotInFlightErrCode):
			respondErrorMsg(c, "too_many_snapshots_in_flight", "team has reached its limit on snapshots being created at once; wait for one to finish", http.StatusTooManyRequests)
		case isSnapshotLimitErr(err, snapshotQuotaErrCode):
			respondErrorMsg(c, "too_many_snapshots", "team or sandbox has reached its snapshot limit; delete some or contact support@superserve.ai for higher", http.StatusTooManyRequests)
		default:
			log.Error().Err(err).Msg("snapshot: insert")
			respondError(c, ErrInternal)
		}
		return
	}

	client, err := h.vmdForHost(ctx, sb.HostID)
	if err != nil {
		h.failSnapshot(row.ID, sb.HostID, nil)
		log.Error().Err(err).Str("host_id", sb.HostID).Msg("snapshot: resolve host")
		respondError(c, ErrHostStateMissing)
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), snapshotCaptureTimeout)
	defer cancel()
	snap, err := client.CreateSavedSnapshot(cctx, sandboxID.String(), row.ID.String(), body.Kind)
	if err != nil {
		if snapshotCaptureRefused(err) {
			h.failSnapshot(row.ID, sb.HostID, client)
			respondSnapshotCaptureError(c, err)
			return
		}
		// The answer was lost, not refused: the host may hold the snapshot.
		// The row stays creating and the sweep settles it from the host.
		h.scheduleSnapshotSweep(row.ID)
		log.Warn().Err(err).Str("snapshot_id", row.ID.String()).Str("host_id", sb.HostID).Msg("snapshot: capture answer lost; left to the sweep")
		c.Header("Retry-After", "60")
		c.JSON(http.StatusAccepted, snapshotJSON(row))
		return
	}
	current, err := h.settleCapture(cctx, row, snap)
	if err != nil {
		// The host holds the snapshot; the sweep records it if this did not.
		log.Error().Err(err).Str("snapshot_id", row.ID.String()).Msg("snapshot: mark ready")
		respondError(c, ErrInternal)
		return
	}
	if current.Status != "ready" || current.DeletedAt.Valid {
		respondSnapshotReplay(c, current)
		return
	}
	c.JSON(http.StatusCreated, snapshotJSON(current))
}

// respondSnapshotReplay answers for a snapshot an earlier request made.
func respondSnapshotReplay(c *gin.Context, row db.SandboxSnapshot) {
	if row.DeletedAt.Valid {
		respondErrorMsg(c, "gone", "the snapshot this request made has been deleted", http.StatusGone)
		return
	}
	c.JSON(http.StatusOK, snapshotJSON(row))
}

func (h *Handlers) snapshotSecretBindings(ctx context.Context, sandboxID uuid.UUID) ([]byte, error) {
	rows, err := h.DB.ListSandboxSecretBindingMeta(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	type binding struct {
		EnvKey   string    `json:"env_key"`
		SecretID uuid.UUID `json:"secret_id"`
	}
	out := make([]binding, 0, len(rows))
	for _, r := range rows {
		out = append(out, binding{EnvKey: r.EnvKey, SecretID: r.SecretID})
	}
	return json.Marshal(out)
}

func (h *Handlers) markSnapshotReady(ctx context.Context, id uuid.UUID, snap vmdclient.SavedSnapshot) (db.SandboxSnapshot, error) {
	return h.DB.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{
		ID:           id,
		BaseMemPath:  optString(snap.BaseMemPath),
		SnapshotPath: optString(snap.SnapshotPath),
		MemPath:      optString(snap.MemPath),
		OverlayPath:  &snap.DiskPath,
		SizeBytes:    snap.SizeBytes,
		FcBuildSha:   optString(snap.FirecrackerSHA256),
	})
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// settleCapture records the host's answer on the row. A row no longer
// creating was settled by the other party or is being deleted; a delete
// takes what the host holds, and the host commits nothing for a deleted id.
func (h *Handlers) settleCapture(ctx context.Context, row db.SandboxSnapshot, snap vmdclient.SavedSnapshot) (db.SandboxSnapshot, error) {
	ready, err := h.markSnapshotReady(ctx, row.ID, snap)
	if err == nil {
		return ready, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return db.SandboxSnapshot{}, err
	}
	return h.DB.GetSandboxSnapshotUnscoped(ctx, row.ID)
}

// scheduleSnapshotSweep makes a row the sweep's to settle now. Detached from
// the request, like failSnapshot.
func (h *Handlers) scheduleSnapshotSweep(id uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), snapshotDeleteTimeout)
	defer cancel()
	if _, err := h.DB.ScheduleSandboxSnapshotSweep(ctx, id); err != nil {
		log.Error().Err(err).Str("snapshot_id", id.String()).Msg("snapshot: schedule for the sweep")
	}
}

// snapshotCaptureRefused reports an answer that says the host did not and
// will not commit the snapshot as things stand. Any other error is an answer
// lost on the way: the host may hold the snapshot, so nothing is destroyed.
func snapshotCaptureRefused(err error) bool {
	switch status.Code(err) {
	case codes.Unimplemented, codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument,
		codes.AlreadyExists, codes.ResourceExhausted:
		return true
	}
	return false
}

// failSnapshot records a capture that did not commit and, given a client,
// removes whatever the host may hold for the id. Detached from the request:
// the row must not stay creating because the caller went away.
func (h *Handlers) failSnapshot(id uuid.UUID, hostID string, client VMDClient) {
	ctx, cancel := context.WithTimeout(context.Background(), snapshotDeleteTimeout)
	defer cancel()
	if _, err := h.DB.MarkSandboxSnapshotFailed(ctx, id); err != nil {
		log.Error().Err(err).Str("snapshot_id", id.String()).Msg("snapshot: mark failed")
	}
	if client != nil {
		if err := client.DeleteSavedSnapshot(ctx, id.String()); err != nil {
			log.Warn().Err(err).Str("snapshot_id", id.String()).Str("host_id", hostID).Msg("snapshot: host cleanup after a failed capture")
		}
	}
}

func respondSnapshotCaptureError(c *gin.Context, err error) {
	switch status.Code(err) {
	case codes.Unimplemented:
		respondErrorMsg(c, "host_not_ready", "the sandbox's host cannot take snapshots yet; retry later", http.StatusServiceUnavailable)
	case codes.NotFound:
		respondErrorMsg(c, "conflict", "sandbox is not running on its host", http.StatusConflict)
	case codes.FailedPrecondition, codes.AlreadyExists:
		respondErrorMsg(c, "conflict", vmdErrorMessage(err), http.StatusConflict)
	case codes.InvalidArgument:
		respondErrorMsg(c, "bad_request", vmdErrorMessage(err), http.StatusBadRequest)
	case codes.ResourceExhausted:
		respondErrorMsg(c, "host_capacity", vmdErrorMessage(err), http.StatusServiceUnavailable)
	default:
		log.Error().Err(err).Msg("snapshot: capture")
		respondError(c, ErrInternal)
	}
}

// ListSandboxSnapshots lists a sandbox's live snapshots, newest first. The
// snapshots outlive the sandbox, so the sandbox itself need not exist.
func (h *Handlers) ListSandboxSnapshots(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}
	pg, err := parsePageParams(c, []string{"created_at"}, "created_at")
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	var offset int64
	if pg.Offset != nil {
		offset = *pg.Offset
	}
	rows, err := h.DB.ListSandboxSnapshots(ctx, db.ListSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID, RowLimit: pg.Limit, RowOffset: offset})
	if err != nil {
		log.Error().Err(err).Msg("snapshot: list")
		respondError(c, ErrInternal)
		return
	}
	total, err := resolveTotal(pg, len(rows), func() (int64, error) {
		return h.DB.CountSandboxSnapshots(ctx, db.CountSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID})
	})
	if err != nil {
		log.Error().Err(err).Msg("snapshot: count")
		respondError(c, ErrInternal)
		return
	}
	out := make([]snapshotResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, snapshotJSON(r))
	}
	c.Header("X-Total-Count", fmt.Sprint(total))
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetSnapshot(c *gin.Context) {
	id, err := parseSnapshotID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}
	row, err := h.DB.GetSandboxSnapshot(c.Request.Context(), db.GetSandboxSnapshotParams{ID: id, TeamID: teamID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("snapshot: get")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, snapshotJSON(row))
}

func (h *Handlers) PatchSnapshot(c *gin.Context) {
	id, err := parseSnapshotID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	var body snapshotPatchRequest
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Name == nil {
		respondErrorMsg(c, "bad_request", "name is required", http.StatusBadRequest)
		return
	}
	if len(*body.Name) < 1 || len(*body.Name) > 64 {
		respondErrorMsg(c, "bad_request", "name must be 1 to 64 characters", http.StatusBadRequest)
		return
	}
	row, err := h.DB.RenameSandboxSnapshot(c.Request.Context(), db.RenameSandboxSnapshotParams{ID: id, TeamID: teamID, Name: body.Name})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("snapshot: rename")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, snapshotJSON(row))
}

// DeleteSnapshot removes a snapshot: the row goes to deleting first, then
// the host gets one attempt within the inline budget a sandbox delete also
// answers under, and a host that does not answer in time leaves the row to
// the sweep rather than the caller waiting.
func (h *Handlers) DeleteSnapshot(c *gin.Context) {
	id, err := parseSnapshotID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	ctx := c.Request.Context()
	row, err := h.DB.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: id, TeamID: teamID})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Msg("snapshot: begin delete")
			respondError(c, ErrInternal)
			return
		}
		if current, gerr := h.DB.GetSandboxSnapshot(ctx, db.GetSandboxSnapshotParams{ID: id, TeamID: teamID}); gerr == nil && current.Status == "creating" {
			respondErrorMsg(c, "conflict", "snapshot is still being created", http.StatusConflict)
			return
		}
		respondErrorMsg(c, "not_found", "Snapshot not found", http.StatusNotFound)
		return
	}
	if err := h.deleteSnapshotOnHost(ctx, row, h.inlineBudget()); err != nil {
		log.Warn().Err(err).Str("snapshot_id", id.String()).Str("host_id", row.HostID).Msg("snapshot: host delete deferred to the sweep")
		c.Header("Retry-After", "30")
		c.JSON(http.StatusAccepted, gin.H{"status": "deleting"})
		return
	}
	c.Status(http.StatusNoContent)
}

// deleteSnapshotOnHost removes the files and records the row deleted. A host
// that no longer knows the id has nothing to remove.
func (h *Handlers) deleteSnapshotOnHost(ctx context.Context, row db.SandboxSnapshot, wait time.Duration) error {
	client, err := h.vmdForHost(ctx, row.HostID)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wait)
	defer cancel()
	if err := client.DeleteSavedSnapshot(dctx, row.ID.String()); err != nil && !isVMDNotFound(err) {
		return err
	}
	_, err = h.DB.MarkSandboxSnapshotDeleted(dctx, row.ID)
	return err
}

// StartSnapshotSweeper settles rows a capture or a delete left behind.
func (h *Handlers) StartSnapshotSweeper(ctx context.Context) {
	logger := log.Logger
	go func() {
		ticker := time.NewTicker(snapshotSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sentrylog.RunSafe("snapshot-sweep", func() { h.SweepSnapshotsOnce(ctx, logger) })
			}
		}
	}()
}

// snapshotSweepHost is one host's share of the sweep: the rows waiting for
// it, in claim order, and whether a worker is taking them.
type snapshotSweepHost struct {
	queue   []snapshotSweepItem
	queued  map[uuid.UUID]struct{}
	running bool
}

type snapshotSweepItem struct {
	row  db.SandboxSnapshot
	done func()
}

// SweepSnapshotsOnce asks the host about every row that is due. Age alone
// proves nothing: a capture whose answer was lost may have committed, so the
// same idempotent request is issued again and the row settles on what the
// host says. The pass only claims and hands over: each host's rows are taken
// in turn by that host's worker, so a host that does not answer holds back
// its own rows and no pass. The returned channel closes once every row this
// pass handed over is done; exported so tests can run a pass directly.
func (h *Handlers) SweepSnapshotsOnce(ctx context.Context, logger zerolog.Logger) <-chan struct{} {
	done := make(chan struct{})
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	rows, err := h.DB.ClaimStuckSandboxSnapshots(qctx, db.ClaimStuckSandboxSnapshotsParams{
		RetryAt:  time.Now().Add(snapshotSweepRetry),
		RowLimit: snapshotSweepBatch,
	})
	cancel()
	if err != nil {
		logger.Error().Err(err).Msg("snapshot sweep: claim")
		close(done)
		return done
	}
	var wg sync.WaitGroup
	h.snapshotSweepMu.Lock()
	if h.snapshotSweepHosts == nil {
		h.snapshotSweepHosts = map[string]*snapshotSweepHost{}
	}
	for _, row := range rows {
		host := h.snapshotSweepHosts[row.HostID]
		if host == nil {
			host = &snapshotSweepHost{queued: map[uuid.UUID]struct{}{}}
			h.snapshotSweepHosts[row.HostID] = host
		}
		// A row this replica already holds is claimed again only because
		// its retry time passed while it waited or ran; it is not doubled.
		if _, held := host.queued[row.ID]; held {
			continue
		}
		host.queued[row.ID] = struct{}{}
		wg.Add(1)
		host.queue = append(host.queue, snapshotSweepItem{row: row, done: wg.Done})
		if !host.running {
			host.running = true
			go h.sweepHost(ctx, row.HostID, logger)
		}
	}
	h.snapshotSweepMu.Unlock()
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// sweepHost takes one host's queued rows in turn until none are left.
func (h *Handlers) sweepHost(ctx context.Context, hostID string, logger zerolog.Logger) {
	for {
		h.snapshotSweepMu.Lock()
		host := h.snapshotSweepHosts[hostID]
		if len(host.queue) == 0 {
			host.running = false
			h.snapshotSweepMu.Unlock()
			return
		}
		item := host.queue[0]
		host.queue = host.queue[1:]
		h.snapshotSweepMu.Unlock()

		if ctx.Err() == nil {
			sentrylog.RunSafe("snapshot-sweep", func() {
				h.sweepSnapshot(ctx, item.row, logger.With().Str("snapshot_id", item.row.ID.String()).Str("host_id", hostID).Logger())
			})
		}
		h.snapshotSweepMu.Lock()
		delete(host.queued, item.row.ID)
		h.snapshotSweepMu.Unlock()
		item.done()
	}
}

func (h *Handlers) sweepSnapshot(ctx context.Context, row db.SandboxSnapshot, logger zerolog.Logger) {
	unsettled := logger.Warn
	if row.Status == "creating" && time.Since(row.CreatedAt) > snapshotSweepStuckAge {
		unsettled = logger.Error
	}
	client, err := h.vmdForHost(ctx, row.HostID)
	if err != nil {
		unsettled().Err(err).Msg("snapshot sweep: host unresolved")
		return
	}
	switch row.Status {
	case "creating":
		cctx, cancel := context.WithTimeout(ctx, snapshotCaptureTimeout)
		snap, err := client.CreateSavedSnapshot(cctx, row.SandboxID.String(), row.ID.String(), row.Kind)
		cancel()
		switch {
		case err == nil:
			current, err := h.settleCapture(ctx, row, snap)
			if err != nil {
				logger.Error().Err(err).Msg("snapshot sweep: mark ready")
				return
			}
			logger.Info().Str("status", current.Status).Msg("snapshot sweep: settled from the host")
		case snapshotCaptureRefused(err):
			h.failSnapshot(row.ID, row.HostID, client)
			logger.Warn().Err(err).Msg("snapshot sweep: settled failed from the host")
		default:
			unsettled().Err(err).Msg("snapshot sweep: host did not settle the capture; will ask again")
		}
	case "deleting":
		if err := h.deleteSnapshotOnHost(ctx, row, snapshotDeleteTimeout); err != nil {
			logger.Warn().Err(err).Msg("snapshot sweep: delete not finished; will ask again")
			return
		}
		logger.Info().Msg("snapshot sweep: delete finished")
	}
}
