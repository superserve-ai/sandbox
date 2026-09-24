package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
// captures and deletes of one id, and a fork takes private copies before it
// uses anything, so a delete is unconditional once a row is ready or failed.
const (
	snapshotKindFS    = "fs"
	snapshotKindMemFS = "mem+fs"
	// The host bounds its own work by the guest's memory and answers before
	// this; the request is detached from the caller so a client that hangs
	// up does not abandon a capture that is already stalling the guest.
	snapshotCaptureTimeout = 10 * time.Minute
	snapshotDeleteTimeout  = 30 * time.Second
	// Captures a team may have in flight at once, on top of the host's own
	// per-host bound.
	snapshotsInFlightPerTeam = 4
	// SQLSTATE raised by the sandbox_snapshot quota trigger.
	snapshotQuotaErrCode = "SS002"

	snapshotSweepInterval = time.Minute
	// A row creating since before this is asked about again; a capture's
	// own budget is minutes, so a row this old has lost its answer.
	snapshotSweepCreatingAge       = 15 * time.Minute
	snapshotSweepBatch       int64 = 50
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

func isSnapshotQuotaErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == snapshotQuotaErrCode
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
	inFlight, err := h.DB.CountTeamSnapshotsCreating(ctx, teamID)
	if err != nil {
		log.Error().Err(err).Msg("snapshot: count captures in flight")
		respondError(c, ErrInternal)
		return
	}
	if inFlight >= snapshotsInFlightPerTeam {
		respondErrorMsg(c, "too_many_snapshots_in_flight", fmt.Sprintf("team has %d snapshots being created; wait for one to finish", inFlight), http.StatusTooManyRequests)
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
	})
	if err != nil {
		switch {
		case body.IdempotencyKey != nil && isUniqueViolation(err):
			// The same request already made a snapshot: answer with it,
			// whatever state it has reached.
			existing, gerr := h.DB.GetSandboxSnapshotByIdempotencyKey(ctx, db.GetSandboxSnapshotByIdempotencyKeyParams{TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: body.IdempotencyKey})
			if gerr != nil {
				log.Error().Err(gerr).Msg("snapshot: idempotent re-read")
				respondError(c, ErrInternal)
				return
			}
			c.JSON(http.StatusOK, snapshotJSON(existing))
		case isSnapshotQuotaErr(err):
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
		h.failSnapshot(row.ID, sb.HostID, client)
		respondSnapshotCaptureError(c, err)
		return
	}
	ready, err := h.markSnapshotReady(cctx, row.ID, snap)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Settled by the sweep, or deleted meanwhile: answer with what the row says.
			if current, gerr := h.DB.GetSandboxSnapshot(ctx, db.GetSandboxSnapshotParams{ID: row.ID, TeamID: teamID}); gerr == nil {
				c.JSON(http.StatusOK, snapshotJSON(current))
				return
			}
		}
		// The host holds the snapshot; the sweep records it if this did not.
		log.Error().Err(err).Str("snapshot_id", row.ID.String()).Msg("snapshot: mark ready")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, snapshotJSON(ready))
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
	case codes.Unavailable, codes.DeadlineExceeded:
		respondErrorMsg(c, "capture_failed", "the snapshot could not be taken right now; retry", http.StatusServiceUnavailable)
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

// DeleteSnapshot removes a snapshot: the row goes to deleting first, so a
// host that does not answer leaves it for the sweep rather than alive.
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
	if err := h.deleteSnapshotOnHost(ctx, row); err != nil {
		log.Warn().Err(err).Str("snapshot_id", id.String()).Str("host_id", row.HostID).Msg("snapshot: host delete deferred to the sweep")
		c.Header("Retry-After", "30")
		c.JSON(http.StatusAccepted, gin.H{"status": "deleting"})
		return
	}
	c.Status(http.StatusNoContent)
}

// deleteSnapshotOnHost removes the files and records the row deleted. A host
// that no longer knows the id has nothing to remove.
func (h *Handlers) deleteSnapshotOnHost(ctx context.Context, row db.SandboxSnapshot) error {
	client, err := h.vmdForHost(ctx, row.HostID)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), snapshotDeleteTimeout)
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

// SweepSnapshotsOnce asks the host about every stale row. Age alone proves
// nothing: a capture whose answer was lost may have committed, so the same
// idempotent request is issued again and the row settles on what the host
// says. Exported so tests can run a pass directly.
func (h *Handlers) SweepSnapshotsOnce(ctx context.Context, logger zerolog.Logger) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	rows, err := h.DB.ListStuckSandboxSnapshots(qctx, db.ListStuckSandboxSnapshotsParams{
		CreatingBefore: time.Now().Add(-snapshotSweepCreatingAge),
		RowLimit:       snapshotSweepBatch,
	})
	cancel()
	if err != nil {
		logger.Error().Err(err).Msg("snapshot sweep: list")
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		h.sweepSnapshot(ctx, row, logger.With().Str("snapshot_id", row.ID.String()).Str("host_id", row.HostID).Logger())
	}
}

func (h *Handlers) sweepSnapshot(ctx context.Context, row db.SandboxSnapshot, logger zerolog.Logger) {
	client, err := h.vmdForHost(ctx, row.HostID)
	if err != nil {
		logger.Warn().Err(err).Msg("snapshot sweep: host unresolved")
		return
	}
	switch row.Status {
	case "creating":
		cctx, cancel := context.WithTimeout(ctx, snapshotCaptureTimeout)
		snap, err := client.CreateSavedSnapshot(cctx, row.SandboxID.String(), row.ID.String(), row.Kind)
		cancel()
		switch {
		case err == nil:
			if _, err := h.markSnapshotReady(ctx, row.ID, snap); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				logger.Error().Err(err).Msg("snapshot sweep: mark ready")
				return
			}
			logger.Info().Msg("snapshot sweep: settled ready from the host")
		case status.Code(err) == codes.NotFound, status.Code(err) == codes.FailedPrecondition,
			status.Code(err) == codes.InvalidArgument, status.Code(err) == codes.AlreadyExists:
			// The host cannot produce this snapshot as things stand.
			h.failSnapshot(row.ID, row.HostID, client)
			logger.Warn().Err(err).Msg("snapshot sweep: settled failed from the host")
		default:
			logger.Warn().Err(err).Msg("snapshot sweep: host did not settle the capture; will ask again")
		}
	case "deleting":
		if err := h.deleteSnapshotOnHost(ctx, row); err != nil {
			logger.Warn().Err(err).Msg("snapshot sweep: delete not finished; will ask again")
			return
		}
		logger.Info().Msg("snapshot sweep: delete finished")
	}
}
