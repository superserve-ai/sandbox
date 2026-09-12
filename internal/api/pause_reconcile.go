package api

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// A pause whose caller gave up is not undone: an error after dispatch does not
// prove the VM still runs. The row stays 'pausing' and this loop asks the host
// again until it answers with a snapshot, NotFound, or a failed precondition;
// anything else is retried.
const (
	pauseReconcileInterval = 30 * time.Second
	// Claimable only after the caller's whole lease, so its attempt is over.
	pauseReconcileMinAge       = pauseLeaseSeconds
	pauseReconcileLease  int32 = 75
	// Must end before the lease does, leaving room for the finalize write.
	pauseReconcileRPC           = 60 * time.Second
	pauseReconcileBatch   int32 = 20
	pauseReconcileWorkers       = 4
	pauseAttentionAfter         = 30 * time.Minute
	// Allowance for clock skew between this process and the database when
	// judging how much of a lease is left.
	pauseLeaseSkew = 5 * time.Second
)

// pauseLease identifies the pause operation a worker holds; every terminal
// write is fenced on it.
type pauseLease struct {
	id      pgtype.UUID
	version int64
}

func pauseRetryAfter() int32 { return 30 + rand.Int32N(30) }

// StartPauseReconciler runs the reconcile loop until ctx ends. Own goroutine:
// its host round trips must not hold off the reaper's tick.
func (h *Handlers) StartPauseReconciler(ctx context.Context) {
	logger := log.Logger
	go func() {
		ticker := time.NewTicker(pauseReconcileInterval)
		defer ticker.Stop()
		logger.Info().Msg("pause reconciler started")
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sentrylog.RunSafe("pause-reconcile", func() { h.ReconcilePendingPausesOnce(ctx, logger) })
			}
		}
	}()
}

// ReconcilePendingPausesOnce lists abandoned pauses, at most a batch per tick,
// and drives each toward a decided state; each worker claims its row at
// dispatch time (see claimEach). Exported so tests can run a tick directly.
func (h *Handlers) ReconcilePendingPausesOnce(ctx context.Context, logger zerolog.Logger) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ids, err := h.DB.ListPendingPauses(qctx, db.ListPendingPausesParams{MinAgeSeconds: pauseReconcileMinAge, MaxRows: pauseReconcileBatch})
	cancel()
	if err != nil {
		logger.Error().Err(err).Msg("pause reconcile: list failed")
		return
	}
	if len(ids) == 0 {
		return
	}
	claimEach(ctx, pauseReconcileWorkers, ids, func(ctx context.Context, id uuid.UUID) (db.ClaimPendingPauseRow, error) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		row, err := h.DB.ClaimPendingPause(cctx, db.ClaimPendingPauseParams{ID: id, MinAgeSeconds: pauseReconcileMinAge, LeaseSeconds: pauseReconcileLease})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error().Err(err).Str("sandbox_id", id.String()).Msg("pause reconcile: claim failed")
		}
		return row, err
	}, func(row db.ClaimPendingPauseRow, claimedAt time.Time) {
		h.reconcilePause(ctx, row, leaseDeadline(row.PauseOpLeaseUntil, claimedAt, pauseReconcileLease), logger)
	})
}

// reconcilePause makes one attempt on a claimed row. leaseUntil is when the
// claim stops being this worker's: nothing is sent to the host unless the
// whole attempt, finalize included, fits before then.
func (h *Handlers) reconcilePause(ctx context.Context, row db.ClaimPendingPauseRow, leaseUntil time.Time, logger zerolog.Logger) {
	lease := pauseLease{id: row.PauseOpID, version: row.PauseOpLeaseVersion}
	l := logger.With().
		Str("sandbox_id", row.ID.String()).
		Str("host_id", row.HostID).
		Str("pause_op_id", uuid.UUID(row.PauseOpID.Bytes).String()).
		Int64("lease_version", row.PauseOpLeaseVersion).
		Logger()
	started := time.Now()

	// One absolute deadline for everything below: the attention write and
	// host resolution spend the same lease as the RPC.
	deadline, ok := attemptDeadline(leaseUntil, pauseReconcileRPC)
	if !ok {
		l.Warn().Msg("pause reconcile: lease too short to dispatch, skipping")
		return
	}
	dctx, dcancel := context.WithDeadline(ctx, deadline)
	defer dcancel()

	if row.PauseOpStartedAt.Valid && !row.PauseOpAttentionAt.Valid && time.Since(row.PauseOpStartedAt.Time) > pauseAttentionAfter {
		h.flagPauseAttention(ctx, row.ID, lease, l)
	}

	// Resolved fresh on every attempt: the host may have been replaced since
	// the caller's try, and only the current host's answer counts.
	vmd, err := h.vmdForHost(dctx, row.HostID)
	if err != nil {
		l.Warn().Err(err).Msg("pause reconcile: host unresolved, retrying later")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
	}
	if !time.Now().Before(deadline) {
		l.Warn().Msg("pause reconcile: lease ran out during host resolution, skipping")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
	}

	snapshotPath, memPath, manifest, ackedToken, err := vmd.PauseInstance(dctx, row.ID.String(), "", uuid.UUID(row.PauseOpID.Bytes).String())
	if err != nil {
		RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultError, row.HostID, time.Since(started))
		if isVMDNotFound(err) || isVMDFailedPrecondition(err) {
			l.Warn().Err(err).Msg("pause reconcile: VM gone from its host, marking failed")
			h.failPause(ctx, row.ID, row.HostID, lease, l)
			return
		}
		l.Warn().Err(err).Msg("pause reconcile: undecided, retrying later")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
	}

	// Finalized and logged as what it was started as, not as a reconcile.
	trigger := "pause"
	if row.PauseOpTrigger != nil && *row.PauseOpTrigger != "" {
		trigger = *row.PauseOpTrigger
	}
	fctx, fcancel := context.WithTimeout(ctx, asyncTimeout)
	defer fcancel()
	params := db.FinalizePauseParams{
		ID:                  row.ID,
		TeamID:              row.TeamID,
		PauseOpID:           lease.id,
		PauseOpLeaseVersion: &lease.version,
		Path:                snapshotPath,
		MemPath:             &memPath,
		Trigger:             trigger,
		PauseToken:          ackedToken,
	}
	applyManifest(&params, manifest)
	if _, err := h.finalizePause(fctx, params); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultError, row.HostID, time.Since(started))
			l.Warn().Msg("pause reconcile: row moved on before finalize")
			return
		}
		if !h.pauseLanded(ctx, row.ID, row.TeamID) {
			RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultError, row.HostID, time.Since(started))
			l.Error().Err(err).Msg("pause reconcile: finalize failed, retrying later")
			h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
			return
		}
		l.Warn().Err(err).Msg("pause reconcile: finalize answer lost after it committed")
	}

	l.Info().Msg("pause reconcile: sandbox paused")
	RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultSuccess, row.HostID, time.Since(started))
	// Attributed to whoever asked for it; automatic pauses carry no actor.
	var actor *uuid.UUID
	if row.PauseOpActorID.Valid {
		id := uuid.UUID(row.PauseOpActorID.Bytes)
		actor = &id
	}
	h.logSandboxActivity(ctx, row.ID, row.TeamID, actor, "sandbox", pauseActivity(trigger), "success", &row.Name, nil, nil)
	if trigger == "pause" {
		// The same product event the request path emits for its own finalize.
		h.captureFor(actor, row.TeamID, "sandbox_paused", map[string]any{"sandbox_id": row.ID.String()})
	}
}

// pauseLanded answers for a finalize whose reply was lost: a row that now
// reads paused with no operation was finalized by the lease holder, since
// nothing else moves a leased row out of 'pausing'.
func (h *Handlers) pauseLanded(ctx context.Context, id, teamID uuid.UUID) bool {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	defer cancel()
	sb, err := h.DB.GetSandbox(rctx, db.GetSandboxParams{ID: id, TeamID: teamID})
	return err == nil && sb.Status == db.SandboxStatusPaused && !sb.PauseOpID.Valid
}

// releasePauseLease hands an undecided pause back for a later attempt.
// retryAfter 0 makes it claimable as soon as it is old enough.
func (h *Handlers) releasePauseLease(ctx context.Context, id uuid.UUID, lease pauseLease, retryAfter int32, l zerolog.Logger) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	defer cancel()
	n, err := h.DB.ReleasePauseLease(rctx, db.ReleasePauseLeaseParams{
		RetryAfterSeconds:   retryAfter,
		ID:                  id,
		PauseOpID:           lease.id,
		PauseOpLeaseVersion: lease.version,
	})
	if err != nil {
		l.Error().Err(err).Msg("release pause lease failed; the lease expires on its own")
		return
	}
	if n == 0 {
		l.Warn().Msg("release pause lease skipped: lease no longer held")
	}
}

// failPause records that the sandbox's host has no VM to pause. Only the
// lease holder may write it, and only while the row is still 'pausing'.
func (h *Handlers) failPause(ctx context.Context, id uuid.UUID, hostID string, lease pauseLease, l zerolog.Logger) {
	started := time.Now()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	defer cancel()
	n, err := h.DB.MarkSandboxFailed(fctx, db.MarkSandboxFailedParams{
		ID:                  id,
		ObservedStatus:      db.SandboxStatusPausing,
		PauseOpID:           lease.id,
		PauseOpLeaseVersion: &lease.version,
	})
	if err != nil {
		RecordSandboxTransition(ctx, "fail", telemetry.ResultError, hostID, time.Since(started))
		l.Error().Err(err).Msg("mark pause failed write failed; the lease expires on its own")
		return
	}
	if n == 0 {
		l.Warn().Msg("mark pause failed skipped: lease no longer held")
		return
	}
	RecordSandboxTransition(ctx, "fail", telemetry.ResultSuccess, hostID, time.Since(started))
	if err := h.DB.DeleteSandboxSecrets(fctx, id); err != nil {
		l.Warn().Err(err).Msg("clear secret bindings after failed pause failed")
	}
}

func (h *Handlers) flagPauseAttention(ctx context.Context, id uuid.UUID, lease pauseLease, l zerolog.Logger) {
	actx, cancel := context.WithTimeout(ctx, asyncTimeout)
	defer cancel()
	n, err := h.DB.MarkPauseAttention(actx, db.MarkPauseAttentionParams{
		ID:                  id,
		PauseOpID:           lease.id,
		PauseOpLeaseVersion: lease.version,
	})
	if err != nil {
		l.Error().Err(err).Msg("mark pause attention failed")
		return
	}
	if n > 0 {
		// Error level so it reaches the error tracker; retries continue.
		l.Error().Msg("pause pending past attention threshold: host has not given a decided answer")
	}
}

// pauseActivity is the activity-log action for a pause cause: "paused" for a
// requested pause, "<cause>_paused" for the automatic ones.
func pauseActivity(trigger string) string {
	if trigger == "pause" {
		return "paused"
	}
	return trigger + "_paused"
}
