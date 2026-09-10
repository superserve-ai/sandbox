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

// A pause whose caller gave up is not undone. The host may have finished it
// after the caller's deadline, and a definite error after dispatch says
// nothing about whether the VM is still running, so reverting the row to
// 'active' is a guess. The row stays 'pausing' and this loop asks the host
// again until it gets an answer it can act on: a snapshot, or NotFound from
// the sandbox's resolved host. Everything else is retried.
const (
	pauseReconcileInterval = 30 * time.Second
	// Claimable once the caller's whole lease has elapsed, so no caller
	// attempt can still be in flight when the reconciler dispatches.
	pauseReconcileMinAge       = pauseLeaseSeconds
	pauseReconcileLease  int32 = 75
	// The RPC ends, one way or another, before the lease does, with room for
	// the finalize write; a request outliving its lease could race the next
	// holder.
	pauseReconcileRPC           = 60 * time.Second
	pauseReconcileBatch   int32 = 20
	pauseReconcileWorkers       = 4
	pauseAttentionAfter         = 30 * time.Minute
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

// ReconcilePendingPausesOnce claims one batch of abandoned pauses and drives
// each toward a decided state. Exported so tests can run a tick directly.
func (h *Handlers) ReconcilePendingPausesOnce(ctx context.Context, logger zerolog.Logger) {
	qctx, qcancel := context.WithTimeout(ctx, 10*time.Second)
	rows, err := h.DB.ClaimPendingPauses(qctx, db.ClaimPendingPausesParams{
		LeaseSeconds:  pauseReconcileLease,
		MinAgeSeconds: pauseReconcileMinAge,
		MaxRows:       pauseReconcileBatch,
	})
	qcancel()
	if err != nil {
		logger.Error().Err(err).Msg("pause reconcile: claim failed")
		return
	}
	if len(rows) == 0 {
		return
	}
	logger.Info().Int("count", len(rows)).Msg("pause reconcile: retrying abandoned pauses")
	dispatchBounded(ctx, rows, pauseReconcileWorkers, func(row db.ClaimPendingPausesRow) {
		h.reconcilePause(ctx, row, logger)
	})
}

func (h *Handlers) reconcilePause(ctx context.Context, row db.ClaimPendingPausesRow, logger zerolog.Logger) {
	lease := pauseLease{id: row.PauseOpID, version: row.PauseOpLeaseVersion}
	l := logger.With().
		Str("sandbox_id", row.ID.String()).
		Str("host_id", row.HostID).
		Str("pause_op_id", uuid.UUID(row.PauseOpID.Bytes).String()).
		Int64("lease_version", row.PauseOpLeaseVersion).
		Logger()
	started := time.Now()

	if row.PauseOpStartedAt.Valid && !row.PauseOpAttentionAt.Valid && time.Since(row.PauseOpStartedAt.Time) > pauseAttentionAfter {
		h.flagPauseAttention(ctx, row.ID, lease, l)
	}

	// Resolved fresh on every attempt: the host may have been replaced since
	// the caller's try, and only the current host's answer counts.
	vmd, err := h.vmdForHost(ctx, row.HostID)
	if err != nil {
		l.Warn().Err(err).Msg("pause reconcile: host unresolved, retrying later")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
	}

	rctx, rcancel := context.WithTimeout(ctx, pauseReconcileRPC)
	snapshotPath, memPath, manifest, ackedToken, err := vmd.PauseInstance(rctx, row.ID.String(), "", uuid.UUID(row.PauseOpID.Bytes).String())
	rcancel()
	if err != nil {
		RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultError, row.HostID, time.Since(started))
		if isVMDNotFound(err) {
			l.Warn().Err(err).Msg("pause reconcile: VM gone from its host, marking failed")
			h.failPause(ctx, row.ID, lease, l)
			return
		}
		l.Warn().Err(err).Msg("pause reconcile: undecided, retrying later")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
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
		Trigger:             "reconcile",
		PauseToken:          ackedToken,
	}
	applyManifest(&params, manifest)
	if _, err := h.finalizePause(fctx, params); err != nil {
		RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultError, row.HostID, time.Since(started))
		if errors.Is(err, pgx.ErrNoRows) {
			l.Warn().Msg("pause reconcile: row moved on before finalize")
			return
		}
		l.Error().Err(err).Msg("pause reconcile: finalize failed, retrying later")
		h.releasePauseLease(ctx, row.ID, lease, pauseRetryAfter(), l)
		return
	}

	l.Info().Msg("pause reconcile: sandbox paused")
	RecordSandboxTransition(ctx, "reconcile_pause", telemetry.ResultSuccess, row.HostID, time.Since(started))
	h.logSandboxActivity(ctx, row.ID, row.TeamID, nil, "sandbox", "paused", "success", &row.Name, nil, nil)
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
func (h *Handlers) failPause(ctx context.Context, id uuid.UUID, lease pauseLease, l zerolog.Logger) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	defer cancel()
	n, err := h.DB.MarkSandboxFailed(fctx, db.MarkSandboxFailedParams{
		ID:                  id,
		ObservedStatus:      db.SandboxStatusPausing,
		PauseOpID:           lease.id,
		PauseOpLeaseVersion: &lease.version,
	})
	if err != nil {
		l.Error().Err(err).Msg("mark pause failed write failed; the lease expires on its own")
		return
	}
	if n == 0 {
		l.Warn().Msg("mark pause failed skipped: lease no longer held")
		return
	}
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
