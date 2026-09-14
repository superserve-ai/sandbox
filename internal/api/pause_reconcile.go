package api

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync/atomic"
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
// dispatch time (see claimBatch). Exported so tests can run a tick directly.
func (h *Handlers) ReconcilePendingPausesOnce(ctx context.Context, logger zerolog.Logger) {
	_, err := claimBatch(ctx, pauseReconcileWorkers, pauseReconcileBatch, func(ctx context.Context, limit int32) ([]uuid.UUID, error) {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return h.DB.ListPendingPauses(qctx, db.ListPendingPausesParams{MinAgeSeconds: pauseReconcileMinAge, MaxRows: limit})
	}, func(ctx context.Context, id uuid.UUID) (db.ClaimPendingPauseRow, error) {
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
	if err != nil {
		logger.Error().Err(err).Msg("pause reconcile: list failed")
	}
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
		if !h.pauseLanded(ctx, row.ID, row.TeamID, lease) {
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

// pauseLanded answers for a finalize whose reply was lost. The lease version
// only moves when a worker claims the operation or a new pause begins, so a
// row still at this lease's version that no longer carries the operation, and
// was not deleted, was finalized by this holder, whatever it has been moved
// to since. A moved version means another worker took the operation over and
// its outcome, success or failed, is that worker's to record.
func (h *Handlers) pauseLanded(ctx context.Context, id, teamID uuid.UUID, lease pauseLease) bool {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), asyncTimeout)
	defer cancel()
	sb, err := h.DB.GetSandbox(rctx, db.GetSandboxParams{ID: id, TeamID: teamID})
	if err != nil || sb.Status == db.SandboxStatusDeleted || sb.PauseOpLeaseVersion != lease.version {
		return false
	}
	return !sb.PauseOpID.Valid || sb.PauseOpID.Bytes != lease.id.Bytes
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

// pauseLeaseSeconds is how long the caller that began a pause owns it before
// the reconciler may take over: the foreground attempts plus a margin.
const pauseLeaseSeconds int32 = 90

// leaseDeadline is when a claim stops being its holder's: the expiry the claim
// returned, or the nominal lease from when it was taken.
func leaseDeadline(stored pgtype.Timestamptz, claimedAt time.Time, leaseSeconds int32) time.Time {
	if stored.Valid {
		return stored.Time
	}
	return claimedAt.Add(time.Duration(leaseSeconds) * time.Second)
}

// attemptDeadline bounds one host attempt: budget from now, or what is left of
// the lease after room for the finalize write and clock skew, whichever comes
// first. ok is false when nothing is left.
func attemptDeadline(leaseUntil time.Time, budget time.Duration) (time.Time, bool) {
	now := time.Now()
	d := now.Add(budget)
	if lease := leaseUntil.Add(-asyncTimeout - pauseLeaseSkew); lease.Before(d) {
		d = lease
	}
	return d, d.After(now)
}

// captureFor is capture for code that no longer holds the request.
func (h *Handlers) captureFor(actorID *uuid.UUID, teamID uuid.UUID, event string, props map[string]any) {
	if h.Analytics == nil {
		return
	}
	var actor string
	if actorID != nil {
		actor = actorID.String()
	}
	h.Analytics.Capture(actor, teamID.String(), event, props)
}

// claimRefillRounds bounds the listings of one claimBatch call: a candidate
// whose claim keeps failing for a reason other than contention would
// otherwise be listed again without end.
const claimRefillRounds = 4

// claimBatch lists and claims until batch rows are claimed or the list runs
// dry, and reports how many were claimed. Every replica lists the same oldest
// candidates, so a claim lost to another replica is replaced from the next
// listing rather than costing this replica its share of the tick.
func claimBatch[T any](ctx context.Context, workers int, batch int32, list func(ctx context.Context, limit int32) ([]uuid.UUID, error), claim func(ctx context.Context, id uuid.UUID) (T, error), process func(row T, claimedAt time.Time)) (int, error) {
	claimed := 0
	for round, remaining := 0, batch; round < claimRefillRounds && remaining > 0; round++ {
		ids, err := list(ctx, remaining)
		if err != nil {
			return claimed, err
		}
		n := claimEach(ctx, workers, ids, claim, process)
		claimed += n
		if int32(len(ids)) < remaining {
			break
		}
		remaining -= int32(n)
	}
	return claimed, nil
}

// claimEach hands candidate ids to at most workers goroutines; each claims
// its candidate at dispatch time (re-checked under lock, leased only then), so
// one scan feeds every worker and no leased row waits. An empty claim is
// skipped; the count of claimed rows is returned.
func claimEach[T any](ctx context.Context, workers int, ids []uuid.UUID, claim func(ctx context.Context, id uuid.UUID) (T, error), process func(row T, claimedAt time.Time)) int {
	var claimed atomic.Int32
	dispatchBounded(ctx, ids, workers, func(id uuid.UUID) {
		claimedAt := time.Now()
		row, err := claim(ctx, id)
		if err != nil {
			return
		}
		claimed.Add(1)
		process(row, claimedAt)
	})
	return int(claimed.Load())
}
