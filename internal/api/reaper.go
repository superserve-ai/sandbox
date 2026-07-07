package api

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// ReaperConfig controls the timeout reaper loop.
type ReaperConfig struct {
	// Interval is how often the reaper polls for expired sandboxes.
	Interval time.Duration
	// BatchSize bounds the number of sandboxes paused per cycle so a
	// sudden wave of expirations cannot tie up the control plane.
	BatchSize int32
	// Parallelism caps concurrent pauses within a single batch. 0 → 10.
	Parallelism int
}

// DefaultReaperConfig returns sensible defaults for the timeout reaper.
func DefaultReaperConfig() ReaperConfig {
	return ReaperConfig{
		Interval:    30 * time.Second,
		BatchSize:   50,
		Parallelism: 10,
	}
}

// StartTimeoutReaper launches a background goroutine that periodically
// pauses active sandboxes whose `timeout_seconds` has elapsed. The window
// tracks the current active session (re-armed on each resume), not total
// lifetime. Already-paused sandboxes are left alone — they are already stopped.
//
// The reaper exits cleanly when ctx is cancelled. Call once at control
// plane startup with the process-lifetime context.
//
// Design notes:
//   - Poll-based instead of a timer-per-sandbox because sandboxes can be
//     created/paused/resumed without going through this process, so a
//     persistent timer would drift from the DB source of truth.
//   - Errors during individual pauses are logged but do not stop the
//     loop — a single broken sandbox should not block the rest.
//   - The batch size bounds work per tick so a burst of expirations
//     cannot starve the control plane for extended periods.
func (h *Handlers) StartTimeoutReaper(ctx context.Context, cfg ReaperConfig) {
	go h.reaperLoop(ctx, cfg)
}

func (h *Handlers) reaperLoop(ctx context.Context, cfg ReaperConfig) {
	parallelism := cfg.Parallelism
	if parallelism <= 0 {
		parallelism = 10
	}
	if int32(parallelism) > cfg.BatchSize {
		parallelism = int(cfg.BatchSize)
	}

	log.Info().
		Dur("interval", cfg.Interval).
		Int32("batch_size", cfg.BatchSize).
		Int("parallelism", parallelism).
		Msg("timeout reaper started")

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	runTick := func() {
		sentrylog.RunSafe("reaper", func() { h.reapOnce(ctx, cfg.BatchSize, parallelism) })
		sentrylog.RunSafe("interval-sweep", func() { h.sweepOrphanedIntervals(ctx) })
		sentrylog.RunSafe("revocation-cleanup", func() { h.cleanupExpiredRevocations(ctx) })
		sentrylog.RunSafe("snapshot-row-sweep", func() { h.sweepOrphanedSnapshotRows(ctx) })
		// Auto-delete runs after the DB-only sweeps (interval/revocation/
		// snapshot) so a slow host during its batch teardown can't delay them.
		sentrylog.RunSafe("auto-delete", func() { h.reapAutoDeleteOnce(ctx, cfg.BatchSize, parallelism) })
	}

	// Run once immediately so a control plane restart does not delay
	// cleanup by up to `interval` seconds.
	runTick()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("timeout reaper exiting")
			return
		case <-ticker.C:
			runTick()
		}
	}
}

// sweepOrphanedIntervals closes intervals left open on no-longer-active
// sandboxes — defense-in-depth for WAU accuracy, off the request path.
func (h *Handlers) sweepOrphanedIntervals(ctx context.Context) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n, err := h.DB.CloseOrphanedActiveIntervals(qctx)
	if err != nil {
		log.Error().Err(err).Msg("reaper: CloseOrphanedActiveIntervals failed")
		return
	}
	if n > 0 {
		log.Warn().Int64("closed", n).Msg("reaper: closed orphaned active intervals")
	}
}

// cleanupExpiredRevocations deletes sandbox_revocation and revoked_proxy_token
// rows past their TTL — once no live JWT can carry them, the entries are moot.
func (h *Handlers) cleanupExpiredRevocations(ctx context.Context) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := h.DB.DeleteExpiredSandboxRevocations(queryCtx)
	if err != nil {
		log.Warn().Err(err).Msg("reaper: cleanup revocations failed")
		return
	}
	if n > 0 {
		log.Info().Int64("reaped", n).Msg("reaper: deleted expired sandbox revocations")
	}

	tn, err := h.DB.DeleteExpiredRevokedProxyTokens(queryCtx)
	if err != nil {
		log.Warn().Err(err).Msg("reaper: cleanup revoked proxy tokens failed")
		return
	}
	if tn > 0 {
		log.Info().Int64("reaped", tn).Msg("reaper: deleted expired revoked proxy tokens")
	}
}

// dispatchBounded runs fn for each item with at most `parallelism` concurrent
// goroutines, stopping dispatch early on ctx cancellation and waiting for all
// started goroutines before returning.
func dispatchBounded[T any](ctx context.Context, items []T, parallelism int, fn func(T)) {
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
dispatch:
	for _, item := range items {
		select {
		case <-ctx.Done():
			break dispatch
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(item T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(item)
		}(item)
	}
	wg.Wait()
}

func (h *Handlers) reapOnce(ctx context.Context, batchSize int32, parallelism int) {
	// Atomically claim expired active sandboxes and mark them 'pausing' in one
	// CTE+UPDATE. FOR UPDATE SKIP LOCKED inside the query ensures that
	// concurrent reaper replicas skip rows already being processed.
	// Use a bounded timeout — if the DB is slow, skip this cycle rather
	// than block the whole loop.
	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	expired, err := h.DB.ClaimExpiredSandboxes(queryCtx, batchSize)
	queryCancel()
	if err != nil {
		log.Error().Err(err).Msg("reaper: ClaimExpiredSandboxes failed")
		return
	}

	if len(expired) == 0 {
		return
	}

	log.Info().Int("count", len(expired)).Msg("reaper: pausing expired sandboxes")

	dispatchBounded(ctx, expired, parallelism, func(sbx db.ClaimExpiredSandboxesRow) {
		h.pauseExpired(ctx, sbx)
	})
}

// sweepOrphanedSnapshotRows deletes snapshot rows for long-destroyed
// sandboxes — the backstop for destroy teardown that never ran (crash or
// shutdown between the soft-delete claim and cleanupSandboxSnapshots).
// Row deletion also unblocks the vm reconciler's disk scan, which reclaims
// the now-orphaned files.
func (h *Handlers) sweepOrphanedSnapshotRows(ctx context.Context) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n, err := h.DB.DeleteSnapshotsOfDestroyedSandboxes(qctx)
	if err != nil {
		log.Warn().Err(err).Msg("reaper: DeleteSnapshotsOfDestroyedSandboxes failed")
		return
	}
	if n > 0 {
		log.Warn().Int64("deleted", n).Msg("reaper: removed snapshot rows orphaned by unfinished destroy teardown")
	}
}

// reapAutoDeleteOnce deletes paused sandboxes whose auto-delete deadline has
// passed. ClaimAutoDeleteSandboxes soft-deletes the rows (revocation written,
// intervals closed) in one guarded statement, so everything after the claim is
// best-effort teardown of VM state and artifacts — same contract as the
// user-initiated DeleteSandbox, where the vm reconciler backstops any teardown
// step that fails.
func (h *Handlers) reapAutoDeleteOnce(ctx context.Context, batchSize int32, parallelism int) {
	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	due, err := h.DB.ClaimAutoDeleteSandboxes(queryCtx, db.ClaimAutoDeleteSandboxesParams{
		BatchSize:           batchSize,
		RevocationExpiresAt: time.Now().Add(SecretsJWTLifetime),
	})
	queryCancel()
	if err != nil {
		log.Error().Err(err).Msg("reaper: ClaimAutoDeleteSandboxes failed")
		return
	}

	if len(due) == 0 {
		return
	}

	log.Info().Int("count", len(due)).Msg("reaper: deleting expired paused sandboxes")

	dispatchBounded(ctx, due, parallelism, func(sbx db.ClaimAutoDeleteSandboxesRow) {
		h.teardownAutoDeleted(ctx, sbx)
	})
}

// autoDeleteTeardownTimeout bounds one sandbox's teardown in the reaper.
// The VMD calls inside carry their own timeouts, but the snapshot DB calls
// do not — without this umbrella a hung query would pin a dispatch slot and
// wedge the reaper loop on wg.Wait.
const autoDeleteTeardownTimeout = 2 * time.Minute

// teardownAutoDeleted reclaims VM state for one sandbox already soft-deleted
// by ClaimAutoDeleteSandboxes, via the same teardown path as DeleteSandbox.
func (h *Handlers) teardownAutoDeleted(ctx context.Context, sbx db.ClaimAutoDeleteSandboxesRow) {
	l := log.With().
		Str("sandbox_id", sbx.ID.String()).
		Str("team_id", sbx.TeamID.String()).
		Str("name", sbx.Name).
		Logger()

	tctx, cancel := context.WithTimeout(ctx, autoDeleteTeardownTimeout)
	defer cancel()
	h.teardownDestroyedSandbox(tctx, sbx.ID, sbx.HostID, sbx.BasePath, sbx.TemplateID)

	l.Info().Msg("reaper: sandbox auto-deleted after paused window elapsed")
	h.logSandboxActivity(tctx, sbx.ID, sbx.TeamID, nil, "sandbox", "auto_deleted", "success", &sbx.Name, nil, nil)
}

// pauseExpired pauses one sandbox that was atomically claimed by
// ClaimExpiredSandboxes (already marked 'pausing' in DB).
//
// This is a distributed transaction across two systems (VMD + Postgres) so
// we use a saga: if any DB step fails after VMD has stopped the VM, we
// compensate by resuming the VM and reverting DB to 'active' so the reaper
// can retry cleanly on the next tick. If compensation itself fails, we mark
// the sandbox as 'failed' to bound the blast radius — operator intervention
// is required, but we never leak it stuck in 'pausing' or loop forever.
//
// Order of operations:
//  1. VMD PauseInstance — stops the VM, writes snapshot files to disk.
//  2. DB FinalizePause — inserts the snapshot row, links it to the sandbox,
//     and flips status from 'pausing' to 'paused' in a single CTE.
//
// Failure handling:
//   - Step 1 fails → VM is still running → revert DB to 'active'.
//   - Step 2 fails → VM is stopped → call rollbackPausedVM (resume + revert).
func (h *Handlers) pauseExpired(ctx context.Context, sbx db.ClaimExpiredSandboxesRow) {
	l := log.With().
		Str("sandbox_id", sbx.ID.String()).
		Str("team_id", sbx.TeamID.String()).
		Str("name", sbx.Name).
		Logger()
	started := time.Now()

	// ClaimExpiredSandboxes's CTE atomically closed the open active
	// interval together with the status transition; nothing to do here.
	// Reverts below reopen a new interval if the sandbox returns to active.

	vmd, vmdLookupErr := h.vmdForHost(ctx, sbx.HostID)
	if vmdLookupErr != nil {
		l.Error().Err(vmdLookupErr).Msg("reaper: resolve VMD failed — reverting to active")
		h.revertToActiveOrFail(ctx, sbx, vmdLookupErr, l)
		return
	}

	vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
	snapshotPath, memPath, err := vmd.PauseInstance(vmdCtx, sbx.ID.String(), "")
	vmdCancel()
	if err != nil {
		// VM never stopped — safe to revert DB to active so the reaper
		// retries on the next tick.
		l.Error().Err(err).Msg("reaper: VMD PauseInstance failed — reverting to active")
		h.revertToActiveOrFail(ctx, sbx, err, l)
		return
	}

	postCtx, postCancel := context.WithTimeout(ctx, vmdTimeout)
	defer postCancel()

	if _, err := h.DB.FinalizePause(postCtx, db.FinalizePauseParams{
		ID:        sbx.ID,
		TeamID:    sbx.TeamID,
		Path:      snapshotPath,
		MemPath:   &memPath,
		SizeBytes: 0,
		Trigger:   "timeout",
	}); err != nil {
		l.Error().Err(err).Msg("reaper: FinalizePause failed — rolling back VMD pause")
		h.rollbackPausedVM(ctx, sbx, snapshotPath, memPath, err, l)
		return
	}

	l.Info().Msg("reaper: sandbox paused due to timeout")
	RecordSandboxTransition(ctx, "timeout_pause", telemetry.ResultSuccess, sbx.HostID, time.Since(started))
	// Interval was already closed at the top of pauseExpired; FinalizePause
	// is the end of the VMD pause work, not the leave-active moment.
	h.logSandboxActivity(ctx, sbx.ID, sbx.TeamID, nil, "sandbox", "timeout_paused", "success", &sbx.Name, nil, nil)
}

// rollbackPausedVM is the saga compensation for a failed pause. The VM is
// already stopped at the VMD layer, so we resume it to bring the system
// back to a consistent state, then revert DB status to 'active' so the
// reaper retries cleanly. If resume or the DB revert fails, we mark the
// sandbox 'failed' so it stops being touched by the reaper.
//
// `cause` is the original DB error that triggered the rollback, propagated
// so the terminal log line tells the operator what actually went wrong.
func (h *Handlers) rollbackPausedVM(ctx context.Context, sbx db.ClaimExpiredSandboxesRow, snapshotPath, memPath string, cause error, l zerolog.Logger) {
	rl := l.With().
		Str("snapshot_path", snapshotPath).
		Str("mem_path", memPath).
		AnErr("cause", cause).
		Logger()

	vmd, vmdLookupErr := h.vmdForHost(ctx, sbx.HostID)
	if vmdLookupErr != nil {
		rl.Error().Err(vmdLookupErr).Msg("reaper: resolve VMD for rollback failed")
		h.markSandboxFailed(ctx, sbx, "resolve VMD failed during rollback", rl)
		return
	}

	vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
	// Reaper rollback resume: brings the VM back up after a pause-DB-write
	// failure, before the customer ever sees the transition.
	_, _, _, err := vmd.ResumeInstance(vmdCtx, sbx.ID.String(), snapshotPath, memPath)
	vmdCancel()
	if err != nil {
		rl.Error().Err(err).Msg("reaper: rollback resume failed")
		h.markSandboxFailed(ctx, sbx, "rollback resume failed after pause DB error", rl)
		return
	}

	// VM is running again — revert DB to active so reaper retries cleanly.
	revertCtx, revertCancel := context.WithTimeout(ctx, asyncTimeout)
	defer revertCancel()
	if err := h.DB.UpdateSandboxStatus(revertCtx, db.UpdateSandboxStatusParams{
		ID:     sbx.ID,
		Status: db.SandboxStatusActive,
		TeamID: sbx.TeamID,
	}); err != nil {
		rl.Error().Err(err).Msg("reaper: rollback DB revert failed (VM resumed but status not updated)")
		h.markSandboxFailed(ctx, sbx, "rollback DB revert failed after pause DB error", rl)
		return
	}

	// Reopen the interval that pauseExpired closed at the top — sandbox
	// is back to active and should resume being counted as such.
	// actor_id is nil because this is a system-initiated revert, not a
	// user action.
	h.openSandboxIntervalInheritActor(ctx, sbx.ID, sbx.TeamID)

	rl.Warn().Msg("reaper: rolled back failed pause, sandbox is active again — will retry next tick")
}

// revertToActiveOrFail is the simple revert path used when VMD pause fails
// before any side effect — the VM is still running, so we just need to
// undo the 'pausing' status. If the revert itself fails, we mark the
// sandbox 'failed' so the reaper does not loop on it.
//
// `cause` is the original VMD error, propagated for terminal logging.
func (h *Handlers) revertToActiveOrFail(ctx context.Context, sbx db.ClaimExpiredSandboxesRow, cause error, l zerolog.Logger) {
	revertCtx, revertCancel := context.WithTimeout(ctx, asyncTimeout)
	defer revertCancel()
	if err := h.DB.UpdateSandboxStatus(revertCtx, db.UpdateSandboxStatusParams{
		ID:     sbx.ID,
		Status: db.SandboxStatusActive,
		TeamID: sbx.TeamID,
	}); err != nil {
		l.Error().Err(err).AnErr("cause", cause).Msg("reaper: revert to active failed (after VMD pause error)")
		h.markSandboxFailed(ctx, sbx, "revert to active failed after VMD pause error", l.With().AnErr("cause", cause).Logger())
		return
	}
	// Reopen the interval that pauseExpired closed at the top — sandbox
	// is back to active. System-initiated revert, so actor_id is nil.
	h.openSandboxIntervalInheritActor(ctx, sbx.ID, sbx.TeamID)
}

// markSandboxFailed sets the sandbox to 'failed' as a terminal state for
// reaper-side compensation paths. Emits a single high-signal log line with
// `reason` and any context already on `l` so on-call has one place to look
// when alerting fires on `status=failed`.
//
// Best-effort: if the DB write itself fails, we log loudly and stop — at
// that point the sandbox is stuck in 'pausing', but the reaper loop is
// already bounded because future ticks only claim 'active' sandboxes.
func (h *Handlers) markSandboxFailed(ctx context.Context, sbx db.ClaimExpiredSandboxesRow, reason string, l zerolog.Logger) {
	started := time.Now()
	failCtx, failCancel := context.WithTimeout(ctx, asyncTimeout)
	defer failCancel()
	// MarkSandboxFailedInTeam's CTE bundles the active-interval close into
	// the same statement; no separate close call needed.
	if err := h.DB.MarkSandboxFailedInTeam(failCtx, db.MarkSandboxFailedInTeamParams{
		ID:     sbx.ID,
		TeamID: sbx.TeamID,
	}); err != nil {
		RecordSandboxTransition(ctx, "fail", telemetry.ResultError, sbx.HostID, time.Since(started))
		l.Error().Err(err).Str("reason", reason).Msg("reaper: TERMINAL — sandbox stuck in 'pausing', mark-failed also failed, manual recovery required")
		return
	}
	RecordSandboxTransition(ctx, "fail", telemetry.ResultSuccess, sbx.HostID, time.Since(started))
	l.Error().Str("reason", reason).Msg("reaper: TERMINAL — sandbox marked 'failed', manual recovery required")
}
