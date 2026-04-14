package api

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ReaperConfig controls the timeout reaper loop.
type ReaperConfig struct {
	// Interval is how often the reaper polls for expired sandboxes.
	Interval time.Duration
	// BatchSize bounds the number of sandboxes paused per cycle so a
	// sudden wave of expirations cannot tie up the control plane.
	BatchSize int32
}

// DefaultReaperConfig returns sensible defaults for the timeout reaper.
func DefaultReaperConfig() ReaperConfig {
	return ReaperConfig{
		Interval:  30 * time.Second,
		BatchSize: 50,
	}
}

// StartTimeoutReaper launches a background goroutine that periodically
// pauses active sandboxes whose `timeout_seconds` hard cap has elapsed since
// their creation. The hard cap is measured from `created_at`. Already-idle
// sandboxes are left alone — they are already stopped.
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
	log.Info().
		Dur("interval", cfg.Interval).
		Int32("batch_size", cfg.BatchSize).
		Msg("timeout reaper started")

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Run once immediately so a control plane restart does not delay
	// cleanup by up to `interval` seconds.
	h.reapOnce(ctx, cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("timeout reaper exiting")
			return
		case <-ticker.C:
			h.reapOnce(ctx, cfg.BatchSize)
		}
	}
}

func (h *Handlers) reapOnce(ctx context.Context, batchSize int32) {
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

	for _, sbx := range expired {
		// Check for shutdown between each pause so we exit promptly.
		select {
		case <-ctx.Done():
			return
		default:
		}

		h.pauseExpired(ctx, sbx)
	}
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
//  2. DB CreateSnapshot — inserts the snapshot row.
//  3. DB SetSandboxSnapshot — links the snapshot to the sandbox.
//  4. DB UpdateSandboxStatus(idle) — finalizes the pause.
//
// Failure handling:
//   - Step 1 fails → VM is still running → revert DB to 'active'.
//   - Steps 2-4 fail → VM is stopped → call rollbackPausedVM (resume + revert).
func (h *Handlers) pauseExpired(ctx context.Context, sbx db.ClaimExpiredSandboxesRow) {
	l := log.With().
		Str("sandbox_id", sbx.ID.String()).
		Str("team_id", sbx.TeamID.String()).
		Str("name", sbx.Name).
		Logger()

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

	// Atomic post-VMD bookkeeping: insert the snapshot row, link it to
	// the sandbox, and flip status from pausing → idle in a single CTE.
	// Same query as the user-initiated PauseSandbox handler, so the two
	// code paths have identical atomicity guarantees.
	triggerName := "timeout"
	if _, err := h.DB.FinalizePause(postCtx, db.FinalizePauseParams{
		ID:        sbx.ID,
		TeamID:    sbx.TeamID,
		Path:      snapshotPath,
		MemPath:   &memPath,
		SizeBytes: 0,
		Saved:     false,
		Name:      &triggerName,
		Trigger:   triggerName,
	}); err != nil {
		l.Error().Err(err).Msg("reaper: FinalizePause failed — rolling back VMD pause")
		h.rollbackPausedVM(ctx, sbx, snapshotPath, memPath, err, l)
		return
	}

	l.Info().Msg("reaper: sandbox paused due to timeout")
	h.logActivityAsync(ctx, sbx.ID, sbx.TeamID, "sandbox", "timeout_paused", "success", &sbx.Name, nil, nil)
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
	_, _, _, err := vmd.ResumeInstance(vmdCtx, sbx.ID.String(), snapshotPath, memPath, nil)
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
	}
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
	failCtx, failCancel := context.WithTimeout(ctx, asyncTimeout)
	defer failCancel()
	if err := h.DB.UpdateSandboxStatus(failCtx, db.UpdateSandboxStatusParams{
		ID:     sbx.ID,
		Status: db.SandboxStatusFailed,
		TeamID: sbx.TeamID,
	}); err != nil {
		l.Error().Err(err).Str("reason", reason).Msg("reaper: TERMINAL — sandbox stuck in 'pausing', mark-failed also failed, manual recovery required")
		return
	}
	l.Error().Str("reason", reason).Msg("reaper: TERMINAL — sandbox marked 'failed', manual recovery required")
}
