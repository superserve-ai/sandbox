package api

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ReaperConfig controls the timeout reaper loop.
type ReaperConfig struct {
	// Interval is how often the reaper polls for expired sandboxes.
	Interval time.Duration
	// BatchSize bounds the number of sandboxes destroyed per cycle so a
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
// destroys sandboxes whose `timeout_seconds` hard cap has elapsed since
// their creation. The hard cap is measured from `created_at`, not from
// `last_activity_at`, so paused / idle sandboxes are NOT exempt — the
// user set a timeout because they wanted the sandbox gone after N
// seconds regardless of state.
//
// The reaper exits cleanly when ctx is cancelled. Call once at control
// plane startup with the process-lifetime context.
//
// Design notes:
//   - Poll-based instead of a timer-per-sandbox because sandboxes can be
//     created/deleted/paused without going through this process, so a
//     persistent timer would drift from the DB source of truth.
//   - Errors during individual destroys are logged but do not stop the
//     loop — a single broken sandbox should not block the rest of the
//     reaper.
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
	// Atomically claim expired sandboxes and mark them deleted in one
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

	log.Info().Int("count", len(expired)).Msg("reaper: destroying expired sandboxes")

	for _, sbx := range expired {
		// Check for shutdown between each destroy so we exit promptly.
		select {
		case <-ctx.Done():
			return
		default:
		}

		h.destroyExpired(ctx, sbx)
	}
}

// destroyExpired cleans up one sandbox that was atomically claimed by
// ClaimExpiredSandboxes. The DB row is already marked deleted by the time
// this runs, so there is no separate DestroySandbox call.
//
// Order of operations:
//  1. VMD destroy (best effort — the DB row is already marked deleted, so
//     if VMD doesn't know the sandbox we still log and continue rather
//     than leaving the activity trail empty).
//  2. Activity log.
func (h *Handlers) destroyExpired(ctx context.Context, sbx db.ClaimExpiredSandboxesRow) {
	l := log.With().
		Str("sandbox_id", sbx.ID.String()).
		Str("team_id", sbx.TeamID.String()).
		Str("name", sbx.Name).
		Logger()

	// Best-effort VMD destroy. Use a short per-sandbox timeout so one
	// stuck sandbox does not stall the whole reaper batch.
	vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
	err := h.VMD.DestroyInstance(vmdCtx, sbx.ID.String(), true)
	vmdCancel()
	if err != nil {
		// The DB row is already deleted, so log a warning and continue.
		// If VMD still has the VM running, the next ExecStartPre cleanup
		// will kill it.
		l.Warn().Err(err).Msg("reaper: VMD destroy failed (DB already marked deleted)")
	}

	l.Info().Msg("reaper: sandbox destroyed due to timeout")

	// Fire-and-forget activity log.
	h.logActivityAsync(ctx, sbx.ID, sbx.TeamID, "sandbox", "timeout_destroyed", "success", &sbx.Name, nil, nil)
}
