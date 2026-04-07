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
	// Query with a bounded timeout — if the DB is slow, we should skip
	// this cycle rather than block the whole loop.
	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	expired, err := h.DB.ListExpiredSandboxes(queryCtx, batchSize)
	queryCancel()
	if err != nil {
		log.Error().Err(err).Msg("reaper: ListExpiredSandboxes failed")
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

// destroyExpired destroys one expired sandbox. Errors are logged but do
// not stop the reaper.
//
// Order of operations:
//  1. VMD destroy (best effort — if VMD doesn't know about the sandbox
//     because it was already cleaned up by a previous cycle or a VMD
//     restart, we still proceed to the DB update so the row does not
//     remain "expired" forever).
//  2. DB destroy (marks destroyed_at + status=deleted).
//  3. Activity log.
func (h *Handlers) destroyExpired(ctx context.Context, sbx db.ListExpiredSandboxesRow) {
	l := log.With().
		Str("sandbox_id", sbx.ID.String()).
		Str("team_id", sbx.TeamID.String()).
		Str("name", sbx.Name).
		Str("status", string(sbx.Status)).
		Logger()

	// Best-effort VMD destroy. Use a short per-sandbox timeout so one
	// stuck sandbox does not stall the whole reaper batch.
	vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
	err := h.VMD.DestroyInstance(vmdCtx, sbx.ID.String(), true)
	vmdCancel()
	if err != nil {
		// Log and continue — we still want to mark the DB row as
		// destroyed so the reaper does not keep retrying this row
		// forever. If VMD genuinely still has the VM, the next
		// ExecStartPre cleanup will kill it.
		l.Warn().Err(err).Msg("reaper: VMD destroy failed; proceeding with DB cleanup")
	}

	dbCtx, dbCancel := context.WithTimeout(ctx, asyncTimeout)
	err = h.DB.DestroySandbox(dbCtx, db.DestroySandboxParams{
		ID:     sbx.ID,
		TeamID: sbx.TeamID,
	})
	dbCancel()
	if err != nil {
		l.Error().Err(err).Msg("reaper: DestroySandbox DB update failed")
		return
	}

	l.Info().Msg("reaper: sandbox destroyed due to timeout")

	// Fire-and-forget activity log — use a detached context so slow
	// writes do not block the next reaper iteration. We pass the reaper
	// context so a shutdown is respected.
	h.logActivityAsync(ctx, sbx.ID, sbx.TeamID, "sandbox", "timeout_destroyed", "success", &sbx.Name, nil, nil)
}
