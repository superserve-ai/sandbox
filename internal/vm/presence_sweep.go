package vm

import (
	"os"
	"path/filepath"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// presenceConvergedMarkerName is the durable per-host record that the
// convergence sweep found (or produced) a presence side-car for every layered
// overlay under SnapshotDir. Once it exists, "auto" strictness enforces and
// the sweep never generates again — from that point, a side-car-less overlay
// is by definition suspect (locally-saved overlays get side-cars from
// Firecracker; only a damaged or half-copied transfer arrives without one),
// and generating from its extents would launder exactly the corruption the
// side-car exists to prevent.
const presenceConvergedMarkerName = ".presence-converged"

// sweepGenerateBudget caps side-car generation per reconcile tick so the
// first pass on a host with many legacy overlays can't blow the reconciler's
// per-pass deadline (each generation is an extent scan plus fsync'd writes).
// Convergence still completes within minutes: budget per tick, one tick per
// reconcile interval.
const sweepGenerateBudget = 100

func (m *Manager) presenceConvergedMarkerPath() string {
	return filepath.Join(m.cfg.SnapshotDir, presenceConvergedMarkerName)
}

// presenceStrict reports whether a layered restore must refuse an overlay
// with no presence side-car. "always"/"never" are operator overrides; the
// default ("auto" / unset) derives enforcement from the converged marker, so
// flipping to strict early — the config mistake that would break legacy
// resumes — is unrepresentable in normal operation.
func (m *Manager) presenceStrict() bool {
	switch m.cfg.RequirePresenceSidecar {
	case "always":
		return true
	case "never":
		return false
	default:
		return m.presenceConverged.Load()
	}
}

// loadPresenceConverged initializes the in-memory converged bit from the
// on-disk marker at startup; the sweep re-derives it every tick thereafter.
func (m *Manager) loadPresenceConverged() {
	if _, err := os.Stat(m.presenceConvergedMarkerPath()); err == nil {
		m.presenceConverged.Store(true)
	}
}

// writePresenceConvergedMarker records convergence durably: content flushed
// and the dirent fsync'd. Durability matters more here than for the side-cars
// it summarizes — those are regenerable while unconverged, but a marker that
// was observable (strict enforcement admitted transfers) and then lost to a
// crash would let the next sweep generate a side-car from a transferred
// overlay's extents. Existence-only semantics, so no temp+rename needed: a
// torn marker is empty-but-present, which still reads as converged.
func (m *Manager) writePresenceConvergedMarker() error {
	f, err := os.OpenFile(m.presenceConvergedMarkerPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte("v1\n")); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(m.cfg.SnapshotDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// sweepPresenceSidecars is the convergence pass: generate a presence side-car
// for every quiesced layered overlay that lacks one, and persist the converged
// marker once none remain. activeUnits are VM IDs with a live Firecracker
// process (their overlays may be mid-write; they'll get side-cars from their
// own next pause instead).
//
// Generation here is sound because a pre-convergence side-car-less overlay on
// an auto/never host is a legacy local artifact: it was dumped on this host
// and never transferred, so its extent map still encodes presence faithfully —
// the same trust the warn-and-scan restore fallback already extends to it at
// restore time. The sweep performs that inference once, at rest, instead of
// on every restore forever. Three guards keep the inference honest:
//
//   - "always" hosts never generate: that mode declares the host's artifacts
//     may be transferred, so extent inference is never sound there.
//   - Convergence is re-derived from the on-disk marker every tick, in both
//     directions — a marker hidden by a late mount or deleted by an operator
//     un-converges the host (strictness drops with it, the safe direction)
//     and the sweep resumes healing; the in-memory bit is only a cache for
//     the restore-path gate.
//   - The final write uses RENAME_NOREPLACE (presence.WriteIfAbsent) plus a
//     post-scan quiesce re-check, so a resume+pause cycle racing a long scan
//     can never replace Firecracker's authoritative side-car with the
//     sweep's stale one.
func (m *Manager) sweepPresenceSidecars(activeUnits map[string]bool) {
	if m.cfg.RequirePresenceSidecar == "always" {
		return
	}
	// Re-derive convergence from disk each tick (both directions).
	if _, err := os.Stat(m.presenceConvergedMarkerPath()); err == nil {
		m.presenceConverged.Store(true)
		return
	}
	m.presenceConverged.Store(false)
	log := m.log.With().Str("component", "presence_sweep").Logger()

	// A missing SnapshotDir (volume not mounted yet) must not converge an
	// empty view of the world; Glob would return nil, nil for it.
	if _, err := os.Stat(m.cfg.SnapshotDir); err != nil {
		log.Warn().Err(err).Msg("snapshot dir unavailable; skipping pass")
		return
	}
	overlays, err := filepath.Glob(filepath.Join(m.cfg.SnapshotDir, "*", "mem.diff"))
	if err != nil {
		log.Warn().Err(err).Msg("overlay glob failed; retrying next pass")
		return
	}
	var generated, busy, failed, deferred int
	for _, mem := range overlays {
		if _, err := os.Stat(presence.SidecarPath(mem)); err == nil || !os.IsNotExist(err) {
			// Present (including the torn-save / un-layerable sentinels, whose
			// loud refusal must be preserved) or unreadable — not ours to touch.
			continue
		}
		if generated >= sweepGenerateBudget {
			deferred++
			continue
		}
		vmID := filepath.Base(filepath.Dir(mem))
		if activeUnits[vmID] || !m.instanceQuiescedForSweep(vmID) {
			busy++
			continue
		}
		bm, err := presence.Scan(mem, os.Getpagesize())
		if err != nil {
			log.Warn().Err(err).Str("path", mem).Msg("extent scan failed; retrying next pass")
			failed++
			continue
		}
		// Re-check after the (possibly long) scan: if the VM woke up meanwhile,
		// the scanned bitmap may describe a mid-rewrite file. WriteIfAbsent is
		// the backstop for the window this check can't close.
		if activeUnits[vmID] || !m.instanceQuiescedForSweep(vmID) {
			busy++
			continue
		}
		switch err := presence.WriteIfAbsent(mem, bm.PageSize, bm.NPages, bm.Bits); {
		case err == nil:
			generated++
		case err == presence.ErrSidecarExists:
			// Firecracker wrote the authoritative side-car mid-scan; ours was
			// stale. The overlay is covered — nothing to count.
		default:
			log.Warn().Err(err).Str("path", mem).Msg("side-car write failed; retrying next pass")
			failed++
		}
	}
	if remaining := busy + failed + deferred; remaining > 0 {
		log.Info().Int("generated", generated).Int("busy", busy).Int("failed", failed).
			Int("deferred", deferred).Msg("presence convergence in progress")
		return
	}
	if err := m.writePresenceConvergedMarker(); err != nil {
		log.Warn().Err(err).Msg("converged marker write failed; retrying next pass")
		return
	}
	m.presenceConverged.Store(true)
	log.Info().Int("generated", generated).
		Msg("presence side-cars converged; strict enforcement active in auto mode")
}

// instanceQuiescedForSweep reports whether vmID's overlay is safe to scan: the
// manager either doesn't know the VM (an orphaned snapshot dir — no process,
// quiescent by definition) or knows it as fully paused. Any transitional or
// running state defers to a later pass.
func (m *Manager) instanceQuiescedForSweep(vmID string) bool {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return true
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.Status == StatusPaused
}
