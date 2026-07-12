package vm

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"

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
// Generation is sound only for overlays this host provably dumped itself —
// their extent maps still encode presence faithfully, the same trust the
// warn-and-scan restore fallback extends at restore time. Provenance is
// checked structurally, not by time: only VMs known to this host as paused
// (in memory or in BoltDB) are eligible. An overlay with no local record may
// be a freshly transferred artifact whose extents a copy already mangled —
// generating from those would launder exactly the corruption the side-car
// exists to prevent, so unknown-provenance overlays are never generated and
// never block convergence (they are the reconciler's orphans to reap; a
// later adoption is gated loudly at restore). Guards keeping the inference
// honest:
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

	if m.state == nil {
		// Only the reconciler calls the sweep, and it requires a state store;
		// without one there is no provenance and nothing may be generated.
		return
	}
	// A missing SnapshotDir (volume not mounted yet) must not converge an
	// empty view of the world.
	if _, err := os.Stat(m.cfg.SnapshotDir); err != nil {
		log.Warn().Err(err).Msg("snapshot dir unavailable; skipping pass")
		return
	}
	// Enumerate from BoltDB, not the filesystem: paused records are the only
	// overlays the sweep may generate for (provenance), and PauseVM accepts a
	// caller-supplied snapshot dir, so overlays need not sit at the default
	// <SnapshotDir>/<vmID>/mem.diff shape a glob would find. The record's
	// MemFilePath is authoritative wherever the overlay lives.
	recs, err := m.state.All()
	if err != nil {
		log.Warn().Err(err).Msg("state store list failed; deferring pass")
		return
	}
	var generated, busy, failed, deferred int
	swept := make(map[string]bool, len(recs))
	for _, rec := range recs {
		if rec.Status != StatusPaused || !isOverlayMemFile(rec.MemFilePath) {
			continue
		}
		mem := rec.MemFilePath
		if swept[mem] {
			continue
		}
		swept[mem] = true
		if _, err := os.Stat(presence.SidecarPath(mem)); err == nil || !os.IsNotExist(err) {
			// Present (including the torn-save / un-layerable sentinels, whose
			// loud refusal must be preserved) or unreadable — not ours to touch.
			continue
		}
		if _, err := os.Stat(mem); os.IsNotExist(err) {
			// Stale record: the overlay is gone, so there is nothing to heal
			// and nothing a restore could load — don't block convergence on it.
			continue
		}
		if generated >= sweepGenerateBudget {
			deferred++
			continue
		}
		if m.instanceBusyForSweep(rec.ID, activeUnits) {
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
		if m.instanceBusyForSweep(rec.ID, activeUnits) {
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

// instanceBusyForSweep reports whether vmID's overlay may be mid-write: a live
// Firecracker unit, or an in-memory instance in any non-paused state. The
// BoltDB record already established provenance and paused-ness at enumeration;
// this catches the VM having woken up since (memory is fresher than the store).
func (m *Manager) instanceBusyForSweep(vmID string, activeUnits map[string]bool) bool {
	if activeUnits[vmID] {
		return true
	}
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.Status != StatusPaused
}

// verifyPresenceRefreshed guards a misordered deploy. A diff save through a
// Firecracker that predates the presence side-car rewrites the overlay but
// not the side-car, leaving a stale bitmap a NEWER Firecracker would later
// trust — silent wrong-layer page resolution under live traffic. A side-car
// whose mtime didn't advance past the save start wasn't written by this
// save: remove it and warn, converting the misorder into loud strict-mode
// refusals (or a sound extent scan pre-convergence) instead of corruption.
// No-op on correctly ordered deployments — the side-car-aware Firecracker
// rewrites the file on every save.
func (m *Manager) verifyPresenceRefreshed(memPath string, saveStart time.Time, log zerolog.Logger) {
	sc := presence.SidecarPath(memPath)
	st, err := os.Stat(sc)
	if os.IsNotExist(err) {
		log.Warn().Str("path", sc).
			Msg("presence side-car absent after diff save — Firecracker predates the side-car format; fix deploy ordering")
		return
	}
	if err != nil {
		log.Warn().Err(err).Str("path", sc).Msg("presence side-car stat failed after diff save")
		return
	}
	if st.ModTime().Before(saveStart) {
		if rmErr := os.Remove(sc); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Warn().Err(rmErr).Str("path", sc).Msg("stale presence side-car removal failed")
			return
		}
		log.Warn().Str("path", sc).
			Msg("presence side-car not refreshed by this diff save — removed stale bitmap; Firecracker predates the side-car format, fix deploy ordering")
	}
}
