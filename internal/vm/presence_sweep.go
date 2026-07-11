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
// on-disk marker at startup.
func (m *Manager) loadPresenceConverged() {
	if _, err := os.Stat(m.presenceConvergedMarkerPath()); err == nil {
		m.presenceConverged.Store(true)
	}
}

// sweepPresenceSidecars is the convergence pass: generate a presence side-car
// for every quiesced layered overlay that lacks one, and persist the converged
// marker once none remain. Pre-marker only — see presenceConvergedMarkerName
// for why it must never run after convergence. activeUnits are VM IDs with a
// live Firecracker process (their overlays may be mid-write; they'll get
// side-cars from their own next pause instead).
//
// Generation here is sound because a pre-convergence side-car-less overlay is
// a legacy local artifact: it was dumped on this host and never transferred,
// so its extent map still encodes presence faithfully — the same trust the
// warn-and-scan restore fallback already extends to it at restore time. The
// sweep just performs that inference once, at rest, instead of on every
// restore forever.
func (m *Manager) sweepPresenceSidecars(activeUnits map[string]bool) {
	if m.presenceConverged.Load() {
		return
	}
	log := m.log.With().Str("component", "presence_sweep").Logger()

	overlays, err := filepath.Glob(filepath.Join(m.cfg.SnapshotDir, "*", "mem.diff"))
	if err != nil {
		log.Warn().Err(err).Msg("overlay glob failed; retrying next pass")
		return
	}
	var generated, skipped, remaining int
	for _, mem := range overlays {
		if _, err := os.Stat(presence.SidecarPath(mem)); err == nil || !os.IsNotExist(err) {
			// Present (including the torn-save / un-layerable sentinels, whose
			// loud refusal must be preserved) or unreadable — not ours to touch.
			continue
		}
		vmID := filepath.Base(filepath.Dir(mem))
		if activeUnits[vmID] || !m.instanceQuiescedForSweep(vmID) {
			skipped++
			remaining++
			continue
		}
		if err := presence.Generate(mem); err != nil {
			log.Warn().Err(err).Str("path", mem).Msg("side-car generation failed; retrying next pass")
			remaining++
			continue
		}
		generated++
	}
	if remaining > 0 {
		log.Info().Int("generated", generated).Int("skipped_busy", skipped).Int("remaining", remaining).
			Msg("presence convergence in progress")
		return
	}
	if err := os.WriteFile(m.presenceConvergedMarkerPath(), []byte("v1\n"), 0o644); err != nil {
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
