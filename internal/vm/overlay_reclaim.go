package vm

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// removeOverlayArtifacts deletes an overlay and every sidecar that describes
// it. Best-effort: a failed remove leaks disk, never correctness.
func removeOverlayArtifacts(overlay string) {
	_ = os.Remove(overlay)
	_ = os.Remove(layeredBaseSidecarPath(overlay))
	_ = os.Remove(presence.SidecarPath(overlay))
	_ = os.Remove(clockFreezeMarkerPath(overlay))
}

// reclaimStrandedOverlay removes the overlay a pause deferred because its
// process could not be confirmed stopped, and clears the deferral durably.
// Callers hold the vm-op lock and invoke it only once the VM is proven at
// rest — the file may still be serving guest pages until then.
//
// A deferred path can be reused by a later pause before the deferral is
// resolved (a crash between the reclaim and its persist replays the stale
// marker). The artifact the record currently references is therefore never
// removed: the marker is simply dropped, since the path is live again.
func (m *Manager) reclaimStrandedOverlay(inst *VMInstance, log zerolog.Logger) {
	inst.mu.Lock()
	overlay, live := inst.StrandedOverlay, inst.MemFilePath
	inst.StrandedOverlay = ""
	inst.mu.Unlock()
	if overlay == "" {
		return
	}
	if overlay == live {
		log.Warn().Str("path", overlay).Msg("stranded overlay is the live artifact again; dropping the stale deferral")
	} else {
		removeOverlayArtifacts(overlay)
		log.Info().Str("path", overlay).Msg("reclaimed a stranded overlay")
	}
	if _, err := m.persistStateIfPresent(inst); err != nil {
		log.Warn().Err(err).Msg("stranded-overlay deferral cleared in memory only; a restart may replay it once")
	}
}
