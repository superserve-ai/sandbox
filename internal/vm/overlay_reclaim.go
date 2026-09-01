package vm

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// removeOverlayArtifacts deletes an overlay and every sidecar that describes
// it. Only the overlay's own removal is reported: the sidecars are small and
// meaningless without it, so a failure there is best-effort, but a guest-sized
// overlay that survives must keep its deferral for another attempt.
func removeOverlayArtifacts(overlay string) error {
	_ = os.Remove(layeredBaseSidecarPath(overlay))
	_ = os.Remove(presence.SidecarPath(overlay))
	_ = os.Remove(clockFreezeMarkerPath(overlay))
	if err := os.Remove(overlay); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// reclaimStrandedOverlay removes the overlay a pause deferred because its
// process could not be confirmed stopped, and clears the deferral durably.
// Callers hold the vm-op lock and invoke it only once the VM is proven at
// rest — the file may still be serving guest pages until then. A removal
// that fails keeps the deferral, so a transient filesystem error costs a
// retry rather than a permanent leak.
//
// A deferred path can be reused by a later pause before the deferral is
// resolved (a crash between the reclaim and its persist replays the stale
// marker). The artifact the record currently references is therefore never
// removed: the marker is simply dropped, since the path is live again.
func (m *Manager) reclaimStrandedOverlay(inst *VMInstance, log zerolog.Logger) {
	inst.mu.RLock()
	overlay, live := inst.StrandedOverlay, inst.MemFilePath
	inst.mu.RUnlock()
	if overlay == "" {
		return
	}
	if overlay == live {
		log.Warn().Str("path", overlay).Msg("stranded overlay is the live artifact again; dropping the stale deferral")
	} else if err := removeOverlayArtifacts(overlay); err != nil {
		log.Warn().Err(err).Str("path", overlay).Msg("stranded overlay not reclaimed; deferral kept for a later attempt")
		return
	} else {
		log.Info().Str("path", overlay).Msg("reclaimed a stranded overlay")
	}
	inst.mu.Lock()
	if inst.StrandedOverlay == overlay {
		inst.StrandedOverlay = ""
	}
	inst.mu.Unlock()
	if _, err := m.persistStateIfPresent(inst); err != nil {
		log.Warn().Err(err).Msg("stranded-overlay deferral cleared in memory only; a restart may replay it once")
	}
}
