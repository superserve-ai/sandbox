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
// process could not be confirmed stopped. Callers invoke it only once the VM
// is proven at rest — the file may still be serving guest pages until then.
// It does not persist: the cleared field lands with the caller's next
// record write, and a deferral that outlives the files only costs a no-op
// remove on the next reclaim.
func reclaimStrandedOverlay(inst *VMInstance, log zerolog.Logger) {
	inst.mu.Lock()
	overlay := inst.StrandedOverlay
	inst.StrandedOverlay = ""
	inst.mu.Unlock()
	if overlay == "" {
		return
	}
	removeOverlayArtifacts(overlay)
	log.Info().Str("path", overlay).Msg("reclaimed a stranded overlay")
}
