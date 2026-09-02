package vm

import (
	"context"
	"os"
	"slices"

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

// hasStrandedOverlay reports whether overlay is already deferred. Caller holds
// inst.mu.
func hasStrandedOverlay(inst *VMInstance, overlay string) bool {
	return slices.Contains(inst.StrandedOverlays, overlay)
}

// reclaimStrandedOverlays removes the overlays pauses deferred because their
// process could not be confirmed stopped, and clears each resolved deferral
// durably. Callers hold the vm-op lock and invoke it only once the VM is
// proven at rest — a file may still be serving guest pages until then. A
// removal that fails keeps that deferral, so a transient filesystem error
// costs a retry rather than a permanent leak.
//
// A deferred path can be reused by a later pause before the deferral is
// resolved (a crash between the reclaim and its persist replays the stale
// marker). The artifact the record currently references is therefore never
// removed: that marker is simply dropped, since the path is live again.
func (m *Manager) reclaimStrandedOverlays(inst *VMInstance, log zerolog.Logger) {
	inst.mu.RLock()
	pending, live := append([]string(nil), inst.StrandedOverlays...), inst.MemFilePath
	inst.mu.RUnlock()
	if len(pending) == 0 {
		return
	}
	var kept []string
	for _, overlay := range pending {
		switch {
		case overlay == live:
			log.Warn().Str("path", overlay).Msg("stranded overlay is the live artifact again; dropping the stale deferral")
		case removeOverlayArtifacts(overlay) != nil:
			log.Warn().Str("path", overlay).Msg("stranded overlay not reclaimed; deferral kept for a later attempt")
			kept = append(kept, overlay)
		default:
			log.Info().Str("path", overlay).Msg("reclaimed a stranded overlay")
		}
	}
	if len(kept) == len(pending) {
		return
	}
	inst.mu.Lock()
	// Deferrals added since the snapshot above are unresolved and stay.
	for _, overlay := range inst.StrandedOverlays {
		if !slices.Contains(pending, overlay) {
			kept = append(kept, overlay)
		}
	}
	inst.StrandedOverlays = kept
	inst.mu.Unlock()
	if _, err := m.persistStateIfPresent(inst); err != nil {
		log.Warn().Err(err).Msg("stranded-overlay deferrals cleared in memory only; a restart may replay them once")
	}
}

// sweepStrandedOverlays reclaims deferred overlays whose VM is already at rest
// with nothing left to observe it: the process ended between passes, or a
// startup reattach stopped it before any pause, resume, or backup worker ran.
// Runs from the reconciler, off every lifecycle path; only instances carrying
// a deferral are probed, so a healthy fleet pays nothing here.
func (m *Manager) sweepStrandedOverlays(ctx context.Context, log zerolog.Logger) {
	var candidates []*VMInstance
	m.mu.RLock()
	for _, inst := range m.vms {
		inst.mu.RLock()
		if inst.Status == StatusPaused && len(inst.StrandedOverlays) > 0 {
			candidates = append(candidates, inst)
		}
		inst.mu.RUnlock()
	}
	m.mu.RUnlock()
	for _, inst := range candidates {
		if ctx.Err() != nil {
			return
		}
		// Non-blocking: a lifecycle op in flight resolves the deferral
		// itself, or the next pass finds it.
		unlock, ok := m.tryLockVMOp(inst.ID)
		if !ok {
			continue
		}
		inst.mu.RLock()
		paused := inst.Status == StatusPaused
		inst.mu.RUnlock()
		if paused && m.vmConfirmedAtRest(ctx, inst.ID) {
			m.reclaimStrandedOverlays(inst, log.With().Str("vm_id", inst.ID).Logger())
		}
		unlock()
	}
}
