package vm

// dirtyTrackingSessionCap is what a Firecracker build advertises when its
// snapshot endpoints accept the guarded-session fields. Both request bodies
// deny unknown fields, so a binary without it rejects the whole request.
const dirtyTrackingSessionCap = "dirty-tracking-session"

// sessionArmingEnabled reports whether a restore may arm a guarded session:
// the flag opts in, and the binary on disk must advertise the fields.
func (m *Manager) sessionArmingEnabled() bool {
	return m.cfg.DirtyTrackingSessionEnabled && m.dirtyTrackingSessionCapable.Load()
}

// restoreWithSessionFallback runs a restore that arms sessionID and, if this
// Firecracker rejects the field as unknown (a rollback under a running
// daemon), clears the capability and retries once unguarded. The refusal is
// raised before any guest state is touched. Returns the session actually
// armed — empty after a fallback, so the caller records none.
func (m *Manager) restoreWithSessionFallback(sessionID string, restore func(sessionID string) (usedPolicy bool, err error)) (armed string, usedPolicy bool, err error) {
	usedPolicy, err = restore(sessionID)
	if sessionID == "" || !isUnknownSessionFieldErr(err) {
		return sessionID, usedPolicy, err
	}
	if m.dirtyTrackingSessionCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected the dirty-tracking session field; restoring unguarded for every restore")
	}
	usedPolicy, err = restore("")
	return "", usedPolicy, err
}

// sessionRejectedAtPause reports whether a guarded pause failed because this
// Firecracker does not know the session fields — a persisted token meeting a
// rolled-back binary. The pause degrades to Full like a mismatch, and the
// capability clears so later restores stop arming.
func (m *Manager) sessionRejectedAtPause(err error) bool {
	if !isUnknownSessionFieldErr(err) {
		return false
	}
	if m.dirtyTrackingSessionCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected the guarded pause fields; guarded pauses are off until the binary advertises them again")
	}
	return true
}
