package vm

import "strings"

// eagerOverlayCap is what a Firecracker build advertises when LoadSnapshot
// accepts mem_backend.eager_overlay. The body denies unknown fields, so a
// binary without it rejects the whole request.
const eagerOverlayCap = "eager-overlay"

const unknownEagerOverlayFieldMarker = "unknown field `eager_overlay`"

// eagerOverlayMaxPSI is the memory or IO pressure (PSI "some" avg10) above
// which a fork skips the pre-copy: it reads the whole overlay from disk into
// memory up front, which a host already waiting on either can least afford.
const eagerOverlayMaxPSI = 10.0

// eagerOverlayPSI reads the memory and IO pressure at the moment a fork asks
// for the pre-copy; a hook so tests do not depend on the host's.
var eagerOverlayPSI = func() (mem, io float64) {
	_, mem, io = cachedPSI()
	return mem, io
}

// eagerOverlayEnabled reports whether a fork restore may ask Firecracker to
// pre-copy its overlay: whenever the binary advertises it and the host is not
// under pressure. PSI reads -1 when unavailable, which does not block.
func (m *Manager) eagerOverlayEnabled() bool {
	if !m.eagerOverlayCapable.Load() {
		return false
	}
	mem, io := eagerOverlayPSI()
	return mem <= eagerOverlayMaxPSI && io <= eagerOverlayMaxPSI
}

// restoreWithEagerOverlayFallback runs restore with eager and, if this
// Firecracker rejects the field as unknown (a rollback under a running
// daemon), clears the capability and retries once without it. The refusal is
// raised before any guest state is touched.
func (m *Manager) restoreWithEagerOverlayFallback(eager bool, restore func(eager bool) error) error {
	if eager && !m.eagerOverlayCapable.Load() {
		eager = false
	}
	err := restore(eager)
	if !eager || err == nil || !strings.Contains(strings.ToLower(err.Error()), unknownEagerOverlayFieldMarker) {
		return err
	}
	if m.eagerOverlayCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected eager_overlay; forks restore without it until the binary advertises it again")
	}
	return restore(false)
}
