package vm

import "strings"

// skipZeroHolesCap is what a Firecracker build advertises when LoadSnapshot
// accepts mem_backend.skip_zero_holes. The body denies unknown fields, so a
// binary without it rejects the whole request.
const skipZeroHolesCap = "skip-zero-holes"

const unknownSkipZeroHolesFieldMarker = "unknown field `skip_zero_holes`"

// zeroHoleBlock is the granularity at which a template build punches all-zero
// memory into holes. It matches the block Firecracker registers at, so every
// punched block is one restore can leave to the kernel.
const zeroHoleBlock = 2 << 20

// skipZeroHolesEnabled reports whether a restore may ask Firecracker to leave
// all-zero memory to the kernel: when the host is switched to it and the binary
// advertises it.
func (m *Manager) skipZeroHolesEnabled() bool {
	return m.cfg.SkipZeroHolesEnabled && m.skipZeroHolesCapable.Load()
}

// restoreWithSkipZeroHolesFallback runs restore with skip and, if this
// Firecracker rejects the field as unknown (a rollback under a running daemon),
// clears the capability and retries once without it. The refusal is raised
// before any guest state is touched.
func (m *Manager) restoreWithSkipZeroHolesFallback(skip bool, restore func(skip bool) error) error {
	err := restore(skip)
	if !skip || err == nil || !strings.Contains(strings.ToLower(err.Error()), unknownSkipZeroHolesFieldMarker) {
		return err
	}
	if m.skipZeroHolesCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected skip_zero_holes; restores register all memory until the binary advertises it again")
	}
	return restore(false)
}
