package vm

import (
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestEagerOverlayEnabled(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	if m.eagerOverlayEnabled(0, 0) {
		t.Fatal("a binary that does not advertise the field must not get it")
	}
	m.eagerOverlayCapable.Store(true)
	if !m.eagerOverlayEnabled(0, 0) || !m.eagerOverlayEnabled(-1, -1) {
		t.Fatal("a capable binary on an unpressured host should pre-copy")
	}
	if m.eagerOverlayEnabled(eagerOverlayMaxPSI+1, 0) || m.eagerOverlayEnabled(0, eagerOverlayMaxPSI+1) {
		t.Fatal("a host under memory or IO pressure should skip the pre-copy")
	}
}

func TestRestoreWithEagerOverlayFallback_UnknownFieldRetriesWithout(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	m.eagerOverlayCapable.Store(true)
	var sent []bool
	err := m.restoreWithEagerOverlayFallback(true, func(eager bool) error {
		sent = append(sent, eager)
		if eager {
			return errors.New("[PUT /snapshot/load][400] unknown field `eager_overlay`, expected one of `backend_path`")
		}
		return nil
	})
	if err != nil || len(sent) != 2 || !sent[0] || sent[1] {
		t.Fatalf("want one refused eager attempt then one without; sent=%v err=%v", sent, err)
	}
	if m.eagerOverlayCapable.Load() {
		t.Fatal("a refusal must clear the capability for later forks")
	}
	sent = nil
	_ = m.restoreWithEagerOverlayFallback(true, func(eager bool) error { sent = append(sent, eager); return nil })
	if len(sent) != 1 || sent[0] {
		t.Fatalf("once cleared, forks must not send the field; sent=%v", sent)
	}
}

func TestRestoreWithEagerOverlayFallback_OtherErrorsAreNotRetried(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	m.eagerOverlayCapable.Store(true)
	calls := 0
	err := m.restoreWithEagerOverlayFallback(true, func(bool) error { calls++; return errors.New("load snapshot: connection refused") })
	if err == nil || calls != 1 || !m.eagerOverlayCapable.Load() {
		t.Fatalf("calls=%d err=%v capable=%v", calls, err, m.eagerOverlayCapable.Load())
	}
}

// False must be omitted, not sent: an older binary refuses the field even as false.
func TestEagerOverlaySerializesOnlyWhenOn(t *testing.T) {
	fc := startSnapshotAPIFake(t, nil)
	for _, eager := range []bool{true, false} {
		if err := RestoreSnapshotUffdInternalWithOverrides(
			fc.socketPath, "/tmp/snap", "/tmp/mem.diff", "/tmp/base", "", "", "eth0", "tap0", "",
			false, false, eager, "", nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"eager_overlay":true`) || strings.Contains(bodies[1], "eager_overlay") {
		t.Fatalf("bodies=%q", bodies)
	}
}
