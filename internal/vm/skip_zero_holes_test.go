package vm

import (
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// False must be omitted, not sent: an older binary refuses the field even as false.
func TestSkipZeroHolesSerializesOnlyWhenOn(t *testing.T) {
	fc := startSnapshotAPIFake(t, nil)
	for _, skip := range []bool{true, false} {
		if err := RestoreSnapshotUffdInternalWithOverrides(
			fc.socketPath, "/tmp/snap", "/tmp/mem", "", "", "", "eth0", "tap0", "",
			false, false, false, skip, "", nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"skip_zero_holes":true`) || strings.Contains(bodies[1], "skip_zero_holes") {
		t.Fatalf("bodies=%q", bodies)
	}
}

func TestRestoreWithSkipZeroHolesFallback_UnknownFieldRetriesWithout(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SkipZeroHolesEnabled: true}}
	m.skipZeroHolesCapable.Store(true)
	var sent []bool
	err := m.restoreWithSkipZeroHolesFallback(m.skipZeroHolesEnabled(), func(skip bool) error {
		sent = append(sent, skip)
		if skip {
			return errors.New("[PUT /snapshot/load][400] unknown field `skip_zero_holes`, expected one of `backend_path`")
		}
		return nil
	})
	if err != nil || len(sent) != 2 || !sent[0] || sent[1] {
		t.Fatalf("want one refused attempt then one without; sent=%v err=%v", sent, err)
	}
	if m.skipZeroHolesEnabled() {
		t.Fatal("a refusal must clear the capability for later restores")
	}

	m.skipZeroHolesCapable.Store(true)
	calls := 0
	err = m.restoreWithSkipZeroHolesFallback(true, func(bool) error { calls++; return errors.New("load snapshot: connection refused") })
	if err == nil || calls != 1 || !m.skipZeroHolesCapable.Load() {
		t.Fatalf("other errors must not retry or clear the capability; calls=%d err=%v", calls, err)
	}
}
