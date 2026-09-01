package main

import (
	"errors"
	"testing"
	"time"
)

// fakeSource is a scripted host clock. Its set() moves the guest clock the
// test observes, so the post-correction re-read is exercised for real.
type fakeSource struct {
	host    time.Time
	hostErr error
	setErr  error
	// setTo records what the guest clock was set to; nil until set() runs.
	setTo *time.Time
	// ineffective makes set() succeed without moving the guest clock, which
	// is what a silently-ignored settime looks like.
	ineffective bool
}

func (f *fakeSource) hostTime() (time.Time, error) { return f.host, f.hostErr }
func (f *fakeSource) set(t time.Time) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.setTo = &t
	return nil
}

// clockUnder wires a wallClock whose "now" is the guest clock: it starts at
// guest, and follows whatever set() adopts unless the source is ineffective.
func clockUnder(src *fakeSource, guest time.Time) *wallClock {
	c := newWallClock(src)
	c.now = func() time.Time {
		if src.setTo != nil && !src.ineffective {
			return *src.setTo
		}
		return guest
	}
	return c
}

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// A guest already within tolerance — a fresh boot, or a legacy restore where
// kvm-clock advanced it — must be left alone. Stepping a correct clock would be
// its own bug.
func TestWallClockWithinToleranceIsUntouched(t *testing.T) {
	src := &fakeSource{host: base.Add(200 * time.Millisecond)}
	c := clockUnder(src, base)
	st, ready := c.sync()
	if !ready {
		t.Fatal("want ready")
	}
	if src.setTo != nil {
		t.Errorf("clock was stepped by %v; within tolerance must not touch it", src.setTo.Sub(base))
	}
	if st.Source != "ptp" || st.CorrectedMs != 0 {
		t.Errorf("status = %+v, want ptp with no correction", st)
	}
}

// The frozen-restore case: the guest is days behind the host and must be
// stepped, then report the size of the step so an operator can see it happened.
func TestWallClockFrozenRestoreIsCorrected(t *testing.T) {
	stale := 10 * 24 * time.Hour
	src := &fakeSource{host: base.Add(stale)}
	c := clockUnder(src, base)
	st, ready := c.sync()
	if !ready {
		t.Fatalf("want ready after correction; status %+v", st)
	}
	if src.setTo == nil || !src.setTo.Equal(src.host) {
		t.Fatalf("clock set to %v, want host time %v", src.setTo, src.host)
	}
	if st.CorrectedMs != stale.Milliseconds() {
		t.Errorf("corrected_ms = %d, want %d", st.CorrectedMs, stale.Milliseconds())
	}
}

// No trusted source is not fatal: only a guest proven at build time to have one
// is ever marked, so a runtime failure is an anomaly to surface, not a reason
// to strand the sandbox unready.
func TestWallClockUnavailableSourceDegradesToReady(t *testing.T) {
	src := &fakeSource{hostErr: errors.New("open /dev/ptp0: no such file")}
	c := clockUnder(src, base)
	st, ready := c.sync()
	if !ready {
		t.Fatal("unavailable source must not block readiness")
	}
	if st.Source != "unavailable" || st.Error == "" {
		t.Errorf("status = %+v, want unavailable with the error surfaced", st)
	}
}

// Host time readable but the guest cannot be brought into tolerance: this guest
// would serve on a stale clock, so it must not be reported ready.
func TestWallClockFailedCorrectionIsNotReady(t *testing.T) {
	t.Run("set_errors", func(t *testing.T) {
		src := &fakeSource{host: base.Add(time.Hour), setErr: errors.New("EPERM")}
		c := clockUnder(src, base)
		st, ready := c.sync()
		if ready {
			t.Fatal("a failed correction must not report ready")
		}
		if st.Source != "ptp" || st.Error == "" {
			t.Errorf("status = %+v, want ptp with the error surfaced", st)
		}
	})
	t.Run("set_silently_ignored", func(t *testing.T) {
		src := &fakeSource{host: base.Add(time.Hour), ineffective: true}
		c := clockUnder(src, base)
		_, ready := c.sync()
		if ready {
			t.Fatal("a set that moved nothing must be caught by the re-read, not trusted")
		}
	})
}

// The boundary is inclusive: exactly at tolerance is left alone.
func TestWallClockToleranceBoundary(t *testing.T) {
	src := &fakeSource{host: base.Add(wallClockTolerance)}
	c := clockUnder(src, base)
	if _, ready := c.sync(); !ready || src.setTo != nil {
		t.Errorf("at exactly the tolerance: ready=%v stepped=%v, want ready and untouched", ready, src.setTo != nil)
	}
	src2 := &fakeSource{host: base.Add(wallClockTolerance + time.Millisecond)}
	c2 := clockUnder(src2, base)
	if _, ready := c2.sync(); !ready || src2.setTo == nil {
		t.Errorf("just past the tolerance: ready=%v stepped=%v, want ready and stepped", ready, src2.setTo != nil)
	}
}
