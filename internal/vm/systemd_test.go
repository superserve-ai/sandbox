package vm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A job result buffered at deadline-time must win over the wait error — the
// select in stopUnit can wake on either when both are ready.
func TestSettleExpiredStopWait_DrainsBufferedResult(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "done"
	if err := settleExpiredStopWait(context.Background(), "u.service", ch, errors.New("deadline")); err != nil {
		t.Fatalf("buffered done should win over the wait error: %v", err)
	}

	ch2 := make(chan string, 1)
	ch2 <- "failed"
	err := settleExpiredStopWait(context.Background(), "u.service", ch2, errors.New("deadline"))
	if err == nil || !strings.Contains(err.Error(), `job result "failed"`) {
		t.Fatalf("buffered failure should surface the job result, got %v", err)
	}
}

// The settle path may clear the stop marker only when the unit is CONCLUSIVELY
// down. A still-deactivating unit reports its stop complete but must KEEP the
// marker — clearing it would let a same-ID relaunch skip the linger query and
// race the winding-down socket.
func TestClassifyStopSettle(t *testing.T) {
	cases := []struct {
		state               string
		notLoaded, ok       bool
		wantStop, wantClear bool
	}{
		{"inactive", false, true, true, true},
		{"failed", false, true, true, true},
		{"", true, true, true, true},               // not-loaded == gone
		{"deactivating", false, true, true, false}, // stop done, marker RETAINED
		{"activating", false, true, true, false},
		{"active", false, true, false, false},
		{"reloading", false, true, false, false},
		{"inactive", false, false, false, false}, // inconclusive read confirms nothing
	}
	for _, c := range cases {
		stop, clear := classifyStopSettle(c.state, c.notLoaded, c.ok)
		if stop != c.wantStop || clear != c.wantClear {
			t.Errorf("classifyStopSettle(%q, notLoaded=%v, ok=%v) = (stop=%v, clear=%v), want (stop=%v, clear=%v)",
				c.state, c.notLoaded, c.ok, stop, clear, c.wantStop, c.wantClear)
		}
	}
}

func TestLingeringState(t *testing.T) {
	for _, s := range []string{"active", "activating", "deactivating"} {
		if !lingeringState(s) {
			t.Errorf("%s should linger", s)
		}
	}
	for _, s := range []string{"inactive", "failed", "reloading", ""} {
		if lingeringState(s) {
			t.Errorf("%s should not linger", s)
		}
	}
}

func TestUnitMaybeWindingDown(t *testing.T) {
	origStart := vmProcessStart
	defer func() { vmProcessStart = origStart }()

	// A young process cannot rule out stops issued by its predecessor.
	vmProcessStart = time.Now()
	if !unitMaybeWindingDown("young.service") {
		t.Error("young process should report maybe-winding-down for any unit")
	}

	vmProcessStart = time.Now().Add(-2 * processSettleWindow)
	if unitMaybeWindingDown("never-stopped.service") {
		t.Error("never-stopped unit on a settled process should be clear")
	}

	// An unconfirmed stop blocks freshness until systemd confirms — no
	// clock-based expiry.
	recordUnitStop("stopped.service")
	if !unitMaybeWindingDown("stopped.service") {
		t.Error("unconfirmed stop should report maybe-winding-down")
	}
	confirmUnitStopped("stopped.service")
	if unitMaybeWindingDown("stopped.service") {
		t.Error("confirmed stop should clear the record")
	}
}

// stopJobResult is a confirmation point: a completed job clears the stop
// record, a failed one keeps it.
func TestStopJobResultConfirmsStop(t *testing.T) {
	recordUnitStop("job.service")
	if err := stopJobResult("job.service", "failed"); err == nil {
		t.Fatal("failed job result should error")
	}
	if _, ok := recentUnitStops.Load("job.service"); !ok {
		t.Error("failed job result must keep the stop record")
	}
	if err := stopJobResult("job.service", "done"); err != nil {
		t.Fatalf("done job result should succeed: %v", err)
	}
	if _, ok := recentUnitStops.Load("job.service"); ok {
		t.Error("done job result should clear the stop record")
	}
}

// processSettleWindow backstops the deactivating units the startup orphan
// scan cannot see (it lists active only). That holds only while the window
// outlasts the reconciler's first orphan sweep plus one stop cycle; this
// pins the inequality so a constant bump elsewhere fails here instead of
// silently shrinking the guard.
func TestProcessSettleWindowCoversOrphanSweep(t *testing.T) {
	cfg := DefaultReconcilerConfig()
	if min := cfg.Interval + cfg.GracePeriod + stopJobWaitCap; processSettleWindow <= min {
		t.Fatalf("processSettleWindow %v must exceed reconciler interval+grace+stop cap %v",
			processSettleWindow, min)
	}
}
