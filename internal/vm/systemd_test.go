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

// The launch gate must hold a launch while a recorded stop is unconfirmed —
// a stop still in PID1's queue executes against whatever holds the unit name
// when it lands — and must fail closed rather than launch over one that never
// settles. Nothing is enqueued before the gate, so its failure needs no
// cleanup.
func TestWaitUnitStopSettle(t *testing.T) {
	origPoll := unitStopSettlePoll
	unitStopSettlePoll = 5 * time.Millisecond
	defer func() { unitStopSettlePoll = origPoll }()

	t.Run("no recorded stop passes immediately", func(t *testing.T) {
		if err := waitUnitStopSettle(context.Background(), "settle-none.service"); err != nil {
			t.Fatalf("no outstanding stop must not block a launch: %v", err)
		}
	})

	t.Run("confirmation releases the gate", func(t *testing.T) {
		unit := "settle-confirm.service"
		recordUnitStop(unit)
		defer confirmUnitStopped(unit)
		go func() {
			time.Sleep(20 * time.Millisecond) // the stop job completes
			confirmUnitStopped(unit)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := waitUnitStopSettle(ctx, unit); err != nil {
			t.Fatalf("a confirmed stop must release the launch: %v", err)
		}
	})

	t.Run("an unsettled stop fails the launch, not the other way around", func(t *testing.T) {
		unit := "settle-never.service"
		recordUnitStop(unit)
		defer confirmUnitStopped(unit)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		err := waitUnitStopSettle(ctx, unit)
		if err == nil {
			t.Fatal("launching over an unsettled stop hands the new VM to the old incarnation's cleanup")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the failure must carry the ctx verdict, got %v", err)
		}
	})
}

func TestUnitStopUnconfirmedExcludesSettleWindow(t *testing.T) {
	// The gate must key on RECORDED stops only: unitMaybeWindingDown reads
	// true for every unit during the young-process window, and gating on it
	// would stall all launches for minutes after a vmd restart.
	if unitStopUnconfirmed("never-touched.service") {
		t.Fatal("a unit with no recorded stop must not read as unconfirmed")
	}
}
