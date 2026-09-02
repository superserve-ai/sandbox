package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCgroup behaves like the v1 freezer: a FROZEN request reads FREEZING for
// a number of polls before settling, or forever if a task cannot stop.
type fakeCgroup struct {
	mu        sync.Mutex
	state     string
	missing   bool  // no cgroup at all (ENOENT)
	readErr   error // cgroup present but unreadable
	stallFor  int   // reads that report FREEZING before FROZEN
	neverDone bool  // stays FREEZING regardless
	stuckThaw bool  // THAWED writes are ignored
	writes    []string
	procs     map[int]string // pid -> freezer path
}

func (f *fakeCgroup) readState() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing {
		return "", os.ErrNotExist
	}
	if f.readErr != nil {
		return "", f.readErr
	}
	if f.state == "FREEZING" {
		if f.neverDone {
			return "FREEZING", nil
		}
		if f.stallFor > 0 {
			f.stallFor--
			return "FREEZING", nil
		}
		f.state = "FROZEN"
	}
	return f.state, nil
}

func (f *fakeCgroup) writeState(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing {
		return os.ErrNotExist
	}
	f.writes = append(f.writes, s)
	switch {
	case s == "FROZEN":
		f.state = "FREEZING"
	case s == "THAWED" && f.stuckThaw:
	default:
		f.state = s
	}
	return nil
}

func (f *fakeCgroup) procCgroup(pid int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.procs[pid]
	if !ok {
		return "", errors.New("no such process")
	}
	return p, nil
}

func newFake() *fakeCgroup { return &fakeCgroup{state: "THAWED", procs: map[int]string{}} }

const testDir = "/sys/fs/cgroup/freezer/workload"

func TestFreezeWaitsForEveryTaskToStop(t *testing.T) {
	cg := newFake()
	cg.stallFor = 3
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if st, _ := cg.readState(); st != "FROZEN" {
		t.Errorf("state %q, want FROZEN", st)
	}
}

// A workload that never fully stops must be left running: the supervisor
// falls back to the slower snapshot.
func TestFreezeTimeoutThawsAndFails(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	fz := newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := fz.freeze(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if errors.Is(err, errThawUnconfirmed) {
		t.Fatalf("thaw was confirmed, error must not claim otherwise: %v", err)
	}
	if last := cg.writes[len(cg.writes)-1]; last != "THAWED" {
		t.Errorf("last write %q, want THAWED", last)
	}
}

// If the undo itself cannot be confirmed, the caller must be told the state
// is unknown rather than "running again".
func TestFreezeTimeoutWithUnconfirmedThawSaysSo(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	cg.stuckThaw = true
	fz := newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := fz.freeze(ctx)
	if !errors.Is(err, errThawUnconfirmed) {
		t.Fatalf("err = %v, want errThawUnconfirmed", err)
	}
}

// The trampoline joins the cgroup before exec, so the command's pid — and
// every descendant — is inside from the first instruction of customer code.
func TestWrapJoinsCgroupBeforeExec(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	name, args := fz.wrap("/usr/bin/python3", []string{"-c", "print(1)", "a b"})
	if name != "/bin/sh" || len(args) < 3 || args[0] != "-c" {
		t.Fatalf("wrap = %s %v, want /bin/sh -c …", name, args)
	}
	if !strings.Contains(args[1], "cgroup.procs") || !strings.Contains(args[1], `exec "$0" "$@"`) {
		t.Errorf("script %q must write the pid then exec $0 $@", args[1])
	}
	if args[2] != "/usr/bin/python3" || args[3] != "-c" || args[4] != "print(1)" || args[5] != "a b" {
		t.Errorf("argv not preserved: %v", args[2:])
	}
}

func TestWrapIsPassthroughWithoutCgroup(t *testing.T) {
	cg := newFake()
	cg.missing = true
	fz := newFreezer(cg, testDir)
	name, args := fz.wrap("/bin/true", []string{"x"})
	if name != "/bin/true" || len(args) != 1 || args[0] != "x" {
		t.Errorf("wrap = %s %v, want passthrough", name, args)
	}
}

func TestConfirmPlaced(t *testing.T) {
	orig := placementWait
	placementWait = 20 * time.Millisecond
	t.Cleanup(func() { placementWait = orig })

	t.Run("in_cgroup_is_fine", func(t *testing.T) {
		cg := newFake()
		cg.procs[7] = "/workload"
		fz := newFreezer(cg, testDir)
		fz.confirmPlaced(7)
		if err := fz.freeze(context.Background()); err != nil {
			t.Fatalf("freeze after a placed process: %v", err)
		}
	})
	// A process that never showed up in the cgroup would keep running through
	// a freeze; refuse until it exits.
	t.Run("outside_refuses_freezes_until_exit", func(t *testing.T) {
		cg := newFake()
		cg.procs[8] = "/"
		fz := newFreezer(cg, testDir)
		fz.confirmPlaced(8)
		if err := fz.freeze(context.Background()); err == nil || !strings.Contains(err.Error(), "8") {
			t.Fatalf("freeze = %v, want refusal naming pid 8", err)
		}
		fz.exited(8)
		if err := fz.freeze(context.Background()); err != nil {
			t.Fatalf("freeze after the straggler exited: %v", err)
		}
	})
}

// Readiness is gated on thaw, so thaw must confirm, not assume.
func TestThawConfirmsOrFails(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	cg.stuckThaw = true
	if err := fz.thaw(); err == nil {
		t.Fatal("thaw that changed nothing must fail")
	}
	cg.stuckThaw = false
	if err := fz.thaw(); err != nil {
		t.Fatalf("thaw: %v", err)
	}
	if fz.isFrozen() {
		t.Error("still frozen after a confirmed thaw")
	}
}

// Absent and unreadable are different: absent degrades, unreadable errors.
func TestMountedDistinguishesAbsentFromBroken(t *testing.T) {
	missing := newFake()
	missing.missing = true
	if err := newFreezer(missing, testDir).thaw(); err != nil {
		t.Errorf("thaw without cgroup: %v, want nil", err)
	}
	broken := newFake()
	broken.readErr = errors.New("EIO")
	if err := newFreezer(broken, testDir).thaw(); err == nil {
		t.Error("thaw on an unreadable cgroup must not report success")
	}
	if err := newFreezer(broken, testDir).freeze(context.Background()); err == nil {
		t.Error("freeze on an unreadable cgroup must be refused")
	}
}

// On wake with a frozen workload, the loop corrects the clock and thaws
// without anyone polling /health.
func TestWakeLoopThawsOnceClockIsRight(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{host: base.Add(48 * time.Hour)}
	clock := clockUnder(src, base)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fz.wakeLoop(ctx, clock, time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for fz.isFrozen() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fz.isFrozen() {
		t.Fatal("workload never thawed")
	}
	if src.setTo == nil {
		t.Error("clock was never corrected before the thaw")
	}
}

// Frozen workload, no host time: stay frozen. Serving would mean a stale clock.
func TestWakeLoopStaysFrozenWithoutHostTime(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{hostErr: errors.New("no ptp")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fz.wakeLoop(ctx, clockUnder(src, base), time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if !fz.isFrozen() {
		t.Fatal("thawed with an uncorrectable clock")
	}
}

func TestFreezeEndpointStatusCodes(t *testing.T) {
	post := func(fz *freezer, path, body string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if path == "/freeze" {
			fz.handleFreeze(rec, req)
		} else {
			fz.handleThaw(rec, req)
		}
		return rec.Code
	}
	t.Run("frozen_is_200", func(t *testing.T) {
		if got := post(newFreezer(newFake(), testDir), "/freeze", ""); got != 200 {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("no_cgroup_is_503", func(t *testing.T) {
		cg := newFake()
		cg.missing = true
		if got := post(newFreezer(cg, testDir), "/freeze", ""); got != 503 {
			t.Errorf("status %d, want 503", got)
		}
	})
	t.Run("budget_exhausted_is_504", func(t *testing.T) {
		cg := newFake()
		cg.neverDone = true
		if got := post(newFreezer(cg, testDir), "/freeze", `{"budget_ms":20}`); got != 504 {
			t.Errorf("status %d, want 504", got)
		}
	})
	t.Run("budget_exhausted_and_thaw_unconfirmed_is_500", func(t *testing.T) {
		cg := newFake()
		cg.neverDone = true
		cg.stuckThaw = true
		if got := post(newFreezer(cg, testDir), "/freeze", `{"budget_ms":20}`); got != 500 {
			t.Errorf("status %d, want 500", got)
		}
	})
	t.Run("thaw_confirmed_is_200", func(t *testing.T) {
		if got := post(newFreezer(newFake(), testDir), "/thaw", ""); got != 200 {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("thaw_unconfirmed_is_500", func(t *testing.T) {
		cg := newFake()
		fz := newFreezer(cg, testDir)
		_ = fz.freeze(context.Background())
		cg.stuckThaw = true
		if got := post(fz, "/thaw", ""); got != 500 {
			t.Errorf("status %d, want 500", got)
		}
	})
}

func TestNilFreezerIsANoOp(t *testing.T) {
	var f *freezer
	f.spawnLock()
	f.confirmPlaced(1)
	f.spawnUnlock()
	f.exited(1)
	if f.available() || f.isFrozen() {
		t.Error("nil freezer must be neither available nor frozen")
	}
	if name, args := f.wrap("/bin/true", nil); name != "/bin/true" || args != nil {
		t.Error("nil freezer must not wrap")
	}
	if err := f.thaw(); err != nil {
		t.Errorf("thaw on nil: %v", err)
	}
	if err := f.freeze(context.Background()); err == nil {
		t.Error("freeze on nil must be refused")
	}
}
