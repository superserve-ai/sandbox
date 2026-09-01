package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCgroup behaves like the v1 freezer: a FROZEN request reads back as
// FREEZING for a number of polls before settling, or forever if a task cannot
// stop — which is what a process in uninterruptible I/O looks like.
type fakeCgroup struct {
	mu        sync.Mutex
	state     string
	missing   bool // no cgroup at all
	stallFor  int  // reads that report FREEZING before FROZEN
	neverDone bool // stays FREEZING regardless
	procs     []int
	addErr    error
	writes    []string
}

func (f *fakeCgroup) readState() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing {
		return "", errors.New("no such file")
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
		return errors.New("no such file")
	}
	f.writes = append(f.writes, s)
	if s == "FROZEN" {
		f.state = "FREEZING"
	} else {
		f.state = s
	}
	return nil
}

func (f *fakeCgroup) addProc(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	f.procs = append(f.procs, pid)
	return nil
}

func newFake() *fakeCgroup { return &fakeCgroup{state: "THAWED"} }

func TestFreezeWaitsForEveryTaskToStop(t *testing.T) {
	cg := newFake()
	cg.stallFor = 3
	fz := newFreezer(cg)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if st, _ := cg.readState(); st != "FROZEN" {
		t.Errorf("state %q, want FROZEN", st)
	}
}

// A workload that never fully stops must not be reported frozen, and must be
// left running: the supervisor falls back to the slower snapshot, and a
// half-frozen guest it does not know about would be the worst outcome.
func TestFreezeTimeoutThawsAndFails(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	fz := newFreezer(cg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := fz.freeze(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if last := cg.writes[len(cg.writes)-1]; last != "THAWED" {
		t.Errorf("last state write %q, want THAWED after a failed freeze", last)
	}
}

// A process boxd could not place would keep running through a freeze, on the
// stale clock. Refuse while it lives; allow again once it has exited.
func TestFreezeRefusesWhileAnUnplacedProcessLives(t *testing.T) {
	cg := newFake()
	cg.addErr = errors.New("EACCES")
	fz := newFreezer(cg)
	fz.place(4242)
	if err := fz.freeze(context.Background()); err == nil || !strings.Contains(err.Error(), "4242") {
		t.Fatalf("freeze = %v, want refusal naming pid 4242", err)
	}
	fz.exited(4242)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatalf("freeze after the straggler exited: %v", err)
	}
}

func TestFreezeWithoutCgroupIsRefused(t *testing.T) {
	cg := newFake()
	cg.missing = true
	fz := newFreezer(cg)
	if fz.available() {
		t.Fatal("want unavailable")
	}
	if err := fz.freeze(context.Background()); err == nil {
		t.Fatal("want refusal when no cgroup exists")
	}
	// And thaw must be a harmless no-op, since the ready path always calls it.
	if err := fz.thaw(); err != nil {
		t.Errorf("thaw without cgroup: %v, want nil", err)
	}
}

func TestThawIsIdempotent(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg)
	if err := fz.freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := fz.thaw(); err != nil {
			t.Fatal(err)
		}
	}
	// Frozen once, thawed once: the second thaw saw THAWED and wrote nothing.
	want := []string{"FROZEN", "THAWED"}
	if strings.Join(cg.writes, ",") != strings.Join(want, ",") {
		t.Errorf("writes %v, want %v", cg.writes, want)
	}
}

func TestPlaceRecordsThePid(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg)
	fz.place(7)
	if len(cg.procs) != 1 || cg.procs[0] != 7 {
		t.Errorf("procs %v, want [7]", cg.procs)
	}
}

// The HTTP surface the supervisor drives: status codes are the contract.
func TestFreezeEndpointStatusCodes(t *testing.T) {
	post := func(fz *freezer, path, body string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		switch path {
		case "/freeze":
			fz.handleFreeze(rec, req)
		case "/thaw":
			fz.handleThaw(rec, req)
		}
		return rec.Code
	}

	t.Run("frozen_is_200", func(t *testing.T) {
		if got := post(newFreezer(newFake()), "/freeze", ""); got != 200 {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("no_cgroup_is_503", func(t *testing.T) {
		cg := newFake()
		cg.missing = true
		if got := post(newFreezer(cg), "/freeze", ""); got != 503 {
			t.Errorf("status %d, want 503", got)
		}
	})
	t.Run("budget_exhausted_is_504", func(t *testing.T) {
		cg := newFake()
		cg.neverDone = true
		if got := post(newFreezer(cg), "/freeze", `{"budget_ms":20}`); got != 504 {
			t.Errorf("status %d, want 504", got)
		}
	})
	t.Run("thaw_is_200", func(t *testing.T) {
		if got := post(newFreezer(newFake()), "/thaw", ""); got != 200 {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("get_is_405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newFreezer(newFake()).handleFreeze(rec, httptest.NewRequest(http.MethodGet, "/freeze", nil))
		if rec.Code != 405 {
			t.Errorf("status %d, want 405", rec.Code)
		}
	})
}

// No freezer configured is a real state, not a bug: spawning and readiness
// must keep working, and only a freeze is refused.
func TestNilFreezerIsANoOp(t *testing.T) {
	var f *freezer
	f.spawnLock()
	f.place(1)
	f.spawnUnlock()
	f.exited(1)
	if f.available() {
		t.Error("nil freezer must not be available")
	}
	if err := f.thaw(); err != nil {
		t.Errorf("thaw on nil: %v", err)
	}
	if err := f.freeze(context.Background()); err == nil {
		t.Error("freeze on nil must be refused")
	}
}
