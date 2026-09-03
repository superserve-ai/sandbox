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
	missing   bool
	readErr   error
	stallFor  int
	neverDone bool
	stuckThaw bool
	writes    []string
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

func newFake() *fakeCgroup { return &fakeCgroup{state: "THAWED"} }

const testDir = "/sys/fs/cgroup/freezer/workload"

func bg() context.Context { return context.Background() }

func TestFreezeWaitsForEveryTaskToStop(t *testing.T) {
	cg := newFake()
	cg.stallFor = 3
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !fz.isFrozen() {
		t.Error("want frozen")
	}
}

// A frozen workload stays frozen until the supervisor says otherwise. Nothing
// inside the guest may release it — from inside, "about to be snapshotted" and
// "just restored" are indistinguishable.
func TestFrozenStaysFrozenUntilTold(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatal(err)
	}
	// Health may be polled any number of times in the window before the
	// snapshot; it must never thaw.
	clock := clockUnder(&fakeSource{host: base}, base)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handleHealth(clock, fz)(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != 503 {
			t.Fatalf("health %d while frozen, want 503 (not ready, and it must not release)", rec.Code)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if !fz.isFrozen() {
		t.Fatal("workload thawed without a /thaw or /wake")
	}
	for _, w := range cg.writes {
		if w == "THAWED" {
			t.Fatal("something wrote THAWED on its own")
		}
	}
}

func TestFreezeTimeoutThawsAndFails(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	fz := newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(bg(), 30*time.Millisecond)
	defer cancel()
	err := fz.freeze(ctx, "t1")
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errThawUnconfirmed) {
		t.Fatalf("err = %v, want deadline exceeded with a confirmed thaw", err)
	}
	if fz.isFrozen() {
		t.Error("still frozen after a failed freeze")
	}
}

func TestFreezeTimeoutWithUnconfirmedThawSaysSo(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	cg.stuckThaw = true
	fz := newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(bg(), 20*time.Millisecond)
	defer cancel()
	if err := fz.freeze(ctx, "t1"); !errors.Is(err, errThawUnconfirmed) {
		t.Fatalf("err = %v, want errThawUnconfirmed", err)
	}
}

// The trampoline joins the cgroup before exec and refuses to run the command
// if it cannot: a process outside the cgroup would survive a freeze.
func TestWrapJoinsCgroupOrDoesNotRun(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	name, args := fz.wrap("/usr/bin/python3", []string{"-c", "print(1)", "a b"})
	if name != "/bin/sh" || len(args) < 3 || args[0] != "-c" {
		t.Fatalf("wrap = %s %v, want /bin/sh -c …", name, args)
	}
	if !strings.Contains(args[1], "cgroup.procs && exec \"$0\" \"$@\"") {
		t.Errorf("script %q must join with && so a failed placement never execs", args[1])
	}
	if strings.Contains(args[1], "2>/dev/null") {
		t.Errorf("script %q must not hide a placement failure", args[1])
	}
	if args[2] != "/usr/bin/python3" || args[3] != "-c" || args[4] != "print(1)" || args[5] != "a b" {
		t.Errorf("argv not preserved: %v", args[2:])
	}
}

func TestWrapIsPassthroughWithoutCgroup(t *testing.T) {
	cg := newFake()
	cg.missing = true
	fz := newFreezer(cg, testDir)
	if name, args := fz.wrap("/bin/true", []string{"x"}); name != "/bin/true" || len(args) != 1 || args[0] != "x" {
		t.Errorf("wrap = %s %v, want passthrough", name, args)
	}
}

func TestThawConfirmsOrFails(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatal(err)
	}
	cg.stuckThaw = true
	if err := fz.thaw("t1"); err == nil {
		t.Fatal("thaw that changed nothing must fail")
	}
	cg.stuckThaw = false
	if err := fz.thaw("t1"); err != nil {
		t.Fatalf("thaw: %v", err)
	}
	if fz.isFrozen() {
		t.Error("still frozen after a confirmed thaw")
	}
}

// Absent and unreadable are different: absent degrades, unreadable errors.
func TestAbsentCgroupDegradesButBrokenErrors(t *testing.T) {
	missing := newFake()
	missing.missing = true
	fz := newFreezer(missing, testDir)
	if fz.available() {
		t.Error("absent cgroup reported available")
	}
	if err := fz.thaw("t1"); err != nil {
		t.Errorf("thaw without cgroup: %v, want nil", err)
	}
	if err := fz.freeze(bg(), "t1"); err == nil {
		t.Error("freeze without cgroup must be refused")
	}
	broken := newFake()
	bfz := newFreezer(broken, testDir)
	broken.readErr = errors.New("EIO")
	if err := bfz.thaw("t1"); err == nil {
		t.Error("thaw on an unreadable cgroup must not report success")
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
	t.Run("frozen_is_200_and_echoes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		fz := newFreezer(newFake(), testDir)
		fz.handleFreeze(rec, httptest.NewRequest(http.MethodPost, "/freeze", strings.NewReader(`{"token":"t1"}`)))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"token":"t1"`) || !strings.Contains(rec.Body.String(), `"version":1`) {
			t.Errorf("status %d body %s, want 200 echoing version and token", rec.Code, rec.Body.String())
		}
	})
	t.Run("no_token_is_400", func(t *testing.T) {
		if got := post(newFreezer(newFake(), testDir), "/freeze", ""); got != 400 {
			t.Errorf("status %d, want 400", got)
		}
	})
	t.Run("no_cgroup_is_503", func(t *testing.T) {
		cg := newFake()
		cg.missing = true
		if got := post(newFreezer(cg, testDir), "/freeze", `{"token":"t1"}`); got != 503 {
			t.Errorf("status %d, want 503", got)
		}
	})
	t.Run("budget_exhausted_is_504", func(t *testing.T) {
		cg := newFake()
		cg.neverDone = true
		if got := post(newFreezer(cg, testDir), "/freeze", `{"budget_ms":20,"token":"t1"}`); got != 504 {
			t.Errorf("status %d, want 504", got)
		}
	})
	t.Run("budget_exhausted_and_thaw_unconfirmed_is_500", func(t *testing.T) {
		cg := newFake()
		cg.neverDone = true
		cg.stuckThaw = true
		if got := post(newFreezer(cg, testDir), "/freeze", `{"budget_ms":20,"token":"t1"}`); got != 500 {
			t.Errorf("status %d, want 500", got)
		}
	})
	t.Run("thaw_confirmed_is_200", func(t *testing.T) {
		fz := newFreezer(newFake(), testDir)
		_ = fz.freeze(bg(), "t1")
		if got := post(fz, "/thaw", `{"token":"t1"}`); got != 200 {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("thaw_unconfirmed_is_500", func(t *testing.T) {
		cg := newFake()
		fz := newFreezer(cg, testDir)
		_ = fz.freeze(bg(), "t1")
		cg.stuckThaw = true
		if got := post(fz, "/thaw", `{"token":"t1"}`); got != 500 {
			t.Errorf("status %d, want 500", got)
		}
	})
}

// The token table: a freeze repeated with its own token succeeds, a second
// token while one is active conflicts, a thaw or wake repeated after success
// succeeds, and a missing or different token is refused without changing state.
func TestFreezeTokenTable(t *testing.T) {
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
	fz := newFreezer(newFake(), testDir)
	steps := []struct {
		path, body string
		want       int
		frozen     bool
	}{
		{"/thaw", `{"token":"t1"}`, 409, false},
		{"/freeze", `{"token":"t1"}`, 200, true},
		{"/freeze", `{"token":"t1"}`, 200, true},
		{"/freeze", `{"token":"t2"}`, 409, true},
		{"/thaw", `{"token":"t2"}`, 409, true},
		{"/thaw", ``, 400, true},
		{"/thaw", `{"token":"t1"}`, 200, false},
		{"/thaw", `{"token":"t1"}`, 200, false},
		{"/thaw", `{"token":"t2"}`, 409, false},
		{"/freeze", `{"token":"t2"}`, 200, true},
		{"/thaw", `{"token":"t1"}`, 409, true},
		{"/thaw", `{"token":"t2"}`, 200, false},
	}
	for i, st := range steps {
		if got := post(fz, st.path, st.body); got != st.want || fz.isFrozen() != st.frozen {
			t.Fatalf("step %d %s %s: code %d frozen %v, want %d %v", i, st.path, st.body, got, fz.isFrozen(), st.want, st.frozen)
		}
	}
}

func TestNilFreezerIsANoOp(t *testing.T) {
	var f *freezer
	f.spawnLock()
	f.spawnUnlock()
	if f.available() || f.isFrozen() {
		t.Error("nil freezer must be neither available nor frozen")
	}
	if name, args := f.wrap("/bin/true", nil); name != "/bin/true" || args != nil {
		t.Error("nil freezer must not wrap")
	}
	if err := f.thaw("t1"); err != nil {
		t.Errorf("thaw on nil: %v", err)
	}
	if err := f.freeze(bg(), "t1"); err == nil {
		t.Error("freeze on nil must be refused")
	}
}
