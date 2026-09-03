package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
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
	onPoll    func() // called on each poll that reads FREEZING
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
		if f.neverDone || f.stallFor > 0 {
			if f.stallFor > 0 {
				f.stallFor--
			}
			if f.onPoll != nil {
				f.onPoll()
			}
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
	// The cgroup may still be stopped: boxd stays frozen under the token, so
	// nothing spawns, a repeat freeze does not claim success, and the thaw
	// retries the cgroup until it answers.
	if !fz.isFrozen() || !fz.holds("t1") {
		t.Fatalf("after an unconfirmed rollback: frozen=%v holds=%v, want both", fz.isFrozen(), fz.holds("t1"))
	}
	if err := fz.beginSpawn(); !errors.Is(err, errWorkloadFrozen) {
		if err == nil {
			fz.endSpawn()
		}
		t.Fatalf("spawn after an unconfirmed rollback: %v, want errWorkloadFrozen", err)
	}
	ctx2, cancel2 := context.WithTimeout(bg(), 20*time.Millisecond)
	defer cancel2()
	if err := fz.freeze(ctx2, "t1"); err == nil {
		t.Fatal("repeat freeze claimed success over an unconfirmed cgroup")
	}
	if err := fz.thaw("t1"); err == nil || !fz.isFrozen() {
		t.Fatalf("thaw of a stuck cgroup: err=%v frozen=%v, want an error and still frozen", err, fz.isFrozen())
	}
	cg.mu.Lock()
	cg.stuckThaw = false
	cg.mu.Unlock()
	if err := fz.thaw("t1"); err != nil || fz.isFrozen() {
		t.Fatalf("thaw once the cgroup answers: err=%v frozen=%v, want released", err, fz.isFrozen())
	}
}

// The trampoline joins the cgroup before exec and refuses to run the command
// if it cannot: a process outside the cgroup would survive a freeze.
func TestWrapJoinsCgroupOrDoesNotRun(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	name, args, placed := fz.wrap("/usr/bin/python3", []string{"-c", "print(1)", "a b"})
	if placed != nil {
		placed.r.Close()
		placed.w.Close()
	}
	if name != "/bin/sh" || len(args) < 3 || args[0] != "-c" || placed == nil {
		t.Fatalf("wrap = %s %v placed=%v, want /bin/sh -c … with a placement pipe", name, args, placed != nil)
	}
	if !strings.Contains(args[1], "cgroup.procs && printf 1 >&3 && exec 3>&- && exec \"$0\" \"$@\"") {
		t.Errorf("script %q must join, report, and only then exec", args[1])
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
	if name, args, placed := fz.wrap("/bin/true", []string{"x"}); name != "/bin/true" || len(args) != 1 || args[0] != "x" || placed != nil {
		t.Errorf("wrap = %s %v placed=%v, want passthrough", name, args, placed != nil)
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
	_ = f.beginSpawn()
	f.endSpawn()
	if f.available() || f.isFrozen() {
		t.Error("nil freezer must be neither available nor frozen")
	}
	if name, args, _ := f.wrap("/bin/true", nil); name != "/bin/true" || args != nil {
		t.Error("nil freezer must not wrap")
	}
	if err := f.thaw("t1"); err != nil {
		t.Errorf("thaw on nil: %v", err)
	}
	if err := f.freeze(bg(), "t1"); err == nil {
		t.Error("freeze on nil must be refused")
	}
}

// A freeze that ran out of budget was rolled back by boxd itself; the
// supervisor's follow-up thaw with the same token must succeed, or a normal
// timeout turns into a failed pause.
func TestTimedOutFreezeAcceptsItsOwnThaw(t *testing.T) {
	cg := newFake()
	cg.neverDone = true
	fz := newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(bg(), 20*time.Millisecond)
	defer cancel()
	if err := fz.freeze(ctx, "t1"); err == nil {
		t.Fatal("freeze must report the timeout")
	}
	if fz.isFrozen() {
		t.Fatal("not rolled back")
	}
	if err := fz.thaw("t1"); err != nil {
		t.Fatalf("follow-up thaw with the timed-out freeze's token: %v", err)
	}
	if err := fz.thaw("t2"); err == nil {
		t.Fatal("a different token must still be refused")
	}
}

// The spawn is not complete until the wrapper has joined the cgroup and said
// so; a wrapper that cannot join never runs the command and is not left alive.
func TestPlacementIsAcknowledgedBeforeSpawnReturns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "freezer.state"), []byte("THAWED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fz := newFreezer(cgroupFS{dir: dir}, dir)
	if !fz.available() {
		t.Fatal("freezer not available over the temp cgroup")
	}

	name, args, placed := fz.wrap("/bin/sh", []string{"-c", "exit 0"})
	cmd := exec.Command(name, args...)
	placed.attach(cmd)
	if err := fz.beginSpawn(); err != nil {
		t.Fatal(err)
	}
	err := cmd.Start()
	if err == nil {
		err = fz.confirmPlacement(cmd, placed)
	}
	fz.endSpawn()
	if err != nil {
		t.Fatalf("placed spawn: %v", err)
	}
	_ = cmd.Wait()
	if b, _ := os.ReadFile(filepath.Join(dir, "cgroup.procs")); strings.TrimSpace(string(b)) == "" {
		t.Error("wrapper did not write its pid before reporting")
	}

	// cgroup.procs unwritable (a directory): the wrapper cannot join, reports
	// nothing, and the spawn is refused with the process dead.
	os.Remove(filepath.Join(dir, "cgroup.procs"))
	if err := os.Mkdir(filepath.Join(dir, "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	name, args, placed = fz.wrap("/bin/sh", []string{"-c", "sleep 30"})
	cmd = exec.Command(name, args...)
	placed.attach(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fz.confirmPlacement(cmd, placed); !errors.Is(err, errNotPlaced) {
		t.Fatalf("unplaced spawn: err=%v, want errNotPlaced", err)
	}
	_ = cmd.Wait()
}

// A failed spawn releases the placement pipe, and a child the confirmation
// killed is reaped rather than left as a zombie.
func TestFailedSpawnReleasesPlacementAndReapsTheChild(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "freezer.state"), []byte("THAWED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "cgroup.procs"), 0o755); err != nil {
		t.Fatal(err)
	}
	fz := newFreezer(cgroupFS{dir: dir}, dir)

	// Start fails: nothing to place, both pipe ends closed.
	name, args, placed := fz.wrap("/nonexistent/binary", nil)
	cmd := exec.Command(name, args...)
	cmd.Path = "/nonexistent/binary"
	placed.attach(cmd)
	err := cmd.Start()
	if perr := fz.confirmPlacement(cmd, placed); err == nil {
		err = perr
	}
	if err == nil || placed.r != nil || placed.w != nil {
		t.Fatalf("err=%v r=%v w=%v; want the start failure with the pipe released", err, placed.r, placed.w)
	}

	// Placement fails: the child is killed and reaped.
	name, args, placed = fz.wrap("/bin/sh", []string{"-c", "sleep 30"})
	cmd = exec.Command(name, args...)
	placed.attach(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fz.confirmPlacement(cmd, placed); !errors.Is(err, errNotPlaced) {
		t.Fatalf("err=%v, want errNotPlaced", err)
	}
	reapKilled(cmd)
	if cmd.ProcessState == nil || cmd.ProcessState.Exited() && cmd.ProcessState.Success() {
		t.Fatalf("child not reaped as killed: %v", cmd.ProcessState)
	}
	if placed.r != nil || placed.w != nil {
		t.Error("pipe not released after a failed placement")
	}
}

// No process starts while the workload is frozen: it would spend its first
// moments outside the cgroup, exactly where a snapshot must not find it.
func TestSpawnIsRefusedWhileFrozen(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	if err := fz.beginSpawn(); err != nil {
		t.Fatal(err)
	}
	fz.endSpawn()
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatal(err)
	}
	if err := fz.beginSpawn(); !errors.Is(err, errWorkloadFrozen) {
		if err == nil {
			fz.endSpawn()
		}
		t.Fatalf("spawn while frozen: err=%v, want errWorkloadFrozen", err)
	}
	if err := fz.thaw("t1"); err != nil {
		t.Fatal(err)
	}
	if err := fz.beginSpawn(); err != nil {
		t.Fatalf("spawn after thaw: %v", err)
	}
	fz.endSpawn()
}

// boxd learns of the freezer from the init script, never by probing: with
// nothing set it is unavailable and touches no file; set, the mount is
// confirmed, and a claimed-but-missing one fails closed.
func TestFreezerFromEnv(t *testing.T) {
	t.Setenv(freezerEnv, "")
	if fz := freezerFromEnv(); fz.available() {
		t.Fatal("freezer available with nothing set")
	}
	dir := t.TempDir()
	t.Setenv(freezerEnv, dir)
	if fz := freezerFromEnv(); fz.available() {
		t.Fatal("a claimed freezer with no state file must fail closed")
	}
	if err := os.WriteFile(filepath.Join(dir, "freezer.state"), []byte("THAWED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if fz := freezerFromEnv(); !fz.available() || fz.dir != dir {
		t.Fatal("a mounted freezer named by the init script must be used")
	}
}

// A spawn refused during a freeze opens nothing: the guard comes before the
// stdio pipes, so a refusal cannot leave a descriptor behind.
func TestRefusedSpawnOpensNothing(t *testing.T) {
	fz := newFreezer(newFake(), testDir)
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatal(err)
	}
	s := newProcessService()
	s.freezer = fz
	emit := func(*pb.ProcessEvent) error { return nil }
	name, args, placed := fz.wrap("/bin/sh", []string{"-c", "true"})
	cmd := exec.Command(name, args...)
	placed.attach(cmd)
	err := s.startPipes(bg(), cmd, placed, emit, new(atomic.Bool), true)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("spawn while frozen: %v", err)
	}
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil || placed.r != nil || placed.w != nil {
		t.Fatalf("refused spawn left descriptors open: stdin=%v stdout=%v stderr=%v placement=%v/%v",
			cmd.Stdin, cmd.Stdout, cmd.Stderr, placed.r, placed.w)
	}
}

// The freeze budget covers waiting for a spawn in flight: the freeze gives
// up on time, touches nothing, and its token counts as released once the
// spawn finishes, so the supervisor's follow-up thaw is answered as done.
func TestFreezeBudgetCoversTheSpawnGuard(t *testing.T) {
	fs := newFake()
	fz := newFreezer(fs, testDir)
	if err := fz.beginSpawn(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := fz.freeze(ctx, "t1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("freeze under a held guard: %v, want the budget to expire", err)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("freeze waited %v for the guard, past its budget", waited)
	}
	if st, _ := fs.readState(); st != "THAWED" || fz.isFrozen() {
		t.Fatalf("abandoned freeze touched the cgroup: state=%q frozen=%v", st, fz.isFrozen())
	}
	fz.endSpawn()
	if err := fz.thaw("t1"); err != nil {
		t.Fatalf("follow-up thaw of the abandoned token: %v", err)
	}
	if err := fz.thaw("t2"); !errors.Is(err, errTokenMismatch) {
		t.Fatalf("thaw of an unknown token: %v, want errTokenMismatch", err)
	}

	// A budget already spent when the guard frees never writes FROZEN.
	spent, cancel := context.WithCancel(bg())
	cancel()
	if err := fz.freeze(spent, "t3"); !errors.Is(err, context.Canceled) {
		t.Fatalf("freeze with a spent budget: %v", err)
	}
	if st, _ := fs.readState(); st != "THAWED" {
		t.Fatalf("spent budget still wrote the cgroup: state=%q", st)
	}
	if err := fz.thaw("t3"); err != nil {
		t.Fatalf("follow-up thaw after a spent budget: %v", err)
	}
}

// A body the handler cannot decode whole never reaches the cgroup, even when
// the fields it did decode would have been enough.
func TestMalformedLifecycleBodiesAreRefused(t *testing.T) {
	cg := newFake()
	fz := newFreezer(cg, testDir)
	if got := post(fz, "/freeze", `{"token":"t1","budget_ms":"bad"}`); got != 400 || fz.isFrozen() {
		t.Fatalf("malformed freeze: code %d frozen %v, want 400 and nothing touched", got, fz.isFrozen())
	}
	if got := post(fz, "/freeze", `{"token":"t1"} garbage`); got != 400 || fz.isFrozen() {
		t.Fatalf("freeze with trailing data: code %d frozen %v, want 400 and nothing touched", got, fz.isFrozen())
	}
	if st, _ := cg.readState(); st != "THAWED" {
		t.Fatalf("malformed freeze reached the cgroup: state %q", st)
	}
	if got := post(fz, "/freeze", `{"token":"t1"}`); got != 200 || !fz.isFrozen() {
		t.Fatalf("well-formed freeze: code %d frozen %v", got, fz.isFrozen())
	}
	if got := post(fz, "/thaw", `{"token":["t1"]}`); got != 400 || !fz.isFrozen() {
		t.Fatalf("malformed thaw: code %d frozen %v, want 400 and still frozen", got, fz.isFrozen())
	}
	if got := post(fz, "/thaw", `{"token":"t1"}{"token":"t1"}`); got != 400 || !fz.isFrozen() {
		t.Fatalf("thaw with a second object: code %d frozen %v, want 400 and still frozen", got, fz.isFrozen())
	}
	rec := httptest.NewRecorder()
	handleWake(clockUnder(&fakeSource{}, time.Now()), fz)(rec, httptest.NewRequest(http.MethodPost, "/wake", strings.NewReader(`{"clock_frozen":false,"token":"t1"} x`)))
	if rec.Code != 400 || !fz.isFrozen() {
		t.Fatalf("wake with trailing data: code %d frozen %v, want 400 and still frozen", rec.Code, fz.isFrozen())
	}
	if got := post(fz, "/thaw", `{"token":"t1"}`); got != 200 || fz.isFrozen() {
		t.Fatalf("well-formed thaw: code %d frozen %v", got, fz.isFrozen())
	}
}

// post sends a lifecycle request straight to its handler and reports the status.
func post(fz *freezer, path, body string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if path == "/freeze" {
		fz.handleFreeze(rec, req)
	} else {
		fz.handleThaw(rec, req)
	}
	return rec.Code
}

// From the first request to stop, health must not read ready: tasks are
// stopping while the cgroup still reads FREEZING. A rolled-back freeze reads
// ready again only once its thaw is confirmed.
func TestFreezingReadsUnreadyFromTheFirstRequest(t *testing.T) {
	cg := newFake()
	cg.stallFor = 3
	fz := newFreezer(cg, testDir)
	readyWhileFreezing := false
	cg.onPoll = func() {
		if !fz.isFrozen() {
			readyWhileFreezing = true
		}
	}
	if err := fz.freeze(bg(), "t1"); err != nil {
		t.Fatal(err)
	}
	if readyWhileFreezing {
		t.Fatal("read ready while the cgroup was FREEZING")
	}

	cg = newFake()
	cg.neverDone = true
	fz = newFreezer(cg, testDir)
	ctx, cancel := context.WithTimeout(bg(), 20*time.Millisecond)
	defer cancel()
	if err := fz.freeze(ctx, "t1"); !errors.Is(err, context.DeadlineExceeded) || fz.isFrozen() {
		t.Fatalf("rolled-back freeze: err=%v frozen=%v, want the deadline and ready again", err, fz.isFrozen())
	}
}
