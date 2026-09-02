package vm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/network"
)

// A guest that reports it cannot correct its clock must fail the wait fast and
// typed, so the restore can be retried the unfrozen way instead of waiting out
// the budget with the customer's processes frozen.
func TestWaitForGuestWakeFailsFastOnUncorrectableClock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	calls := 0
	var sawPolicy bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wake" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var b struct {
			ClockFrozen bool `json:"clock_frozen"`
		}
		_ = jsonDecode(r, &b)
		sawPolicy = b.ClockFrozen
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"clock","wall_clock":{"source":"unavailable","error":"open /dev/ptp0: no such file"}}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	start := time.Now()
	err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true)
	if !errors.Is(err, ErrGuestClockUnready) {
		t.Fatalf("err = %v, want ErrGuestClockUnready", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v; must not wait out the budget", time.Since(start))
	}
	if calls < clockUnreadyPolls {
		t.Errorf("gave up after %d polls, want at least %d", calls, clockUnreadyPolls)
	}
	if !sawPolicy {
		t.Error("the guest must be told the clock was frozen")
	}
}

func TestWaitForGuestWakeReadyIsNil(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","wall_clock":{"source":"ptp"}}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	if err := waitForGuestWake(context.Background(), "127.0.0.1", 2*time.Second, false); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// A record that still owes a wake must get one on recovery — with the policy
// its restore used — never a health poll, which would take a stopped workload
// for a ready sandbox.
func TestVerifyBoxdReadyCompletesAPendingWake(t *testing.T) {
	origWake, origAdopt := boxdWakeGuest, adoptionBoxdReady
	t.Cleanup(func() { boxdWakeGuest, adoptionBoxdReady = origWake, origAdopt })
	m := &Manager{log: zerolog.Nop()}

	t.Run("pending_wake_is_sent_with_its_policy", func(t *testing.T) {
		var sawFrozen *bool
		boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool) error {
			sawFrozen = &frozen
			return nil
		}
		adoptionBoxdReady = func(context.Context, *Manager, string) error {
			t.Fatal("a pending wake must not be verified by health")
			return nil
		}
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true}
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", inst); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if sawFrozen == nil || !*sawFrozen {
			t.Error("wake not sent, or sent without the frozen policy")
		}
		if inst.WakePending {
			t.Error("WakePending still set after a completed wake")
		}
	})

	t.Run("no_pending_wake_uses_health", func(t *testing.T) {
		boxdWakeGuest = func(context.Context, string, time.Duration, bool) error {
			t.Fatal("no wake owed; must not send one")
			return nil
		}
		called := false
		adoptionBoxdReady = func(context.Context, *Manager, string) error { called = true; return nil }
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", &VMInstance{ID: "vm"}); err != nil || !called {
			t.Fatalf("err=%v called=%v; want health verification", err, called)
		}
	})

	t.Run("uncorrectable_clock_latches_the_host_and_fails", func(t *testing.T) {
		m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{GuestClockFreezeEnabled: true}}
		m.clockRealtimeCapable.Store(true)
		boxdWakeGuest = func(context.Context, string, time.Duration, bool) error { return ErrGuestClockUnready }
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true}
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", inst); !errors.Is(err, ErrGuestClockUnready) {
			t.Fatalf("err = %v, want ErrGuestClockUnready", err)
		}
		if !inst.WakePending {
			t.Error("a failed wake must leave WakePending set")
		}
		if m.clockPolicyFor(true) != nil {
			t.Error("host not latched to unfrozen restores")
		}
	})
}

// The wake state must survive a daemon restart, or recovery cannot know it
// owes one.
func TestWakeStateSurvivesRecordRoundTrip(t *testing.T) {
	rec := toRecord(&VMInstance{ID: "vm", WakePending: true, ClockFrozen: true})
	if !rec.WakePending || !rec.ClockFrozen {
		t.Fatalf("toRecord dropped wake state: %+v", rec)
	}
	got := toInstance(rec)
	if !got.WakePending || !got.ClockFrozen {
		t.Errorf("toInstance dropped wake state: pending=%v frozen=%v", got.WakePending, got.ClockFrozen)
	}
}

// A guest from before the wake protocol answers /wake with 404. With nothing
// frozen its health is its readiness; with a frozen clock nothing but /wake
// may vouch for it.
func TestWaitForGuestWakeLegacyGuest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	var healthPolls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			healthPolls.Add(1)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	if err := waitForGuestWake(context.Background(), "127.0.0.1", 2*time.Second, false); err != nil {
		t.Fatalf("unfrozen: want readiness from /health, got %v", err)
	}
	if healthPolls.Load() == 0 {
		t.Fatal("unfrozen: /health was never consulted")
	}
	healthPolls.Store(0)
	if err := waitForGuestWake(context.Background(), "127.0.0.1", 300*time.Millisecond, true); err == nil {
		t.Fatal("frozen: a guest without /wake must not be verified by /health")
	}
	if n := healthPolls.Load(); n != 0 {
		t.Fatalf("frozen: /health polled %d times", n)
	}
}

// An image holding a frozen workload owes a wake before the resume commits,
// whether or not this restore froze the clock — with the policy off, the
// workload is still stopped in the image.
func TestResumeWakesFrozenWorkloadBeforeCommit(t *testing.T) {
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	corrects := true
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		CorrectsWallClock: &corrects,
	}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: &fakeNetMgr{},
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, error) { return false, nil }
	wakes := 0
	var sawFrozen bool
	var statusAtWake VMStatus
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool) error {
		wakes++
		sawFrozen = frozen
		inst.mu.RLock()
		statusAtWake = inst.Status
		inst.mu.RUnlock()
		return nil
	}

	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if wakes != 1 {
		t.Fatalf("wakes = %d, want exactly one synchronous wake", wakes)
	}
	if sawFrozen {
		t.Error("the clock was not frozen; the wake must say so")
	}
	if statusAtWake == StatusRunning {
		t.Error("Running was committed before the workload was released")
	}
}

// An in-place restore whose guest cannot correct a frozen clock relaunches
// with the clock running on the overlay, slot and record it already owns.
// Recreating the overlay would truncate it.
func TestRestoreInPlaceClockFallbackKeepsOverlayAndSlot(t *testing.T) {
	origWake, origDead := boxdWakeGuest, vmDeadForRetry
	t.Cleanup(func() { boxdWakeGuest, vmDeadForRetry = origWake, origDead })
	vmDeadForRetry = func(*Manager, string) bool { return true }

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	basePath := filepath.Join(dir, "base.ext4")
	for _, p := range []string{snapPath, memPath, basePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(WallClockMarkerPath(memPath), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "vm-1", "overlay.ext4")
	if err := os.MkdirAll(filepath.Dir(overlay), 0o755); err != nil {
		t.Fatal(err)
	}
	const data = "customer data"
	if err := os.WriteFile(overlay, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNetMgr{}
	prev := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: overlay,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		cfg:        ManagerConfig{RunDir: dir, GuestClockFreezeEnabled: true},
		netMgr:     fake,
		vms:        map[string]*VMInstance{"vm-1": prev},
		restoreSem: make(chan struct{}, 1),
	}
	mgr.clockRealtimeCapable.Store(true)
	launches := 0
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launches++
		return 4321, SupervisionUnit, nil
	}
	var policies []*bool
	mgr.restoreSnapshotHook = func(_, _, _ string, clock *bool) error {
		policies = append(policies, clock)
		return nil
	}
	wakes := 0
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool) error {
		wakes++
		if wakes == 1 {
			if !frozen {
				t.Error("first wake must carry the frozen policy")
			}
			return ErrGuestClockUnready
		}
		if frozen {
			t.Error("the relaunch must run the clock")
		}
		return nil
	}

	inst, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: basePath}, nil, "team", "owner", "", nil, 0)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if launches != 2 || wakes != 2 {
		t.Fatalf("launches=%d wakes=%d, want 2 and 2", launches, wakes)
	}
	if len(policies) != 2 || policies[0] == nil || *policies[0] || policies[1] != nil {
		t.Fatalf("clock policies = %v, want frozen then legacy", policies)
	}
	if got, _ := os.ReadFile(overlay); string(got) != data {
		t.Fatalf("overlay = %q, want the original contents", got)
	}
	if len(fake.setupCalls) != 1 || len(fake.teardownCalls) != 0 || len(fake.cleanupCalls) != 0 {
		t.Fatalf("network setup=%v teardown=%v cleanup=%v; the slot must be kept", fake.setupCalls, fake.teardownCalls, fake.cleanupCalls)
	}
	mgr.mu.RLock()
	tracked := mgr.vms["vm-1"] == inst
	mgr.mu.RUnlock()
	if !tracked {
		t.Fatal("instance was untracked between passes")
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusRunning || inst.WakePending || inst.ClockFrozen {
		t.Errorf("status=%v wakePending=%v clockFrozen=%v", inst.Status, inst.WakePending, inst.ClockFrozen)
	}
	if inst.CorrectsWallClock == nil || !*inst.CorrectsWallClock {
		t.Error("the image property must survive the fallback")
	}
	if !mgr.guestClockUnready.Load() {
		t.Error("host not latched")
	}
}
