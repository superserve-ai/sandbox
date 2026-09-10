package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true, "tok")
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

// The verdict needs consecutive answers of one kind: an answer of another
// kind, or another status, in between starts the count over, so a guest
// that was recovering is not parked on failures that were not consecutive.
func TestWaitForGuestWakeVerdictNeedsAConsecutiveStreak(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []int // 0: clock, 1: thaw, 2: HTTP 500
		want    error
		calls   int
	}{
		{"a_thaw_answer_breaks_a_clock_streak", []int{0, 0, 1, 0, 0, 0}, ErrGuestClockUnready, 6},
		{"another_status_breaks_the_streak", []int{1, 1, 2, 1, 1, 1}, ErrGuestThawFailed, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
			if err != nil {
				t.Skipf("port %d busy: %v", boxdPort, err)
			}
			calls := 0
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := calls
				calls++
				if i >= len(tc.answers) {
					i = len(tc.answers) - 1
				}
				w.Header().Set("Content-Type", "application/json")
				switch tc.answers[i] {
				case 0:
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"status":"clock","wall_clock":{"error":"no ptp"}}`))
				case 1:
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"status":"thaw","wall_clock":{"error":"cgroup busy"}}`))
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			srv.Listener = ln
			srv.Start()
			defer srv.Close()
			err = waitForGuestWake(context.Background(), "127.0.0.1", 10*time.Second, true, "tok")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if calls != tc.calls {
				t.Fatalf("verdict after %d answers, want %d: the streak must restart at the interruption", calls, tc.calls)
			}
		})
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
	if err := waitForGuestWake(context.Background(), "127.0.0.1", 2*time.Second, false, "tok"); err != nil {
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
		var sawToken string
		boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, token string) error {
			sawFrozen = &frozen
			sawToken = token
			return nil
		}
		adoptionBoxdReady = func(context.Context, *Manager, string) error {
			t.Fatal("a pending wake must not be verified by health")
			return nil
		}
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok"}
		if err := m.verifyBoxdReady(context.Background(), "10.0.0.2", inst); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if sawFrozen == nil || !*sawFrozen || sawToken != "tok" {
			t.Error("wake not sent, or sent without the frozen policy and the record's token")
		}
		if inst.WakePending {
			t.Error("WakePending still set after a completed wake")
		}
	})

	t.Run("no_pending_wake_uses_health", func(t *testing.T) {
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error {
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
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return ErrGuestClockUnready }
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
	frozen := true
	rec := toRecord(&VMInstance{ID: "vm", WakePending: true, ClockFrozen: true, SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok", WakeToken: "tok", ArtifactID: "a"})
	if !rec.WakePending || !rec.ClockFrozen || rec.SnapshotWorkloadFrozen == nil || !*rec.SnapshotWorkloadFrozen || rec.FreezeToken != "tok" || rec.ArtifactID != "a" {
		t.Fatalf("toRecord dropped wake state: %+v", rec)
	}
	got := toInstance(rec)
	if !got.WakePending || !got.ClockFrozen || got.SnapshotWorkloadFrozen == nil || !*got.SnapshotWorkloadFrozen || got.FreezeToken != "tok" || got.ArtifactID != "a" {
		t.Errorf("toInstance dropped wake state: pending=%v frozen=%v image=%v", got.WakePending, got.ClockFrozen, got.SnapshotWorkloadFrozen)
	}
}

// An image holding a frozen workload owes a wake before the resume commits,
// whether or not this restore froze the clock — with the policy off, the
// workload is still stopped in the image.
func TestResumeWakesFrozenWorkloadBeforeCommit(t *testing.T) {
	useTempFloor(t)
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
	frozen := true
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok",
		IP: "10.9.9.9", // the slot of an earlier run; this resume takes a new one
	}
	fake := &fakeNetMgr{}
	slot, _ := fake.SetupVM(context.Background(), "probe", nil)
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: fake,
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	// The launch runs after the record owes the wake and before the guest is
	// woken: what recovery would read after a crash here must already name
	// this run's slot and token.
	var ipAtLaunch, tokenAtLaunch string
	var owedAtLaunch bool
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		inst.mu.RLock()
		ipAtLaunch, tokenAtLaunch, owedAtLaunch = inst.IP, inst.WakeToken, inst.WakePending
		inst.mu.RUnlock()
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }
	wakes := 0
	var sawFrozen, owedAtWake bool
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, _ string) error {
		wakes++
		sawFrozen = frozen
		inst.mu.RLock()
		owedAtWake = inst.WakePending && inst.Unverified
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
	if !owedAtWake {
		t.Error("the record must owe the wake while the workload is still frozen")
	}
	if !owedAtLaunch || ipAtLaunch != slot.HostIP || tokenAtLaunch != "tok" {
		t.Errorf("at launch: owed=%v ip=%q token=%q; want the owed record to name this run's slot %q and token", owedAtLaunch, ipAtLaunch, tokenAtLaunch, slot.HostIP)
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusRunning || inst.Unverified || inst.WakePending {
		t.Errorf("after resume: status=%v unverified=%v wakePending=%v", inst.Status, inst.Unverified, inst.WakePending)
	}
	if inst.FreezeToken != "tok" || inst.WakeToken != "" {
		t.Errorf("after resume: freeze=%q wake=%q; want the committed token and nothing in flight", inst.FreezeToken, inst.WakeToken)
	}
}

// A frozen resume that fails after publishing its wake-owed record puts the
// sandbox back to Paused, so the record does not advertise a guest that never
// came back.
func TestFrozenResumeFailureRevertsToPaused(t *testing.T) {
	useTempFloor(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	frozen := true
	pausedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		SnapshotWorkloadFrozen: &frozen, PausedAt: pausedAt, FreezeToken: "rec",
		IP: "10.9.9.9", // an earlier run's slot, long released
	}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: &fakeNetMgr{},
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	var owedAtLaunch bool
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		inst.mu.RLock()
		owedAtLaunch = inst.Status == StatusRunning && inst.WakePending
		inst.mu.RUnlock()
		return 0, SupervisionUnit, errors.New("launch failed")
	}
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err == nil {
		t.Fatal("want the launch failure")
	}
	if !owedAtLaunch {
		t.Error("the wake-owed record must be published before the launch")
	}
	// The slot this run took goes back to the pool: the record must not keep
	// naming it, or a retry would claim whatever sandbox holds it next.
	inst.mu.RLock()
	ip, ns, token, inflight := inst.IP, inst.Namespace, inst.FreezeToken, inst.WakeToken
	inst.mu.RUnlock()
	if ip != "10.9.9.9" || ns != "" || token != "rec" || inflight != "" {
		t.Errorf("after the failure: ip=%q ns=%q token=%q inflight=%q; want the entry identity back and nothing in flight", ip, ns, token, inflight)
	}

	// An override resolves its token from its own manifest; a failed resume
	// from it must hand the record's own token back with the record's image,
	// or the next ordinary resume presents the wrong token.
	override := filepath.Join(dir, "other.snap")
	if err := os.WriteFile(override, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, override, "disk")
	var tokenAtLaunch string
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		inst.mu.RLock()
		tokenAtLaunch = inst.WakeToken
		inst.mu.RUnlock()
		return 0, SupervisionUnit, errors.New("launch failed")
	}
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", override, nil); err == nil {
		t.Fatal("want the launch failure")
	}
	inst.mu.RLock()
	mem, token, inflight := inst.MemFilePath, inst.FreezeToken, inst.WakeToken
	inst.mu.RUnlock()
	if tokenAtLaunch != "disk" {
		t.Errorf("token in flight at launch %q, want the override's", tokenAtLaunch)
	}
	if mem != memPath || token != "rec" || inflight != "" {
		t.Errorf("after the failed override resume: mem=%q token=%q inflight=%q; want the record's own image and token", mem, token, inflight)
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused || inst.WakePending || inst.Unverified {
		t.Errorf("after failure: status=%v wakePending=%v unverified=%v, want Paused and nothing owed", inst.Status, inst.WakePending, inst.Unverified)
	}
	if !inst.PausedAt.Equal(pausedAt) {
		t.Errorf("PausedAt = %v, want the original %v kept for the reclaim order", inst.PausedAt, pausedAt)
	}
}

// An in-place restore whose guest cannot correct a frozen clock relaunches
// with the clock running on the overlay, slot and record it already owns.
// Recreating the overlay would truncate it.
func TestRestoreInPlaceClockFallbackKeepsOverlayAndSlot(t *testing.T) {
	useTempFloor(t)
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
	seedFrozenManifest(t, memPath, "tok")
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
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, token string) error {
		wakes++
		if token != "tok" {
			t.Errorf("wake %d carried token %q, want the manifest's", wakes, token)
		}
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
	if len(fake.setupCalls) != 1 || len(fake.teardownCalls) != 0 || len(fake.cleanupVMCalls) != 0 {
		t.Fatalf("network setup=%v teardown=%v cleanup=%v; the slot must be kept", fake.setupCalls, fake.teardownCalls, fake.cleanupVMCalls)
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

// The vCPUs must not run ahead of the record that owes their wake: a restore
// whose record cannot be made durable fails before the load.
func TestRestoreAbortsBeforeLoadWithoutDurableWakeRecord(t *testing.T) {
	useTempFloor(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	rw, err := OpenStateStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rw.Close()
	store, err := OpenStateStoreReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	basePath := filepath.Join(dir, "base.ext4")
	for _, p := range []string{snapPath, memPath, basePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Only a frozen image owes a wake, and so only a frozen image has a record
	// that must be durable before the load.
	seedFrozenManifest(t, memPath, "tok")
	fake := &fakeNetMgr{}
	mgr := &Manager{
		log:        zerolog.Nop(),
		cfg:        ManagerConfig{RunDir: dir},
		netMgr:     fake,
		state:      store,
		vms:        map[string]*VMInstance{},
		restoreSem: make(chan struct{}, 1),
	}
	launches := 0
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launches++
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreSnapshotHook = func(string, string, string, *bool) error {
		t.Error("snapshot loaded without a durable wake record")
		return nil
	}

	_, err = mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: basePath, DeltaDir: filepath.Join(dir, "delta")}, nil, "team", "owner", "", nil, 0)
	if err == nil || launches != 1 {
		t.Fatalf("err=%v launches=%d, want a failure after one launch", err, launches)
	}
	if len(fake.cleanupVMCalls) != 1 {
		t.Errorf("cleanup calls = %v, want the slot released", fake.cleanupVMCalls)
	}
}

// When Firecracker refuses the clock option, the record must say the clock ran
// before the legacy retry can run the vCPUs.
func TestRestoreLegacyRetrySeesDurableClockPolicy(t *testing.T) {
	useTempFloor(t)
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, _ string) error {
		if frozen {
			t.Error("the legacy restore ran the clock; the wake must say so")
		}
		return nil
	}

	dir := t.TempDir()
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	basePath := filepath.Join(dir, "base.ext4")
	for _, p := range []string{snapPath, memPath, basePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFrozenManifest(t, memPath, "tok")
	mgr := &Manager{
		log:        zerolog.Nop(),
		cfg:        ManagerConfig{RunDir: dir, GuestClockFreezeEnabled: true},
		netMgr:     &fakeNetMgr{},
		state:      store,
		vms:        map[string]*VMInstance{},
		restoreSem: make(chan struct{}, 1),
	}
	mgr.clockRealtimeCapable.Store(true)
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		return 4321, SupervisionUnit, nil
	}
	unknownField := errors.New("load snapshot: [PUT /snapshot/load][400] Bad Request: unknown field `clock_realtime`")
	var durableAtRetry *VMRecord
	mgr.restoreSnapshotHook = func(_, _, _ string, clock *bool) error {
		if clock != nil {
			return unknownField
		}
		durableAtRetry, _ = store.Get("vm-1")
		return nil
	}

	inst, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: basePath, DeltaDir: filepath.Join(dir, "delta")}, nil, "team", "owner", "", nil, 0)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if durableAtRetry == nil || durableAtRetry.ClockFrozen || !durableAtRetry.WakePending {
		t.Fatalf("record at the legacy retry = %+v, want durable, clock running, wake owed", durableAtRetry)
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.ClockFrozen {
		t.Error("instance still claims a frozen clock")
	}
}

// A guest that can correct its clock, paused without freezing, must be resumed
// the legacy way: the image fact says unfrozen even though the guest fact says
// capable, and only the image fact may freeze a clock or owe a wake.
func TestResumeOfUnfrozenPauseDoesNotFreezeOrWake(t *testing.T) {
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })
	// The detached readiness probe after the commit may poll the wake endpoint;
	// a wake before the commit, or one claiming a frozen clock, may not happen.
	var mu sync.Mutex
	var beforeCommit, frozenWakes int
	var inst *VMInstance
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, _ string) error {
		inst.mu.RLock()
		st := inst.Status
		inst.mu.RUnlock()
		mu.Lock()
		defer mu.Unlock()
		if st != StatusRunning {
			beforeCommit++
		}
		if frozen {
			frozenWakes++
		}
		return nil
	}

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	corrects, frozen := true, false
	inst = &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		CorrectsWallClock: &corrects, SnapshotWorkloadFrozen: &frozen,
	}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir, GuestClockFreezeEnabled: true},
		netMgr: &fakeNetMgr{},
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	mgr.clockRealtimeCapable.Store(true)
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }

	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	mu.Lock()
	if beforeCommit != 0 || frozenWakes != 0 {
		t.Errorf("wakes before commit=%d claiming frozen=%d; an unfrozen image owes neither", beforeCommit, frozenWakes)
	}
	mu.Unlock()
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.CorrectsWallClock == nil || !*inst.CorrectsWallClock {
		t.Error("the guest fact must survive an unfrozen resume")
	}
	if inst.SnapshotWorkloadFrozen == nil || *inst.SnapshotWorkloadFrozen {
		t.Error("the image fact must say unfrozen")
	}
}

// A guest a crashed pause left frozen is released on reattach with the token
// the intent carries; a token the guest never froze under means the crash came
// first, and nothing is owed, once the workload is confirmed running. A guest
// that cannot be released, or is frozen under another token, is not served.
func TestReattachReleasesAGuestAnInterruptedPauseFroze(t *testing.T) {
	raiseFloorForTest(t)
	origThaw, origRunning := boxdThawGuest, boxdGuestRunning
	t.Cleanup(func() { boxdThawGuest, boxdGuestRunning = origThaw, origRunning })
	mismatch := fmt.Errorf("%w: status token", ErrGuestTokenMismatch)
	cases := []struct {
		name       string
		thaw       error
		running    error
		wantStatus VMStatus
		wantIntent bool
	}{
		{"released", nil, nil, StatusRunning, false},
		{"never_frozen", mismatch, nil, StatusRunning, false},
		{"frozen_under_another_token", mismatch, errors.New(`guest workload status "frozen"`), StatusError, true},
		{"unreachable", errors.New("connection refused"), nil, StatusError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := OpenStateStore(filepath.Join(dir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			vmDir := filepath.Join(dir, "vm-1")
			if err := os.MkdirAll(vmDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "a"}); err != nil {
				t.Fatal(err)
			}
			rec := VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionUnit, IP: "10.0.0.2"}
			if err := store.Put(rec); err != nil {
				t.Fatal(err)
			}
			var sawToken string
			boxdThawGuest = func(_ context.Context, _ string, token string) error { sawToken = token; return tc.thaw }
			boxdGuestRunning = func(context.Context, string) error { return tc.running }
			mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
			inst := mgr.reattachByID("vm-1", false)
			if inst == nil || sawToken != "tok" {
				t.Fatalf("inst=%v token=%q, want the record published and the intent's token presented", inst, sawToken)
			}
			inst.mu.RLock()
			st := inst.Status
			inst.mu.RUnlock()
			if st != tc.wantStatus {
				t.Errorf("status %v, want %v", st, tc.wantStatus)
			}
			_, serr := os.Stat(pauseIntentPath(vmDir))
			if present := serr == nil; present != tc.wantIntent {
				t.Errorf("intent present=%v, want %v", present, tc.wantIntent)
			}
		})
	}
}

// A record that owes a wake is not served until the wake completes: a request
// arriving through the lazy path completes it inline, the startup pass queues it
// for the pool, and a request during that wait sees the pool's outcome.
func TestReattachCompletesOwedWakesBeforeServing(t *testing.T) {
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })
	newStore := func(t *testing.T) (*Manager, *StateStore) {
		t.Helper()
		dir := t.TempDir()
		store, err := OpenStateStore(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok", Supervision: SupervisionUnit, IP: "10.0.0.2"}); err != nil {
			t.Fatal(err)
		}
		return &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}, store
	}

	t.Run("lazy_path_wakes_inline", func(t *testing.T) {
		mgr, store := newStore(t)
		var sawFrozen bool
		var sawToken string
		boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, frozen bool, token string) error {
			sawFrozen, sawToken = frozen, token
			return nil
		}
		inst := mgr.reattachByID("vm-1", false)
		if inst == nil || !sawFrozen || sawToken != "tok" {
			t.Fatalf("inst=%v frozen=%v token=%q, want the wake sent with the record's policy and token", inst, sawFrozen, sawToken)
		}
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		if inst.Status != StatusRunning || inst.WakePending || inst.Unverified {
			t.Errorf("status=%v wakePending=%v unverified=%v", inst.Status, inst.WakePending, inst.Unverified)
		}
		if rec, _ := store.Get("vm-1"); rec == nil || rec.WakePending {
			t.Error("the completed wake was not made durable")
		}
	})

	t.Run("lazy_path_parks_a_guest_that_will_not_wake", func(t *testing.T) {
		mgr, _ := newStore(t)
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return errors.New("no answer") }
		inst := mgr.reattachByID("vm-1", false)
		if inst == nil {
			t.Fatal("a parked record must still be tracked, as Error")
		}
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		if inst.Status != StatusError {
			t.Errorf("status %v, want Error", inst.Status)
		}
	})

	t.Run("startup_pass_queues_and_the_pool_resolves", func(t *testing.T) {
		mgr, store := newStore(t)
		// The startup pass checks the unit is live before anything else; make
		// it so, with the API socket present, as the other startup-pass tests do.
		origDown := vmUnitFullyDown
		vmUnitFullyDown = func(string) bool { return false }
		t.Cleanup(func() { vmUnitFullyDown = origDown })
		socket := filepath.Join(t.TempDir(), "firecracker.sock")
		if err := os.WriteFile(socket, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		rec, _ := store.Get("vm-1")
		rec.SocketPath = socket
		if err := store.Put(*rec); err != nil {
			t.Fatal(err)
		}
		wakes := 0
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { wakes++; return nil }
		if inst, ok := mgr.reattachRecord(context.Background(), *rec, true); inst != nil || ok {
			t.Fatal("the startup pass must not publish a guest that owes a wake")
		}
		if mgr.pendingWake("vm-1") == nil {
			t.Fatal("not queued")
		}
		// The lifecycle lock is held for the worker: a restore for this id
		// would wait on it, not on the pool.
		if _, ok := mgr.tryLockVMOp("vm-1"); ok {
			t.Fatal("lifecycle lock not reserved while the wake is pending")
		}
		// A request during the wait sees the pool's outcome.
		got := make(chan *VMInstance, 1)
		go func() { got <- mgr.reattachByID("vm-1", false) }()
		if n := mgr.drainPendingWakes(context.Background()); n != 1 || wakes != 1 {
			t.Fatalf("drained=%d wakes=%d, want one guest woken once", n, wakes)
		}
		select {
		case inst := <-got:
			if inst == nil || inst.WakePending {
				t.Fatalf("request got %v, want the woken instance", inst)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("request never saw the pool's outcome")
		}
		if mgr.pendingWake("vm-1") != nil {
			t.Error("still queued after resolution")
		}
		if unlock, ok := mgr.tryLockVMOp("vm-1"); !ok {
			t.Error("lifecycle lock not released after the pool published")
		} else {
			unlock()
		}
	})

	t.Run("startup_pass_leaves_a_locked_vm_to_its_request", func(t *testing.T) {
		mgr, store := newStore(t)
		origDown := vmUnitFullyDown
		vmUnitFullyDown = func(string) bool { return false }
		t.Cleanup(func() { vmUnitFullyDown = origDown })
		socket := filepath.Join(t.TempDir(), "firecracker.sock")
		if err := os.WriteFile(socket, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		rec, _ := store.Get("vm-1")
		rec.SocketPath = socket
		unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		if inst, ok := mgr.reattachRecord(context.Background(), *rec, true); inst != nil || ok || mgr.pendingWake("vm-1") != nil {
			t.Fatalf("inst=%v ok=%v queued=%v; a VM whose lock a request holds must not be queued", inst, ok, mgr.pendingWake("vm-1") != nil)
		}
	})

	t.Run("pool_abandons_an_instance_a_request_replaced", func(t *testing.T) {
		mgr, store := newStore(t)
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error {
			t.Error("a replaced instance must not be woken")
			return nil
		}
		rec, _ := store.Get("vm-1")
		stale := toInstance(*rec)
		unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
		if err != nil {
			t.Fatal(err)
		}
		mgr.queuePendingWake(stale, unlock)
		// A request won the id first: the replacement owns map and record.
		replacement := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionUnit, IP: "10.0.0.9"}
		mgr.vms["vm-1"] = replacement
		if err := store.Put(toRecord(replacement)); err != nil {
			t.Fatal(err)
		}
		if n := mgr.drainPendingWakes(context.Background()); n != 0 {
			t.Fatalf("drained %d, want the stale instance abandoned", n)
		}
		if mgr.vms["vm-1"] != replacement {
			t.Error("the replacement was displaced")
		}
		if got, _ := store.Get("vm-1"); got == nil || got.IP != "10.0.0.9" || got.WakePending {
			t.Errorf("record = %+v; the stale instance must not be persisted over the replacement", got)
		}
	})
}

// A wake the guest refuses as belonging to another freeze means the image and
// its record describe different snapshots. The restore fails as a
// precondition, the VM is durably Error, and the artifacts stay for inspection.
func TestTokenMismatchFailsRestoreAndResumeWithoutRetry(t *testing.T) {
	useTempFloor(t)
	origWake, origDead := boxdWakeGuest, vmDeadForRetry
	t.Cleanup(func() { boxdWakeGuest, vmDeadForRetry = origWake, origDead })
	vmDeadForRetry = func(*Manager, string) bool { return true }
	wakes := 0
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error {
		wakes++
		return fmt.Errorf("%w: status token", ErrGuestTokenMismatch)
	}
	newDir := func(t *testing.T) (dir, snapPath, memPath string) {
		dir = t.TempDir()
		snapPath, memPath = filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap")
		for _, p := range []string{snapPath, memPath, filepath.Join(dir, "base.ext4")} {
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		seedFrozenManifest(t, memPath, "tok")
		return dir, snapPath, memPath
	}

	t.Run("restore", func(t *testing.T) {
		dir, snapPath, memPath := newDir(t)
		mgr := &Manager{
			log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir, GuestClockFreezeEnabled: true}, netMgr: &fakeNetMgr{},
			vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1),
		}
		mgr.clockRealtimeCapable.Store(true)
		mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
			return 4321, SupervisionUnit, nil
		}
		mgr.restoreSnapshotHook = func(string, string, string, *bool) error { return nil }
		wakes = 0
		_, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: filepath.Join(dir, "base.ext4"), DeltaDir: filepath.Join(dir, "delta")}, nil, "team", "owner", "", nil, 0)
		if status.Code(err) != codes.FailedPrecondition || wakes != 1 {
			t.Fatalf("err=%v wakes=%d, want FailedPrecondition after one wake", err, wakes)
		}
		for _, p := range []string{snapPath, memPath, WallClockMarkerPath(memPath)} {
			if _, serr := os.Stat(p); serr != nil {
				t.Errorf("artifact %s not retained: %v", p, serr)
			}
		}
		mgr.mu.RLock()
		inst := mgr.vms["vm-1"]
		mgr.mu.RUnlock()
		if inst != nil {
			inst.mu.RLock()
			st := inst.Status
			inst.mu.RUnlock()
			if st != StatusError {
				t.Errorf("status %v, want Error", st)
			}
		}
	})

	t.Run("resume", func(t *testing.T) {
		dir, snapPath, memPath := newDir(t)
		frozen := true
		inst := &VMInstance{
			ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
			SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: filepath.Join(dir, "base.ext4"),
			SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok",
		}
		mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}}
		mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
			return 4321, SupervisionUnit, nil
		}
		mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }
		unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		wakes = 0
		_, rerr := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
		if status.Code(rerr) != codes.FailedPrecondition || wakes != 1 {
			t.Fatalf("err=%v wakes=%d, want FailedPrecondition after one wake", rerr, wakes)
		}
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		if inst.Status != StatusError {
			t.Errorf("status %v, want Error and not reverted to Paused", inst.Status)
		}
	})
}

// useTempFloor points the rollback-floor evidence at a temp file: a frozen
// restore refuses to launch until the floor is durable, and the test host has
// no fleet directory to record it in.
func useTempFloor(t *testing.T) {
	t.Helper()
	isolateEvidence(t, t.TempDir())
}

// The eager pass and a request share one flight per VM. When the pass finds
// the request holding the lifecycle lock and leaves the wake to it, the
// request must not read that as "no such VM": it reattaches itself.
func TestRequestJoiningADeferredStartupFlightReattachesItself(t *testing.T) {
	origWake, origHook := boxdWakeGuest, reattachHook
	t.Cleanup(func() { boxdWakeGuest, reattachHook = origWake, origHook })
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return nil }

	dir := t.TempDir()
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	socket := filepath.Join(dir, "firecracker.sock")
	if err := os.WriteFile(socket, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok", Supervision: SupervisionUnit, IP: "10.0.0.2", SocketPath: socket}); err != nil {
		t.Fatal(err)
	}
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}

	// The request holds the lock, as restore and resume do before reattaching.
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// Hold the eager flight open at its start until the requests have joined
	// it, counting every reattach that runs.
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var reattaches atomic.Int32
	reattachHook = func(string) {
		reattaches.Add(1)
		once.Do(func() { close(started); <-release })
	}
	eager := make(chan *VMInstance, 1)
	go func() { eager <- mgr.reattachByID("vm-1", true) }()
	<-started
	lazy := make(chan *VMInstance, 2)
	go func() { lazy <- mgr.reattachByID("vm-1", false) }()
	go func() { lazy <- mgr.reattachByID("vm-1", false) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	if got := <-eager; got != nil {
		t.Fatalf("eager pass published %v over a locked VM", got)
	}
	var got []*VMInstance
	for i := 0; i < 2; i++ {
		select {
		case inst := <-lazy:
			got = append(got, inst)
		case <-time.After(5 * time.Second):
			t.Fatal("a request never got its instance")
		}
	}
	for _, inst := range got {
		if inst == nil {
			t.Fatal("a request read the deferral as a missing VM")
		}
		inst.mu.RLock()
		st, pending := inst.Status, inst.WakePending
		inst.mu.RUnlock()
		if st != StatusRunning || pending {
			t.Errorf("status=%v wakePending=%v, want woken and Running", st, pending)
		}
	}
	if got[0] != got[1] {
		t.Error("the two requests got different instances")
	}
	// The eager attempt plus exactly one shared recovery: joiners never each
	// run their own against the same guest.
	if n := reattaches.Load(); n != 2 {
		t.Errorf("reattaches = %d, want 2 (eager + one shared retry)", n)
	}
}

// A resume publishes its wake-owed record before it launches Firecracker. A
// crash in that window must not reap the sandbox as a failed create: the
// paused image is intact, so the record returns to Paused. A create's record
// in the same state has nowhere to return to and is reaped as before.
func TestInterruptedResumeReturnsToPaused(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return true }
	t.Cleanup(func() { vmUnitFullyDown = origDown })
	for _, tc := range []struct {
		name       string
		fromPaused bool
		wantKept   bool
	}{
		{"resume_returns_to_paused", true, true},
		{"create_is_reaped", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := OpenStateStore(filepath.Join(dir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			snapPath, memPath := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap")
			for _, p := range []string{snapPath, memPath} {
				if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			pausedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
			// What a resume from an override leaves if vmd dies before its
			// launch: the record's own image and token, and the override's
			// token in flight.
			rec := VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "rec", WakeToken: "disk", WakeSnapshotPath: filepath.Join(dir, "other-vm.snap"), WakeMemPath: filepath.Join(dir, "other.snap"), WakeOwedFromPaused: tc.fromPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, PausedAt: pausedAt}
			if err := store.Put(rec); err != nil {
				t.Fatal(err)
			}
			mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
			inst, _ := mgr.reattachRecord(context.Background(), rec, true)
			got, _ := store.Get("vm-1")
			if !tc.wantKept {
				if got != nil {
					t.Fatalf("record kept: %+v; a failed create must be reaped", got)
				}
				return
			}
			if got == nil || got.Status != StatusPaused || got.WakePending || got.Unverified || got.WakeOwedFromPaused {
				t.Fatalf("record = %+v, want Paused with nothing owed", got)
			}
			if got.FreezeToken != "rec" || got.WakeToken != "" || got.MemFilePath != memPath || got.WakeMemPath != "" {
				t.Errorf("record = %+v; want its own image and token kept and the in-flight image dropped", got)
			}
			if !got.PausedAt.Equal(pausedAt) {
				t.Errorf("PausedAt = %v, want the original %v kept for the reclaim order", got.PausedAt, pausedAt)
			}
			if inst != nil {
				inst.mu.RLock()
				defer inst.mu.RUnlock()
				if inst.Status != StatusPaused {
					t.Errorf("instance status %v, want Paused", inst.Status)
				}
			}
		})
	}
}

// A reattached resume whose guest will not wake goes back to Paused with
// nothing owed, as the resume's own failure path would. (A create in the
// same state is parked as Error with its wake still owed; see the lazy-path
// test above.)
func TestUnwakeableReattachedResumeReturnsToPaused(t *testing.T) {
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return errors.New("no answer") }
	dir := t.TempDir()
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok", WakeOwedFromPaused: true, Supervision: SupervisionUnit, IP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
	inst := mgr.reattachByID("vm-1", false)
	if inst == nil {
		t.Fatal("a parked record must still be tracked")
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused || inst.WakePending || inst.WakeOwedFromPaused {
		t.Errorf("status=%v wakePending=%v fromPaused=%v, want Paused and nothing owed", inst.Status, inst.WakePending, inst.WakeOwedFromPaused)
	}
	if rec, _ := store.Get("vm-1"); rec == nil || rec.Status != StatusPaused || rec.WakePending {
		t.Errorf("record = %+v, want Paused and durable", rec)
	}
}

// A snapshot pauses the vCPUs before it writes, so a release after a
// snapshot that then failed, or after a crash between the two, must resume
// Firecracker before the guest can answer the thaw.
func TestReleaseOfAFrozenGuestUnpausesFirecrackerFirst(t *testing.T) {
	origUnpause, origThaw := fcUnpauseVM, boxdThawGuest
	t.Cleanup(func() { fcUnpauseVM, boxdThawGuest = origUnpause, origThaw })
	var order []string
	fcUnpauseVM = func(ctx context.Context, socket string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the unpause must be bounded: a stuck Firecracker API must not hang cleanup or recovery")
		}
		order = append(order, "unpause:"+socket)
		return nil
	}
	boxdThawGuest = func(_ context.Context, _, token string) error { order = append(order, "thaw:"+token); return nil }
	m := &Manager{log: zerolog.Nop()}
	if err := m.releaseFrozenGuest(context.Background(), "/run/vm.sock", "10.0.0.2", "tok"); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "unpause:/run/vm.sock" || order[1] != "thaw:tok" {
		t.Fatalf("order = %v, want the unpause before the thaw", order)
	}
	// Recovery after a crash takes the same path, with the record's socket.
	raiseFloorForTest(t)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "a"}); err != nil {
		t.Fatal(err)
	}
	order = nil
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}}
	inst := &VMInstance{ID: "vm-1", IP: "10.0.0.2", SocketPath: "/run/vm-1.sock"}
	if !mgr.recoverPauseIntent(context.Background(), inst, zerolog.Nop()) {
		t.Fatal("recovery reported the guest could not be released")
	}
	if len(order) != 2 || order[0] != "unpause:/run/vm-1.sock" || order[1] != "thaw:tok" {
		t.Fatalf("recovery order = %v, want the unpause before the thaw", order)
	}
}

// A stuck Firecracker API bounds the release: the unpause gives up on its
// own budget and the thaw is still attempted.
func TestReleaseOfAFrozenGuestIsBoundedByAStuckFirecracker(t *testing.T) {
	origUnpause, origThaw := fcUnpauseVM, boxdThawGuest
	t.Cleanup(func() { fcUnpauseVM, boxdThawGuest = origUnpause, origThaw })
	fcUnpauseVM = func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
	thawed := false
	boxdThawGuest = func(context.Context, string, string) error { thawed = true; return nil }
	m := &Manager{log: zerolog.Nop()}
	start := time.Now()
	if err := m.releaseFrozenGuest(context.Background(), "/run/vm.sock", "10.0.0.2", "tok"); err != nil || !thawed {
		t.Fatalf("err=%v thawed=%v; want the thaw attempted after the unpause gave up", err, thawed)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("release took %v; the unpause must be bounded", took)
	}
}

// A token mismatch is terminal. The Error a resume writes owes nothing, so a
// restart does not return it to Paused; a reattached wake the guest refuses
// as another freeze's is Error, not Paused, however the resume began.
func TestTokenMismatchStaysErrorThroughRecovery(t *testing.T) {
	origWake, origDown := boxdWakeGuest, vmUnitFullyDown
	t.Cleanup(func() { boxdWakeGuest, vmUnitFullyDown = origWake, origDown })

	t.Run("error_record_with_no_unit_is_not_returned_to_paused", func(t *testing.T) {
		vmUnitFullyDown = func(string) bool { return true }
		dir := t.TempDir()
		store, err := OpenStateStore(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		// What an older write could have left: Error, yet still owing.
		rec := VMRecord{ID: "vm-1", Status: StatusError, WakePending: true, WakeOwedFromPaused: true, FreezeToken: "tok", WakeToken: "tok", Supervision: SupervisionUnit}
		if err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
		mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
		mgr.reattachRecord(context.Background(), rec, true)
		if got, _ := store.Get("vm-1"); got != nil && got.Status == StatusPaused {
			t.Fatalf("record = %+v; a terminal Error must not become Paused", got)
		}
	})

	t.Run("refused_wake_on_a_reattached_resume_is_error", func(t *testing.T) {
		vmUnitFullyDown = func(string) bool { return false }
		boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error {
			return fmt.Errorf("%w: status token", ErrGuestTokenMismatch)
		}
		dir := t.TempDir()
		store, err := OpenStateStore(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok", WakeOwedFromPaused: true, Supervision: SupervisionUnit, IP: "10.0.0.2"}); err != nil {
			t.Fatal(err)
		}
		mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
		inst := mgr.reattachByID("vm-1", false)
		if inst == nil {
			t.Fatal("a parked record must still be tracked")
		}
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		if inst.Status != StatusError {
			t.Errorf("status %v, want Error: a refused wake is terminal even for a resume", inst.Status)
		}
	})
}

// A failed create must not wait on the state store: the Running write that
// overlaps the readiness wait is joined by the failure worker, off the reply.
// The writer is held from inside the launch, once that write is the only one
// left, and the guest never answers.
func TestFailedRestoreDoesNotWaitOnTheStore(t *testing.T) {
	useTempFloor(t)
	origProbe, origDead := boxdHealthProbe, vmDeadForRetry
	t.Cleanup(func() { boxdHealthProbe, vmDeadForRetry = origProbe, origDead })
	vmDeadForRetry = func(*Manager, string) bool { return true }
	boxdHealthProbe = func(context.Context, string, time.Duration) error { return errors.New("guest never answered") }

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	basePath := filepath.Join(dir, "base.ext4")
	for _, p := range []string{snapPath, memPath, basePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	held := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		time.Sleep(50 * time.Millisecond) // let the failure worker's write land before the store closes
		store.Close()
	})
	mgr := &Manager{
		log:        zerolog.Nop(),
		cfg:        ManagerConfig{RunDir: dir},
		netMgr:     &fakeNetMgr{},
		vms:        map[string]*VMInstance{},
		restoreSem: make(chan struct{}, 1),
		state:      store,
	}
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		go func() {
			_ = store.db.Update(func(*bolt.Tx) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreSnapshotHook = func(_, _, _ string, _ *bool) error { return nil }

	start := time.Now()
	_, rerr := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: basePath}, nil, "team", "owner", "", nil, 0)
	took := time.Since(start)
	if rerr == nil {
		t.Fatal("restore succeeded without a ready guest")
	}
	if took > 2*time.Second {
		t.Fatalf("a failed restore took %v with the store held; the reply must not wait on it", took)
	}
	mgr.mu.RLock()
	inst := mgr.vms["vm-1"]
	mgr.mu.RUnlock()
	if inst != nil {
		inst.mu.RLock()
		st := inst.Status
		inst.mu.RUnlock()
		if st != StatusError {
			t.Fatalf("status %v after the failed restore, want Error before the reply", st)
		}
	}
	// Once the store is free, the deferred write converges the record to
	// Error: the Running write it joined first cannot land after it.
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec, gerr := store.Get("vm-1")
		if gerr == nil && rec != nil && rec.Status == StatusError {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable record never reached Error after the store was released: rec=%+v err=%v", rec, gerr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A rollback that cannot be made durable leaves a record naming this run's
// slot. The slot then stays reserved for this sandbox rather than going back
// to the pool, where the next sandbox to receive it could be claimed by a
// retry after a restart.
func TestFrozenResumeRollbackThatCannotPersistKeepsTheSlot(t *testing.T) {
	useTempFloor(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			store.Close()
		}
	})
	frozen := true
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		SnapshotWorkloadFrozen: &frozen, FreezeToken: "rec",
	}
	if err := store.Put(toRecord(inst)); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNetMgr{}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: fake,
		vms:    map[string]*VMInstance{"vm-1": inst},
		state:  store,
	}
	// The store dies under the resume: the launch fails and the rollback's
	// write cannot land.
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		store.Close()
		closed = true
		return 0, SupervisionUnit, errors.New("launch failed")
	}
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err == nil {
		t.Fatal("want the launch failure")
	}
	if len(fake.setupCalls) != 1 {
		t.Fatalf("setup calls = %v, want the slot taken once", fake.setupCalls)
	}
	if len(fake.teardownCalls) != 0 {
		t.Fatalf("teardown calls = %v; the slot must stay reserved while the durable record still names it", fake.teardownCalls)
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused {
		t.Errorf("status %v, want Paused in memory", inst.Status)
	}
}

// A resume from an override that died after loading the override and before
// its commit: recovery wakes the override's guest, and the record must then
// name the override as its image, or a retry of the same resume would miss
// the already-running check and relaunch over the recovered guest.
func TestRecoveredOverrideResumeCommitsTheImageItWoke(t *testing.T) {
	useTempFloor(t)
	origWake, origDown, origDead := boxdWakeGuest, vmUnitFullyDown, vmDeadForRetry
	t.Cleanup(func() { boxdWakeGuest, vmUnitFullyDown, vmDeadForRetry = origWake, origDown, origDead })
	// The recovered guest's process is alive for the retry's liveness check.
	vmUnitFullyDown = func(string) bool { return false }
	vmDeadForRetry = func(*Manager, string) bool { return false }

	dir := t.TempDir()
	own := filepath.Join(dir, "mem.snap")
	ownSnap := filepath.Join(dir, "vm.snap")
	override := filepath.Join(dir, "other.snap")
	overrideSnap := filepath.Join(dir, "other-vm.snap")
	for _, p := range []string{own, ownSnap, override, overrideSnap} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFrozenManifest(t, override, "disk")
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning, Unverified: true, Supervision: SupervisionUnit, IP: "10.0.0.2",
		SnapshotPath: ownSnap, MemFilePath: own, FreezeToken: "rec",
		WakePending: true, ClockFrozen: true, WakeOwedFromPaused: true,
		WakeToken: "disk", WakeSnapshotPath: overrideSnap, WakeMemPath: override,
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	var sawToken string
	boxdWakeGuest = func(_ context.Context, _ string, _ time.Duration, _ bool, token string) error {
		sawToken = token
		return nil
	}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
	inst := mgr.reattachByID("vm-1", false)
	if inst == nil || sawToken != "disk" {
		t.Fatalf("inst=%v token=%q, want the override's guest woken with its token", inst, sawToken)
	}
	got, _ := store.Get("vm-1")
	if got == nil || got.Status != StatusRunning || got.WakePending || got.MemFilePath != override || got.SnapshotPath != overrideSnap || got.FreezeToken != "disk" || got.WakeMemPath != "" || got.WakeToken != "" {
		t.Fatalf("record = %+v; want the override committed as the record's image, nothing in flight", got)
	}

	// The lost reply's retry names the override: the sandbox is already up.
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		t.Fatal("the retry relaunched a recovered guest")
		return 0, SupervisionUnit, nil
	}
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	again, err := mgr.resumeVMLocked(context.Background(), "vm-1", overrideSnap, override, nil)
	if err != nil || again != inst {
		t.Fatalf("retry: err=%v same=%v; want the running instance returned as is", err, again == inst)
	}
}

// A pause whose freeze reply was lost and whose thaw could not be confirmed
// leaves the guest frozen under its token, recorded in the intent. A retry
// must resolve that freeze before it writes an intent with a new token, or
// the old token, the only way to release the guest, is gone.
func TestPauseResolvesAnEarlierFreezeBeforeReplacingItsIntent(t *testing.T) {
	useTempFloor(t)
	raiseFloorForTest(t)
	origF, origT, origR, origDown, origUnpause := boxdFreezeGuest, boxdThawGuest, boxdGuestRunning, vmUnitFullyDown, fcUnpauseVM
	t.Cleanup(func() {
		boxdFreezeGuest, boxdThawGuest, boxdGuestRunning, vmUnitFullyDown, fcUnpauseVM = origF, origT, origR, origDown, origUnpause
	})
	vmUnitFullyDown = func(string) bool { return false }
	var unpaused []string
	fcUnpauseVM = func(_ context.Context, socket string) error { unpaused = append(unpaused, socket); return nil }

	// Cgroup-supervised: an error on this path asks whether the VM is dead,
	// and a cgroup the host never had reads as alive everywhere, while a
	// unit systemd never had reads as dead where systemd is present.
	newPause := func(t *testing.T) (*Manager, string, string) {
		t.Helper()
		fc := startSnapshotAPIFake(t, nil)
		dir := t.TempDir()
		vmDir := filepath.Join(dir, "vm-1")
		if err := os.MkdirAll(vmDir, 0o755); err != nil {
			t.Fatal(err)
		}
		memSnap := filepath.Join(vmDir, "mem.snap")
		if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// What the earlier pause left: its intent, under its token.
		if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", FreezeToken: "A", ArtifactID: "earlier"}); err != nil {
			t.Fatal(err)
		}
		corrects := true
		inst := &VMInstance{
			ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2",
			SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects, ArtifactID: "current",
		}
		m := &Manager{
			log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst},
			cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir, GuestClockFreezeEnabled: true},
		}
		m.clockRealtimeCapable.Store(true)
		return m, vmDir, fc.socketPath
	}

	t.Run("an_unconfirmed_release_refuses_the_pause_and_keeps_the_token", func(t *testing.T) {
		m, vmDir, socket := newPause(t)
		unpaused = nil
		var thawed []string
		boxdThawGuest = func(_ context.Context, _, token string) error {
			thawed = append(thawed, token)
			return errors.New("connection refused")
		}
		boxdFreezeGuest = func(context.Context, string, string) (freezeEcho, error) {
			t.Error("a new freeze was sent while an earlier one was unresolved")
			return freezeEcho{}, errors.New("unexpected")
		}
		if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err == nil {
			t.Fatal("want the pause refused")
		}
		if len(thawed) != 1 || thawed[0] != "A" {
			t.Fatalf("thaws = %v, want exactly the earlier token presented", thawed)
		}
		// The earlier attempt may have left the vCPUs paused; the guest cannot
		// answer until Firecracker resumes them.
		if len(unpaused) != 1 || unpaused[0] != socket {
			t.Fatalf("unpause calls = %v, want one on the VM's socket before the thaw", unpaused)
		}
		in, err := readPauseIntent(vmDir)
		if err != nil || in == nil || in.FreezeToken != "A" {
			t.Fatalf("intent = %+v err=%v; the earlier token must survive a refused pause", in, err)
		}
	})

	// A pause that will not freeze — a custom directory here — must still not
	// publish a frozen guest as an unfrozen image.
	t.Run("a_pause_that_will_not_freeze_resolves_it_or_is_refused", func(t *testing.T) {
		m, vmDir, _ := newPause(t)
		custom := t.TempDir()
		boxdThawGuest = func(context.Context, string, string) error { return errors.New("connection refused") }
		boxdFreezeGuest = func(context.Context, string, string) (freezeEcho, error) {
			t.Error("a custom-directory pause froze the guest")
			return freezeEcho{}, errors.New("unexpected")
		}
		if _, _, _, err := m.PauseVM(context.Background(), "vm-1", custom, ""); err == nil {
			t.Fatal("want the pause refused while the earlier freeze is unresolved")
		}
		if in, _ := readPauseIntent(vmDir); in == nil || in.FreezeToken != "A" {
			t.Fatal("the earlier intent must survive the refused pause")
		}
		// Released: the pause goes on unfrozen, and the spent intent is gone.
		boxdThawGuest = func(context.Context, string, string) error { return nil }
		_, _, _, _ = m.PauseVM(context.Background(), "vm-1", custom, "")
		if in, _ := readPauseIntent(vmDir); in != nil {
			t.Fatalf("intent = %+v after the release; a resolved intent must be cleared", in)
		}
	})

	t.Run("a_confirmed_release_lets_the_pause_go_on_under_a_new_token", func(t *testing.T) {
		m, vmDir, _ := newPause(t)
		var thawed []string
		boxdThawGuest = func(_ context.Context, _, token string) error { thawed = append(thawed, token); return nil }
		frozeUnder := ""
		boxdFreezeGuest = func(_ context.Context, _, token string) (freezeEcho, error) {
			frozeUnder = token
			return freezeEcho{Version: WakeProtocolVersion, Token: token}, nil
		}
		boxdGuestRunning = func(context.Context, string) error { return nil }
		_, _, _, _ = m.PauseVM(context.Background(), "vm-1", vmDir, "")
		if len(thawed) == 0 || thawed[0] != "A" {
			t.Fatalf("thaws = %v, want the earlier token released first", thawed)
		}
		if frozeUnder == "" || frozeUnder == "A" {
			t.Fatalf("froze under %q, want a fresh token after the release", frozeUnder)
		}
		if in, _ := readPauseIntent(vmDir); in != nil && in.FreezeToken == "A" {
			t.Fatal("the intent still names the released freeze")
		}
	})
}

// phaseSink records the latency phases a manager emits.
type phaseSink struct {
	telemetry.Recorder
	mu     sync.Mutex
	phases []telemetry.LatencyPhase
}

func (p *phaseSink) RecordLatencyPhase(_ context.Context, ph telemetry.LatencyPhase) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phases = append(p.phases, ph)
}

func (p *phaseSink) has(op, phase string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ph := range p.phases {
		if ph.Op == op && ph.Phase == phase {
			return true
		}
	}
	return false
}

// A pause that fails inside its freeze is one of the pauses worth seeing:
// its phases land in the distributions like a failed snapshot's do.
func TestFailedFreezeLandsInPausePhases(t *testing.T) {
	useTempFloor(t)
	origF, origT, origDown := boxdFreezeGuest, boxdThawGuest, vmUnitFullyDown
	t.Cleanup(func() { boxdFreezeGuest, boxdThawGuest, vmUnitFullyDown = origF, origT, origDown })
	vmUnitFullyDown = func(string) bool { return false }
	boxdFreezeGuest = func(context.Context, string, string) (freezeEcho, error) {
		return freezeEcho{}, errors.New("connection reset")
	}
	boxdThawGuest = func(context.Context, string, string) error { return errors.New("connection refused") }

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrects := true
	inst := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Supervision: SupervisionUnit, IP: "10.0.0.2",
		SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects,
	}
	sink := &phaseSink{}
	m := &Manager{
		log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, recorder: sink,
		cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir, GuestClockFreezeEnabled: true},
	}
	m.clockRealtimeCapable.Store(true)
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err == nil {
		t.Fatal("want the pause to fail inside its freeze")
	}
	if !sink.has("pause", "freeze") || !sink.has("pause", "total") {
		t.Fatalf("phases = %+v; want the failed pause's freeze and total recorded", sink.phases)
	}
	if sink.has("pause", "snapshot") {
		t.Fatalf("phases = %+v; a pause that never snapshotted must not report a snapshot phase", sink.phases)
	}
}

// An ad-hoc snapshot is never marked, so it restores without a wake: taken of
// a guest an earlier pause left frozen, it would publish a stopped workload
// for good. It resolves that freeze first, or refuses.
func TestAdHocSnapshotResolvesAnEarlierFreezeOrRefuses(t *testing.T) {
	useTempFloor(t)
	raiseFloorForTest(t)
	origT, origUnpause := boxdThawGuest, fcUnpauseVM
	t.Cleanup(func() { boxdThawGuest, fcUnpauseVM = origT, origUnpause })
	fcUnpauseVM = func(context.Context, string) error { return nil }

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", FreezeToken: "A", ArtifactID: "earlier"}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, ArtifactID: "current"}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}

	var thawed []string
	boxdThawGuest = func(_ context.Context, _, token string) error {
		thawed = append(thawed, token)
		return errors.New("connection refused")
	}
	if _, _, err := m.CreateVMSnapshot(context.Background(), "vm-1", filepath.Join(dir, "adhoc")); err == nil {
		t.Fatal("want the snapshot refused while the earlier freeze is unresolved")
	}
	if len(thawed) != 1 || thawed[0] != "A" || len(fc.snapshotBodies()) != 0 {
		t.Fatalf("thaws=%v requests=%d; want the earlier token presented and no snapshot taken", thawed, len(fc.snapshotBodies()))
	}
	boxdThawGuest = func(context.Context, string, string) error { return nil }
	if _, _, err := m.CreateVMSnapshot(context.Background(), "vm-1", filepath.Join(dir, "adhoc")); err != nil {
		t.Fatalf("snapshot after the release: %v", err)
	}
	if in, _ := readPauseIntent(vmDir); in != nil {
		t.Fatalf("intent = %+v; a resolved intent must be cleared", in)
	}
}

// An ad-hoc snapshot takes the VM's lifecycle lock: while a pause is in
// flight, its fresh intent must not be read as an abandoned freeze and the
// guest that pause is freezing released. The snapshot waits for the pause.
func TestAdHocSnapshotWaitsForAPauseInFlight(t *testing.T) {
	useTempFloor(t)
	raiseFloorForTest(t)
	origT, origUnpause := boxdThawGuest, fcUnpauseVM
	t.Cleanup(func() { boxdThawGuest, fcUnpauseVM = origT, origUnpause })
	fcUnpauseVM = func(context.Context, string) error { return nil }
	thaws := 0
	boxdThawGuest = func(context.Context, string, string) error { thaws++; return nil }

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, ArtifactID: "current"}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}

	// A pause in flight: it holds the lock and has just recorded its intent.
	unlock, err := m.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", FreezeToken: "B", ArtifactID: "next"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, _, err := m.CreateVMSnapshot(ctx, "vm-1", filepath.Join(dir, "adhoc")); err == nil {
		t.Fatal("the snapshot ran beside a pause in flight")
	}
	if thaws != 0 || len(fc.snapshotBodies()) != 0 {
		t.Fatalf("thaws=%d requests=%d; the pause's guest must be left alone", thaws, len(fc.snapshotBodies()))
	}
	if in, _ := readPauseIntent(vmDir); in == nil || in.FreezeToken != "B" {
		t.Fatal("the pause's intent was cleared by the snapshot")
	}
	// The pause completes: its intent names the record's artifact now.
	inst.mu.Lock()
	inst.ArtifactID = "next"
	inst.mu.Unlock()
	unlock()
	if _, _, err := m.CreateVMSnapshot(context.Background(), "vm-1", filepath.Join(dir, "adhoc")); err != nil {
		t.Fatalf("snapshot after the pause: %v", err)
	}
	if thaws != 0 {
		t.Fatalf("thaws=%d; a completed pause's leftover intent is nothing to release", thaws)
	}
}

// A pause whose stop of Firecracker fails records Paused over a process that
// may still hold the guest, its workload frozen for the image the pause
// published. An ad-hoc snapshot of it, never marked, would restore without a
// wake: only a running VM may be snapshotted this way.
func TestAdHocSnapshotRefusesAPausedVM(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cgroup-supervised with no cgroup on this host: the pause's stop cannot
	// be confirmed, which is the case where Firecracker may survive.
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err != nil {
		t.Fatalf("pause: %v", err)
	}
	inst.mu.RLock()
	st := inst.Status
	inst.mu.RUnlock()
	if st != StatusPaused {
		t.Fatalf("status after the pause %v, want Paused", st)
	}
	before := len(fc.snapshotBodies())
	_, _, err := m.CreateVMSnapshot(context.Background(), "vm-1", filepath.Join(dir, "adhoc"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err=%v, want FailedPrecondition for a paused VM", err)
	}
	if got := len(fc.snapshotBodies()); got != before {
		t.Fatalf("snapshot requests went from %d to %d; a refused snapshot must send none", before, got)
	}
}

// A request that meets a queued wake waits for the pool to reach it: behind
// n others it is served within ceil(n/workers) rounds of a wake's budget.
func TestPendingWakeWaitBoundCoversTheQueue(t *testing.T) {
	round := wakeRecoveryRound
	if round <= boxdResumeReadyBudget+restoreErrorStopBudget {
		t.Fatalf("round %v must cover the wake budget and a failed wake's teardown", round)
	}
	for _, tc := range []struct {
		queued int
		rounds int
	}{{0, 1}, {1, 1}, {wakeRecoveryWorkers, 1}, {wakeRecoveryWorkers + 1, 2}, {3*wakeRecoveryWorkers + 1, 4}} {
		if got := pendingWakeWaitBound(tc.queued); got != time.Duration(tc.rounds)*round {
			t.Errorf("queued=%d: bound %v, want %d rounds of %v", tc.queued, got, tc.rounds, round)
		}
	}
}

// A short freeze budget still reaches the guest as a positive budget: the
// reserve for the reply scales down with it instead of consuming it whole.
func TestFreezeRequestKeepsAPositiveGuestBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(boxdPort))
	if err != nil {
		t.Skipf("port %d busy: %v", boxdPort, err)
	}
	var seen int64 = -1
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			BudgetMs int64  `json:"budget_ms"`
			Token    string `json:"token"`
		}
		_ = jsonDecode(r, &b)
		seen = b.BudgetMs
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":1,"capability":"wake","token":"` + b.Token + `"}`))
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	echo, err := postBoxdFreeze(ctx, "127.0.0.1", "tok")
	if err != nil || echo.Token != "tok" {
		t.Fatalf("echo=%+v err=%v; want the freeze sent and echoed under a 100ms budget", echo, err)
	}
	if seen <= 0 || seen >= 100 {
		t.Fatalf("guest budget %dms, want positive and below the caller's 100ms", seen)
	}
}

// A pause that will not freeze leaves the manifest of the last good image in
// place until its own snapshot has replaced that image: a pause that fails
// first must not turn a frozen image into one a restore reads as legacy.
func TestUnfrozenPauseKeepsTheOldManifestUntilItsSnapshotLands(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })

	fail := true
	fc := startSnapshotAPIFake(t, func(_, _ string) (int, string) {
		if fail {
			return http.StatusInternalServerError, `{"fault_message":"disk full"}`
		}
		return http.StatusNoContent, ""
	})
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The image this VM was resumed from holds a frozen workload.
	seedFrozenManifest(t, memSnap, "A")
	corrects := false
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}

	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err == nil {
		t.Fatal("want the snapshot failure")
	}
	if man, err := ReadWallClockManifest(memSnap); err != nil || man == nil || !man.WorkloadFrozen {
		t.Fatalf("manifest=%+v err=%v; the last good image's manifest must survive a failed pause", man, err)
	}

	fail = false
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if man, err := ReadWallClockManifest(memSnap); err != nil || man != nil {
		t.Fatalf("manifest=%+v err=%v; the replaced image is unfrozen and must carry no manifest", man, err)
	}
}

// A request that meets a queued wake early in the startup pass waits for
// the pool to start before its bound runs: the scan ahead of the pool is
// not counted in the queue, and giving up during it would report a live,
// recoverable VM as missing.
func TestRequestForAQueuedWakeWaitsForThePoolToStart(t *testing.T) {
	origWake, origBound := boxdWakeGuest, pendingWakeWaitBoundFor
	t.Cleanup(func() { boxdWakeGuest, pendingWakeWaitBoundFor = origWake, origBound })
	pendingWakeWaitBoundFor = func(int) time.Duration { return 50 * time.Millisecond }
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return nil }

	dir := t.TempDir()
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rec := VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", WakeToken: "tok", Supervision: SupervisionUnit, IP: "10.0.0.2"}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}, state: store, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}}
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	mgr.queuePendingWake(toInstance(rec), unlock)

	type outcome struct {
		inst *VMInstance
		ok   bool
	}
	got := make(chan outcome, 1)
	go func() {
		inst, ok := mgr.reattachRecord(context.Background(), rec, false)
		got <- outcome{inst, ok}
	}()
	// Well past the bound, the pool has not started: the request must still
	// be waiting rather than have reported the VM missing.
	select {
	case o := <-got:
		t.Fatalf("request returned inst=%v ok=%v before the pool started", o.inst, o.ok)
	case <-time.After(300 * time.Millisecond):
	}
	if n := mgr.drainPendingWakes(context.Background()); n != 1 {
		t.Fatalf("drained %d, want the queued wake served", n)
	}
	select {
	case o := <-got:
		if o.inst == nil || !o.ok {
			t.Fatalf("request got inst=%v ok=%v, want the recovered VM", o.inst, o.ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request never returned after the pool served its wake")
	}
}

// An unfrozen pause whose manifest write fails must not leave an old frozen
// manifest beside its new image: a restore would present that token to a
// guest that already answered it and run the clock uncorrected. The stale
// manifest goes, and the image reads as legacy.
func TestUnfrozenPauseWhoseManifestWriteFailsLeavesNoStaleFrozenOne(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, memSnap, "A")
	// The writer's temporary file cannot be created: a directory sits at its path.
	if err := os.Mkdir(WallClockMarkerPath(memSnap)+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	corrects := true
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if man, err := ReadWallClockManifest(memSnap); err != nil || man != nil {
		t.Fatalf("manifest=%+v err=%v; the stale frozen manifest must be gone when the new one could not be written", man, err)
	}
}

// A frozen pause's durable manifest write is timed as its own phase.
func TestFrozenPauseRecordsTheManifestPhase(t *testing.T) {
	useTempFloor(t)
	raiseFloorForTest(t)
	origF, origT, origDown := boxdFreezeGuest, boxdThawGuest, vmUnitFullyDown
	t.Cleanup(func() { boxdFreezeGuest, boxdThawGuest, vmUnitFullyDown = origF, origT, origDown })
	vmUnitFullyDown = func(string) bool { return false }
	boxdFreezeGuest = func(_ context.Context, _, token string) (freezeEcho, error) {
		return freezeEcho{Version: WakeProtocolVersion, Token: token}, nil
	}
	boxdThawGuest = func(context.Context, string, string) error { return nil }

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrects := true
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects}
	sink := &phaseSink{}
	m := &Manager{
		log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, recorder: sink,
		cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir, GuestClockFreezeEnabled: true},
	}
	m.clockRealtimeCapable.Store(true)
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if man, err := ReadWallClockManifest(memSnap); err != nil || man == nil || !man.WorkloadFrozen {
		t.Fatalf("manifest=%+v err=%v; want the frozen image's manifest written", man, err)
	}
	if !sink.has("pause", "manifest") || !sink.has("pause", "freeze") {
		t.Fatalf("phases = %+v; want the durable manifest write and the freeze recorded", sink.phases)
	}
}

// A restore of a VM from the image it was paused into whose wake merely does
// not happen returns the record to Paused: the image is intact, and an Error
// record owing nothing would be reaped as stale by the next restart. A wake
// the guest refuses as another freeze's stays terminal.
func TestFrozenRestoreOfAPausedVMFailingItsWakeReturnsToPaused(t *testing.T) {
	useTempFloor(t)
	origWake, origDead := boxdWakeGuest, vmDeadForRetry
	t.Cleanup(func() { boxdWakeGuest, vmDeadForRetry = origWake, origDead })
	vmDeadForRetry = func(*Manager, string) bool { return true }
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return errors.New("no answer") }

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	basePath := filepath.Join(dir, "base.ext4")
	for _, p := range []string{snapPath, memPath, basePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFrozenManifest(t, memPath, "tok")
	overlay := filepath.Join(dir, "vm-1", "overlay.ext4")
	if err := os.MkdirAll(filepath.Dir(overlay), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, []byte("customer data"), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	pausedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	prev := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: overlay, PausedAt: pausedAt,
	}
	if err := store.Put(toRecord(prev)); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		cfg:        ManagerConfig{RunDir: dir, GuestClockFreezeEnabled: true},
		netMgr:     &fakeNetMgr{},
		vms:        map[string]*VMInstance{"vm-1": prev},
		restoreSem: make(chan struct{}, 1),
		state:      store,
	}
	mgr.clockRealtimeCapable.Store(true)
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreSnapshotHook = func(_, _, _ string, _ *bool) error { return nil }

	if _, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{BasePath: basePath}, nil, "team", "owner", "", nil, 0); err == nil {
		t.Fatal("want the wake failure")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec, gerr := store.Get("vm-1")
		if gerr == nil && rec != nil && rec.Status == StatusPaused {
			if rec.WakePending || rec.WakeOwedFromPaused || rec.WakeToken != "" || !rec.PausedAt.Equal(pausedAt) {
				t.Fatalf("record = %+v; want Paused owing nothing, in its place in the reclaim order", rec)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable record never returned to Paused: rec=%+v err=%v", rec, gerr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A destroy that lands around the wake-owed write must win: the write is
// erased again and the launch aborted, never a record resurrected for a VM
// the user destroyed.
func TestDestroyDuringAFrozenResumeLeavesNoRecord(t *testing.T) {
	useTempFloor(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	frozen := true
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok",
	}
	if err := store.Put(toRecord(inst)); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{
		log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{},
		vms: map[string]*VMInstance{"vm-1": inst}, state: store,
	}
	// The destroy lands under the launch, after the wake-owed write began:
	// the record is gone and the id no longer this instance's.
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		mgr.mu.Lock()
		delete(mgr.vms, "vm-1")
		mgr.mu.Unlock()
		mgr.deleteState("vm-1")
		return 0, SupervisionUnit, errors.New("launch failed")
	}
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err == nil {
		t.Fatal("want the resume to fail")
	}
	if rec, gerr := store.Get("vm-1"); gerr == nil && rec != nil {
		t.Fatalf("record = %+v; a destroyed VM's record was resurrected by the wake-owed write", rec)
	}
}

// An unfrozen pause that replaces an existing manifest replaces it durably
// and times it: the one there may say frozen under a token already answered.
func TestUnfrozenPauseReplacingAManifestDoesSoDurably(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })

	fc := startSnapshotAPIFake(t, nil)
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, memSnap, "A")
	corrects := true
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects}
	sink := &phaseSink{}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, recorder: sink, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err != nil {
		t.Fatalf("pause: %v", err)
	}
	man, err := ReadWallClockManifest(memSnap)
	if err != nil || man == nil || man.WorkloadFrozen || man.FreezeToken != "" {
		t.Fatalf("manifest=%+v err=%v; want the frozen manifest replaced by an unfrozen one", man, err)
	}
	if !sink.has("pause", "manifest") {
		t.Fatalf("phases = %+v; a durable replacement must be timed", sink.phases)
	}
}

// An unfrozen pause that overwrites an image whose manifest says frozen
// records an intent first: a crash between the rewrite and the manifest's
// replacement then leaves an intent a restore refuses on, and recovery
// removes the stale manifest before it clears the intent.
func TestUnfrozenOverwriteOfAFrozenImageIsCoveredByAnIntent(t *testing.T) {
	useTempFloor(t)
	raiseFloorForTest(t)
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false }
	t.Cleanup(func() { vmUnitFullyDown = origDown })

	fc := startSnapshotAPIFake(t, func(_, _ string) (int, string) {
		return http.StatusInternalServerError, `{"fault_message":"disk full"}`
	})
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memSnap := filepath.Join(vmDir, "mem.snap")
	if err := os.WriteFile(memSnap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, memSnap, "A")
	corrects := false
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, IP: "10.0.0.2", SocketPath: fc.socketPath, MemFilePath: memSnap, CorrectsWallClock: &corrects, ArtifactID: "current"}
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, cfg: ManagerConfig{SnapshotDir: dir, RunDir: dir}}

	// The rewrite dies (here: the snapshot fails) with the old manifest
	// still beside the image, and the intent recorded.
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", vmDir, ""); err == nil {
		t.Fatal("want the snapshot failure")
	}
	in, err := readPauseIntent(vmDir)
	if err != nil || in == nil || in.FreezeToken != "" || in.ArtifactID == "" || in.ArtifactID == "current" {
		t.Fatalf("intent = %+v err=%v; want an intent naming the rewrite, without a token", in, err)
	}
	if blocked, _ := pauseIntentBlocks(vmDir, "current"); !blocked {
		t.Fatal("a restore of the image must be refused while the rewrite's intent stands")
	}

	// Recovery after a restart: the stale frozen manifest goes, then the intent.
	if !m.recoverPauseIntent(context.Background(), inst, zerolog.Nop()) {
		t.Fatal("recovery must succeed for a rewrite that froze nothing")
	}
	if man, err := ReadWallClockManifest(memSnap); err != nil || man != nil {
		t.Fatalf("manifest=%+v err=%v; the stale frozen manifest must be removed before the intent is cleared", man, err)
	}
	if in, _ := readPauseIntent(vmDir); in != nil {
		t.Fatalf("intent = %+v; want it cleared after recovery", in)
	}
}
