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
	"testing"
	"time"

	"github.com/rs/zerolog"
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
		inst := &VMInstance{ID: "vm", WakePending: true, ClockFrozen: true, FreezeToken: "tok"}
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
	rec := toRecord(&VMInstance{ID: "vm", WakePending: true, ClockFrozen: true, SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok", ArtifactID: "a"})
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
		SnapshotWorkloadFrozen: &frozen,
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
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusRunning || inst.Unverified || inst.WakePending {
		t.Errorf("after resume: status=%v unverified=%v wakePending=%v", inst.Status, inst.Unverified, inst.WakePending)
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
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
		SnapshotWorkloadFrozen: &frozen,
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
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused || inst.WakePending || inst.Unverified {
		t.Errorf("after failure: status=%v wakePending=%v unverified=%v, want Paused and nothing owed", inst.Status, inst.WakePending, inst.Unverified)
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

// An interrupted pause leaves its intent marker beside the image, and nothing
// launches over such an image until it is inspected.
func TestInterruptedPauseRefusesResumeAndRestore(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(dir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "interrupted"}); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := pauseIntentBlocks(dir, "other"); !blocked {
		t.Fatal("intent not visible after write")
	}
	launched := false
	launch := func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}

	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
	}
	mgr := &Manager{
		log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{},
		vms: map[string]*VMInstance{"vm-1": inst}, restoreSem: make(chan struct{}, 1),
	}
	mgr.launchFirecrackerHook = launch
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
	unlock()
	if status.Code(rerr) != codes.FailedPrecondition || launched {
		t.Fatalf("resume: err=%v launched=%v, want FailedPrecondition before launch", rerr, launched)
	}

	fresh := &Manager{
		log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, netMgr: &fakeNetMgr{},
		vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1),
	}
	fresh.launchFirecrackerHook = launch
	_, cerr := fresh.RestoreVMSnapshot(context.Background(), "vm-2", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if status.Code(cerr) != codes.FailedPrecondition || launched {
		t.Fatalf("restore: err=%v launched=%v, want FailedPrecondition before launch", cerr, launched)
	}

	if err := clearPauseIntent(dir); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if blocked, _ := pauseIntentBlocks(dir, ""); blocked {
		t.Fatal("still blocked after clear")
	}
}

// A pause that completed but could not remove its intent leaves one naming the
// artifact the record already describes; the next resume clears it and goes on.
func TestCompletedPauseIntentClearsItself(t *testing.T) {
	origWake := boxdWakeGuest
	t.Cleanup(func() { boxdWakeGuest = origWake })
	boxdWakeGuest = func(context.Context, string, time.Duration, bool, string) error { return nil }
	dir := t.TempDir()
	snapPath, memPath, rootfs := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap"), filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(dir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "done"}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs, ArtifactID: "done",
	}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}}
	launched := false
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil || !launched {
		t.Fatalf("resume: err=%v launched=%v, want the completed pause's intent cleared and the resume to proceed", err, launched)
	}
	if _, err := os.Stat(pauseIntentPath(dir)); !os.IsNotExist(err) {
		t.Error("intent still present after the resume")
	}
}

// A guest a crashed pause left frozen is released on reattach with the token
// the intent carries; a token the guest never froze under means the crash came
// first, and nothing is owed. A guest that cannot be released is not served.
func TestReattachReleasesAGuestAnInterruptedPauseFroze(t *testing.T) {
	origThaw := boxdThawGuest
	t.Cleanup(func() { boxdThawGuest = origThaw })
	cases := []struct {
		name       string
		thaw       error
		wantStatus VMStatus
		wantIntent bool
	}{
		{"released", nil, StatusRunning, false},
		{"never_frozen", fmt.Errorf("%w: status token", ErrGuestTokenMismatch), StatusRunning, false},
		{"unreachable", errors.New("connection refused"), StatusError, true},
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
		if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Unverified: true, WakePending: true, ClockFrozen: true, FreezeToken: "tok", Supervision: SupervisionUnit, IP: "10.0.0.2"}); err != nil {
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

// A frozen image is only restored once the rollback floor is durable on this
// host; a floor that cannot be written refuses the restore before any launch.
func TestFrozenRestoreRequiresTheFloor(t *testing.T) {
	origPath := wakeProtocolEvidencePath
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidencePath = filepath.Join(blocker, "evidence")
	wakeProtocolEvidenceDone.Store(false)
	t.Cleanup(func() { wakeProtocolEvidencePath = origPath; wakeProtocolEvidenceDone.Store(false) })

	dir := t.TempDir()
	snapPath, memPath, rootfs := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap"), filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFrozenManifest(t, memPath, "tok")
	launched := false
	launch := func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}
	frozen := true
	inst := &VMInstance{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs, SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok"}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, restoreSem: make(chan struct{}, 1)}
	mgr.launchFirecrackerHook = launch
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
	unlock()
	if status.Code(rerr) != codes.Unavailable || launched {
		t.Fatalf("resume: err=%v launched=%v, want Unavailable before launch", rerr, launched)
	}
	fresh := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1)}
	fresh.launchFirecrackerHook = launch
	_, cerr := fresh.RestoreVMSnapshot(context.Background(), "vm-2", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if status.Code(cerr) != codes.Unavailable || launched {
		t.Fatalf("restore: err=%v launched=%v, want Unavailable before launch", cerr, launched)
	}
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
	orig := wakeProtocolEvidencePath
	wakeProtocolEvidencePath = filepath.Join(t.TempDir(), "evidence")
	wakeProtocolEvidenceDone.Store(false)
	t.Cleanup(func() { wakeProtocolEvidencePath = orig; wakeProtocolEvidenceDone.Store(false) })
}
