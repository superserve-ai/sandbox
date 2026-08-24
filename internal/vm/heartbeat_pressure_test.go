package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func pressureCfg(sample HostPressure) HeartbeatConfig {
	return HeartbeatConfig{
		HostID:             "host-a",
		AdvertiseVMDAddr:   "10.0.0.9:50051",
		AdvertiseProxyAddr: "10.0.0.9:5007",
		Region:             "us-test1",
		CapacityMemoryMib:  1024,
		CapacityVcpus:      8,
		Pressure:           func() HostPressure { return sample },
		MaxSandboxes:       40,
		MaxNetworkSlots:    500,
	}
}

// Pressure publishes to its OWN endpoint with the identity fence and the
// operator limits, never inside the heartbeat body.
func TestSendPressurePublishesSummary(t *testing.T) {
	var got pressureRequest
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode pressure: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := pressureCfg(HostPressure{
		RunningSandboxes: 7, ProvisioningSandboxes: 2, PausedSandboxes: 11,
		AllocatedMemoryMib: 7168, AllocatedVcpus: 14,
		UsedNetSlots: 20, ProvisioningNetSlots: 3, WarmNetSlots: 64, NetSlotCeiling: 65000,
	})
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL+"/internal/hosts/host-a/pressure", "tok", &pressureState{}, zerolog.Nop())

	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q, want PUT", gotMethod)
	}
	if got.VMDAddr != "10.0.0.9:50051" {
		t.Fatalf("vmd_addr = %q (identity fence missing)", got.VMDAddr)
	}
	if got.RunningSandboxes != 7 || got.ProvisioningSandboxes != 2 || got.PausedSandboxes != 11 ||
		got.AllocatedMemoryMib != 7168 || got.AllocatedVcpus != 14 ||
		got.UsedNetSlots != 20 || got.ProvisioningNetSlots != 3 || got.WarmNetSlots != 64 ||
		got.NetSlotCeiling != 65000 || got.MaxSandboxes != 40 || got.MaxNetworkSlots != 500 {
		t.Fatalf("payload = %+v", got)
	}
}

// A 404 means an older control plane without the route: back off, then
// re-probe after the interval. Only 404 backs off — identity conflicts
// and server errors retry at the normal cadence.
func TestSendPressureBacksOffOn404AndReprobes(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := pressureCfg(HostPressure{})
	ps := &pressureState{}
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
	if calls != 1 || !ps.unsupported {
		t.Fatalf("calls=%d unsupported=%v after first 404", calls, ps.unsupported)
	}
	// Backed off: the next beats send nothing until the probe counter runs
	// out. Capture the interval first — each call decrements it.
	interval := ps.beatsUntilProbe
	for i := 0; i < interval-1; i++ {
		sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
	}
	if calls != 1 {
		t.Fatalf("calls=%d during backoff, want still 1", calls)
	}
	// The probe beat sends again.
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
	if calls != 2 {
		t.Fatalf("calls=%d after probe beat, want 2", calls)
	}
}

// 409 and 5xx must NOT back off: they are identity or server problems
// that retry at the normal cadence, not "old control plane".
func TestSendPressureDoesNotBackOffOnConflictOr5xx(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusInternalServerError} {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(status)
		}))
		cfg := pressureCfg(HostPressure{})
		ps := &pressureState{}
		sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
		sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
		if ps.unsupported || calls != 2 {
			t.Fatalf("status %d: unsupported=%v calls=%d, want no backoff", status, ps.unsupported, calls)
		}
		srv.Close()
	}
}

// No pressure func or no advertise config publishes nothing: hosts
// without the multi-host env behave exactly as before this feature.
func TestSendPressureRequiresConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("pressure request sent without config")
	}))
	defer srv.Close()

	cfg := pressureCfg(HostPressure{})
	cfg.Pressure = nil
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", &pressureState{}, zerolog.Nop())

	cfg = pressureCfg(HostPressure{})
	cfg.AdvertiseVMDAddr = ""
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", &pressureState{}, zerolog.Nop())
}

// CapacityPressure counts running/creating instances, skips paused
// allocations while still counting the paused population, and includes
// in-flight template builds — a busy build host must not look idle.
func TestCapacityPressureCountsInstancesAndBuilds(t *testing.T) {
	// A settled host: outside the young-process window, so the paused
	// VM's exclusion below tests the steady state, not the post-restart
	// conservative over-count.
	origStart := vmProcessStart
	vmProcessStart = time.Now().Add(-time.Hour)
	defer func() { vmProcessStart = origStart }()
	m := &Manager{
		vms: map[string]*VMInstance{
			"r1": {Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}},
			"r2": {Status: StatusRunning, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}},
			"c1": {Status: StatusCreating, Config: VMConfig{VCPU: 1, MemoryMiB: 512}},
			"p1": {Status: StatusPaused, Config: VMConfig{VCPU: 8, MemoryMiB: 8192}},
		},
		builds: map[string]*buildRecord{},
	}
	// One in-flight build; a completed one has already released its
	// counters at worker exit and contributes nothing.
	if _, err := m.registerBuild("b1", "tpl", 2, 4096, func() {}); err != nil {
		t.Fatal(err)
	}
	seedPressureIndex(m)
	p := m.CapacityPressure()
	if p.RunningSandboxes != 2 || p.ProvisioningSandboxes != 2 || p.PausedSandboxes != 1 {
		t.Fatalf("counts = %+v", p)
	}
	// 1024+2048+512 (instances) + 4096 (running build) = 7680; paused excluded.
	if p.AllocatedMemoryMib != 7680 || p.AllocatedVcpus != 2+4+1+2 {
		t.Fatalf("allocations = %+v", p)
	}
}

// Publication holds off until the startup reattach completes: a restart
// must never publish a near-zero snapshot of a half-rebuilt map.
func TestSendPressureWaitsForReattach(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ready := false
	cfg := pressureCfg(HostPressure{})
	cfg.PressureReady = func() bool { return ready }
	ps := &pressureState{}
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
	if calls != 0 {
		t.Fatalf("published before reattach completed (calls=%d)", calls)
	}
	ready = true
	sendPressure(context.Background(), srv.Client(), cfg, srv.URL, "tok", ps, zerolog.Nop())
	if calls != 1 {
		t.Fatalf("calls=%d after ready, want 1", calls)
	}
}

// Error-status VMs split by liveness: one whose stop was never confirmed
// keeps its allocation counted, while a provably-settled error record (a
// pre-launch failure, or a confirmed stop — e.g. a failed resume
// retained for retry) holds no process and must not subtract phantom
// capacity indefinitely.
func TestCapacityPressureCountsErrorVMAllocations(t *testing.T) {
	origStart := vmProcessStart
	vmProcessStart = time.Now().Add(-time.Hour) // settled host
	defer func() { vmProcessStart = origStart }()

	m := &Manager{
		vms: map[string]*VMInstance{
			"r1":        {Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}},
			"e-live":    {Status: StatusError, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}},
			"e-settled": {Status: StatusError, Config: VMConfig{VCPU: 8, MemoryMiB: 8192}},
		},
	}
	// e-live's stop was never confirmed; e-settled has no such signal.
	recordUnitStop(systemdUnitName("e-live"))
	defer confirmUnitStopped(systemdUnitName("e-live"))

	seedPressureIndex(m)
	p := m.CapacityPressure()
	if p.RunningSandboxes != 1 || p.ProvisioningSandboxes != 0 {
		t.Fatalf("counts = %+v (error VMs must not count as running/provisioning)", p)
	}
	// 1024 (running) + 2048 (possibly-live error); the settled error's
	// 8192 excluded.
	if p.AllocatedMemoryMib != 3072 || p.AllocatedVcpus != 6 {
		t.Fatalf("allocations = %+v, want only the possibly-live error VM included", p)
	}
}

// Build pressure comes from counters released at worker exit, not from
// the registry's terminal status: a cancelled build stays counted while
// its subprocess may still be dying, and pressure never scans the
// (indefinitely retained) registry.
func TestCapacityPressureBuildCountersReleaseAtWorkerExit(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}, builds: map[string]*buildRecord{}}
	rec, err := m.registerBuild("b1", "tpl", 2, 4096, func() {})
	if err != nil {
		t.Fatal(err)
	}
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 1 || p.AllocatedMemoryMib != 4096 {
		t.Fatalf("after register: %+v", p)
	}
	// Cancel marks the record terminal — the counters must NOT release.
	if !m.setBuildStatus("b1", BuildStatusCancelled) {
		t.Fatal("cancel transition failed")
	}
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 1 || p.AllocatedMemoryMib != 4096 {
		t.Fatalf("after cancel (subprocess may live): %+v, want still counted", p)
	}
	// The last build VM exits: allocation returns, the workflow count
	// holds until the worker itself returns (hash-only interval).
	m.releaseBuildAlloc(rec, 2, 4096)
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 1 || p.AllocatedMemoryMib != 0 {
		t.Fatalf("after VM exit: %+v, want allocation released but still provisioning", p)
	}
	// Idempotent: the worker's safety-net defer must not double-release.
	m.releaseBuildAlloc(rec, 2, 4096)
	if got := m.buildPressureMem.Load(); got != 0 {
		t.Fatalf("mem counter = %d after double release, want 0", got)
	}
	m.buildPressureCount.Add(-1)
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 0 || p.AllocatedMemoryMib != 0 {
		t.Fatalf("after worker exit: %+v, want fully released", p)
	}
}

// PressureReady fails CLOSED when the state inventory cannot be read: an
// empty instance map on a possibly-full host must suppress publication
// (leaving the previous report visibly aging) rather than advertise
// fresh zeros that invite over-placement.
func TestPressureReadyFailsClosedOnUnreadableState(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listLiveFirecrackerUnits }()
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Closed store: All() errors, exactly like a corrupt/unreadable DB.
	st.Close()
	m := &Manager{state: st, vms: map[string]*VMInstance{}}
	m.ReattachAll(context.Background())
	if m.PressureReady() {
		t.Fatal("PressureReady = true after a failed state read; must fail closed")
	}

	// A readable (empty) store completes normally and enables publication.
	st2, err := OpenStateStore(filepath.Join(dir, "vmd2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	m2 := &Manager{state: st2, vms: map[string]*VMInstance{}}
	m2.ReattachAll(context.Background())
	if !m2.PressureReady() {
		t.Fatal("PressureReady = false after a successful reattach")
	}

	// No state store at all: nothing to reattach, empty is the truth.
	m3 := &Manager{vms: map[string]*VMInstance{}}
	m3.ReattachAll(context.Background())
	if !m3.PressureReady() {
		t.Fatal("PressureReady = false with no state store configured")
	}
}

// A panic mid-reattach must leave publication CLOSED: the completion
// store is explicit at the successful return, never a defer — a defer
// runs during panic unwinding and would mark a half-rebuilt map ready,
// publishing exactly the partial snapshot the gate exists to suppress.
func TestPressureReadyStaysClosedOnReattachPanic(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}
	reattachHook = func(string) { panic("mid-pass failure") }
	defer func() { reattachHook = nil }()

	func() {
		// Stands in for the startup goroutine's sentrylog.Recover.
		defer func() {
			if recover() == nil {
				t.Error("expected the reattach panic to propagate")
			}
		}()
		m.ReattachAll(context.Background())
	}()

	if m.PressureReady() {
		t.Fatal("PressureReady = true after a panic mid-reattach; the gate must stay closed")
	}
}

// A recordless orphan unit — a live Firecracker outside the instance map
// — keeps publication closed: its memory is real and unrepresentable, so
// a report would be a fresh undercount. A failed orphan scan is treated
// the same: an unobserved orphan cannot be ruled out.
func TestPressureReadyStaysClosedOnOrphansOrFailedScan(t *testing.T) {
	defer func() { listActiveFCUnits = listLiveFirecrackerUnits }()

	newMgr := func(t *testing.T) *Manager {
		st, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}}
	}

	// Orphan unit present.
	listActiveFCUnits = func(context.Context) ([]string, error) { return []string{"ghost-vm"}, nil }
	m := newMgr(t)
	m.ReattachAll(context.Background())
	if m.PressureReady() {
		t.Fatal("PressureReady = true with a recordless orphan unit alive")
	}

	// Orphan scan failed.
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, context.DeadlineExceeded }
	m2 := newMgr(t)
	m2.ReattachAll(context.Background())
	if m2.PressureReady() {
		t.Fatal("PressureReady = true after a failed orphan scan")
	}

	// Clean scan: publication opens.
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	m3 := newMgr(t)
	m3.ReattachAll(context.Background())
	if !m3.PressureReady() {
		t.Fatal("PressureReady = false after a clean, conclusive pass")
	}

	// A unit that appears in the scan but is REPRESENTED in the current
	// instance map is not an orphan — it is a create/restore that raced
	// the background pass and must not keep the gate closed.
	listActiveFCUnits = func(context.Context) ([]string, error) { return []string{"racing-vm"}, nil }
	m4 := newMgr(t)
	m4.vms["racing-vm"] = &VMInstance{Status: StatusRunning, Config: VMConfig{VCPU: 1, MemoryMiB: 256}}
	m4.ReattachAll(context.Background())
	if !m4.PressureReady() {
		t.Fatal("PressureReady = false for a concurrently created, fully represented VM")
	}
}

// A stale record's failure handling has two legitimate endings, and the
// publication gate must read them differently:
//   - unit-supervised, stop unconfirmed: the record is PARKED as Error in
//     the instance map — represented, its allocation still counted — so
//     the gate may open;
//   - cgroup-supervised, death unprovable (no delegated subtree, or a
//     populated group): reattach returns with the record retained and NO
//     instance — a possibly-live Firecracker pressure cannot see — so
//     the gate must stay closed.
func TestPressureReadyStaysClosedOnRetainedUnrepresentedRecord(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	origDown, origStop := vmUnitFullyDown, staleUnitStopConfirmed
	defer func() {
		listActiveFCUnits = listLiveFirecrackerUnits
		vmUnitFullyDown, staleUnitStopConfirmed = origDown, origStop
	}()
	vmUnitFullyDown = func(string) bool { return false }                         // not provably terminal
	staleUnitStopConfirmed = func(context.Context, string) bool { return false } // stop unconfirmed

	run := func(t *testing.T, supervision Supervision) *Manager {
		dir := t.TempDir()
		st, err := OpenStateStore(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if err := st.Put(VMRecord{ID: "vm-1", Status: StatusRunning,
			Supervision: supervision,
			SocketPath:  filepath.Join(dir, "missing.sock")}); err != nil {
			t.Fatal(err)
		}
		m := &Manager{log: zerolog.Nop(), state: st,
			vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
		m.ReattachAll(context.Background())
		return m
	}

	// Cgroup mode with no delegated subtree: death unprovable, record
	// retained, no instance — closed.
	if m := run(t, SupervisionCgroup); m.PressureReady() {
		t.Fatal("PressureReady = true with a retained, unrepresented cgroup record")
	}

	// Unit mode: the unconfirmed stop parks the record as Error IN the
	// map — represented and counted — so the gate opens.
	m := run(t, SupervisionUnit)
	if !m.PressureReady() {
		t.Fatal("PressureReady = false for a parked (represented) Error record")
	}
	if _, ok := m.vms["vm-1"]; !ok {
		t.Fatal("parked record not in the instance map")
	}
}

// "Paused" can lie about the process: mid-resume (restore window, op
// lock held) and after an unconfirmed pause stop, Firecracker may be
// live while the status reads Paused. Those windows must count the
// allocation; a settled paused VM must not.
func TestCapacityPressureCountsLivePausedWindows(t *testing.T) {
	origStart := vmProcessStart
	vmProcessStart = time.Now().Add(-time.Hour) // outside the settle window
	defer func() { vmProcessStart = origStart }()

	m := &Manager{vms: map[string]*VMInstance{
		"settled":   {Status: StatusPaused, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}},
		"resuming":  {Status: StatusPaused, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}},
		"unstopped": {Status: StatusPaused, Config: VMConfig{VCPU: 8, MemoryMiB: 4096}},
	}}
	// Mid-resume: the lifecycle op lock is held.
	m.vmOpCh("resuming") <- struct{}{}
	defer func() { <-m.vmOpCh("resuming") }()
	// Unconfirmed stop: the unit oracle remembers it.
	recordUnitStop(systemdUnitName("unstopped"))
	defer confirmUnitStopped(systemdUnitName("unstopped"))

	seedPressureIndex(m)
	p := m.CapacityPressure()
	if p.PausedSandboxes != 3 {
		t.Fatalf("paused = %d, want 3", p.PausedSandboxes)
	}
	// resuming (2048+4) + unstopped (4096+8); settled excluded.
	if p.AllocatedMemoryMib != 6144 || p.AllocatedVcpus != 12 {
		t.Fatalf("allocations = %+v, want only the live-window paused VMs counted", p)
	}
}

// A surviving template-builder from the previous daemon holds unsizable
// build-VM memory: publication stays gated until it exits.
func TestPressureReadyWaitsForSurvivingBuilders(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)
	alive := map[int]bool{101: true, 102: true}
	m.builderAlive = func(bp builderProc) bool { return alive[bp.pid] }
	m.SetSurvivingBuilders([]builderProc{{pid: 101, start: 7}, {pid: 102, start: 9}})

	if m.PressureReady() {
		t.Fatal("PressureReady = true with surviving builders alive")
	}
	alive[101] = false
	if m.PressureReady() {
		t.Fatal("PressureReady = true with one surviving builder alive")
	}
	alive[102] = false
	if !m.PressureReady() {
		t.Fatal("PressureReady = false after all surviving builders exited")
	}
	// The list only shrinks: once open, it stays open.
	if !m.PressureReady() {
		t.Fatal("gate reclosed after opening")
	}
}

// Survivor discovery must never cost startup anything, yet the gate must
// be closed from the instant it is requested: a heartbeat firing
// mid-scan publishes nothing, and the result opens the gate only after
// it lands.
func TestPressureReadyClosedWhileBuilderScanPending(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)

	release := make(chan struct{})
	m.builderScan = func(string) ([]builderProc, error) {
		<-release
		return nil, nil
	}
	m.ScanSurvivingBuildersAsync("/usr/local/bin/template-builder")
	if m.PressureReady() {
		t.Fatal("PressureReady = true while the survivor scan is still running")
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for !m.PressureReady() {
		if time.Now().After(deadline) {
			t.Fatal("PressureReady never opened after the scan completed empty")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A destroy racing the end of reattach removes the instance BEFORE
// deleting the record; the gate must re-observe rather than permanently
// close on that middle state.
func TestPressureReadySurvivesConcurrentTeardown(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listLiveFirecrackerUnits }()

	st, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}}
	// Mid-teardown at gate time: instance already gone from the map,
	// record still present, destroying marker held. The record delete
	// lands shortly after — as a real destroy's would.
	m.destroying.Store("vm-1", struct{}{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = st.Delete("vm-1")
		m.destroying.Delete("vm-1")
	}()
	m.ReattachAll(context.Background())
	if !m.PressureReady() {
		t.Fatal("PressureReady = false after a concurrent teardown completed cleanly")
	}
}

// findSurvivingBuilders must not classify builders spawned by THIS
// daemon as predecessors: their registry counters already size them, and
// gating on them would suppress publication for the whole build.
func TestFindSurvivingBuildersExcludesOwnChildren(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	survivors, err := findSurvivingBuilders("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	for _, bp := range survivors {
		if bp.pid == cmd.Process.Pid {
			t.Fatal("own child classified as a predecessor survivor")
		}
	}
}

// Build-prefixed cgroups are exempt from the orphan gate ONLY while an
// in-flight registry build owns them: a leftover build or recorder VM
// from a dead daemon has no registry entry and must keep the gate
// closed like any other unrepresented Firecracker.
func TestBuildAllocCoversDistinguishesLeftovers(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}, builds: map[string]*buildRecord{}}
	rec, err := m.registerBuild("build-row-uuid-1", "tpl-a", 1, 1024, func() {})
	if err != nil {
		t.Fatal(err)
	}
	// Current build VM: exempt while the allocation covers it. The
	// recorder id is covered only during ITS recording window.
	if !m.buildAllocCovers("build-row-uuid-1") {
		t.Fatal("in-flight build cgroup not exempt")
	}
	if m.buildAllocCovers("build-record-tpl-a") {
		t.Fatal("recorder covered outside its recording window")
	}
	m.buildsMu.Lock()
	rec.RecorderLive = true
	m.buildsMu.Unlock()
	if !m.buildAllocCovers("build-record-tpl-a") {
		t.Fatal("in-flight build's recorder cgroup not exempt during recording")
	}
	// Leftovers from a previous daemon: not exempt.
	if m.buildAllocCovers("build-row-uuid-9") {
		t.Fatal("unknown build cgroup exempted")
	}
	if m.buildAllocCovers("build-record-tpl-z") {
		t.Fatal("leftover recorder cgroup exempted")
	}
	// A cancel marks the build terminal while its recorder may still be
	// tearing down with the counters held: coverage must persist until
	// the ALLOCATION releases, or the recorder is counted twice for the
	// teardown window.
	if !m.setBuildStatus("build-row-uuid-1", BuildStatusCancelled) {
		t.Fatal("cancel failed")
	}
	if !m.buildAllocCovers("build-row-uuid-1") || !m.buildAllocCovers("build-record-tpl-a") {
		t.Fatal("cancelled-but-unreleased build lost coverage: recorder double-counted during teardown")
	}
	// Allocation returned: no longer covered, terminal or not.
	m.releaseBuildAlloc(rec, 1, 1024)
	if m.buildAllocCovers("build-row-uuid-1") || m.buildAllocCovers("build-record-tpl-a") {
		t.Fatal("alloc-released build's cgroups still exempted")
	}
}

// An unconfirmed cgroup-mode pause stop has no unit-oracle entry; the
// vmStopUnconfirmed marker must keep the allocation counted, and a
// later confirmed pause clears it.
func TestCapacityPressureCountsUnconfirmedCgroupStop(t *testing.T) {
	origStart := vmProcessStart
	vmProcessStart = time.Now().Add(-time.Hour)
	defer func() { vmProcessStart = origStart }()

	m := &Manager{vms: map[string]*VMInstance{
		"cg1": {Status: StatusPaused, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}},
	}}
	m.vmStopUnconfirmed.Store("cg1", struct{}{})
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.AllocatedMemoryMib != 2048 || p.AllocatedVcpus != 4 {
		t.Fatalf("allocations = %+v, want the unconfirmed-stop VM counted", p)
	}
	m.vmStopUnconfirmed.Delete("cg1")
	seedPressureIndex(m)
	if p := m.CapacityPressure(); p.AllocatedMemoryMib != 0 {
		t.Fatalf("allocations = %+v, want zero after the stop was resolved", p)
	}
}

// The access-pattern recorder lives in the instance map while its build's
// counters still hold the allocation: the instance loop must skip
// build-prefixed VMs or the build is double-counted for the whole
// recording window.
func TestCapacityPressureSkipsBuildInstances(t *testing.T) {
	m := &Manager{
		vms: map[string]*VMInstance{
			"build-record-tpl-a": {Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 4096}},
			"customer-vm":        {Status: StatusRunning, Config: VMConfig{VCPU: 1, MemoryMiB: 512}},
		},
		builds: map[string]*buildRecord{},
	}
	recA, err := m.registerBuild("build-tpl-a", "tpl-a", 2, 4096, func() {})
	if err != nil {
		t.Fatal(err)
	}
	m.buildsMu.Lock()
	recA.RecorderLive = true // recording in progress
	m.buildsMu.Unlock()
	seedPressureIndex(m)
	p := m.CapacityPressure()
	if p.RunningSandboxes != 1 {
		t.Fatalf("running = %d, want 1 (recorder is not a customer sandbox)", p.RunningSandboxes)
	}
	// 512 (customer) + 4096 (build counters, once) — not 8704.
	if p.AllocatedMemoryMib != 4608 || p.AllocatedVcpus != 3 {
		t.Fatalf("allocations = %+v, want the build counted exactly once", p)
	}

	// The recorder's teardown failed and the build moved on: allocation
	// returned, recorder still alive in the map. It must now be counted
	// directly — the leaked process would otherwise be invisible forever.
	m.releaseBuildAlloc(recA, 2, 4096)
	seedPressureIndex(m)
	p = m.CapacityPressure()
	if p.AllocatedMemoryMib != 4608 || p.AllocatedVcpus != 3 {
		t.Fatalf("allocations = %+v, want the leaked recorder counted by the instance loop", p)
	}
	if p.RunningSandboxes != 2 {
		t.Fatalf("running = %d, want 2 (leaked recorder now visible)", p.RunningSandboxes)
	}
}

// A recycled pid must not hold the survivor gate: identity is pid AND
// kernel start time, so a stranger reusing the pid fails the check and
// the gate opens.
func TestSurvivorGateReleasesOnPIDRecycle(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)
	// The "alive" probe sees SOME process at pid 101 — but with a
	// different start time than the recorded survivor.
	m.builderAlive = builderProcAliveWith(func(pid int) (uint64, bool) {
		return 999, true // recycled: different identity
	})
	m.SetSurvivingBuilders([]builderProc{{pid: 101, start: 7}})
	if !m.PressureReady() {
		t.Fatal("PressureReady = false for a recycled pid; the original survivor is gone")
	}
}

// builderProcAliveWith builds an identity-checking probe over a stubbed
// start-time reader, mirroring builderProcAlive's comparison.
func builderProcAliveWith(startOf func(pid int) (uint64, bool)) func(builderProc) bool {
	return func(bp builderProc) bool {
		start, ok := startOf(bp.pid)
		return ok && start == bp.start
	}
}

// A predecessor build's cgroup gates DYNAMICALLY: the orphaned builder
// tears its own VM down on exit, so the gate reopens when the group
// empties instead of staying closed until the next daemon restart.
func TestPressureReadyReopensAfterPredecessorBuildCgroupEmpties(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)
	m.pendingBuildCgroups = []string{"build-tpl-x"}
	// cgroups == nil: death unprovable — gate stays closed.
	if m.PressureReady() {
		t.Fatal("PressureReady = true with a pending predecessor build cgroup")
	}
	// The group is proven empty: gate reopens and the entry drops.
	m.pendingBuildCgroups = nil
	if !m.PressureReady() {
		t.Fatal("PressureReady = false after the predecessor build cgroup emptied")
	}
}

// vmStopUnconfirmed is in-memory: a restart forgets that a
// cgroup-supervised Paused/Error record's stop never confirmed. Reattach
// must reconstruct the marker from the still-populated group so pressure
// keeps charging the live process past the settle window.
func TestReattachReconstructsCgroupStopMarkers(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listActiveFirecrackerUnits }()

	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Cgroup-supervised paused record; its group still has a member.
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionCgroup}); err != nil {
		t.Fatal(err)
	}
	tree := &cgroupTree{vms: filepath.Join(dir, "vms")}
	if err := os.MkdirAll(tree.vmCgroupDir("vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"),
		[]byte("populated 1\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	m.ReattachAll(context.Background())

	if _, marked := m.vmStopUnconfirmed.Load("vm-1"); !marked {
		t.Fatal("marker not reconstructed for a populated cgroup behind a paused record")
	}

	// An EMPTY group must not re-mark: the stop resolved before the
	// restart.
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"),
		[]byte("populated 0\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m2 := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	m2.ReattachAll(context.Background())
	if _, marked := m2.vmStopUnconfirmed.Load("vm-1"); marked {
		t.Fatal("marker reconstructed for a provably empty cgroup")
	}
}

// A terminal build id may be re-registered while the OLD worker still
// runs its deferred cleanup: the release must act on the generation that
// incremented the counters, never on whatever record the id now names —
// or the replacement build's allocation is silently hidden for life.
func TestReleaseBuildAllocIsGenerationKeyed(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}, builds: map[string]*buildRecord{}}
	recOld, err := m.registerBuild("build-b1", "tpl", 2, 4096, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if !m.setBuildStatus("build-b1", BuildStatusCancelled) {
		t.Fatal("cancel failed")
	}
	// Reuse: a new build replaces the terminal record under the same id.
	recNew, err := m.registerBuild("build-b1", "tpl", 4, 8192, func() {})
	if err != nil {
		t.Fatal(err)
	}
	// The old worker's deferred cleanup fires late.
	m.releaseBuildAlloc(recOld, 2, 4096)

	// The replacement's allocation must be fully intact and covered.
	if got := m.buildPressureMem.Load(); got != 8192 {
		t.Fatalf("mem counter = %d after old worker's release, want 8192", got)
	}
	if !m.buildAllocCovers("build-b1") {
		t.Fatal("replacement build lost coverage to the old worker's release")
	}
	m.releaseBuildAlloc(recNew, 4, 8192)
	if got := m.buildPressureMem.Load(); got != 0 {
		t.Fatalf("mem counter = %d after both releases, want 0", got)
	}
}

// stopUnitDuringRestoreError is the shared cleanup for failed restores
// and resumes: an unconfirmed cgroup stop there must set the marker
// before the caller persists a non-live status, or the surviving
// Firecracker's memory disappears from pressure once the settle window
// expires.
func TestRestoreErrorCleanupMarksUnconfirmedCgroupStop(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Cgroup-supervised record whose group cannot be proven empty: the
	// tree has a populated group, so stopVM's kill path fails to confirm.
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup}); err != nil {
		t.Fatal(err)
	}
	tree := &cgroupTree{vms: filepath.Join(dir, "vms")}
	if err := os.MkdirAll(tree.vmCgroupDir("vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"),
		[]byte("populated 1\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}

	m.stopUnitDuringRestoreError("vm-1")
	if _, marked := m.vmStopUnconfirmed.Load("vm-1"); !marked {
		t.Fatal("unconfirmed cgroup stop in restore-error cleanup did not set the marker")
	}
}

// A recorder leaked by build A (teardown failed, allocation released)
// must stay instance-counted even while build B of the SAME template
// runs: B's counters carry only B's VMs, and template-scoped coverage
// would re-hide the leak for B's whole lifetime.
func TestLeakedRecorderNotHiddenByLaterBuild(t *testing.T) {
	m := &Manager{
		vms: map[string]*VMInstance{
			"build-record-tpl-a": {Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 4096}},
		},
		builds: map[string]*buildRecord{},
	}
	recA, err := m.registerBuild("build-a", "tpl-a", 2, 4096, func() {})
	if err != nil {
		t.Fatal(err)
	}
	m.buildsMu.Lock()
	recA.RecorderLive = true
	m.buildsMu.Unlock()
	// A's recorder teardown fails; A releases its allocation and exits.
	m.releaseBuildAlloc(recA, 2, 4096)
	if !m.setBuildStatus("build-a", BuildStatusFailed) {
		t.Fatal("fail transition")
	}
	m.buildPressureCount.Add(-1)

	// Build B for the same template starts (not yet recording).
	if _, err := m.registerBuild("build-b", "tpl-a", 4, 8192, func() {}); err != nil {
		t.Fatal(err)
	}
	seedPressureIndex(m)
	p := m.CapacityPressure()
	// 8192 (B's counters) + 4096 (leaked recorder, instance-counted).
	if p.AllocatedMemoryMib != 12288 || p.AllocatedVcpus != 6 {
		t.Fatalf("allocations = %+v, want leaked recorder visible alongside B", p)
	}
}

// A stale unconfirmed-stop marker (an earlier pause) must be cleared by
// a later cleanup whose stop CONFIRMS: the residue it described was
// displaced by the resume's relaunch, and the confirmed stop of the
// replacement proves nothing lives on. Only an unconfirmed cleanup
// re-marks.
func TestRestoreErrorCleanupClearsStaleMarkerOnConfirmedStop(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup}); err != nil {
		t.Fatal(err)
	}
	// The group is conclusively EMPTY: the stop confirms immediately.
	tree := &cgroupTree{vms: filepath.Join(dir, "vms")}
	if err := os.MkdirAll(tree.vmCgroupDir("vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.events"),
		[]byte("populated 0\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.vmCgroupDir("vm-1"), "cgroup.kill"),
		[]byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	m.vmStopUnconfirmed.Store("vm-1", struct{}{}) // stale, from an earlier pause

	m.stopUnitDuringRestoreError("vm-1")
	if _, marked := m.vmStopUnconfirmed.Load("vm-1"); marked {
		t.Fatal("stale marker survived a confirmed stop; a gone process stays charged forever")
	}
}

// seedPressureIndex mirrors a test-constructed vms map into the pressure
// index, as the production membership helpers do.
func seedPressureIndex(m *Manager) {
	for id, inst := range m.vms {
		m.indexVM(id, inst)
	}
}

// A failed scan must keep the gate closed and retry — never convert to
// an empty success — and only a successful scan clears the pending flag.
func TestSurvivorScanRetriesOnFailure(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)
	calls := 0
	m.builderScan = func(string) ([]builderProc, error) {
		calls++
		if calls == 1 {
			return nil, os.ErrDeadlineExceeded // transient failure
		}
		return nil, nil
	}
	m.ScanSurvivingBuildersAsync("/usr/local/bin/template-builder")
	// While the first attempt has failed and the retry waits, the gate
	// must be closed.
	deadline := time.Now().Add(5 * time.Second)
	for m.PressureReady() {
		if time.Now().After(deadline) {
			t.Fatal("gate open during failed survivor scan")
		}
		time.Sleep(2 * time.Millisecond)
		if calls >= 2 {
			break
		}
	}
	// The retry (1s backoff) succeeds and the gate opens.
	deadline = time.Now().Add(5 * time.Second)
	for !m.PressureReady() {
		if time.Now().After(deadline) {
			t.Fatalf("gate never opened after scan succeeded (calls=%d)", calls)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Identity probing is three-way: absent stat = gone, mismatched start =
// recycled = gone, everything else inconclusive = retained.
func TestBuilderProcAliveVerdicts(t *testing.T) {
	// A real live process (ourselves): matching identity = alive.
	self := os.Getpid()
	start, ok := procStartTime(strconv.Itoa(self))
	if !ok {
		t.Skip("cannot read own stat")
	}
	if !builderProcAlive(builderProc{pid: self, start: start}) {
		t.Fatal("live process with matching identity read as gone")
	}
	// Same pid, wrong start time: recycled → gone.
	if builderProcAlive(builderProc{pid: self, start: start + 999}) {
		t.Fatal("recycled identity read as alive")
	}
	// Nonexistent pid: conclusively gone.
	if builderProcAlive(builderProc{pid: 1 << 22, start: 1}) {
		t.Fatal("absent process read as alive")
	}
}
