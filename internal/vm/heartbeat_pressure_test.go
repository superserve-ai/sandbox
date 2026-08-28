package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func pressureCfg(sample HostPressure) HeartbeatConfig {
	return HeartbeatConfig{
		HostID:            "host-a",
		VMDAddr:           "10.0.0.9:50051",
		ProxyAddr:         "10.0.0.9:5007",
		Region:            "us-test1",
		CapacityMemoryMib: 1024,
		CapacityVcpus:     8,
		Pressure:          func() HostPressure { return sample },
		MaxSandboxes:      40,
		MaxNetworkSlots:   500,
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
	cfg.VMDAddr = ""
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
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}, pressureAccounting: true}
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
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}, pressureAccounting: true}
	m2.ReattachAll(context.Background())
	if _, marked := m2.vmStopUnconfirmed.Load("vm-1"); marked {
		t.Fatal("marker reconstructed for a provably empty cgroup")
	}
}

// The reconstruction exists ONLY to keep a future pressure report
// honest, so a host that does not publish must not run it: no marker
// work, and — the reason it matters — no fleet-sized walk competing with
// the creates and restores arriving during a restart.
func TestReattachSkipsMarkerReconstructionWithoutPressureAccounting(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listActiveFirecrackerUnits }()

	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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

	// Same fixture as the reconstruction test above, accounting off.
	m := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	m.ReattachAll(context.Background())
	if _, marked := m.vmStopUnconfirmed.Load("vm-1"); marked {
		t.Fatal("pressure-only marker reconstruction ran on a host that never publishes")
	}
}

// The reconstruction walk must not hold the lifecycle mutex: a restart
// scan that did would make every concurrent create and restore (both
// take m.mu.Lock to publish their instance) queue behind a fleet-sized
// pass, and because the walk locks each instance, one instance held by a
// slow write would turn a single-VM stall into a fleet-wide one. Proven
// by holding m.mu for the duration of a reattach and requiring it to
// finish anyway.
func TestReattachMarkerReconstructionDoesNotHoldFleetLock(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listActiveFirecrackerUnits }()

	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tree := &cgroupTree{vms: filepath.Join(dir, "vms")}
	m := &Manager{log: zerolog.Nop(), state: st, cgroups: tree,
		vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}, pressureAccounting: true}

	// A populated index the walk must range over, with the lifecycle
	// map deliberately left empty: ranging pressureIndex is the point.
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("vm-%d", i)
		inst := &VMInstance{ID: id, Status: StatusPaused, Supervision: SupervisionCgroup}
		m.indexVM(id, inst)
	}

	// Hold the fleet lock for longer than the walk should take. A walk
	// that acquires m.mu cannot finish until this releases; one that
	// does not is unaffected.
	m.mu.Lock()
	release := time.AfterFunc(2*time.Second, m.mu.Unlock)
	defer release.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ReattachAll(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("reattach blocked on the fleet lock; the marker walk must range pressureIndex instead")
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

// An in-place restore stops the previous Firecracker before installing
// its replacement: through that window the OLD instance must stay
// visible to pressure (the index entry survives the map delete), and the
// replacement overwrites the same key when installed.
func TestInPlaceReplaceKeepsOldInstanceIndexed(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}}
	old := &VMInstance{Status: StatusRunning, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}}
	m.vms["vm-1"] = old
	m.indexVM("vm-1", old)

	// The in-place window: removed from the map, stop in flight — but
	// still indexed.
	delete(m.vms, "vm-1")
	if p := m.CapacityPressure(); p.AllocatedMemoryMib != 2048 {
		t.Fatalf("allocations = %+v, want the stopping VM still counted", p)
	}

	// Replacement installs over the same key.
	repl := &VMInstance{Status: StatusCreating, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}}
	m.vms["vm-1"] = repl
	m.indexVM("vm-1", repl)
	if p := m.CapacityPressure(); p.AllocatedMemoryMib != 1024 || p.ProvisioningSandboxes != 1 {
		t.Fatalf("allocations = %+v, want only the replacement counted", p)
	}
}

// A predecessor build's systemd unit gates dynamically, mirroring the
// cgroup case: the orphaned builder tears its own VM down on exit, and
// the reconciler skips build-prefixed ids, so a permanent conclusive
// close would suppress publication until the next restart.
func TestPressureReadyReopensAfterPredecessorBuildUnitExits(t *testing.T) {
	origDead := vmUnitFullyDown
	defer func() { vmUnitFullyDown = origDead }()

	m := &Manager{vms: map[string]*VMInstance{}}
	m.reattachComplete.Store(true)
	m.pendingBuildUnits = []string{"build-tpl-x"}
	// The unit is still terminating: closed.
	vmUnitFullyDown = func(string) bool { return false }
	if m.PressureReady() {
		t.Fatal("PressureReady = true with a pending predecessor build unit")
	}
	// The unit exits (probe confirms): reopens and the entry drops.
	vmUnitFullyDown = func(string) bool { return true }
	if !m.PressureReady() {
		t.Fatal("PressureReady = false after the predecessor build unit exited")
	}
	m.mu.Lock()
	left := len(m.pendingBuildUnits)
	m.mu.Unlock()
	if left != 0 {
		t.Fatalf("pending units = %d after confirmed exit, want 0", left)
	}
}

// Completion is generation-bound like the allocation release: a replaced
// worker's result must never become the replacement build's terminal
// state (which the replacement's own worker could then never overwrite).
func TestCompleteBuildDropsReplacedWorkerResult(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, builds: map[string]*buildRecord{}}
	recOld, err := m.registerBuild("build-x", "tpl", 1, 1024, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if !m.setBuildStatus("build-x", BuildStatusCancelled) {
		t.Fatal("cancel failed")
	}
	recNew, err := m.registerBuild("build-x", "tpl", 1, 1024, func() {})
	if err != nil {
		t.Fatal(err)
	}
	// The old worker finishes late: its completion must be dropped.
	m.completeBuild("build-x", recOld, nil, os.ErrDeadlineExceeded)
	m.buildsMu.RLock()
	status := m.builds["build-x"].Status
	m.buildsMu.RUnlock()
	if status.IsTerminal() {
		t.Fatalf("replacement build terminated by the replaced worker's result (status %s)", status)
	}
	// The replacement's own completion lands normally.
	m.completeBuild("build-x", recNew, &BuildTemplateResult{}, nil)
	m.buildsMu.RLock()
	status = m.builds["build-x"].Status
	m.buildsMu.RUnlock()
	if status != BuildStatusReady {
		t.Fatalf("replacement's own completion did not land (status %s)", status)
	}
}

// A VM whose allocation was never declared adds ZERO memory and vCPUs to
// the totals — the same as no VM at all — so a host holding them would
// publish as idle while running real workloads. Recovery is what closes
// that, and the fixture deliberately starts from the empty config such a
// record really carries: one that declared its own sizes would assume
// away the condition under test.
func TestPressureCountsVMsWithUndeclaredSizes(t *testing.T) {
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		return 4, 8192, nil // what Firecracker reports for the restored VM
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "restored", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)
	if inst.Config.VCPU != 0 || inst.Config.MemoryMiB != 0 {
		t.Fatal("fixture must start with an undeclared allocation")
	}

	m.backfillMachineConfigAsync(inst)
	awaitBackfill(t, done)

	m.reattachComplete.Store(true)
	p := m.CapacityPressure()
	if p.RunningSandboxes != 1 {
		t.Fatalf("running = %d, want 1", p.RunningSandboxes)
	}
	if p.AllocatedMemoryMib != 8192 || p.AllocatedVcpus != 4 {
		t.Fatalf("allocation = %d MiB / %d vcpu, want 8192/4 — a restored VM must not publish as free capacity",
			p.AllocatedMemoryMib, p.AllocatedVcpus)
	}
}

// A declared allocation is authoritative: no probe, no overwrite.
func TestBackfillSkipsVMsThatDeclaredTheirSize(t *testing.T) {
	probed := make(chan struct{}, 1)
	stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		probed <- struct{}{}
		return 99, 99, nil
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "declared", Status: StatusRunning, SocketPath: "/run/fc.sock",
		Config: VMConfig{VCPU: 2, MemoryMiB: 1024}}
	m.backfillMachineConfigAsync(inst)

	select {
	case <-probed:
		t.Fatal("probed a VM whose allocation was already declared")
	case <-time.After(200 * time.Millisecond):
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Config.VCPU != 2 || inst.Config.MemoryMiB != 1024 {
		t.Fatalf("declared allocation overwritten: %d/%d", inst.Config.VCPU, inst.Config.MemoryMiB)
	}
}

// A failed probe must leave the zeros rather than invent a size: an
// under-count shows up as a host that looks emptier than it is, while a
// guess is wrong in a direction nothing can detect. The VM stays queued
// for another attempt, so no completion arrives while it remains
// eligible — that is the point of retrying.
func TestBackfillLeavesSizeUnknownWhenProbeFails(t *testing.T) {
	probed := make(chan struct{}, 8)
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		select {
		case probed <- struct{}{}:
		default:
		}
		return 0, 0, fmt.Errorf("connection refused")
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "unreachable", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)
	m.backfillMachineConfigAsync(inst)

	select {
	case <-probed:
	case <-time.After(3 * time.Second):
		t.Fatal("the probe never ran")
	}
	inst.mu.RLock()
	vcpu, mem := inst.Config.VCPU, inst.Config.MemoryMiB
	inst.mu.RUnlock()
	if vcpu != 0 || mem != 0 {
		t.Fatalf("invented an allocation after a failed probe: %d/%d", vcpu, mem)
	}

	// Retire it so the retry loop lets go and the seams restore without
	// live work still reading them.
	m.mu.Lock()
	delete(m.vms, inst.ID)
	m.unindexVM(inst.ID)
	m.mu.Unlock()
	awaitBackfill(t, done)
}

// stubMachineConfigProbe swaps the probe seam and returns a channel that
// fires when the backfill goroutine exits. Restoring the seams is
// deferred to cleanup AFTER that join, so the package-level swap never
// races the detached work.
func stubMachineConfigProbe(t *testing.T, probe func(context.Context, string) (uint32, uint32, error)) <-chan string {
	t.Helper()
	done := make(chan string, 4)
	prevProbe, prevDone, prevBackoff := machineConfigProbe, machineConfigBackfillDone, machineConfigProbeBackoff
	machineConfigProbe = probe
	machineConfigBackfillDone = func(vmID string) { done <- vmID }
	// Retries are exercised for their behavior, not their timing: a real
	// backoff would make the retry tests take seconds and let cleanup
	// restore these seams while a goroutine is still looping.
	machineConfigProbeBackoff = time.Millisecond
	t.Cleanup(func() {
		machineConfigProbe, machineConfigBackfillDone = prevProbe, prevDone
		machineConfigProbeBackoff = prevBackoff
	})
	return done
}

func awaitBackfill(t *testing.T, done <-chan string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("allocation backfill never ran — an undeclared VM keeps a zero size and publishes as free capacity")
	}
}

// A destroy that lands while the probe is in flight must not have its
// record resurrected. Recovery writes no record at all, which is what
// makes this impossible rather than merely unlikely — a conditional
// write would still land on a REPLACEMENT that reused the id.
func TestBackfillDoesNotResurrectDestroyedRecords(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	release, entered := make(chan struct{}), make(chan struct{})
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		close(entered)
		<-release // hold the probe open so the destroy wins the race
		return 4, 8192, nil
	})

	m := &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "doomed", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)
	if ok := m.persistState(inst); !ok {
		t.Fatal("seed persist failed")
	}

	m.backfillMachineConfigAsync(inst)
	// The probe must be IN FLIGHT before the destroy, or the goroutine
	// exits at its first identity check and the write this test is about
	// never happens — a pass that proves nothing.
	<-entered

	// The destroy: instance gone from the map, record deleted.
	m.mu.Lock()
	delete(m.vms, inst.ID)
	m.unindexVM(inst.ID)
	m.mu.Unlock()
	if err := st.Delete(inst.ID); err != nil {
		t.Fatal(err)
	}

	close(release)
	awaitBackfill(t, done)

	rec, err := st.Get(inst.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if rec != nil {
		t.Fatalf("backfill resurrected a destroyed VM's record: %+v", rec)
	}
}

// An id reused by an in-place replace must not have the OLD instance's
// probe touch the replacement — neither its record nor its in-memory
// size. Identity is checked by pointer, never by id.
func TestBackfillDoesNotOverwriteAReplacementUnderTheSameID(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	release, entered := make(chan struct{}), make(chan struct{})
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		close(entered)
		<-release
		return 4, 8192, nil // the OLD instance's shape
	})

	m := &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	old := &VMInstance{ID: "reused", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[old.ID] = old
	m.indexVM(old.ID, old)
	m.backfillMachineConfigAsync(old)
	<-entered // the old instance's probe must be in flight before the replace

	// The replace: a different instance takes the id, with its own size.
	replacement := &VMInstance{ID: "reused", Status: StatusRunning, SocketPath: "/run/fc2.sock",
		Config: VMConfig{VCPU: 1, MemoryMiB: 512}}
	m.mu.Lock()
	m.vms[replacement.ID] = replacement
	m.indexVM(replacement.ID, replacement)
	m.mu.Unlock()
	if ok := m.persistState(replacement); !ok {
		t.Fatal("replacement persist failed")
	}

	close(release)
	awaitBackfill(t, done)

	rec, err := st.Get(replacement.ID)
	if err != nil || rec == nil {
		t.Fatalf("replacement record missing: %v", err)
	}
	if rec.VCPU != 1 || rec.MemoryMiB != 512 {
		t.Fatalf("old instance's probe overwrote the replacement: %d/%d", rec.VCPU, rec.MemoryMiB)
	}
	replacement.mu.RLock()
	defer replacement.mu.RUnlock()
	if replacement.Config.VCPU != 1 || replacement.Config.MemoryMiB != 512 {
		t.Fatalf("replacement's in-memory size clobbered: %d/%d",
			replacement.Config.VCPU, replacement.Config.MemoryMiB)
	}
}

// A transient probe failure must not leave a live VM uncounted forever:
// the backfill retries while the instance is still current, so one bad
// socket read cannot make the host advertise that memory as free for the
// VM's whole lifetime.
func TestBackfillRetriesTransientProbeFailures(t *testing.T) {
	var attempts atomic.Int32
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		if attempts.Add(1) < 3 {
			return 0, 0, fmt.Errorf("connection refused")
		}
		return 2, 2048, nil
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "flaky", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)

	m.backfillMachineConfigAsync(inst)
	awaitBackfill(t, done)

	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Config.VCPU != 2 || inst.Config.MemoryMiB != 2048 {
		t.Fatalf("allocation not recovered after transient failures: %d/%d",
			inst.Config.VCPU, inst.Config.MemoryMiB)
	}
	if got := attempts.Load(); got < 3 {
		t.Fatalf("probe attempts = %d, want the retries that recovered it", got)
	}
}

// Retrying must stop when the VM goes away, or a destroyed VM's backfill
// spins for the life of the process.
func TestBackfillStopsRetryingOnceTheVMIsGone(t *testing.T) {
	var attempts atomic.Int32
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		attempts.Add(1)
		return 0, 0, fmt.Errorf("connection refused")
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "vanishing", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)
	m.backfillMachineConfigAsync(inst)

	// Let the first attempt fail, then retire the instance.
	time.Sleep(50 * time.Millisecond)
	m.mu.Lock()
	delete(m.vms, inst.ID)
	m.unindexVM(inst.ID)
	m.mu.Unlock()

	awaitBackfill(t, done)
	settled := attempts.Load()
	time.Sleep(200 * time.Millisecond)
	if got := attempts.Load(); got != settled {
		t.Fatalf("probe kept retrying after the VM was gone: %d then %d", settled, got)
	}
}

// An unsized VM adds zero to the allocation totals, which is exactly
// what an ABSENT VM adds — so without a separate signal a host full of
// legacy records publishes as idle. The count is what makes the
// undercount visible to whoever reads the report.
func TestPressureReportsUnknownAllocations(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	sized := &VMInstance{ID: "sized", Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}}
	legacy := &VMInstance{ID: "legacy", Status: StatusRunning} // pre-contract record
	for _, inst := range []*VMInstance{sized, legacy} {
		m.vms[inst.ID] = inst
		m.indexVM(inst.ID, inst)
	}
	m.reattachComplete.Store(true)

	p := m.CapacityPressure()
	if p.RunningSandboxes != 2 {
		t.Fatalf("running = %d, want 2", p.RunningSandboxes)
	}
	if p.AllocatedMemoryMib != 1024 || p.AllocatedVcpus != 2 {
		t.Fatalf("allocation = %d MiB / %d vcpu, want only the sized VM's", p.AllocatedMemoryMib, p.AllocatedVcpus)
	}
	if p.UnknownAllocationVMs != 1 {
		t.Fatalf("unknown allocations = %d, want 1 — the undercount must be visible, not silent",
			p.UnknownAllocationVMs)
	}

	// Fully described hosts say so with a zero, so a reader can tell
	// "nothing unknown" from "never reported".
	legacy.mu.Lock()
	legacy.Config = VMConfig{VCPU: 1, MemoryMiB: 512}
	legacy.mu.Unlock()
	if p := m.CapacityPressure(); p.UnknownAllocationVMs != 0 {
		t.Fatalf("unknown allocations = %d after both VMs were sized, want 0", p.UnknownAllocationVMs)
	}
}

// Reattach can find hundreds of legacy records; recovering them all at
// once would fire hundreds of concurrent Firecracker calls exactly when
// the daemon is busiest. The pool bounds that.
func TestBackfillRecoveryIsBounded(t *testing.T) {
	var mu sync.Mutex
	inFlight, peak := 0, 0
	release := make(chan struct{})
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
		return 2, 1024, nil
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	const total = machineConfigRecoveryWorkers * 5
	insts := make([]*VMInstance, 0, total)
	// Publish every instance BEFORE any recovery starts: the workers read
	// the map under m.mu, so the test must not mutate it alongside them.
	m.mu.Lock()
	for i := 0; i < total; i++ {
		inst := &VMInstance{ID: fmt.Sprintf("legacy-%d", i), Status: StatusRunning, SocketPath: "/run/fc.sock"}
		m.vms[inst.ID] = inst
		m.indexVM(inst.ID, inst)
		insts = append(insts, inst)
	}
	m.mu.Unlock()
	for _, inst := range insts {
		m.backfillMachineConfigAsync(inst)
	}

	// Let the pool saturate, then assert it never exceeded its budget.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		saturated := inFlight >= machineConfigRecoveryWorkers
		mu.Unlock()
		if saturated || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	for i := 0; i < total; i++ {
		awaitBackfill(t, done)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak > machineConfigRecoveryWorkers {
		t.Fatalf("peak concurrent probes = %d, want at most %d", peak, machineConfigRecoveryWorkers)
	}
	if peak == 0 {
		t.Fatal("no probe ever ran; the bound was not exercised")
	}
}

// Jitter only ever lengthens a wait: it exists to spread a fleet's
// retries, and must never shorten the backoff into a tighter loop.
func TestJitterDurationOnlyExtends(t *testing.T) {
	const base = time.Second
	sawDifferent := false
	for i := 0; i < 200; i++ {
		got := jitterDuration(base)
		if got < base {
			t.Fatalf("jittered wait %v is shorter than the backoff %v", got, base)
		}
		if got > base+base/2 {
			t.Fatalf("jittered wait %v exceeds the 1.5x bound", got)
		}
		if got != base {
			sawDifferent = true
		}
	}
	if !sawDifferent {
		t.Fatal("jitter never varied the wait; a fleet would still retry in lockstep")
	}
	if got := jitterDuration(0); got != 0 {
		t.Fatalf("jitterDuration(0) = %v, want 0", got)
	}
}

// The invariant that removes the id-reuse race entirely: recovery never
// writes a durable record. An identity check followed by a separate
// write is a window — the instance can be replaced in between, and a
// conditional write would then land on the successor, overwriting its
// pid, socket and network state with the old run's. No write, no window.
func TestBackfillNeverWritesDurableState(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		return 4, 8192, nil
	})

	m := &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	inst := &VMInstance{ID: "legacy", Status: StatusRunning, SocketPath: "/run/fc.sock"}
	m.vms[inst.ID] = inst
	m.indexVM(inst.ID, inst)
	if ok := m.persistState(inst); !ok {
		t.Fatal("seed persist failed")
	}

	m.backfillMachineConfigAsync(inst)
	awaitBackfill(t, done)

	// In memory the size is recovered...
	inst.mu.RLock()
	vcpu, mem := inst.Config.VCPU, inst.Config.MemoryMiB
	inst.mu.RUnlock()
	if vcpu != 4 || mem != 8192 {
		t.Fatalf("allocation not recovered in memory: %d/%d", vcpu, mem)
	}
	// ...but the record is untouched, and a later legitimate write (a
	// pause, a status change) is what carries it durably.
	rec, err := st.Get(inst.ID)
	if err != nil || rec == nil {
		t.Fatalf("record missing: %v", err)
	}
	if rec.VCPU != 0 || rec.MemoryMiB != 0 {
		t.Fatalf("recovery wrote the record (%d/%d); that write can land on a replacement that reused the id",
			rec.VCPU, rec.MemoryMiB)
	}
}

// A settled paused VM and a provably dead error record are charged NO
// memory, so flagging them unknown would report a host as unable to
// describe itself over VMs that hold nothing — and a consumer would
// refuse to place on a host that is in fact idle.
func TestUnknownAllocationCountsOnlyChargedVMs(t *testing.T) {
	// Past the post-restart settle window, where "could not tell" still
	// counts by design; this test is about VMs that are conclusively
	// holding nothing.
	origStart := vmProcessStart
	vmProcessStart = time.Now().Add(-time.Hour)
	defer func() { vmProcessStart = origStart }()

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	// Unsized and settled: paused with no live process, plus an error
	// record whose process provably never launched. Neither is charged.
	for _, id := range []string{"settled-paused", "dead-error"} {
		status := StatusPaused
		if id == "dead-error" {
			status = StatusError
		}
		inst := &VMInstance{ID: id, Status: status}
		m.vms[id] = inst
		m.indexVM(id, inst)
	}
	m.reattachComplete.Store(true)

	if p := m.CapacityPressure(); p.UnknownAllocationVMs != 0 {
		t.Fatalf("unknown allocations = %d over VMs that hold nothing, want 0", p.UnknownAllocationVMs)
	}

	// A running unsized VM IS charged (as zero), so it must count.
	live := &VMInstance{ID: "live", Status: StatusRunning}
	m.vms[live.ID] = live
	m.indexVM(live.ID, live)
	if p := m.CapacityPressure(); p.UnknownAllocationVMs != 1 {
		t.Fatalf("unknown allocations = %d, want 1 for the charged unsized VM", p.UnknownAllocationVMs)
	}
}

// Unreachable sockets must not starve the pool: the worker slot is held
// for the probe only, never across the backoff, or a handful of dead VMs
// would block every recoverable one behind them.
func TestBackfillRetriesDoNotStarveThePool(t *testing.T) {
	probed := make(chan struct{}, 64)
	done := stubMachineConfigProbe(t, func(_ context.Context, socket string) (uint32, uint32, error) {
		if socket == "/run/good.sock" {
			return 2, 1024, nil
		}
		probed <- struct{}{}
		return 0, 0, fmt.Errorf("connection refused")
	})
	// Long relative to the deadline below, so holding a slot across it is
	// visible; at the millisecond backoff the other tests use, both
	// shapes look identical.
	machineConfigProbeBackoff = 2 * time.Second

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	stuck := make([]*VMInstance, 0, machineConfigRecoveryWorkers)
	m.mu.Lock()
	for i := 0; i < machineConfigRecoveryWorkers; i++ {
		inst := &VMInstance{ID: fmt.Sprintf("stuck-%d", i), Status: StatusRunning, SocketPath: "/run/dead.sock"}
		m.vms[inst.ID] = inst
		m.indexVM(inst.ID, inst)
		stuck = append(stuck, inst)
	}
	good := &VMInstance{ID: "good", Status: StatusRunning, SocketPath: "/run/good.sock"}
	m.vms[good.ID] = good
	m.indexVM(good.ID, good)
	m.mu.Unlock()

	for _, inst := range stuck {
		m.backfillMachineConfigAsync(inst)
	}
	// Every unreachable VM must have REACHED its probe before the
	// recoverable one is offered: otherwise the good VM can win a free
	// slot by scheduling luck and the pool's behavior is never tested.
	for i := 0; i < machineConfigRecoveryWorkers; i++ {
		select {
		case <-probed:
		case <-time.After(5 * time.Second):
			t.Fatal("unreachable VMs never reached their probes")
		}
	}
	m.backfillMachineConfigAsync(good)

	recovered := make(chan struct{})
	go func() {
		for {
			good.mu.RLock()
			ok := good.Config.MemoryMiB == 1024
			good.mu.RUnlock()
			if ok {
				close(recovered)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	select {
	case <-recovered:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a recoverable VM never got a worker slot; retries are holding the pool")
	}

	// Retire the stuck VMs so their loops end and the seams restore
	// without a live goroutine still reading them.
	m.mu.Lock()
	for _, inst := range stuck {
		delete(m.vms, inst.ID)
		m.unindexVM(inst.ID)
	}
	m.mu.Unlock()
	for i := 0; i < machineConfigRecoveryWorkers+1; i++ {
		awaitBackfill(t, done)
	}
}

// Recovery must cost a FIXED number of goroutines, not one per unsized
// VM: a restart with a large legacy fleet would otherwise create
// thousands, each mostly asleep between retries. Bounding the probes is
// not the same as bounding the workers.
func TestBackfillWorkersAreFixedRegardlessOfFleetSize(t *testing.T) {
	release := make(chan struct{})
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		<-release
		return 2, 1024, nil
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	const fleet = 500
	insts := make([]*VMInstance, 0, fleet)
	m.mu.Lock()
	for i := 0; i < fleet; i++ {
		inst := &VMInstance{ID: fmt.Sprintf("legacy-%d", i), Status: StatusRunning, SocketPath: "/run/fc.sock"}
		m.vms[inst.ID] = inst
		m.indexVM(inst.ID, inst)
		insts = append(insts, inst)
	}
	m.mu.Unlock()

	before := runtime.NumGoroutine()
	for _, inst := range insts {
		m.backfillMachineConfigAsync(inst)
	}
	// Let everything that is going to start, start.
	time.Sleep(200 * time.Millisecond)
	growth := runtime.NumGoroutine() - before
	// Workers + dispatcher, plus slack for the runtime's own scheduling.
	if limit := machineConfigRecoveryWorkers + 8; growth > limit {
		t.Fatalf("recovery grew the goroutine count by %d for %d VMs (limit %d); it must not scale with the fleet",
			growth, fleet, limit)
	}

	close(release)
	for i := 0; i < fleet; i++ {
		awaitBackfill(t, done)
	}
}

// A paused VM has no Firecracker listening, so probing one retries
// against a dead socket forever. Reattach skips paused records for that
// reason — which leaves resume as the only moment a legacy paused VM can
// be sized, and it must take it.
func TestBackfillSkipsPausedVMsAndResumeRecoversThem(t *testing.T) {
	probed := make(chan string, 4)
	done := stubMachineConfigProbe(t, func(context.Context, string) (uint32, uint32, error) {
		probed <- "probed"
		return 2, 2048, nil
	})

	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	paused := &VMInstance{ID: "paused-legacy", Status: StatusPaused, SocketPath: "/run/fc.sock"}
	m.vms[paused.ID] = paused
	m.indexVM(paused.ID, paused)

	m.backfillMachineConfigAsync(paused)
	select {
	case <-probed:
		t.Fatal("probed a paused VM; its Firecracker is gone and the retry would never end")
	case <-time.After(200 * time.Millisecond):
	}

	// Resume makes it askable again, and recovery must then size it —
	// otherwise it stays unknown for life and its host stays
	// under-described.
	paused.mu.Lock()
	paused.Status = StatusRunning
	paused.mu.Unlock()
	m.backfillMachineConfigAsync(paused)
	awaitBackfill(t, done)

	paused.mu.RLock()
	defer paused.mu.RUnlock()
	if paused.Config.VCPU != 2 || paused.Config.MemoryMiB != 2048 {
		t.Fatalf("resumed VM never recovered its size: %d/%d", paused.Config.VCPU, paused.Config.MemoryMiB)
	}
}
