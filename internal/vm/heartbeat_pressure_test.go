package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// Error-status VMs keep their allocations counted: an error record can
// retain a possibly-live Firecracker, so its memory is still real.
func TestCapacityPressureCountsErrorVMAllocations(t *testing.T) {
	m := &Manager{
		vms: map[string]*VMInstance{
			"r1": {Status: StatusRunning, Config: VMConfig{VCPU: 2, MemoryMiB: 1024}},
			"e1": {Status: StatusError, Config: VMConfig{VCPU: 4, MemoryMiB: 2048}},
		},
	}
	p := m.CapacityPressure()
	if p.RunningSandboxes != 1 || p.ProvisioningSandboxes != 0 {
		t.Fatalf("counts = %+v (error VM must not count as running/provisioning)", p)
	}
	if p.AllocatedMemoryMib != 3072 || p.AllocatedVcpus != 6 {
		t.Fatalf("allocations = %+v, want error VM's resources included", p)
	}
}

// Build pressure comes from counters released at worker exit, not from
// the registry's terminal status: a cancelled build stays counted while
// its subprocess may still be dying, and pressure never scans the
// (indefinitely retained) registry.
func TestCapacityPressureBuildCountersReleaseAtWorkerExit(t *testing.T) {
	m := &Manager{vms: map[string]*VMInstance{}, builds: map[string]*buildRecord{}}
	if _, err := m.registerBuild("b1", "tpl", 2, 4096, func() {}); err != nil {
		t.Fatal(err)
	}
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 1 || p.AllocatedMemoryMib != 4096 {
		t.Fatalf("after register: %+v", p)
	}
	// Cancel marks the record terminal — the counters must NOT release.
	if !m.setBuildStatus("b1", BuildStatusCancelled) {
		t.Fatal("cancel transition failed")
	}
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 1 || p.AllocatedMemoryMib != 4096 {
		t.Fatalf("after cancel (subprocess may live): %+v, want still counted", p)
	}
	// Worker exit releases.
	m.buildPressureCount.Add(-1)
	m.buildPressureMem.Add(-4096)
	m.buildPressureVcpus.Add(-2)
	if p := m.CapacityPressure(); p.ProvisioningSandboxes != 0 || p.AllocatedMemoryMib != 0 {
		t.Fatalf("after worker exit: %+v, want released", p)
	}
}

// PressureReady fails CLOSED when the state inventory cannot be read: an
// empty instance map on a possibly-full host must suppress publication
// (leaving the previous report visibly aging) rather than advertise
// fresh zeros that invite over-placement.
func TestPressureReadyFailsClosedOnUnreadableState(t *testing.T) {
	listActiveFCUnits = func(context.Context) ([]string, error) { return nil, nil }
	defer func() { listActiveFCUnits = listActiveFirecrackerUnits }()
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
	defer func() { listActiveFCUnits = listActiveFirecrackerUnits }()

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
		listActiveFCUnits = listActiveFirecrackerUnits
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
	m.builderAlive = func(pid int) bool { return alive[pid] }
	m.SetSurvivingBuilders([]int{101, 102})

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
