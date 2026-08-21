package vm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
