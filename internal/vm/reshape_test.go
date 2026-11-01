package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// Every refusal happens before the revival teardown, which removes the
// paused disk: a shape Firecracker would reject at boot must not cost the
// sandbox its pause.
func TestReshapeVMRefusesBeforeTeardown(t *testing.T) {
	dir := t.TempDir()
	net := &fakeNetMgr{}
	m := &Manager{log: zerolog.Nop(), netMgr: net, unitDead: func(context.Context, string) bool { return false }}
	m.cfg = ManagerConfig{RunDir: filepath.Join(dir, "run"), SnapshotDir: filepath.Join(dir, "snapshots")}
	m.vms = map[string]*VMInstance{
		"vm-running":  {ID: "vm-running", Status: StatusRunning, Config: VMConfig{VCPU: 1, MemoryMiB: 1024}},
		"vm-reshaped": {ID: "vm-reshaped", Status: StatusRunning, RevivedDisk: filepath.Join(m.reshapeStageDir("vm-reshaped"), "rootfs.ext4"), Config: VMConfig{VCPU: 1, MemoryMiB: 1024}},
		"vm-gone":     {ID: "vm-gone", Status: StatusPaused, SnapshotPath: filepath.Join(dir, "snapshots", "vm-gone", "vmstate.snap"), Config: VMConfig{VCPU: 1, MemoryMiB: 1024}},
	}
	ctx := context.Background()
	open := &sandboxNetworkRules{}

	for _, tc := range []struct {
		name      string
		id        string
		vcpu, mem uint32
		rules     *sandboxNetworkRules
		want      codes.Code
	}{
		{"traversal id", "../escape", 2, 2048, open, codes.InvalidArgument},
		{"zero vcpu", "vm-running", 0, 2048, open, codes.InvalidArgument},
		{"too many vcpus", "vm-running", reshapeMaxVCPU + 1, 2048, open, codes.InvalidArgument},
		{"too little memory", "vm-running", 2, reshapeMinMemMiB - 1, open, codes.InvalidArgument},
		{"no egress policy", "vm-gone", 2, 2048, nil, codes.InvalidArgument},
		{"running at another shape", "vm-running", 2, 2048, open, codes.FailedPrecondition},
		{"running at the shape but never reshaped", "vm-running", 1, 1024, open, codes.FailedPrecondition},
		{"paused with nothing to boot", "vm-gone", 2, 2048, open, codes.FailedPrecondition},
	} {
		if _, err := m.ReshapeVM(ctx, tc.id, tc.vcpu, tc.mem, tc.rules); status.Code(err) != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	// A retry after a lost response finds the VM it reshaped already at
	// its target and reapplies the policy: a vmd restart in between
	// reattaches the VM without it.
	deny := &sandboxNetworkRules{deniedCIDRs: []string{"0.0.0.0/0"}}
	inst, err := m.ReshapeVM(ctx, "vm-reshaped", 1, 1024, deny)
	if err != nil || inst.ID != "vm-reshaped" {
		t.Fatalf("retry at the current shape: %v, want the running VM", err)
	}
	if len(net.firewallCalls) != 1 || len(net.firewallCalls[0].deniedCIDRs) != 1 {
		t.Fatalf("firewall calls = %+v, want the retry's deny rule applied", net.firewallCalls)
	}
}

// A failed attempt leaves only the durable record, marked pending, while
// the on-demand loader refuses it; the retry must still find its anchor.
func TestReshapeVMRetryFindsTheDurableAnchor(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snap := filepath.Join(dir, "snapshots", "vm-1", "vmstate.snap")
	if err := st.Put(VMRecord{ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, RevivalPending: true, VCPU: 1, MemoryMiB: 1024}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: st, vms: map[string]*VMInstance{}, netMgr: &fakeNetMgr{}}
	m.cfg = ManagerConfig{RunDir: filepath.Join(dir, "run"), SnapshotDir: filepath.Join(dir, "snapshots")}

	// No staged disk: the refusal names it, proving the retry got past
	// the missing in-memory instance to the staged-disk check.
	_, err = m.ReshapeVM(context.Background(), "vm-1", 2, 2048, &sandboxNetworkRules{})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "staged reshape disk") {
		t.Fatalf("err = %v, want the staged-disk refusal", err)
	}
}

func TestReshapeVMRequiresTheEgressPolicy(t *testing.T) {
	a := NewGRPCAdapter(newTestManager())
	for _, net := range []*vmdpb.SandboxNetworkConfig{nil, {}} {
		_, err := a.ReshapeVM(context.Background(), &vmdpb.ReshapeVMRequest{VmId: "vm-1", Vcpu: 2, MemMib: 2048, SandboxNetwork: net})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("sandbox_network %v: err = %v, want InvalidArgument without an egress policy", net, err)
		}
	}
}

// A paused record whose stop was never confirmed may still have a guest
// writing its disk; nothing is staged from it.
func TestReshapeVMRefusesADiskNotAtRest(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snapshots", "vm-1", "vmstate.snap"))
	mem := touch(t, filepath.Join(dir, "snapshots", "vm-1", "mem.snap"))
	disk := touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, unitDead: func(context.Context, string) bool { return false }}
	m.cfg = ManagerConfig{RunDir: filepath.Join(dir, "run"), SnapshotDir: filepath.Join(dir, "snapshots")}
	m.vms = map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused, SnapshotPath: snap, MemFilePath: mem, DiskPath: disk, Config: VMConfig{VCPU: 1, MemoryMiB: 1024}}}

	_, err := m.ReshapeVM(context.Background(), "vm-1", 2, 2048, &sandboxNetworkRules{})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "at rest") {
		t.Fatalf("err = %v, want the at-rest refusal", err)
	}
	if _, serr := os.Stat(m.reshapeStageDir("vm-1")); !os.IsNotExist(serr) {
		t.Fatalf("staging dir exists (%v); nothing may be staged from a disk not at rest", serr)
	}
}
