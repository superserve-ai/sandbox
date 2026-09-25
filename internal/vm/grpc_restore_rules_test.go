package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// knownSlotNetMgr is a network manager that knows every VM's slot.
type knownSlotNetMgr struct{ *fakeNetMgr }

func (knownSlotNetMgr) GetVMNetInfo(string) *network.VMNetInfo {
	return &network.VMNetInfo{HostIP: "192.0.2.5"}
}

// A restore's egress rules reach the VM's firewall and are attested; a
// request without rules attests none.
func TestRestoreSnapshotInstallsAndAttestsItsEgressRules(t *testing.T) {
	dir := t.TempDir()
	snapPath, memPath := filepath.Join(dir, "vmstate.snap"), filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The seeded VM's unit is alive, so the restore adopts it.
	origDead := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	t.Cleanup(func() { vmDeadForRetry = origDead })
	net := &fakeNetMgr{}
	mgr := &Manager{
		log:        zerolog.Nop(),
		netMgr:     knownSlotNetMgr{net},
		restoreSem: make(chan struct{}, 1),
		vms: map[string]*VMInstance{"vm-1": {
			ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5", SnapshotPath: snapPath, MemFilePath: memPath,
		}},
	}
	a := NewGRPCAdapter(mgr)
	req := &vmdpb.RestoreSnapshotRequest{VmId: "vm-1", SnapshotPath: snapPath, MemFilePath: memPath}
	resp, err := a.RestoreSnapshot(context.Background(), req)
	if err != nil || resp.GetNetworkRulesApplied() || len(net.firewallCalls) != 0 {
		t.Fatalf("restore without rules: applied=%v firewall=%v err=%v", resp.GetNetworkRulesApplied(), net.firewallCalls, err)
	}
	req.SandboxNetwork = &vmdpb.SandboxNetworkConfig{Egress: &vmdpb.SandboxNetworkEgressConfig{
		AllowedCidrs: []string{"198.51.100.0/24"}, DeniedCidrs: []string{"0.0.0.0/0"},
	}}
	resp, err = a.RestoreSnapshot(context.Background(), req)
	if err != nil || !resp.GetNetworkRulesApplied() {
		t.Fatalf("restore with rules: applied=%v err=%v", resp.GetNetworkRulesApplied(), err)
	}
	// Adopted: the rules go in once more, for the proxy half a restart drops.
	if len(net.firewallCalls) != 1 || net.firewallCalls[0].allowedCIDRs[0] != "198.51.100.0/24" || net.firewallCalls[0].deniedCIDRs[0] != "0.0.0.0/0" {
		t.Fatalf("firewall calls = %+v; want the request's rules once", net.firewallCalls)
	}
}
