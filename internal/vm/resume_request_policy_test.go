package vm

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// slotNetMgr is fakeNetMgr with a live slot, so egress rules can land.
type slotNetMgr struct {
	fakeNetMgr
	info *network.VMNetInfo
}

func (s *slotNetMgr) GetVMNetInfo(string) *network.VMNetInfo { return s.info }

func runningForAdoption(t *testing.T) *VMInstance {
	t.Helper()
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	t.Cleanup(func() { vmDeadForRetry = orig })
	return &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
}

// A retried resume that adopts the running VM applies the request's egress
// rules again and reports it, since the proxy's copy does not survive a
// daemon restart. Without a slot to hang the proxy rules on it reports
// nothing applied, so the caller pushes them itself.
func TestResumeVM_AdoptionAppliesRequestRules(t *testing.T) {
	rules := &sandboxNetworkRules{allowedCIDRs: []string{"10.0.0.0/8"}}

	t.Run("no rules", func(t *testing.T) {
		existing := runningForAdoption(t)
		mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}
		inst, applied, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
		if err != nil || inst != existing || !applied {
			t.Fatalf("got inst=%v applied=%v err=%v, want the existing VM with nothing left to apply", inst == existing, applied, err)
		}
	})
	t.Run("slot present", func(t *testing.T) {
		existing := runningForAdoption(t)
		net := &slotNetMgr{info: &network.VMNetInfo{HostIP: "10.11.0.5"}}
		mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}, netMgr: net}
		_, applied, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", rules)
		if err != nil || !applied {
			t.Fatalf("applied=%v err=%v, want the rules applied on adoption", applied, err)
		}
		if len(net.firewallCalls) != 1 || net.firewallCalls[0].vmID != "vm-1" || len(net.firewallCalls[0].allowedCIDRs) != 1 {
			t.Fatalf("firewall calls = %+v, want one for vm-1 with the request's CIDR", net.firewallCalls)
		}
	})
	t.Run("slot missing", func(t *testing.T) {
		existing := runningForAdoption(t)
		net := &fakeNetMgr{}
		mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}, netMgr: net}
		inst, applied, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", rules)
		if err != nil || inst != existing {
			t.Fatalf("adoption must still return the VM, got inst=%v err=%v", inst == existing, err)
		}
		if applied {
			t.Fatal("rules cannot be fully applied without a slot for the proxy half; must not be reported applied")
		}
	})
}

// The resume RPC stamps the request's policy on the record before the
// guest runs and attests it; a request without one leaves the record alone
// and attests nothing; an unknown access mode is refused before anything.
func TestGRPCAdapterResumeVM_StampsAndAttestsPolicy(t *testing.T) {
	origProbe := boxdHealthProbe
	boxdHealthProbe = func(context.Context, string, time.Duration) error { return nil }
	t.Cleanup(func() { boxdHealthProbe = origProbe })

	newAdapter := func(t *testing.T) (*GRPCAdapter, *VMInstance) {
		existing := runningForAdoption(t)
		// The readiness gate re-checks IP ownership: a Running record and a live slot.
		store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		if err := store.Put(VMRecord{ID: existing.ID, Status: StatusRunning, IP: existing.IP}); err != nil {
			t.Fatal(err)
		}
		mgr := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": existing}, netMgr: &slotNetMgr{info: &network.VMNetInfo{HostIP: existing.IP}}}
		return &GRPCAdapter{mgr: mgr}, existing
	}

	t.Run("unknown access refused", func(t *testing.T) {
		a, _ := newAdapter(t)
		_, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{VmId: "vm-1", PreviewAccess: "sideways"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
	})
	t.Run("policy stamped and attested", func(t *testing.T) {
		a, existing := newAdapter(t)
		resp, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{
			VmId: "vm-1", PreviewAccess: preview.AccessPublic, PreviewPolicyRevision: 3,
			PreviewPorts: []*vmdpb.PreviewPort{{Port: 3000, Access: preview.AccessPublic}},
		})
		if err != nil {
			t.Fatalf("ResumeVM: %v", err)
		}
		if resp.GetPreviewProtocol() != preview.HostCapabilityPorts {
			t.Fatalf("preview_protocol = %q, want %q", resp.GetPreviewProtocol(), preview.HostCapabilityPorts)
		}
		if resp.GetPreviewPolicyRevision() != 3 {
			t.Fatalf("preview_policy_revision = %d, want the request's 3", resp.GetPreviewPolicyRevision())
		}
		if !resp.GetNetworkRulesApplied() {
			t.Fatal("a request without rules must report nothing left to apply")
		}
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.PreviewPolicyRevision != 3 || existing.PreviewAccess != preview.AccessPublic || existing.PreviewPorts[3000].Access != preview.AccessPublic {
			t.Fatalf("record policy = %q rev %d ports %+v, want the request's", existing.PreviewAccess, existing.PreviewPolicyRevision, existing.PreviewPorts)
		}
	})
	t.Run("record already newer keeps its policy and reports it", func(t *testing.T) {
		a, existing := newAdapter(t)
		existing.PreviewAccess, existing.PreviewPolicyRevision = preview.AccessPrivate, 5
		resp, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{
			VmId: "vm-1", PreviewAccess: preview.AccessPublic, PreviewPolicyRevision: 3,
		})
		if err != nil {
			t.Fatalf("ResumeVM: %v", err)
		}
		if resp.GetPreviewProtocol() != preview.HostCapabilityPorts || resp.GetPreviewPolicyRevision() != 5 {
			t.Fatalf("attestation = %q rev %d, want attested at the record's 5", resp.GetPreviewProtocol(), resp.GetPreviewPolicyRevision())
		}
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.PreviewAccess != preview.AccessPrivate || existing.PreviewPolicyRevision != 5 {
			t.Fatalf("record policy = %q rev %d, want the newer one kept", existing.PreviewAccess, existing.PreviewPolicyRevision)
		}
	})
	t.Run("no policy carried", func(t *testing.T) {
		a, existing := newAdapter(t)
		resp, err := a.ResumeVM(context.Background(), &vmdpb.ResumeVMRequest{VmId: "vm-1"})
		if err != nil {
			t.Fatalf("ResumeVM: %v", err)
		}
		if resp.GetPreviewProtocol() != "" {
			t.Fatalf("preview_protocol = %q, want none without a policy in the request", resp.GetPreviewProtocol())
		}
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.PreviewPolicyRevision != 0 || existing.PreviewAccess != "" {
			t.Fatalf("record policy changed to %q rev %d without a policy in the request", existing.PreviewAccess, existing.PreviewPolicyRevision)
		}
	})
}
