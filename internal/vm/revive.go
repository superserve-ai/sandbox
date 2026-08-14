package vm

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReviveVM cold-boots a sandbox whose VM died, from a salvaged copy of
// its own disk. The salvaged image carries the sandbox's identity (its
// boxd config, workspace, everything it wrote), so unlike a template
// clone nothing is re-injected: the guest boots as itself, on a fresh
// network slot. Residue of the dead VM (run dir, unit or cgroup,
// network slot) is force-torn-down first through the same path
// DestroyVM uses, so revive is safe on a zombie whose process is gone
// but whose slot state remains. The salvage is copied, never booted in
// place: a failed revive leaves it pristine for retry.
//
// The caller owns the control-plane side: the DB row flips to active
// only after this returns, and the ordinary auto-pause machinery then
// takes the revived sandbox through the standard pause path, which is
// what lands it paused with a fresh, uploaded generation.
func (m *Manager) ReviveVM(ctx context.Context, vmID, diskPath string, vcpu, memMiB uint32) (*VMInstance, error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	fi, err := os.Stat(diskPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path %q is not a regular file", diskPath)
	}
	// The whole revival transaction holds the VM's lifecycle lock:
	// without it, two concurrent revives for one id can interleave so
	// that the loser's teardown destroys the winner's freshly booted VM.
	// DestroyVM deliberately does not take this lock, so calling it
	// below cannot deadlock.
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Never revive over a live or healthy VM. The recorded status is
	// exactly what a zombie lies about (a dead VM's record still says
	// running), so liveness is probed from the process: a recorded
	// running VM whose Firecracker actually answers for this id is
	// alive and refused, while a record without a live process is the
	// zombie this exists for. A paused VM with its snapshot is healthy
	// at rest and refused too: resume owns that path, not revive.
	if inst, err := m.getInstance(vmID); err == nil {
		inst.mu.RLock()
		st, pid, snap := inst.Status, inst.PID, inst.SnapshotPath
		inst.mu.RUnlock()
		switch {
		case (st == StatusRunning || st == StatusCreating) && pidIsVMFirecracker(pid, vmID):
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s has a live process; revive only replaces dead VMs", vmID)
		case st == StatusPaused && snap != "":
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s is paused with a snapshot; resume owns healthy paused VMs", vmID)
		}
	}
	// Force-clear the zombie's residue. Fail closed on error: booting
	// over half-cleared state (a live unit, an occupied network slot)
	// is exactly the wedge class the teardown exists to prevent.
	if err := m.DestroyVM(ctx, vmID, true); err != nil {
		return nil, fmt.Errorf("clear residue: %w", err)
	}
	inst, err := m.coldBootFromRootfs(ctx, vmID, diskPath, vcpu, memMiB)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	ip := inst.IP
	inst.mu.RUnlock()
	// Revival is only real when the guest is: Firecracker accepting the
	// boot proves nothing about a corrupt or incompatible salvaged disk,
	// and reporting success on a wedged guest would flip the DB row to
	// active for a sandbox nobody can reach. On failure, tear the VM
	// back down so the retry starts clean and the salvage stays
	// pristine.
	if err := m.waitForBoxd(ctx, ip, reviveBoxdReadyBudget); err != nil {
		_ = m.DestroyVM(ctx, vmID, true)
		return nil, status.Errorf(codes.Unavailable, "guest did not become ready: %v", err)
	}
	// Durable record: reattach and the reconciler must know this VM
	// after a vmd restart, exactly like any created VM. A revival the
	// state store cannot record is not a revival: an unrecorded running
	// VM would be invisible to reconciliation and refused by the next
	// revive's liveness probe, so fail closed and tear down.
	if !m.persistState(inst) {
		_ = m.DestroyVM(ctx, vmID, true)
		return nil, status.Error(codes.Internal, "revived VM could not be durably recorded; torn down for clean retry")
	}
	return inst, nil
}

// reviveBoxdReadyBudget bounds the wait for a revived guest's boxd. Cold
// boots run full guest init (no warm memory image), so this is more
// generous than the resume budget.
const reviveBoxdReadyBudget = 90 * time.Second
