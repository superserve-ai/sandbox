package vm

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
)

// Firecracker refuses more vCPUs than this; checked before the teardown,
// which a boot-time refusal would otherwise follow.
const (
	reshapeMaxVCPU   = 32
	reshapeMinMemMiB = 128
)

// ReshapeVM cold-boots a paused sandbox from its own disk at a new vCPU
// count and memory size. A snapshot only restores at the shape it was
// taken, so memory and processes are lost and files survive.
//
// The disk and block map are staged outside the run directory first,
// because the revival teardown removes it. A failed boot leaves the
// sandbox paused with its artifacts gone and the staged copy in place;
// a retry boots from that copy, including after a vmd restart.
//
// rules is required: the host does not record egress policy, so a nil
// policy would bring a restricted sandbox back open.
func (m *Manager) ReshapeVM(ctx context.Context, vmID string, vcpu, memMiB uint32, rules *sandboxNetworkRules) (*VMInstance, error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	if vcpu == 0 || vcpu > reshapeMaxVCPU {
		return nil, status.Errorf(codes.InvalidArgument, "vcpu must be between 1 and %d", reshapeMaxVCPU)
	}
	if memMiB < reshapeMinMemMiB {
		return nil, status.Errorf(codes.InvalidArgument, "mem_mib must be at least %d", reshapeMinMemMiB)
	}
	if rules == nil {
		return nil, status.Error(codes.InvalidArgument, "egress policy is required")
	}
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	var (
		st                       VMStatus
		unverified               bool
		curVCPU, curMem          uint32
		snap, mem, baseMem, base string
		teamID, ownerID          string
		disk, revivedDisk        string
	)
	stageDir := m.reshapeStageDir(vmID)
	inst, ierr := m.getInstance(vmID)
	if ierr == nil {
		inst.mu.RLock()
		st, unverified = inst.Status, inst.Unverified
		curVCPU, curMem = inst.Config.VCPU, inst.Config.MemoryMiB
		snap, mem, baseMem, base = inst.SnapshotPath, inst.MemFilePath, inst.BaseMemPath, inst.Config.BasePath
		teamID, ownerID, revivedDisk = inst.TeamID, inst.OwnerID, inst.RevivedDisk
		netInfo := &network.VMNetInfo{HostIP: inst.IP, TAPDevice: inst.TAPDevice, Namespace: inst.Namespace}
		inst.mu.RUnlock()
		disk = m.instanceDiskPath(inst)

		// A retry after a lost response finds its own work done: a live VM
		// at the target shape that booted from this sandbox's staged disk.
		// Policy is reapplied: a vmd restart in between reattaches the VM
		// without it, and a retry may carry a corrected policy.
		if st == StatusRunning && !unverified && curVCPU == vcpu && curMem == memMiB &&
			filepath.Dir(revivedDisk) == stageDir && !m.vmConfirmedAtRest(ctx, vmID) {
			// DestroyVM bypasses the op lock but holds the record-owner lock
			// for its whole run; holding it across the reapply keeps a
			// destroy from recycling the slot under these rules.
			unlockOwner := m.lockRecordOwner(vmID)
			defer unlockOwner()
			m.mu.RLock()
			_, tracked := m.vms[vmID]
			m.mu.RUnlock()
			if _, destroying := m.destroying.Load(vmID); !tracked || destroying {
				return nil, status.Errorf(codes.Aborted, "vm %s was destroyed during the reshape retry", vmID)
			}
			if err := m.applySandboxNetworkRules(vmID, netInfo, rules); err != nil {
				return nil, status.Errorf(codes.Internal, "reapply network rules on idempotent reshape: %v", err)
			}
			// A crash after the commit skips the normal cleanup; the staged
			// clone would pin the pre-reshape disk for the sandbox's life.
			_ = os.RemoveAll(stageDir)
			return inst, nil
		}
	}

	if ierr != nil || st == StatusError {
		// A failed or interrupted attempt leaves the durable record as the
		// anchor (marked RevivalPending) and the staged disk beside it.
		rec, gerr := m.stateRecord(vmID)
		if gerr != nil || !rec.RevivalPending {
			if ierr != nil {
				return nil, ierr
			}
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s must be paused to reshape", vmID)
		}
		st, snap, base, teamID, ownerID = StatusPaused, rec.SnapshotPath, rec.BasePath, rec.TeamID, rec.OwnerID
		curVCPU, curMem = rec.VCPU, rec.MemoryMiB
		mem, disk = "", ""
	}
	if st != StatusPaused || snap == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s must be paused to reshape", vmID)
	}

	diskName := "rootfs.ext4"
	if base != "" {
		diskName = "overlay.ext4"
	}
	stagedDisk := filepath.Join(stageDir, diskName)
	stagedMap := ""
	start := time.Now()
	if mem != "" && pauseArtifactsPresent(snap, mem, baseMem, disk, base) {
		// A pause whose stop was never confirmed still records Paused; a
		// clone taken while the guest may still write would boot torn.
		if !m.vmConfirmedAtRest(ctx, vmID) {
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s is not confirmed at rest; its disk cannot be staged", vmID)
		}
		// The paused disk is authoritative; any copy left by an earlier
		// failed attempt predates it and is replaced.
		if err := os.RemoveAll(stageDir); err != nil {
			return nil, status.Errorf(codes.Internal, "clear reshape staging: %v", err)
		}
		if err := os.MkdirAll(stageDir, 0o700); err != nil {
			return nil, status.Errorf(codes.Internal, "reshape staging: %v", err)
		}
		if err := syncDir(filepath.Dir(stageDir)); err != nil {
			return nil, status.Errorf(codes.Internal, "reshape staging: %v", err)
		}
		if err := stageReshapeFile(ctx, disk, stagedDisk); err != nil {
			return nil, status.Errorf(codes.Internal, "stage disk: %v", err)
		}
		if blockMap := overlayBlockMapPath(snap); base != "" && statRegularFile(blockMap) {
			stagedMap = filepath.Join(stageDir, filepath.Base(blockMap))
			if err := stageReshapeFile(ctx, blockMap, stagedMap); err != nil {
				return nil, status.Errorf(codes.Internal, "stage block map: %v", err)
			}
		}
	} else if statRegularFile(stagedDisk) {
		if p := filepath.Join(stageDir, filepath.Base(overlayBlockMapPath(snap))); base != "" && statRegularFile(p) {
			stagedMap = p
		}
	} else {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s has neither its pause artifacts nor a staged reshape disk", vmID)
	}

	staged := time.Since(start)
	revived, err := m.reviveVMLocked(ctx, vmID, stagedDisk, base, stagedMap, false, false, true, teamID, ownerID, vcpu, memMiB, rules, "")
	if err != nil {
		// Revival put the paused record back; memory must follow it or
		// the retry finds no paused VM to boot from.
		m.restorePausedAnchor(vmID)
		return nil, err
	}
	_ = os.RemoveAll(stageDir)
	m.log.Info().Str("vm_id", vmID).
		Uint32("from_vcpu", curVCPU).Uint32("from_mem_mib", curMem).
		Uint32("vcpu", vcpu).Uint32("mem_mib", memMiB).
		Dur("staging", staged).
		Dur("total", time.Since(start)).
		Msg("sandbox reshaped")
	return revived, nil
}

// reshapeStageDir is where a reshape stages the disk it boots. Resolved
// like revive resolves the disk it records, so the live VM's RevivedDisk
// can be matched against it.
func (m *Manager) reshapeStageDir(vmID string) string {
	root := m.cfg.SnapshotDir
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	return filepath.Join(root, vmID, "reshape")
}

// stateRecord reads vmID's durable record directly: the on-demand loader
// parks a record whose revival is pending while this caller holds the op
// lock.
func (m *Manager) stateRecord(vmID string) (*VMRecord, error) {
	if m.state == nil {
		return nil, status.Error(codes.NotFound, "no state store")
	}
	rec, err := m.state.Get(vmID)
	if err != nil || rec == nil {
		return nil, status.Errorf(codes.NotFound, "vm %s has no durable record", vmID)
	}
	return rec, nil
}

// stageReshapeFile reflinks src to dst through a temporary name, so a
// crash mid-copy never leaves a partial file under the name a retry boots.
// The copy is synced before it is named: the revival teardown deletes the
// source next, and after a power loss the copy is all a retry has.
func stageReshapeFile(ctx context.Context, src, dst string) error {
	tmp := dst + ".tmp"
	if err := reflinkFileExact(ctx, src, tmp); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}
