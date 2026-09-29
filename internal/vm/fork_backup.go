package vm

import (
	"context"
	"errors"
	"os"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// savedSnapshotFilesMissing reports whether a fork of the saved snapshot
// would fail on a file this host no longer has.
func (m *Manager) savedSnapshotFilesMissing(snapshotID string) bool {
	dir, err := m.savedSnapshotDir(snapshotID)
	if err != nil {
		return false
	}
	man, err := readSavedSnapshotManifest(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	missing := func(path string) bool { return path != "" && !statRegularFile(path) }
	return !statRegularFile(man.DiskPath) || missing(man.BasePath) ||
		(man.SnapshotPath != "" && (!statRegularFile(man.SnapshotPath) || !statRegularFile(man.MemPath) || missing(man.BaseMemPath)))
}

// forkAlreadyBooted reports a fork of the snapshot already running as vmID,
// whose retry the ordinary restore adopts.
func (m *Manager) forkAlreadyBooted(vmID, snapshotID string) bool {
	m.lazyReattach(vmID)
	existing, _ := m.retriedForkTarget(vmID, snapshotID)
	return existing != nil
}

func savedSnapshotMissingErr(snapshotID string) error {
	st := status.Newf(codes.FailedPrecondition, "saved snapshot %s: files missing on host; retry with its backup generation", snapshotID)
	if withInfo, err := st.WithDetails(&errdetails.ErrorInfo{Reason: vmdclient.SavedSnapshotMissingReason, Domain: "vmd"}); err == nil {
		return withInfo.Err()
	}
	return st.Err()
}

// forkFromBackup creates a VM from a saved snapshot whose files are gone
// from this host by cold booting the disk its backup holds. Backups carry no
// memory, so the VM starts fresh with the snapshot's files.
func (m *Manager) forkFromBackup(ctx context.Context, vmID, generation string, cfg VMConfig, teamID, ownerID, previewAccess string, previewPorts map[int32]PreviewPortPolicy, previewPolicyRevision int64) (*VMInstance, error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Errorf(codes.InvalidArgument, "vm_id %q must be a valid per-VM identifier", vmID)
	}
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if inst, err := m.getInstance(vmID); err == nil {
		inst.mu.RLock()
		running := inst.Status == StatusRunning && !inst.Unverified
		ours := inst.SourceSnapshotID == cfg.SavedSnapshotID && inst.BackupGeneration == generation
		inst.mu.RUnlock()
		switch {
		case running && ours && !vmDeadForRetry(m, vmID):
			// A retry of a fork that booted: adopt it.
			if cfg.EgressRules != nil && !m.applyAdoptedNetworkRules(vmID, cfg.EgressRules) {
				return nil, status.Errorf(codes.Unavailable, "fork adopted vm %s but could not reinstall its egress rules", vmID)
			}
			return inst, nil
		case running:
			return nil, status.Errorf(codes.AlreadyExists, "vm %s is already running", vmID)
		}
		// What a failed attempt left behind.
		if err := m.DestroyVM(ctx, vmID, true); err != nil {
			return nil, err
		}
	}
	r, release, err := m.fetchBackup(ctx, "restore", vmID, backup.SnapshotOwner(cfg.SavedSnapshotID), generation)
	if err != nil {
		return nil, err
	}
	defer release()
	m.log.Info().Str("vm_id", vmID).Str("saved_snapshot_id", cfg.SavedSnapshotID).Str("generation", generation).
		Msg("fork: saved snapshot missing on host; cold booting its backup")
	tBoot := time.Now()
	seed := func(inst *VMInstance) {
		inst.Unverified = true
		inst.BackupGeneration = generation
		inst.SourceSnapshotID = cfg.SavedSnapshotID
		inst.TeamID, inst.OwnerID = teamID, ownerID
		inst.PreviewAccess = previewAccess
		inst.PreviewPorts = clonePreviewPorts(previewPorts)
		inst.PreviewPolicyRevision = previewPolicyRevision
		inst.PreviewTokenPolicyRevision = inferPreviewTokenPolicyRevision(previewPorts, previewPolicyRevision)
	}
	inst, err := m.coldBootFromRootfs(ctx, vmID, r.Disk, r.Base, r.BlockMap, cfg.EgressRules, seed, nil, true, SupervisionUnit, cfg.VCPU, cfg.MemoryMiB)
	if err == nil {
		inst.mu.RLock()
		ip := inst.IP
		inst.mu.RUnlock()
		if werr := m.waitForBoxd(ctx, ip, reviveBoxdReadyBudget); werr != nil {
			_ = m.DestroyVM(context.WithoutCancel(ctx), vmID, true)
			err = status.Errorf(codes.Unavailable, "guest did not become ready: %v", werr)
		}
	}
	m.recordPhases("restore", "backup", map[string]time.Duration{"backup_boot": time.Since(tBoot)})
	if err != nil {
		if ctx.Err() != nil {
			// The download is done and the caller's retry is imminent.
			m.retainStagingForRetry(vmID)
			return nil, err
		}
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		return nil, err
	}
	inst.mu.Lock()
	inst.Unverified = false
	inst.mu.Unlock()
	if !m.persistState(inst) {
		_ = m.DestroyVM(context.WithoutCancel(ctx), vmID, true)
		return nil, status.Error(codes.Internal, "forked VM could not be durably recorded; torn down for clean retry")
	}
	_ = os.RemoveAll(m.restoreStagingDir(vmID))
	return inst, nil
}
