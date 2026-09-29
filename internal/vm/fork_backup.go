package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// savedSnapshotFilesMissing reports whether a fork of the snapshot man
// describes would fail on a file this host no longer has.
func savedSnapshotFilesMissing(man *SavedSnapshotManifest) bool {
	missing := func(path string) bool { return path != "" && !statRegularFile(path) }
	return !statRegularFile(man.DiskPath) || missing(man.BasePath) ||
		(man.SnapshotPath != "" && (!statRegularFile(man.SnapshotPath) || !statRegularFile(man.MemPath) || missing(man.BaseMemPath)))
}

func savedSnapshotMissingErr(snapshotID string) error {
	st := status.Newf(codes.FailedPrecondition, "saved snapshot %s: files missing on host; retry with its backup generation", snapshotID)
	if withInfo, err := st.WithDetails(&errdetails.ErrorInfo{Reason: vmdclient.SavedSnapshotMissingReason, Domain: "vmd"}); err == nil {
		return withInfo.Err()
	}
	return st.Err()
}

// backupForkTracked reports a VM this host booted, or is booting, from the
// snapshot's backup as vmID. The caller has loaded the VM's record.
func (m *Manager) backupForkTracked(vmID, snapshotID string) bool {
	m.mu.RLock()
	inst := m.vms[vmID]
	m.mu.RUnlock()
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.SourceSnapshotID == snapshotID && inst.BackupGeneration != ""
}

// adoptBackupFork returns the live VM a fork from the snapshot's backup
// already booted as vmID, with its egress rules reinstalled. Nil when there
// is none. The caller holds the VM's op lock, so the boot has committed.
func (m *Manager) adoptBackupFork(vmID, snapshotID, generation string, rules *sandboxNetworkRules) (*VMInstance, error) {
	m.lazyReattach(vmID)
	m.mu.RLock()
	inst := m.vms[vmID]
	m.mu.RUnlock()
	if inst == nil {
		return nil, nil
	}
	inst.mu.RLock()
	ours := inst.Status == StatusRunning && !inst.Unverified && inst.SourceSnapshotID == snapshotID &&
		inst.BackupGeneration != "" && (generation == "" || inst.BackupGeneration == generation)
	inst.mu.RUnlock()
	if !ours || vmDeadForRetry(m, vmID) {
		return nil, nil
	}
	if rules != nil && !m.applyAdoptedNetworkRules(vmID, rules) {
		return nil, status.Errorf(codes.Unavailable, "fork adopted vm %s but could not reinstall its egress rules", vmID)
	}
	return inst, nil
}

// forkFromBackup creates a VM from a saved snapshot whose files are gone
// from this host by cold booting the disk its backup holds. Backups carry no
// memory, so the VM starts fresh with the snapshot's files. A destroy that
// lands at any point wins, as it does over a revival.
func (m *Manager) forkFromBackup(ctx context.Context, vmID, generation string, cfg VMConfig, teamID, ownerID, previewAccess string, previewPorts map[int32]PreviewPortPolicy, previewPolicyRevision int64) (*VMInstance, error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Errorf(codes.InvalidArgument, "vm_id %q must be a valid per-VM identifier", vmID)
	}
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if inst, err := m.adoptBackupFork(vmID, cfg.SavedSnapshotID, generation, cfg.EgressRules); inst != nil || err != nil {
		return inst, err
	}
	if generation == "" {
		return nil, savedSnapshotMissingErr(cfg.SavedSnapshotID)
	}
	if !m.BackupRestoreEnabled() {
		return nil, status.Errorf(codes.Unavailable, "vm %s: backup restore is off on this host", vmID)
	}
	// Own teardowns release nothing until the VM is confirmed exited, since a
	// stop can return while the unit is still deactivating. They keep the
	// staged download for the retry and are counted, so only someone else's
	// destroy, from here on, reads as one.
	epoch := m.destroyEpoch(vmID)
	selfDestroys := uint64(0)
	teardown := func(c context.Context) error {
		c, cancel := context.WithTimeout(context.WithoutCancel(c), reviveTeardownBudget)
		defer cancel()
		if err := m.stopLeftoverLife(c, vmID); err != nil || !m.vmConfirmedAtRest(c, vmID) {
			m.setStatus(vmID, StatusError)
			m.vmStopUnconfirmed.Store(vmID, struct{}{})
			return status.Errorf(codes.Unavailable, "vm %s is not confirmed stopped (%v); left for a forced destroy", vmID, err)
		}
		if err := m.DestroyVM(context.WithValue(c, reviveTeardownCtxKey{}, true), vmID, true); err != nil {
			return err
		}
		selfDestroys++
		return nil
	}
	destroyed := func() error {
		if m.destroyEpoch(vmID) != epoch+selfDestroys {
			return status.Errorf(codes.Aborted, "vm %s was destroyed while its fork was starting; the destroy is authoritative", vmID)
		}
		return nil
	}
	inst, instErr := m.getInstance(vmID)
	if instErr == nil {
		inst.mu.RLock()
		running := inst.Status == StatusRunning && !inst.Unverified
		inst.mu.RUnlock()
		if running {
			return nil, status.Errorf(codes.AlreadyExists, "vm %s is already running", vmID)
		}
	}
	// What a failed attempt left behind. A life this daemon lost before
	// recording it may still run on the disk the boot replaces.
	if _, dirErr := os.Stat(filepath.Join(m.cfg.RunDir, vmID)); instErr == nil || !errors.Is(dirErr, os.ErrNotExist) {
		if err := teardown(ctx); err != nil {
			return nil, err
		}
	}
	if err := destroyed(); err != nil {
		return nil, err
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
	inst = nil
	err = destroyed()
	if err == nil {
		inst, err = m.coldBootFromRootfs(ctx, vmID, r.Disk, r.Base, r.BlockMap, cfg.EgressRules, seed, destroyed, true, SupervisionUnit, cfg.VCPU, cfg.MemoryMiB)
	}
	if err == nil {
		inst.mu.RLock()
		ip := inst.IP
		inst.mu.RUnlock()
		if werr := m.waitForBoxd(ctx, ip, reviveBoxdReadyBudget); werr != nil {
			err = status.Errorf(codes.Unavailable, "guest did not become ready: %v", werr)
			if terr := teardown(ctx); terr != nil {
				err = status.Errorf(codes.Internal, "guest did not become ready (%v): %v", werr, terr)
			}
		}
	}
	m.recordPhases("restore", "backup", map[string]time.Duration{"backup_boot": time.Since(tBoot)})
	if err != nil {
		if ctx.Err() != nil && destroyed() == nil {
			// The download is done and the caller's retry is imminent.
			m.retainStagingForRetry(vmID)
			return nil, err
		}
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		return nil, err
	}
	// The verified record is written only if no destroy got in first;
	// DestroyVM holds the record-owner lock for its whole run.
	inst.mu.Lock()
	inst.Unverified = false
	inst.mu.Unlock()
	unlockCommit := m.lockRecordOwner(vmID)
	m.mu.RLock()
	_, tracked := m.vms[vmID]
	m.mu.RUnlock()
	_, destroying := m.destroying.Load(vmID)
	if !tracked || destroying || destroyed() != nil {
		unlockCommit()
		_ = teardown(ctx)
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		return nil, status.Errorf(codes.Aborted, "vm %s was destroyed while its fork was completing", vmID)
	}
	wrote := m.persistState(inst)
	unlockCommit()
	if !wrote {
		_ = teardown(ctx)
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		return nil, status.Error(codes.Internal, "forked VM could not be durably recorded; torn down for clean retry")
	}
	_ = os.RemoveAll(m.restoreStagingDir(vmID))
	return inst, nil
}
