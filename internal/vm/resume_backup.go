package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// pausedDiskPath is the disk a paused record boots from: recorded, or
// inferred from the run directory exactly as resume infers it.
func pausedDiskPath(runDir, vmID, diskPath, runDirID, basePath string) string {
	if diskPath != "" {
		return diskPath
	}
	key := vmID
	if runDirID != "" {
		key = runDirID
	}
	name := "rootfs.ext4"
	if basePath != "" {
		name = "overlay.ext4"
	}
	return filepath.Join(runDir, key, name)
}

// pauseArtifactsPresent reports whether every file a resume needs still
// exists; the memory base and the disk base only count when recorded.
func pauseArtifactsPresent(snap, mem, baseMem, disk, base string) bool {
	return statRegularFile(snap) && mem != "" && statRegularFile(mem) &&
		(baseMem == "" || statRegularFile(baseMem)) &&
		statRegularFile(disk) && (base == "" || statRegularFile(base))
}

// pauseArtifactsMissing is true for a paused record whose resume would
// fail on a file the host no longer has.
func (m *Manager) pauseArtifactsMissing(vmID, snapshotPath, memPath string) bool {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused {
		return false
	}
	disk := pausedDiskPath(m.cfg.RunDir, vmID, inst.DiskPath, inst.RunDirID, inst.Config.BasePath)
	return !pauseArtifactsPresent(snapshotPath, memPath, inst.BaseMemPath, disk, inst.Config.BasePath)
}

// resumeFromBackupLocked brings a paused sandbox back from its newest
// bucket generation when the pause artifacts are gone from the host. The
// backup holds the disk, not the memory, so the sandbox boots cold with
// its files intact; the revive copies the disk, so the staging dir is
// dropped afterwards either way.
func (m *Manager) resumeFromBackupLocked(ctx context.Context, vmID string, rules *sandboxNetworkRules) (*VMInstance, error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	teamID, ownerID, vcpu, memMiB := inst.TeamID, inst.OwnerID, inst.Config.VCPU, inst.Config.MemoryMiB
	inst.mu.RUnlock()

	dest := filepath.Join(m.backupRestoreRoot, vmID)
	if err := os.RemoveAll(dest); err != nil {
		return nil, status.Errorf(codes.Internal, "clear restore dir: %v", err)
	}
	if err := os.MkdirAll(m.backupRestoreRoot, 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "restore root: %v", err)
	}
	defer os.RemoveAll(dest)

	log := m.log.With().Str("vm_id", vmID).Logger()
	start := time.Now()
	reader := &backup.CachingBaseReader{Inner: m.backupReader, Dir: filepath.Join(m.backupRestoreRoot, ".base-cache")}
	r, err := backup.FetchNewest(ctx, reader, m.backupLister, vmID, dest, func(format string, args ...any) {
		log.Debug().Msgf(format, args...)
	})
	if err != nil {
		if errors.Is(err, backup.ErrNoBackup) {
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host and no backup in the bucket", vmID)
		}
		return nil, status.Errorf(codes.Unavailable, "vm %s: fetch backup: %v", vmID, err)
	}
	log.Info().Str("generation", r.Manifest.Generation).Dur("fetch", time.Since(start)).
		Msg("resume: pause artifacts missing on host; reviving from backup")
	return m.reviveVMLocked(ctx, vmID, r.Disk, r.Base, r.Standalone, false, teamID, ownerID, vcpu, memMiB, rules)
}
