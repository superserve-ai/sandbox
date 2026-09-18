package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
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
	if snapshotPath == "" {
		snapshotPath = inst.SnapshotPath
	}
	if memPath == "" {
		memPath = inst.MemFilePath
	}
	disk := pausedDiskPath(m.cfg.RunDir, vmID, inst.DiskPath, inst.RunDirID, inst.Config.BasePath)
	return !pauseArtifactsPresent(snapshotPath, memPath, inst.BaseMemPath, disk, inst.Config.BasePath)
}

// backupRevivedTarget returns the live VM a backup-backed resume for the
// same recorded pause already booted, so a retry of that request adopts
// it instead of failing on artifacts the cold boot never had.
func (m *Manager) backupRevivedTarget(vmID, anchorKey string) *VMInstance {
	if anchorKey == "" {
		return nil
	}
	m.mu.RLock()
	existing := m.vms[vmID]
	m.mu.RUnlock()
	if existing == nil {
		return nil
	}
	existing.mu.RLock()
	match := existing.Status == StatusRunning && !existing.Unverified && existing.BackupAnchor == anchorKey
	existing.mu.RUnlock()
	if !match || vmDeadForRetry(m, vmID) {
		return nil
	}
	return existing
}

// backupFlight is one fetch of a sandbox's backup, shared by every resume
// attempt for the same recorded pause and detached from the RPC deadlines
// that observe it, so a retry picks the download up where it stands.
type backupFlight struct {
	anchorKey string
	done      chan struct{}
	restored  backup.Restored
	err       error
}

func (m *Manager) backupFlightFor(vmID, anchorKey string, anchor backup.CaptureAnchor, dest string) (*backupFlight, error) {
	m.backupFlightsMu.Lock()
	defer m.backupFlightsMu.Unlock()
	if f := m.backupFlights[vmID]; f != nil {
		if f.anchorKey != anchorKey {
			return nil, status.Errorf(codes.Aborted, "vm %s: a restore of a different pause is in flight", vmID)
		}
		return f, nil
	}
	f := &backupFlight{anchorKey: anchorKey, done: make(chan struct{})}
	m.backupFlights[vmID] = f
	go func() {
		defer sentrylog.Recover("backup-fetch")
		defer close(f.done)
		ctx, cancel := context.WithTimeout(context.Background(), m.backupRestore.FetchBudget)
		defer cancel()
		select {
		case m.backupFetchSem <- struct{}{}:
			defer func() { <-m.backupFetchSem }()
		case <-ctx.Done():
			f.err = ctx.Err()
			return
		}
		var reader backup.BlobReader = m.backupReader
		if m.backupRestore.Limiter != nil {
			reader = &backup.LimitedReader{Inner: reader, Limiter: m.backupRestore.Limiter}
		}
		cacheDir := m.backupBaseDir()
		reader = &backup.CachingBaseReader{Inner: reader, Dir: cacheDir}
		log := m.log.With().Str("vm_id", vmID).Logger()
		f.restored, f.err = backup.FetchMatching(ctx, reader, m.backupLister, vmID, anchor, dest, func(format string, args ...any) {
			log.Debug().Msgf(format, args...)
		})
		if m.backupRestore.CacheBytes > 0 {
			if _, perr := backup.PruneBaseCache(cacheDir, m.backupRestore.CacheBytes); perr != nil {
				log.Warn().Err(perr).Msg("backup base cache prune")
			}
		}
		m.sweepPromotedBases(cacheDir)
	}()
	return f, nil
}

func (m *Manager) backupBaseDir() string { return filepath.Join(m.backupRestoreRoot, ".base-cache") }

// promoteBase moves a base materialized inside the staging dir to a path
// that outlives it: the revived VM keeps reading the base for its whole
// life, and a later pause or resume must reopen it.
func (m *Manager) promoteBase(r *backup.Restored, dest string) error {
	if r.Base == "" || !strings.HasPrefix(r.Base, dest+string(filepath.Separator)) {
		return nil
	}
	if err := os.MkdirAll(m.backupBaseDir(), 0o700); err != nil {
		return err
	}
	stable := filepath.Join(m.backupBaseDir(), filepath.Base(r.Base))
	if _, err := os.Stat(stable); err != nil {
		if err := os.Rename(r.Base, stable); err != nil {
			return err
		}
	}
	r.Base = stable
	return nil
}

// sweepPromotedBases drops promoted bases no tracked VM reads any more.
func (m *Manager) sweepPromotedBases(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	inUse := map[string]bool{}
	m.mu.RLock()
	for _, inst := range m.vms {
		inst.mu.RLock()
		inUse[inst.Config.BasePath] = true
		inst.mu.RUnlock()
	}
	m.mu.RUnlock()
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "base-") || !strings.HasSuffix(e.Name(), ".ext4") {
			continue
		}
		if path := filepath.Join(dir, e.Name()); !inUse[path] {
			_ = os.Remove(path)
		}
	}
}

func (m *Manager) backupFlightDone(vmID string, f *backupFlight) {
	m.backupFlightsMu.Lock()
	if m.backupFlights[vmID] == f {
		delete(m.backupFlights, vmID)
	}
	m.backupFlightsMu.Unlock()
}

// resumeFromBackupLocked brings a paused sandbox back from the bucket
// generation that carries the pause the control plane recorded, when the
// pause artifacts are gone from the host. Backups hold the disk and not
// the memory, so the sandbox boots cold with its files intact. The fetch
// runs on its own budget; a caller whose deadline expires first gets
// Unavailable and its retry joins the same fetch.
func (m *Manager) resumeFromBackupLocked(ctx context.Context, vmID string, anchor backup.CaptureAnchor, rules *sandboxNetworkRules) (*VMInstance, error) {
	if len(anchor) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host and the pause has no recorded digests to match a backup against", vmID)
	}
	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	teamID, ownerID, vcpu, memMiB := inst.TeamID, inst.OwnerID, inst.Config.VCPU, inst.Config.MemoryMiB
	inst.mu.RUnlock()
	if err := os.MkdirAll(m.backupRestoreRoot, 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "restore root: %v", err)
	}
	anchorKey := backup.AnchorKey(anchor)
	dest := filepath.Join(m.backupRestoreRoot, vmID)
	tFetch := time.Now()
	flight, err := m.backupFlightFor(vmID, anchorKey, anchor, dest)
	if err != nil {
		return nil, err
	}
	select {
	case <-flight.done:
	case <-ctx.Done():
		return nil, status.Errorf(codes.Unavailable, "vm %s: backup restore in progress; retry", vmID)
	}
	m.backupFlightDone(vmID, flight)
	m.recordPhases("resume", "backup", map[string]time.Duration{"backup_fetch": time.Since(tFetch)})
	if flight.err != nil {
		if errors.Is(flight.err, backup.ErrNoMatchingBackup) {
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host and no backup carries the recorded pause", vmID)
		}
		return nil, status.Errorf(codes.Unavailable, "vm %s: fetch backup: %v", vmID, flight.err)
	}
	r := flight.restored
	if err := m.promoteBase(&r, dest); err != nil {
		return nil, status.Errorf(codes.Internal, "vm %s: keep restored base: %v", vmID, err)
	}
	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Str("generation", r.Manifest.Generation).Dur("fetch", time.Since(tFetch)).
		Msg("resume: pause artifacts missing on host; reviving from backup")
	tBoot := time.Now()
	revived, err := m.reviveVMLocked(ctx, vmID, r.Disk, r.Base, r.Standalone, false, teamID, ownerID, vcpu, memMiB, rules)
	m.recordPhases("resume", "backup", map[string]time.Duration{"backup_boot": time.Since(tBoot)})
	if err != nil {
		return nil, err
	}
	revived.mu.Lock()
	revived.BackupAnchor = anchorKey
	revived.mu.Unlock()
	_, _ = m.persistStateIfPresent(revived)
	_ = os.RemoveAll(dest)
	return revived, nil
}
