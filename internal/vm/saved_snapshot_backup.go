package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// SavedSnapshotBackupSweep is how often committed saved snapshots are checked
// for a backup that was never queued, or was lost with the journal.
const SavedSnapshotBackupSweep = 30 * time.Minute

// savedSnapshotHashSlots keeps a burst of captures from saturating the disk,
// apart from the pause rehash slots so snapshots never delay a pause's backup.
var savedSnapshotHashSlots = make(chan struct{}, 1)

// SnapshotBackupCapability is the string a vmd that reads saved-snapshot
// backup queue entries carries; the host guard greps the binary for it.
const SnapshotBackupCapability = "snapshot-backup-1"

// snapshotBackupEvidencePath is made durable before the first saved-snapshot
// entry is queued; from then on the host guard refuses a vmd that cannot read one.
var snapshotBackupEvidencePath = "/var/lib/sandbox/snapshot-backup-evidence"

const snapshotBackupEvidenceNote = "this host has queued saved snapshot backups\n"

var (
	snapshotBackupEvidenceDurable atomic.Bool
	snapshotBackupEvidenceMu      sync.Mutex
)

// ensureSnapshotBackupFloor is durable once, then free.
func ensureSnapshotBackupFloor() error {
	if snapshotBackupEvidenceDurable.Load() {
		return nil
	}
	snapshotBackupEvidenceMu.Lock()
	defer snapshotBackupEvidenceMu.Unlock()
	if snapshotBackupEvidenceDurable.Load() {
		return nil
	}
	if _, err := os.Stat(snapshotBackupEvidencePath); err == nil {
		// Visible, but not proven durable by this process.
		if err := syncDir(filepath.Dir(snapshotBackupEvidencePath)); err != nil {
			return err
		}
	} else if err := raiseEvidenceFile(snapshotBackupEvidencePath, snapshotBackupEvidenceNote); err != nil {
		return err
	}
	snapshotBackupEvidenceDurable.Store(true)
	return nil
}

// savedSnapshotBackupMarker records, in a saved snapshot's directory, the
// generation its disk was queued as, so a sweep learns whether the backup is
// pending or done without hashing the disk again.
const savedSnapshotBackupMarker = "backup.generation"

// backupSavedSnapshot hashes a committed saved snapshot's disk, with the
// block map saved beside it, and queues them for upload. Memory stays on the
// host, as it does for pauses. Reports whether the disk is queued or backed up.
func (m *Manager) backupSavedSnapshot(ctx context.Context, man *SavedSnapshotManifest, log zerolog.Logger) bool {
	if m.backupEnqueue == nil {
		return false
	}
	select {
	case savedSnapshotHashSlots <- struct{}{}:
		defer func() { <-savedSnapshotHashSlots }()
	case <-ctx.Done():
		return false
	}
	files := make([]backup.TaskFile, 0, 2)
	add := func(name, path, basePath string) error {
		sum, size, err := backup.HashFileApparent(ctx, path)
		// A saved snapshot's files are next read only at upload; keeping
		// them cached would evict pages paused sandboxes resume from.
		_ = backup.DropPageCache(path)
		if err != nil {
			return err
		}
		f := backup.TaskFile{Name: name, Path: path, SHA256: sum, Size: size, BasePath: basePath}
		if v, ok := allocatedBytes(path); ok {
			f.AllocatedBytes = v
		}
		if basePath != "" {
			if f.BaseSHA256, err = baseDigest(ctx, basePath, basePath); err != nil {
				return err
			}
		}
		files = append(files, f)
		return nil
	}
	hashFailed := func(what, path string, err error) bool {
		// Only the snapshot's own file being gone means it was deleted while
		// it waited its turn; a base gone from under it is a failure.
		if _, serr := os.Stat(path); errors.Is(err, os.ErrNotExist) && errors.Is(serr, os.ErrNotExist) {
			log.Info().Msg("saved snapshot backup: snapshot deleted before its " + what + " was hashed")
		} else {
			log.Warn().Err(err).Msg("saved snapshot backup: " + what + " hash failed; not queued")
		}
		return false
	}
	// A cold boot of an overlay trusts the block map saved with it.
	if man.SnapshotPath != "" && man.BasePath != "" {
		if p := overlayBlockMapPath(man.SnapshotPath); statRegularFile(p) {
			if err := add(backup.BlockMapName, p, ""); err != nil {
				return hashFailed("block map", p, err)
			}
		}
	}
	// Restore reads the disk as rootfs.ext4, whatever the capture named it.
	if err := add("rootfs.ext4", man.DiskPath, man.BasePath); err != nil {
		return hashFailed("disk", man.DiskPath, err)
	}
	task := backup.Task{
		SnapshotID: man.SnapshotID,
		Generation: backup.GenerationKey(files),
		Files:      files,
		// Below pauses: a pause's generation is the only copy of state
		// the sandbox is still changing.
		Priority: backup.PriorityCheckpoint,
	}
	if !m.savedSnapshotBackupCovered(task) {
		if err := ensureSnapshotBackupFloor(); err != nil {
			log.Error().Err(err).Msg("saved snapshot backup: rollback floor not raised; not queued")
			return false
		}
		if err := m.backupEnqueue(task); err != nil {
			log.Error().Err(err).Msg("saved snapshot backup: enqueue failed")
			return false
		}
	}
	m.markSavedSnapshotBackup(ctx, man.SnapshotID, task.Generation, log)
	log.Info().Str("generation", task.Generation).Msg("saved snapshot backup queued")
	return true
}

func (m *Manager) savedSnapshotBackupCovered(task backup.Task) bool {
	if m.backupCovered == nil {
		return false
	}
	covered, err := m.backupCovered(task)
	return err == nil && covered
}

// markSavedSnapshotBackup records the queued generation beside the
// snapshot's files, under the id's lock so it can never land in a directory
// a delete is removing. Best-effort: a missing marker only costs a rehash.
func (m *Manager) markSavedSnapshotBackup(ctx context.Context, snapshotID, generation string, log zerolog.Logger) {
	dir, err := m.savedSnapshotDir(snapshotID)
	if err != nil {
		return
	}
	unlock, err := m.lockSavedSnapshot(ctx, snapshotID)
	if err != nil {
		return
	}
	defer unlock()
	if _, err := readSavedSnapshotManifest(dir); err != nil {
		return
	}
	marker := filepath.Join(dir, savedSnapshotBackupMarker)
	tmp := marker + ".tmp"
	if err := os.WriteFile(tmp, []byte(generation), 0o600); err == nil {
		err = os.Rename(tmp, marker)
		if err != nil {
			log.Warn().Err(err).Msg("saved snapshot backup: marker not recorded")
		}
	}
}

// RecoverSavedSnapshotBackups queues every committed saved snapshot whose
// backup is neither pending nor done: one captured while backup was off, one
// whose queued upload was abandoned, or one lost with the journal.
func (m *Manager) RecoverSavedSnapshotBackups(ctx context.Context, log zerolog.Logger) {
	if m.backupEnqueue == nil || m.cfg.SnapshotDir == "" {
		return
	}
	root := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Msg("saved snapshot backup sweep: listing failed")
		}
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		// Staging and tombstones are dot-prefixed; only committed
		// snapshots carry a readable manifest.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		man, err := readSavedSnapshotManifest(dir)
		if err != nil {
			continue
		}
		if gen, err := os.ReadFile(filepath.Join(dir, savedSnapshotBackupMarker)); err == nil &&
			m.savedSnapshotBackupCovered(backup.Task{SnapshotID: man.SnapshotID, Generation: strings.TrimSpace(string(gen))}) {
			continue
		}
		m.backupSavedSnapshot(ctx, man, log.With().Str("snapshot_id", man.SnapshotID).Logger())
	}
}
