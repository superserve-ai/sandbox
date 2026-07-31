package vm

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// SetBackupEnqueue installs the durability pipeline's enqueue hook. Called
// once at startup before VMs exist, same pattern as SetStateStore. A nil
// hook (backup disabled) makes pause behave exactly as before.
func (m *Manager) SetBackupEnqueue(fn func(backup.Task)) {
	m.backupEnqueue = fn
}

// pauseRehashBudget bounds the asynchronous rehash of a pause whose
// synchronous hashing was skipped or partial. Generous by design: the
// retry runs off the RPC path, where a large disk taking minutes is
// acceptable and losing the pause's backup is not.
const pauseRehashBudget = 10 * time.Minute

// backupPause hashes a pause's durable artifacts and enqueues them for
// backup. When the synchronous attempt cannot produce an enqueueable
// manifest (the RPC deadline left no hash budget, or an artifact failed
// to hash), it retries once asynchronously with its own budget instead
// of dropping the pause: a warn log is not durable coverage, and a host
// loss after a silently skipped enqueue loses the pause outright. If the
// sandbox resumes while the rehash runs, the digests capture torn bytes
// and the uploader's pre-verification abandons that generation, which is
// the same safe outcome as any mutated source.
func (m *Manager) backupPause(ctx context.Context, vmID, snapshotPath, diskPath, diskBasePath string, log zerolog.Logger) []ManifestEntry {
	manifest := collectPauseManifest(ctx, snapshotPath, diskPath, diskBasePath, log)
	if m.backupEnqueue == nil {
		return manifest
	}
	if m.enqueueBackup(vmID, manifest) {
		return manifest
	}
	log.Warn().Str("vm_id", vmID).
		Msg("pause backup not enqueueable synchronously; retrying with async rehash")
	go func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseRehashBudget)
		defer cancel()
		// The rehash must digest pause-time bytes, proven rather than
		// assumed: a resume that writes and then QUIESCES before the
		// hash would otherwise produce digests of post-resume bytes
		// that verify cleanly and publish a manifest pairing a mutated
		// disk with the pause-time vmstate. The instance must be paused
		// on this same snapshot before and after the hash, and the disk
		// inode must not have changed across it; any violation drops
		// the rehash (a later re-pause enqueues its own generation).
		before, err := os.Stat(diskPath)
		if err != nil || !m.pausedAt(vmID, snapshotPath) {
			log.Warn().Str("vm_id", vmID).
				Msg("pause backup dropped: sandbox no longer at-rest for rehash")
			return
		}
		retried := collectPauseManifest(rctx, snapshotPath, diskPath, diskBasePath, log)
		after, err := os.Stat(diskPath)
		if err != nil || !os.SameFile(before, after) ||
			!before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() ||
			!m.pausedAt(vmID, snapshotPath) {
			log.Warn().Str("vm_id", vmID).
				Msg("pause backup dropped: disk changed during rehash")
			return
		}
		if !m.enqueueBackup(vmID, retried) {
			log.Error().Str("vm_id", vmID).
				Msg("pause backup dropped: rehash also produced no enqueueable manifest")
		}
	}()
	return manifest
}

// pausedAt reports whether the sandbox is currently paused on exactly
// this snapshot. Reads the live map only: a lazy reattach here would
// resurrect state for a sandbox the rehash should simply drop.
func (m *Manager) pausedAt(vmID, snapshotPath string) bool {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.Status == StatusPaused && inst.SnapshotPath == snapshotPath
}

// enqueueBackup hands a pause's manifest to the backup pipeline,
// reporting whether a task was enqueued. The generation is
// content-addressed over every artifact digest, so genuine retries
// converge on the same immutable objects while any changed artifact
// starts a fresh generation. A manifest without a disk entry (hash
// skipped or failed) has no durable generation to ship; it is never
// guessed at, and backupPause owns retrying it.
//
// Enqueue is a local BoltDB write (milliseconds) and must never fail the
// pause: the artifacts on disk are valid regardless, and the journal is
// the retry mechanism, not the caller.
func (m *Manager) enqueueBackup(vmID string, manifest []ManifestEntry) bool {
	if m.backupEnqueue == nil || len(manifest) == 0 {
		return false
	}
	hasDisk := false
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		if e.FileName == "rootfs.ext4" {
			hasDisk = true
		}
		files = append(files, backup.TaskFile{
			Name:     e.FileName,
			Path:     e.Path,
			SHA256:   e.SHA256,
			Size:     e.SizeBytes,
			BasePath: e.BasePath,
		})
	}
	if !hasDisk {
		m.log.Warn().Str("vm_id", vmID).
			Msg("pause manifest has no disk digest; generation not enqueued for backup")
		return false
	}
	m.backupEnqueue(backup.Task{
		SandboxID: vmID,
		// Keyed on every artifact digest: any changed artifact means a new
		// generation, so create-only dedupe can never mix old and new
		// objects under one prefix.
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   backup.PriorityPause,
	})
	return true
}
