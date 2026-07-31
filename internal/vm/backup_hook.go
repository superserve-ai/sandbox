package vm

import (
	"github.com/superserve-ai/sandbox/internal/backup"
)

// SetBackupEnqueue installs the durability pipeline's enqueue hook. Called
// once at startup before VMs exist, same pattern as SetStateStore. A nil
// hook (backup disabled) makes pause behave exactly as before.
func (m *Manager) SetBackupEnqueue(fn func(backup.Task)) {
	m.backupEnqueue = fn
}

// enqueueBackup hands a pause's manifest to the backup pipeline. The
// generation is content-addressed over every artifact digest, so genuine
// retries converge on the same immutable objects while any changed
// artifact starts a fresh generation. A manifest
// without a disk entry (hash skipped or failed) has no durable generation
// to ship; it is skipped here and surfaced by coverage monitoring, never
// guessed at.
//
// Enqueue is a local BoltDB write (milliseconds) and must never fail the
// pause: the artifacts on disk are valid regardless, and the journal is
// the retry mechanism, not the caller.
func (m *Manager) enqueueBackup(vmID string, manifest []ManifestEntry) {
	if m.backupEnqueue == nil || len(manifest) == 0 {
		return
	}
	hasDisk := false
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		if e.FileName == "rootfs.ext4" {
			hasDisk = true
		}
		files = append(files, backup.TaskFile{
			Name:   e.FileName,
			Path:   e.Path,
			SHA256: e.SHA256,
			Size:   e.SizeBytes,
		})
	}
	if !hasDisk {
		m.log.Warn().Str("vm_id", vmID).
			Msg("pause manifest has no disk digest; generation not enqueued for backup")
		return
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
}
