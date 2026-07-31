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

// enqueueBackup hands a pause's manifest to the backup pipeline. The disk
// artifact's digest is the generation's content address, so retries and
// unchanged re-pauses converge on the same immutable objects. A manifest
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
	var generation string
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		if e.FileName == "rootfs.ext4" {
			generation = e.SHA256
		}
		files = append(files, backup.TaskFile{
			Name:   e.FileName,
			Path:   e.Path,
			SHA256: e.SHA256,
			Size:   e.SizeBytes,
		})
	}
	if generation == "" {
		m.log.Warn().Str("vm_id", vmID).
			Msg("pause manifest has no disk digest; generation not enqueued for backup")
		return
	}
	m.backupEnqueue(backup.Task{
		SandboxID:  vmID,
		Generation: generation,
		Files:      files,
		Priority:   backup.PriorityPause,
	})
}
