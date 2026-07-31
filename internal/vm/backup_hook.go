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
// hook (backup disabled) makes pause behave exactly as before. The hook
// returns the journal write's error so callers can retry: an enqueue that
// fails (disk exhaustion, I/O error) and only logs would report the pause
// as covered while nothing reached BoltDB.
func (m *Manager) SetBackupEnqueue(fn func(backup.Task) error) {
	m.backupEnqueue = fn
}

// pauseRehashBudget bounds the asynchronous rehash of a pause whose
// synchronous hashing was skipped or partial. Generous by design: the
// retry runs off the RPC path, where a large disk taking minutes is
// acceptable and losing the pause's backup is not.
const pauseRehashBudget = 10 * time.Minute

// enqueueRetryAttempts bounds re-enqueues of a complete manifest whose
// journal write failed. The digests already describe pause-time bytes,
// so these retries need neither hashing nor a still-paused sandbox.
const enqueueRetryAttempts = 3

// pauseManifestComplete reports whether the manifest carries both durable
// artifacts a restore needs. The pair is the unit of durability: a
// disk-only generation would publish a manifest that restore rejects,
// and a vmstate-only one has no filesystem at all.
func pauseManifestComplete(manifest []ManifestEntry) bool {
	var disk, vmstate bool
	for _, e := range manifest {
		switch e.FileName {
		case "rootfs.ext4":
			disk = true
		case "vmstate.snap":
			vmstate = true
		}
	}
	return disk && vmstate
}

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
	if pauseManifestComplete(manifest) && m.enqueueBackup(vmID, manifest) {
		m.deletePendingBackup(vmID, log)
		return manifest
	}
	// The pause still owes its enqueue. Persist that fact BEFORE the
	// async work: the goroutine below can run for minutes, and a crash
	// or deploy inside its window would otherwise erase the only record
	// that this pause needs coverage. Startup recovery re-runs pending
	// records once reattach has rebuilt the instance map.
	pb := PendingBackup{VMID: vmID, SnapshotPath: snapshotPath, DiskPath: diskPath, DiskBasePath: diskBasePath}
	m.persistPendingBackup(pb, log)
	if pauseManifestComplete(manifest) {
		// The hashes are good; only the journal write failed. Retry the
		// write with the manifest already in hand: its digests describe
		// pause-time bytes whatever the sandbox does next (the uploader's
		// pre-verification catches any divergence), so this retry needs
		// neither a rehash nor a still-paused sandbox.
		log.Warn().Str("vm_id", vmID).
			Msg("pause backup journal write failed; retrying enqueue")
		go m.retryEnqueue(vmID, manifest, log)
		return manifest
	}
	log.Warn().Str("vm_id", vmID).
		Msg("pause backup not enqueueable synchronously; retrying with async rehash")
	go m.rehashPendingBackup(ctx, pb, log)
	return manifest
}

// rehashPendingBackup rehashes a pause's artifacts off the RPC path and
// enqueues them, proving at-rest bytes rather than assuming them: a
// resume that writes and then QUIESCES before the hash would otherwise
// produce digests of post-resume bytes that verify cleanly and publish a
// manifest pairing a mutated disk with the pause-time vmstate. The proof
// is threefold: the instance is paused on this snapshot, the systemd
// unit is confirmed dead (the recorded status alone is not proof: pause
// records StatusPaused even when its stop attempts failed, and resume
// starts the unit before flipping the status), and the disk inode did
// not change across the hash. Terminal outcomes clear the pending
// record; only exhausted journal retries keep it for the next boot.
func (m *Manager) rehashPendingBackup(ctx context.Context, pb PendingBackup, log zerolog.Logger) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseRehashBudget)
	defer cancel()
	before, err := os.Stat(pb.DiskPath)
	if err != nil || !m.atRest(rctx, pb.VMID, pb.SnapshotPath) {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup dropped: sandbox no longer at-rest for rehash")
		m.deletePendingBackup(pb.VMID, log)
		return
	}
	retried := collectPauseManifest(rctx, pb.SnapshotPath, pb.DiskPath, pb.DiskBasePath, log)
	after, err := os.Stat(pb.DiskPath)
	if err != nil || !os.SameFile(before, after) ||
		!before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() ||
		!m.atRest(rctx, pb.VMID, pb.SnapshotPath) {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup dropped: disk changed during rehash")
		m.deletePendingBackup(pb.VMID, log)
		return
	}
	if m.enqueueBackup(pb.VMID, retried) {
		m.deletePendingBackup(pb.VMID, log)
		return
	}
	if !pauseManifestComplete(retried) {
		log.Error().Str("vm_id", pb.VMID).
			Msg("pause backup dropped: rehash also produced no enqueueable manifest")
		m.deletePendingBackup(pb.VMID, log)
		return
	}
	// The rehash earned a complete manifest; a transient journal failure
	// must not throw it away when the synchronous path's equivalent
	// failure gets retries.
	m.retryEnqueue(pb.VMID, retried, log)
}

// RecoverPendingBackups re-runs every pause that still owed its backup
// enqueue when the previous process exited. Call after reattach has
// rebuilt the instance map: the at-rest proof reads it, and an empty map
// would drop every record as superseded. No-op when backup is disabled
// or persistence is off.
func (m *Manager) RecoverPendingBackups(ctx context.Context, log zerolog.Logger) {
	if m.backupEnqueue == nil || m.state == nil {
		return
	}
	pending, err := m.state.ListPendingBackups()
	if err != nil {
		log.Error().Err(err).Msg("pending backup recovery: list failed")
		return
	}
	for _, pb := range pending {
		log.Info().Str("vm_id", pb.VMID).Msg("recovering pending pause backup")
		go m.rehashPendingBackup(ctx, pb, log)
	}
}

// retryEnqueue re-attempts a journal write for a manifest whose digests
// already describe at-rest bytes: only the write failed, so no rehash
// and no still-paused sandbox is needed (the uploader's pre-verification
// catches divergence). Bounded backoff; a journal that keeps failing
// leaves the pending record for the next boot's recovery.
func (m *Manager) retryEnqueue(vmID string, manifest []ManifestEntry, log zerolog.Logger) {
	delay := time.Second
	for attempt := 0; attempt < enqueueRetryAttempts; attempt++ {
		time.Sleep(delay)
		delay *= 2
		if m.enqueueBackup(vmID, manifest) {
			m.deletePendingBackup(vmID, log)
			return
		}
	}
	log.Error().Str("vm_id", vmID).
		Msg("pause backup journal writes kept failing; pending record kept for recovery")
}

// persistPendingBackup and deletePendingBackup tolerate a nil state
// store (tests, persistence disabled): the async retry still runs, it
// just loses crash durability.
func (m *Manager) persistPendingBackup(pb PendingBackup, log zerolog.Logger) {
	if m.state == nil {
		return
	}
	if err := m.state.PutPendingBackup(pb); err != nil {
		log.Error().Err(err).Str("vm_id", pb.VMID).Msg("persist pending backup failed")
	}
}

func (m *Manager) deletePendingBackup(vmID string, log zerolog.Logger) {
	if m.state == nil {
		return
	}
	if err := m.state.DeletePendingBackup(vmID); err != nil {
		log.Error().Err(err).Str("vm_id", vmID).Msg("clear pending backup failed")
	}
}

// atRest reports whether a sandbox's artifacts are provably not being
// written: the instance is paused on exactly this snapshot AND the
// systemd unit is confirmed dead. The recorded status alone is
// insufficient in both directions: pause records StatusPaused even when
// its stop attempts failed, and resume starts the unit before flipping
// the status away from paused.
func (m *Manager) atRest(ctx context.Context, vmID, snapshotPath string) bool {
	return m.pausedAt(vmID, snapshotPath) && m.unitConfirmedDead(ctx, vmID)
}

// unitConfirmedDead consults systemd (overridable for tests via the
// unitDead field) about whether the sandbox's unit is definitely stopped.
func (m *Manager) unitConfirmedDead(ctx context.Context, vmID string) bool {
	if m.unitDead != nil {
		return m.unitDead(ctx, vmID)
	}
	return unitDefinitelyDead(ctx, systemdUnitName(vmID))
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
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		files = append(files, backup.TaskFile{
			Name:       e.FileName,
			Path:       e.Path,
			SHA256:     e.SHA256,
			Size:       e.SizeBytes,
			BasePath:   e.BasePath,
			BaseSHA256: e.BaseSHA256,
		})
	}
	if !pauseManifestComplete(manifest) {
		m.log.Warn().Str("vm_id", vmID).
			Msg("pause manifest missing a durable artifact digest; generation not enqueued for backup")
		return false
	}
	if err := m.backupEnqueue(backup.Task{
		SandboxID: vmID,
		// Keyed on every artifact digest: any changed artifact means a new
		// generation, so create-only dedupe can never mix old and new
		// objects under one prefix.
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   backup.PriorityPause,
	}); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).
			Msg("backup enqueue failed; pause not journaled")
		return false
	}
	return true
}
