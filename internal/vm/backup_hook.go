package vm

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// SetBackupStaging points the enqueue path at the uploader's hard-link
// staging tree. Same startup-only pattern as SetBackupEnqueue.
func (m *Manager) SetBackupStaging(dir string) {
	m.backupStaging = dir
}

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
	pb := newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath)
	m.persistPendingBackup(pb, log)
	if pauseManifestComplete(manifest) {
		// The hashes are good; only the journal write failed. Retry the
		// write with the manifest already in hand: its digests describe
		// pause-time bytes whatever the sandbox does next (the uploader's
		// pre-verification catches any divergence), so this retry needs
		// neither a rehash nor a still-paused sandbox.
		log.Warn().Str("vm_id", vmID).
			Msg("pause backup journal write failed; retrying enqueue")
		go m.retryEnqueue(pb, manifest, log)
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
	// One worker per VM: the periodic sweep and startup recovery may both
	// find the same record while a worker is mid-hash, and a second
	// concurrent hash of the same multi-GB artifacts buys nothing (the
	// journal already dedupes the enqueue).
	// Heal BEFORE the busy guard: a newer pause whose initial persist
	// failed while an older worker holds the in-flight slot would
	// otherwise exit here with neither a durable marker nor a worker.
	// Healing is newest-wins, so this durably records the newest pause
	// even when it cannot run yet; the sweep picks it up after the older
	// worker's exact-token cleanup no-ops against it.
	m.healPendingBackup(pb, log)
	if _, busy := m.pendingInFlight.LoadOrStore(pb.VMID, struct{}{}); busy {
		return
	}
	defer m.pendingInFlight.Delete(pb.VMID)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseRehashBudget)
	defer cancel()
	// Superseded (the instance is no longer paused on this snapshot)
	// deletes the record: a resume, destroy, or newer pause owns coverage
	// now. Everything merely INCONCLUSIVE (a stat error, a liveness probe
	// that cannot prove death, a disk that changed under a still-paused
	// instance) keeps the record instead: deleting on a transient failure
	// would permanently drop coverage the next recovery could earn.
	if !m.pausedAt(pb.VMID, pb.SnapshotPath) {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup superseded: sandbox no longer paused on this snapshot")
		m.deletePendingBackupIf(pb, log)
		return
	}
	before, err := os.Stat(pb.DiskPath)
	if err != nil || !m.unitConfirmedDead(rctx, pb.VMID) {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("pause backup rehash inconclusive; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	if pb.DiskBasePath != "" {
		// The base dependency's identity must be the PAUSE-TIME one: a
		// base replaced or rebuilt at the same path after the pause
		// would otherwise be hashed and recorded as the dependency of an
		// overlay written against the original. The overlay's own at-rest
		// checks cannot see this; only the identity captured when the
		// marker was created can.
		cur, err := baseIdentity(pb.DiskBasePath)
		if err != nil {
			log.Warn().Err(err).Str("vm_id", pb.VMID).
				Msg("pause backup rehash inconclusive: base identity unreadable; keeping pending record")
			m.healPendingBackup(pb, log)
			return
		}
		if pb.BaseIdentity == "" || cur != pb.BaseIdentity {
			log.Error().Str("vm_id", pb.VMID).
				Msg("pause backup dropped: overlay base no longer the pause-time file")
			m.deletePendingBackupIf(pb, log)
			return
		}
	}
	retried := collectPauseManifest(rctx, pb.SnapshotPath, pb.DiskPath, pb.DiskBasePath, log)
	if !m.pausedAt(pb.VMID, pb.SnapshotPath) {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup superseded during rehash")
		m.deletePendingBackupIf(pb, log)
		return
	}
	after, err := os.Stat(pb.DiskPath)
	if err != nil || !os.SameFile(before, after) ||
		!before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() ||
		!m.unitConfirmedDead(rctx, pb.VMID) {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("pause backup rehash not provably at-rest; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	if m.enqueueBackup(pb.VMID, retried) {
		m.deletePendingBackupIf(pb, log)
		return
	}
	if !pauseManifestComplete(retried) {
		// Unhashable while at rest: only a provably MISSING artifact is
		// unrecoverable (nothing will bring the file back for this
		// pause). A transient open or read failure on files that still
		// exist keeps the record; the periodic sweep retries it.
		if fileMissing(pb.SnapshotPath) || fileMissing(pb.DiskPath) {
			log.Error().Str("vm_id", pb.VMID).
				Msg("pause backup dropped: artifact missing at rest")
			m.deletePendingBackupIf(pb, log)
			return
		}
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup rehash failed transiently; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	// The rehash earned a complete manifest; a transient journal failure
	// must not throw it away when the synchronous path's equivalent
	// failure gets retries.
	m.retryEnqueue(pb, retried, log)
}

// pendingBackupSweepInterval paces retries of retained pending records:
// a record kept on an inconclusive proof or transient failure must not
// wait for the next process restart to try again.
const pendingBackupSweepInterval = 5 * time.Minute

// RecoverPendingBackups re-runs every pause that still owed its backup
// enqueue when the previous process exited, then keeps sweeping
// periodically so records retained on transient failures retry within
// this process's lifetime. Call after reattach has rebuilt the instance
// map: the at-rest proof reads it, and an empty map would drop every
// record as superseded. No-op when backup is disabled or persistence is
// off.
func (m *Manager) RecoverPendingBackups(ctx context.Context, log zerolog.Logger) {
	if m.backupEnqueue == nil || m.state == nil {
		return
	}
	m.runPendingBackups(ctx, log)
	interval := m.pendingSweepInterval
	if interval <= 0 {
		interval = pendingBackupSweepInterval
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.runPendingBackups(ctx, log)
			}
		}
	}()
}

func (m *Manager) runPendingBackups(ctx context.Context, log zerolog.Logger) {
	pending, err := m.state.ListPendingBackups()
	if err != nil {
		log.Error().Err(err).Msg("pending backup recovery: list failed")
		return
	}
	for _, pb := range pending {
		log.Info().Str("vm_id", pb.VMID).Msg("retrying pending pause backup")
		go m.rehashPendingBackup(ctx, pb, log)
	}
}

// fileMissing reports a definite ENOENT; any other stat outcome (success
// or transient error) is not proof of absence.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

// retryEnqueue re-attempts a journal write for a manifest whose digests
// already describe at-rest bytes: only the write failed, so no rehash
// and no still-paused sandbox is needed (the uploader's pre-verification
// catches divergence). Bounded backoff; a journal that keeps failing
// leaves the pending record for the next boot's recovery.
func (m *Manager) retryEnqueue(pb PendingBackup, manifest []ManifestEntry, log zerolog.Logger) {
	m.healPendingBackup(pb, log)
	delay := time.Second
	for attempt := 0; attempt < enqueueRetryAttempts; attempt++ {
		time.Sleep(delay)
		delay *= 2
		if m.enqueueBackup(pb.VMID, manifest) {
			m.deletePendingBackupIf(pb, log)
			return
		}
	}
	log.Error().Str("vm_id", pb.VMID).
		Msg("pause backup journal writes kept failing; pending record kept for recovery")
	m.healPendingBackup(pb, log)
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

// deletePendingBackupIf clears the record only while pb's token still
// owns it: async workers may outlive the pause that spawned them, and a
// newer pause's record must survive an older worker's cleanup.
func (m *Manager) deletePendingBackupIf(pb PendingBackup, log zerolog.Logger) {
	if m.state == nil {
		return
	}
	if err := m.state.DeletePendingBackupIf(pb.VMID, pb.Token); err != nil {
		log.Error().Err(err).Str("vm_id", pb.VMID).Msg("clear pending backup failed")
	}
}

// healPendingBackup re-persists a worker's record on every keep-path:
// the initial persist can fail (disk exhaustion, transient I/O), and a
// keep decision without a durable record would evaporate with the
// process. Owner-guarded, so a newer pause's record is never clobbered.
func (m *Manager) healPendingBackup(pb PendingBackup, log zerolog.Logger) {
	if m.state == nil {
		return
	}
	if err := m.state.PutPendingBackupIfOwner(pb); err != nil {
		log.Error().Err(err).Str("vm_id", pb.VMID).Msg("re-persist pending backup failed")
	}
}

// newPendingBackup builds a marker for a pause's owed backup, capturing
// the overlay base's stat identity at creation so the rehash can prove
// it is hashing the pause-time base and not a same-path replacement.
func newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath string) PendingBackup {
	pb := PendingBackup{
		VMID: vmID, SnapshotPath: snapshotPath, DiskPath: diskPath, DiskBasePath: diskBasePath,
		Token: newPendingToken(),
	}
	if diskBasePath != "" {
		if id, err := baseIdentity(diskBasePath); err == nil {
			pb.BaseIdentity = id
		}
	}
	return pb
}

// pendingTokenCounter disambiguates tokens minted in the same nanosecond.
var pendingTokenCounter atomic.Uint64

// Tokens are fixed-width so lexical order is creation order: healing is
// newest-wins and needs to compare ownership age.
func newPendingToken() string {
	return fmt.Sprintf("%020d-%012d", time.Now().UnixNano(), pendingTokenCounter.Add(1))
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
// unitDead field) about whether the sandbox's unit is fully down. The
// probe requires a terminal state: unitDefinitelyDead's weaker "not
// active" answer calls a deactivating unit dead while its Firecracker
// may still be flushing guest writes.
func (m *Manager) unitConfirmedDead(ctx context.Context, vmID string) bool {
	if m.unitDead != nil {
		return m.unitDead(ctx, vmID)
	}
	return unitFullyDown(ctx, systemdUnitName(vmID))
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
	task := backup.Task{
		SandboxID: vmID,
		// Keyed on every artifact digest: any changed artifact means a new
		// generation, so create-only dedupe can never mix old and new
		// objects under one prefix.
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   backup.PriorityPause,
	}
	// Stage before enqueueing: teardown of a destroyed sandbox unlinks
	// the artifacts, and the queued upload must survive it to honor the
	// retention promise for deleted sandboxes. Hard links pin the inodes
	// until the uploader acks; on a staging failure the original paths
	// remain, preserving the previous best-effort behavior.
	if m.backupStaging != "" {
		if err := backup.StageTask(m.backupStaging, &task); err != nil {
			m.log.Warn().Err(err).Str("vm_id", vmID).
				Msg("backup staging failed; uploading from original paths")
		}
	}
	if err := m.backupEnqueue(task); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).
			Msg("backup enqueue failed; pause not journaled")
		return false
	}
	return true
}
