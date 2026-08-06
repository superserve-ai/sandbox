package vm

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// SetBackupCovered installs the journal's coverage probe: whether a
// task's owner+generation is already pending in the queue or recorded as
// completed. Recovery sweeps use it to skip work that is already
// durable; nil (backup disabled, or older wiring) means "never covered",
// which only costs idempotent re-enqueues the journal dedupes anyway.
func (m *Manager) SetBackupCovered(fn func(backup.Task) (bool, error)) {
	m.backupCovered = fn
}

// retryWithBackoff runs attempt with doubling delays until it succeeds
// or enqueueRetryAttempts are exhausted, reporting whether it succeeded.
// The first attempt is already behind the caller; this helper owns only
// the retries, so it sleeps before every call.
func retryWithBackoff(attempt func() bool) bool {
	delay := time.Second
	for i := 0; i < enqueueRetryAttempts; i++ {
		time.Sleep(delay)
		delay *= 2
		if attempt() {
			return true
		}
	}
	return false
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
	// Pin the base identity BEFORE hashing: the marker must carry the
	// pre-hash identity, or a base swapped during the hash is laundered
	// into the record as the legitimate dependency.
	pb := newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath)
	manifest := collectPauseManifest(ctx, snapshotPath, diskPath, diskBasePath, log)
	if m.backupEnqueue == nil {
		return manifest
	}
	if diskBasePath != "" {
		if cur, err := baseIdentity(diskBasePath); err != nil || cur != pb.BaseIdentity {
			// The hashed base cannot be proven to be the pause-time one:
			// strip the disk entry so the manifest is incomplete and the
			// rehash path (which re-pins and re-proves) owns it.
			log.Warn().Err(err).Str("vm_id", vmID).
				Msg("base identity changed across pause hash; deferring to rehash")
			manifest = withoutDiskEntry(manifest)
		}
	}
	// The RPC path stops at a millisecond marker write: staging copies
	// artifact bytes when reflink is unavailable, and neither that nor
	// journal I/O may eat the RPC's remaining deadline after hashing
	// already spent its budget. The marker is the durable intent; the
	// detached worker stages, enqueues, and clears it, and a crash in
	// between leaves the marker for startup recovery.
	m.persistPendingBackup(pb, log)
	if pauseManifestComplete(manifest) {
		// Clone-staging runs inline: PauseVM still holds the VM op lock,
		// so nothing can resume and no at-rest proof is needed, and a
		// reflink costs microseconds. Only the byte-copy fallback (non
		// reflink filesystems) defers to the worker; a destroy racing
		// that worker is the residual, and only on such filesystems.
		if m.backupStaging != "" {
			t := rebuildTask(vmID, manifest)
			if all, err := backup.StageTaskClone(m.backupStaging, &t); err == nil && all {
				manifest = manifestWithTaskPaths(manifest, t)
			}
		}
		go m.finishPauseEnqueue(pb, manifest, log)
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
	// Superseded (the sandbox is provably no longer paused on this
	// snapshot) deletes the record: a resume, destroy, or newer pause
	// owns coverage now. Everything merely INCONCLUSIVE (a stat error, a
	// liveness probe that cannot prove death, an instance the startup
	// reattach has not loaded yet, a disk that changed under a
	// still-paused instance) keeps the record instead: deleting on a
	// transient state would permanently drop coverage the next recovery
	// could earn.
	switch m.pendingVerdict(pb.VMID, pb.SnapshotPath) {
	case pendingSuperseded:
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup superseded: sandbox no longer paused on this snapshot")
		m.deletePendingBackupIf(pb, log)
		return
	case pendingInconclusive:
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause backup inconclusive: sandbox state unreadable; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	case pendingEligible:
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
	if pb.DiskBasePath != "" {
		// Re-check AFTER hashing too: the disk hash can run for minutes,
		// and a base swapped inside that window would have been stat'ed
		// fresh and recorded as the dependency, which the uploader
		// cannot catch (the recorded digest matches the new base's
		// bytes). The pre-hash check alone leaves that window open.
		cur, err := baseIdentity(pb.DiskBasePath)
		if err != nil {
			log.Warn().Err(err).Str("vm_id", pb.VMID).
				Msg("pause backup rehash inconclusive: base identity unreadable after hash; keeping pending record")
			m.healPendingBackup(pb, log)
			return
		}
		if cur != pb.BaseIdentity {
			log.Error().Str("vm_id", pb.VMID).
				Msg("pause backup dropped: base replaced during rehash")
			m.deletePendingBackupIf(pb, log)
			return
		}
	}
	if v := m.pendingVerdict(pb.VMID, pb.SnapshotPath); v != pendingEligible {
		if v == pendingInconclusive {
			log.Warn().Str("vm_id", pb.VMID).
				Msg("pause backup inconclusive after rehash; keeping pending record")
			m.healPendingBackup(pb, log)
			return
		}
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
	if ok, staged := m.enqueueBackup(pb.VMID, retried); ok {
		if staged {
			m.deletePendingBackupIf(pb, log)
			return
		}
		// Journaled from mutable paths (staging failed even at rest):
		// the marker stays so a later sweep can upgrade the queued
		// entry, exactly like the pause path's unstaged handoff.
		log.Warn().Str("vm_id", pb.VMID).
			Msg("rehash enqueued unstaged; keeping marker for staging upgrade")
		m.healPendingBackup(pb, log)
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

// pendingRehashConcurrency bounds concurrent recovery/sweep rehash
// workers: a restart with a backlog must not start one full-file rehash
// per sandbox and saturate the host's disk bandwidth (the upload limiter
// caps network, not hashing). Saturated passes stop early; the sweep
// retries the remainder.
const pendingRehashConcurrency = 2

// ensureRehashSlots lazily creates the shared rehash bound. Both the
// pause recovery and the template-build sweep route their hashing
// through this one channel, so their combined disk pressure stays under
// pendingRehashConcurrency no matter which recovery started first.
func (m *Manager) ensureRehashSlots() chan struct{} {
	m.rehashSlotsOnce.Do(func() {
		m.rehashSlots = make(chan struct{}, pendingRehashConcurrency)
	})
	return m.rehashSlots
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
	m.ensureRehashSlots()
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
		select {
		case m.rehashSlots <- struct{}{}:
		default:
			// All slots busy: the rest of the backlog waits for the next
			// sweep rather than piling up unbounded hash work.
			log.Info().Msg("pending backup slots saturated; remaining records wait for the next sweep")
			return
		}
		log.Info().Str("vm_id", pb.VMID).Msg("retrying pending pause backup")
		go func(pb PendingBackup) {
			defer func() { <-m.rehashSlots }()
			m.rehashPendingBackup(ctx, pb, log)
		}(pb)
	}
}

// fileMissing reports a definite ENOENT; any other stat outcome (success
// or transient error) is not proof of absence.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

// finishPauseEnqueue completes a fully hashed pause off the RPC path:
// stage the artifacts (a byte copy when reflink is unavailable), write
// the journal entry, clear the marker. The digests already describe
// pause-time bytes, so no rehash and no still-paused sandbox is needed;
// a destroy racing the instants before staging lands surfaces as a
// vanished source and the marker clears as superseded on a later sweep.
func (m *Manager) finishPauseEnqueue(pb PendingBackup, manifest []ManifestEntry, log zerolog.Logger) {
	// Same single-worker-per-VM guard as the rehash: a sweep worker for
	// this VM racing us would double-stage and double-enqueue; heal
	// first so a busy exit still leaves the durable marker.
	m.healPendingBackup(pb, log)
	if _, busy := m.pendingInFlight.LoadOrStore(pb.VMID, struct{}{}); busy {
		return
	}
	defer m.pendingInFlight.Delete(pb.VMID)
	ok, staged := m.enqueueBackup(pb.VMID, manifest)
	if ok {
		if staged {
			m.deletePendingBackupIf(pb, log)
			return
		}
		// Journaled but from mutable paths: the marker stays, and the
		// sweep's worker retries under the at-rest proof; its enqueue
		// dedupes against this generation and upgrades the queued paths
		// to staged ones, after which the marker clears.
		log.Warn().Str("vm_id", pb.VMID).
			Msg("pause enqueued unstaged; keeping marker for staging upgrade")
		m.healPendingBackup(pb, log)
		return
	}
	log.Warn().Str("vm_id", pb.VMID).
		Msg("pause backup journal write failed; retrying enqueue")
	m.retryEnqueue(pb, manifest, log)
}

// retryEnqueue re-attempts a journal write for a manifest whose digests
// already describe at-rest bytes: only the write failed, so no rehash
// and no still-paused sandbox is needed (the uploader's pre-verification
// catches divergence). Bounded backoff; a journal that keeps failing
// leaves the pending record for the next boot's recovery.
func (m *Manager) retryEnqueue(pb PendingBackup, manifest []ManifestEntry, log zerolog.Logger) {
	m.healPendingBackup(pb, log)
	var staged bool
	enqueued := retryWithBackoff(func() bool {
		ok, s := m.enqueueBackup(pb.VMID, manifest)
		staged = s
		return ok
	})
	if !enqueued {
		log.Error().Str("vm_id", pb.VMID).
			Msg("pause backup journal writes kept failing; pending record kept for recovery")
		m.healPendingBackup(pb, log)
		return
	}
	if staged {
		m.deletePendingBackupIf(pb, log)
		return
	}
	// Journaled but from mutable paths: keep the marker so the
	// sweep can upgrade the queued row, like every other path.
	log.Warn().Str("vm_id", pb.VMID).
		Msg("retry enqueued unstaged; keeping marker for staging upgrade")
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

// pendingVerdict classifies a pending record against the sandbox's
// current state. The in-memory map alone cannot answer: startup reattach
// may not have loaded a paused VM yet (or exited early), and mistaking
// not-yet-loaded for destroyed would delete coverage the sandbox is
// still owed. The durable record is the authority when the map has no
// entry: present-and-paused on this snapshot is eligible, definitively
// absent is superseded (destroyed), and an unreadable store is
// inconclusive.
type pendingVerdictKind int

const (
	pendingEligible pendingVerdictKind = iota
	pendingSuperseded
	pendingInconclusive
)

func (m *Manager) pendingVerdict(vmID, snapshotPath string) pendingVerdictKind {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if ok {
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		if inst.Status == StatusPaused && inst.SnapshotPath == snapshotPath {
			return pendingEligible
		}
		return pendingSuperseded
	}
	if m.state == nil {
		return pendingSuperseded
	}
	rec, err := m.state.Get(vmID)
	if err != nil {
		return pendingInconclusive
	}
	if rec == nil {
		return pendingSuperseded
	}
	if rec.Status == StatusPaused && rec.SnapshotPath == snapshotPath {
		return pendingEligible
	}
	return pendingSuperseded
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
func (m *Manager) enqueueBackup(vmID string, manifest []ManifestEntry) (bool, bool) {
	if m.backupEnqueue == nil || len(manifest) == 0 {
		return false, false
	}
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		files = append(files, backup.TaskFile{
			Name:           e.FileName,
			Path:           e.Path,
			SHA256:         e.SHA256,
			Size:           e.SizeBytes,
			BasePath:       e.BasePath,
			BaseStagedPath: e.BaseStagedPath,
			BaseSHA256:     e.BaseSHA256,
		})
	}
	if !pauseManifestComplete(manifest) {
		m.log.Warn().Str("vm_id", vmID).
			Msg("pause manifest missing a durable artifact digest; generation not enqueued for backup")
		return false, false
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
	// retention promise for deleted sandboxes. Staging is only trusted
	// under the at-rest proof held ACROSS the snapshot: this worker runs
	// off the pause operation lock, so a client's immediate resume can
	// win the race and a reflink would capture post-resume bytes (or the
	// copy a torn mixture). When the proof fails or staging errors, the
	// task keeps its original mutable paths (the uploader's
	// pre-verification decides, the pre-staging contract) and the caller
	// keeps the pending marker so a later sweep can upgrade the entry;
	// the journal upgrades a deduped generation's paths in place.
	// With staging disabled there is nothing to upgrade later: the
	// original paths ARE the handoff, as before staging existed.
	staged := m.backupStaging == ""
	if m.backupStaging != "" && taskFullyStaged(m.backupStaging, task) {
		// Already snapshotted (inline clone under the pause op lock, or
		// a re-enqueue of staged paths): nothing mutable remains, so no
		// at-rest proof is needed.
		staged = true
	} else if m.backupStaging != "" {
		snapPath, diskPath := "", ""
		for _, f := range task.Files {
			switch f.Name {
			case "vmstate.snap":
				snapPath = f.Path
			case "rootfs.ext4":
				diskPath = f.Path
			}
		}
		before, statErr := os.Stat(diskPath)
		if statErr == nil && m.atRest(probeCtx(), vmID, snapPath) {
			if err := backup.StageTask(m.backupStaging, &task); err != nil {
				m.log.Warn().Err(err).Str("vm_id", vmID).
					Msg("backup staging failed; uploading from original paths")
			} else if after, err := os.Stat(diskPath); err == nil &&
				os.SameFile(before, after) &&
				before.ModTime().Equal(after.ModTime()) && before.Size() == after.Size() &&
				m.atRest(probeCtx(), vmID, snapPath) {
				staged = true
			} else {
				m.log.Warn().Str("vm_id", vmID).
					Msg("sandbox left at-rest during staging; uploading from original paths")
				task = rebuildTask(vmID, manifest)
			}
		}
	}
	task.Staged = staged && m.backupStaging != ""
	if err := m.backupEnqueue(task); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).
			Msg("backup enqueue failed; pause not journaled")
		return false, false
	}
	return true, staged
}

// probeCtx bounds a systemd liveness probe: these run on detached
// workers whose own contexts are generous, and an unresponsive systemd
// must fail the probe (inconclusive) rather than hang the worker.
func probeCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = cancel // bounded by the deadline; the probe is short-lived
	return ctx
}

// withoutDiskEntry strips the rootfs entry, rendering the manifest
// incomplete so the retry machinery owns the pause.
func withoutDiskEntry(manifest []ManifestEntry) []ManifestEntry {
	out := manifest[:0:0]
	for _, e := range manifest {
		if e.FileName != "rootfs.ext4" {
			out = append(out, e)
		}
	}
	return out
}

// manifestWithTaskPaths mirrors a staged task's rewritten paths back
// onto the manifest entries, so downstream enqueue rebuilds see the
// staged locations.
func manifestWithTaskPaths(manifest []ManifestEntry, task backup.Task) []ManifestEntry {
	byName := map[string]backup.TaskFile{}
	for _, f := range task.Files {
		byName[f.Name] = f
	}
	out := make([]ManifestEntry, len(manifest))
	copy(out, manifest)
	for i, e := range out {
		if f, ok := byName[e.FileName]; ok {
			out[i].Path = f.Path
			out[i].BaseStagedPath = f.BaseStagedPath
		}
	}
	return out
}

// taskFullyStaged reports whether every task path (bases included)
// already lives under the staging root.
func taskFullyStaged(root string, task backup.Task) bool {
	prefix := root + string(os.PathSeparator)
	for _, f := range task.Files {
		if !strings.HasPrefix(f.Path, prefix) {
			return false
		}
		if f.BasePath != "" && !strings.HasPrefix(f.BaseStagedPath, prefix) {
			return false
		}
	}
	return len(task.Files) > 0
}

// rebuildTask reconstructs the enqueue task from the manifest with its
// original paths, discarding any staged rewrites.
func rebuildTask(vmID string, manifest []ManifestEntry) backup.Task {
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		files = append(files, backup.TaskFile{
			Name:           e.FileName,
			Path:           e.Path,
			SHA256:         e.SHA256,
			Size:           e.SizeBytes,
			BasePath:       e.BasePath,
			BaseStagedPath: e.BaseStagedPath,
			BaseSHA256:     e.BaseSHA256,
		})
	}
	return backup.Task{
		SandboxID:  vmID,
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   backup.PriorityPause,
	}
}

// enqueueTemplateBackup hands a completed template build's hashed artifact
// set to the backup pipeline, reporting whether the generation is covered
// (enqueued now, still pending, or already completed). Same contract as
// enqueueBackup: a nil hook (backup disabled) is a no-op, and the enqueue
// is a local journal write that must never fail the build; the caller
// owns retrying a failed write. Template builds ride the checkpoint
// priority: a template is rebuildable, so a multi-GiB build upload must
// never head-of-line block a pause generation, which is unique user data.
func (m *Manager) enqueueTemplateBackup(templateID, buildID string, manifest []ManifestEntry) bool {
	if m.backupEnqueue == nil || len(manifest) == 0 {
		return false
	}
	files := make([]backup.TaskFile, 0, len(manifest))
	for _, e := range manifest {
		// No BasePath/BaseSHA256, deliberately: the build's base image is
		// already a REGULAR member of this artifact set (collectBuildManifest
		// hashes it via extraPaths), so it ships inside the template's own
		// generation. Declaring it a base dependency too would make the
		// uploader also ship it as a shared bases/ object: the same bytes
		// twice.
		files = append(files, backup.TaskFile{
			Name:   e.FileName,
			Path:   e.Path,
			SHA256: e.SHA256,
			Size:   e.SizeBytes,
		})
	}
	task := backup.Task{
		TemplateID: templateID,
		BuildID:    buildID,
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   backup.PriorityCheckpoint,
	}
	// Already pending or already completed means nothing to do: recovery
	// sweeps and repeated status-poll adoptions funnel through here, and
	// without this gate an already-acked generation would be re-uploaded
	// on every pass.
	if m.backupCovered != nil {
		if covered, err := m.backupCovered(task); err == nil && covered {
			return true
		}
	}
	if err := m.backupEnqueue(task); err != nil {
		m.log.Error().Err(err).Str("template_id", templateID).Str("build_vm_id", buildID).
			Msg("backup enqueue failed; build not journaled")
		return false
	}
	return true
}
