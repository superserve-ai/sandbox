package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// SetBackupStaging points the enqueue path at the uploader-visible
// staging tree. Same startup-only pattern as SetBackupEnqueue.
func (m *Manager) SetBackupStaging(dir string) {
	m.backupStaging = dir
}

// SetPauseStagingRoot points the pause RPC path's own inline staging at
// its always-local tree (see pauseStagingRoot), separate from
// SetBackupStaging's uploader-visible root. Same startup-only pattern as
// SetBackupEnqueue.
func (m *Manager) SetPauseStagingRoot(dir string) {
	m.pauseStagingRoot = dir
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

// SetBackupMetrics installs the optional backup metrics recorder. Same
// startup-only pattern as SetBackupEnqueue; a nil recorder (metrics
// disabled) is safe at every call site, and recording never affects
// backup behavior.
func (m *Manager) SetBackupMetrics(rec *telemetry.BackupRecorder) {
	m.backupMetrics = rec
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
func (m *Manager) backupPause(ctx context.Context, vmID, snapshotPath, diskPath, diskBasePath, pauseToken string, log zerolog.Logger) []ManifestEntry {
	// The pause-hook histogram measures exactly the synchronous time this
	// hook holds the pause RPC path (detached workers are excluded by
	// construction: they run past the return). A size-dependent
	// synchronous term added here would otherwise surface only in logs;
	// the metric makes that class of regression alert instead of hide.
	start := time.Now()
	defer func() {
		m.backupMetrics.RecordPauseHookDuration(ctx, time.Since(start))
	}()
	// NOTHING here may scale with apparent disk size: pause latency must
	// track what the guest dirtied, and hashing a sparse overlay's full
	// apparent content costs seconds regardless of hasher. All
	// size-dependent hashing runs in the detached worker; the RPC path
	// pays a marker write, an O(real bytes) staging copy, and the
	// tens-of-KB vmstate hash for the control plane's manifest rows.
	manifest := collectVMStateEntry(ctx, snapshotPath, log)
	if m.backupEnqueue == nil {
		return manifest
	}
	pb := newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath, pauseToken)
	// Inline sparse staging under the still-held VM operation lock:
	// copying scales with REAL bytes (the same O(dirtied) scaling as the
	// pause itself, tens of ms for typical overlays), and the immutable
	// copies close the fast-resume window entirely: a resume racing the
	// worker cannot mutate a snapshot, so even an instantly-resumed
	// pause keeps its backup. Oversized or failed staging falls back to
	// the marker-only path, whose worker requires the at-rest proof and
	// concedes fast-resume pauses to supersession. Gated on
	// pauseStagingRoot, not backupStaging: this copy must stay on
	// SnapshotDir's filesystem for reflink and the base pin's hard link
	// to work, regardless of where backupStaging (the uploader-visible
	// root) points — see SetPauseStagingRoot.
	if m.pauseStagingRoot != "" {
		// A control-plane retry of the same pause must not pay a second
		// copy: reuse the existing marker (its staged files, base pin,
		// and pause-time base identity) when one covers this snapshot.
		if prev, ok := m.reusablePendingBackup(vmID, snapshotPath); ok {
			// Same artifacts, NEW logical pause: supersede the marker with
			// fresh OWNERSHIP as well as the new pause token. Rotating only
			// the pause token would leave a still-running old worker's
			// owner-guarded writes valid — it could enqueue its stale
			// in-memory token and then delete the refreshed marker, leaving
			// nothing to retry with the new identity. With a new ownership
			// token the old worker's heal and delete both no-op (not
			// owner), its own busy-guard exit is followed by the sweep
			// re-running this marker, and a stale-token enqueue it may
			// still land is corrected when this marker's run re-enqueues
			// the generation (the journal keeps the newest token on
			// dedupe).
			if pauseToken != "" && prev.PauseToken != pauseToken {
				prev.Token = newPendingToken()
				prev.PauseToken = pauseToken
				m.persistPendingBackup(prev, log)
			}
			go m.rehashPendingBackup(ctx, prev, log)
			return manifest
		}
		stageStart := time.Now()
		dir, staged, err := backup.StagePending(ctx, m.pauseStagingRoot, vmID, pb.Token, diskBasePath, map[string]string{
			"vmstate.snap": snapshotPath,
			"rootfs.ext4":  diskPath,
		})
		m.backupMetrics.RecordStageDuration(ctx, time.Since(stageStart))
		if err == nil {
			pb.OrigSnapshotPath = snapshotPath
			pb.OrigDiskPath = diskPath
			pb.StagedDir = dir
			pb.SnapshotPath = staged["vmstate.snap"]
			pb.DiskPath = staged["rootfs.ext4"]
			if diskBasePath != "" {
				// Stat through diskBasePath, not the pin: baseIdentity
				// embeds the path string it's given, and the fallback
				// comparison this identity feeds (when the pin is later
				// lost, e.g. absorbed away by FinishPendingStage) always
				// re-derives its "current" identity from diskBasePath. An
				// identity captured via the pin's path could never match
				// that, even with the base completely unchanged. The pin
				// and diskBasePath share one inode (hard link), so
				// stat-ing either returns identical dev/ino/size/ctime;
				// only the path component differs, and diskBasePath is
				// the one worth recording. Read after the link exists so
				// the ctime bump linking causes is captured.
				if id, err := baseIdentity(diskBasePath); err == nil {
					pb.BaseIdentity = id
				}
			}
		} else if !errors.Is(err, backup.ErrStageTooLarge) {
			log.Warn().Err(err).Str("vm_id", vmID).
				Msg("inline pause staging failed; worker will need the at-rest proof")
		} else {
			log.Info().Str("vm_id", vmID).
				Msg("packed disk exceeds inline staging budget; deferring to at-rest worker")
		}
	}
	m.persistPendingBackup(pb, log)
	go m.rehashPendingBackup(ctx, pb, log)
	return manifest
}

// rehashPendingBackup is the detached owner of a pause's backup. For
// staged markers it hashes the immutable pending copies (no at-rest
// proof: a snapshot cannot be mutated by a resume, and destroy
// retention is the point). For unstaged markers (oversized or failed
// staging) it runs the at-rest flow over the mutable originals, proving
// the bytes are not being written before trusting a hash of them.
// Terminal outcomes clear the pending record; only transient failures
// keep it for the sweep. Returns the generation this call enqueued (""
// when it enqueued nothing) and whether it ran the flow at all: false
// means the per-VM busy guard yielded to an older worker. The
// generation is read from the capture slot while the guard is still
// held, so it is attributable to this call by construction: no other
// worker for this VM can interleave an enqueue before the read.
func (m *Manager) rehashPendingBackup(ctx context.Context, pb PendingBackup, log zerolog.Logger) (string, bool) {
	if m.rehashDone != nil {
		defer m.rehashDone()
	}
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
		return "", false
	}
	defer m.pendingInFlight.Delete(pb.VMID)
	// Clear any stale capture at guard acquisition: a previous worker's
	// enqueue may have left its generation in the slot after releasing
	// the guard. From here, only this run's flow can write it, so
	// whatever the guarded read finds below is this call's enqueue.
	m.lastSandboxEnqueue.Delete(pb.VMID)
	capturedGen := func() string {
		if v, ok := m.lastSandboxEnqueue.LoadAndDelete(pb.VMID); ok {
			if gen, _ := v.(string); gen != "" {
				return gen
			}
		}
		return ""
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pauseRehashBudget)
	defer cancel()
	if pb.StagedDir != "" {
		pb = m.resolveStagedLocation(pb)
		// Immutable pause-time copies need no at-rest proof and are
		// never superseded by a resume or even a destroy: the copies ARE
		// the pause's bytes, a running guest cannot mutate them, and the
		// retention promise wants a destroyed sandbox's last pause in
		// the bucket.
		m.enqueueStagedPending(rctx, pb, log)
		return capturedGen(), true
	}
	m.rehashUnstagedLocked(rctx, pb, log)
	return capturedGen(), true
}

// rehashUnstagedLocked is the at-rest flow over mutable original paths,
// callable only under the pendingInFlight guard (rehashPendingBackup and
// the staged flow's lost-copies fallback).
func (m *Manager) rehashUnstagedLocked(rctx context.Context, pb PendingBackup, log zerolog.Logger) {
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
	if err != nil || !m.vmConfirmedAtRest(rctx, pb.VMID) {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("pause backup rehash inconclusive; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	// The same at-rest proof that admits the backup is what an overlay
	// stranded by this pause's Full fallback was waiting for.
	if inst := m.trackedInstance(pb.VMID); inst != nil {
		reclaimStrandedOverlay(inst, log)
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
	hashStart := time.Now()
	tHash := time.Now()
	retried := collectPauseManifest(rctx, pb.SnapshotPath, pb.DiskPath, pb.DiskBasePath, pb.DiskBasePath, log)
	m.recordPhases("pause", "", map[string]time.Duration{"manifest_hash": time.Since(tHash)})
	m.backupMetrics.RecordHashDuration(rctx, time.Since(hashStart))
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
		!m.vmConfirmedAtRest(rctx, pb.VMID) {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("pause backup rehash not provably at-rest; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	if ok, staged, _ := m.enqueueBackup(pb.VMID, retried, pb.backupPriority(), pb.PauseToken); ok {
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

// enqueueStagedPending hashes a pause's immutable staged copies and
// enqueues them. The staged files carry no mutation risk, so the only
// checks that remain are the base's (the base is not staged: guests
// never write it, but a template rebuild can replace it).
func (m *Manager) enqueueStagedPending(ctx context.Context, pb PendingBackup, log zerolog.Logger) {
	// Every keep-path below renews the staged directory: the sweep's
	// grace is mtime-based and the journal cannot see pending-token
	// directories, so liveness is signalled by touch.
	backup.RenewStaged(pb.StagedDir)
	if fileMissing(pb.SnapshotPath) || fileMissing(pb.DiskPath) {
		// The staged copies are gone (orphan sweep after an extreme
		// outage, manual cleanup). If the sandbox is still paused on the
		// original artifacts, fall back to the at-rest flow over them
		// rather than dropping coverage.
		if pb.OrigSnapshotPath != "" && !fileMissing(pb.OrigDiskPath) {
			log.Warn().Str("vm_id", pb.VMID).
				Msg("staged copies missing; falling back to at-rest flow over original paths")
			fallback := pb
			fallback.StagedDir = ""
			fallback.SnapshotPath = pb.OrigSnapshotPath
			fallback.DiskPath = pb.OrigDiskPath
			m.healPendingBackup(fallback, log)
			m.rehashUnstagedLocked(ctx, fallback, log)
			return
		}
		log.Error().Str("vm_id", pb.VMID).
			Msg("staged pause backup dropped: staged artifacts missing")
		m.dropStagedPending(pb, log)
		return
	}
	baseSrc := pb.DiskBasePath
	if pb.DiskBasePath != "" {
		if pin := filepath.Join(pb.StagedDir, backup.BasePinName); !fileMissing(pin) {
			// The pin froze the pause-time inode: no identity proof
			// needed, and template GC cannot invalidate the pair.
			baseSrc = pin
		} else {
			cur, err := baseIdentity(pb.DiskBasePath)
			if err != nil {
				if os.IsNotExist(err) {
					// The base is definitively gone (template GC after a
					// destroy) and was never pinned: the pair can never
					// ship. Terminal, not transient.
					log.Error().Str("vm_id", pb.VMID).
						Msg("staged pause backup dropped: unpinned base deleted")
					m.dropStagedPending(pb, log)
					return
				}
				log.Warn().Err(err).Str("vm_id", pb.VMID).
					Msg("staged pause backup inconclusive: base identity unreadable; keeping pending record")
				m.healPendingBackup(pb, log)
				return
			}
			if pb.BaseIdentity == "" || cur != pb.BaseIdentity {
				log.Error().Str("vm_id", pb.VMID).
					Msg("staged pause backup dropped: overlay base no longer the pause-time file")
				m.dropStagedPending(pb, log)
				return
			}
		}
	}
	hashStart := time.Now()
	tHash := time.Now()
	entries := collectPauseManifest(ctx, pb.SnapshotPath, pb.DiskPath, baseSrc, pb.DiskBasePath, log)
	m.recordPhases("pause", "", map[string]time.Duration{"manifest_hash": time.Since(tHash)})
	m.backupMetrics.RecordHashDuration(ctx, time.Since(hashStart))
	if !pauseManifestComplete(entries) {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("staged pause backup hash failed transiently; keeping pending record")
		m.healPendingBackup(pb, log)
		return
	}
	if baseSrc != pb.DiskBasePath {
		// The manifest hashed the pin; the recorded identity stays the
		// real base path.
		for i := range entries {
			if entries[i].BasePath != "" {
				entries[i].BasePath = pb.DiskBasePath
			}
		}
	}
	files := make([]backup.TaskFile, 0, len(entries))
	for _, e := range entries {
		files = append(files, backup.TaskFile{
			Name: e.FileName, Path: e.Path, SHA256: e.SHA256, Size: e.SizeBytes,
			BasePath: e.BasePath, BaseSHA256: e.BaseSHA256,
		})
	}
	// The base joins the staging tree too (immutable, identity-pinned
	// above), so the enqueued task is FULLY staged and needs no at-rest
	// fallback, which could not succeed for a resumed sandbox anyway.
	if pb.DiskBasePath != "" {
		baseStageStart := time.Now()
		stagedBase, err := backup.StageSharedBase(m.backupStaging, baseSrc, baseSHAFromEntries(entries), false)
		m.backupMetrics.RecordStageDuration(ctx, time.Since(baseStageStart))
		if err != nil {
			log.Warn().Err(err).Str("vm_id", pb.VMID).
				Msg("staged pause backup: base staging failed; keeping pending record")
			m.healPendingBackup(pb, log)
			return
		}
		for i := range entries {
			if entries[i].BasePath != "" {
				entries[i].BaseStagedPath = stagedBase
			}
		}
	}
	gen := backup.GenerationKey(files)
	// Persist the FINAL locations before renaming, and require the write
	// to land: with the marker updated first, a crash at any later point
	// recovers (the fallback below finds the pending directory when the
	// rename has not happened yet), while a failed marker write simply
	// returns with the still-accurate pending-path marker for a later
	// retry. Proceeding past a failed write would risk a marker pointing
	// at a path the rename is about to delete.
	final := pb
	final.StagedDir = filepath.Join(filepath.Dir(pb.StagedDir), gen)
	final.SnapshotPath = filepath.Join(final.StagedDir, "vmstate.snap")
	final.DiskPath = filepath.Join(final.StagedDir, "rootfs.ext4")
	if !m.persistPendingBackupChecked(final, log) {
		m.healPendingBackup(pb, log)
		return
	}
	finalPaths, err := backup.FinishPendingStage(pb.StagedDir, gen, map[string]string{
		"vmstate.snap": pb.SnapshotPath,
		"rootfs.ext4":  pb.DiskPath,
	})
	if err != nil {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("staged pause backup: rename to generation failed; keeping pending record")
		return
	}
	pb = final
	// Promote the finalized generation from the RPC path's always-local
	// tree (pauseStagingRoot) into the uploader-visible tree it actually
	// hashes and streams from (backupStaging) — which may be a
	// different disk, moved there specifically to keep that repeated
	// read traffic off the array serving live VM I/O. This runs off the
	// RPC path (backupPause returned long ago), so paying a real
	// cross-filesystem copy here is fine even though it would not be on
	// the pause path itself. When the two roots are the same tree (the
	// default, unconfigured case) StageTask's reuse-if-present check
	// finds the destination already there and does no actual I/O.
	uploadPaths := finalPaths
	if m.backupStaging != "" {
		promoted := &backup.Task{
			SandboxID:  pb.VMID,
			Generation: gen,
			Files: []backup.TaskFile{
				{Name: "vmstate.snap", Path: finalPaths["vmstate.snap"]},
				{Name: "rootfs.ext4", Path: finalPaths["rootfs.ext4"]},
			},
		}
		if err := backup.StageTask(m.backupStaging, promoted); err != nil {
			log.Warn().Err(err).Str("vm_id", pb.VMID).
				Msg("staged pause backup: promotion to upload-visible staging failed; keeping pending record")
			return
		}
		uploadPaths = make(map[string]string, len(promoted.Files))
		for _, f := range promoted.Files {
			uploadPaths[f.Name] = f.Path
		}
	}
	for i := range entries {
		if p, ok := uploadPaths[entries[i].FileName]; ok {
			entries[i].Path = p
		}
	}
	if ok, _, _ := m.enqueueBackup(pb.VMID, entries, pb.backupPriority(), pb.PauseToken); ok {
		m.deletePendingBackupIf(pb, log)
		// Deliberately NOT cleaning up the local (pauseStagingRoot) copy
		// here, even though it is usually redundant once promotion has
		// landed a copy in the upload-visible tree: the journal dedupes
		// same-generation enqueues by content, and a row that was already
		// Staged (e.g. queued by a pre-promotion deploy, or a previous
		// attempt at this exact generation) keeps ITS OWN paths rather
		// than adopting this call's — enqueueBackup succeeding here is
		// no proof the journal actually points at the promoted copy
		// rather than still at this local one. pauseStagingRoot's own
		// periodic sweep is the safe cleanup path: it only reclaims a
		// generation once the journal has no pending row for it at all
		// (SweepStaging's HasPending check), which by construction can't
		// be true while any row — old paths or new — still needs a copy
		// of this generation to exist somewhere.
		return
	}
	m.retryEnqueue(pb, entries, log)
}

// persistPendingBackupChecked is persistPendingBackup with a hard
// success requirement, for ordering-sensitive callers.
func (m *Manager) persistPendingBackupChecked(pb PendingBackup, log zerolog.Logger) bool {
	if m.state == nil {
		return true
	}
	if err := m.state.PutPendingBackupIfOwner(pb); err != nil {
		log.Warn().Err(err).Str("vm_id", pb.VMID).
			Msg("persist of renamed staged paths failed; keeping pending-path marker")
		return false
	}
	// PutPendingBackupIfOwner silently yields to a NEWER token; confirm
	// this token still owns the slot before acting on the "persisted"
	// state, or a stale worker would rename under the newer pause's
	// marker.
	cur, ok, err := m.state.GetPendingBackup(pb.VMID)
	if err != nil || !ok || cur.Token != pb.Token {
		log.Warn().Str("vm_id", pb.VMID).
			Msg("newer pause owns the marker; abandoning this worker's rename")
		return false
	}
	return true
}

// baseSHAFromEntries returns the disk entry's base digest.
func baseSHAFromEntries(entries []ManifestEntry) string {
	for _, e := range entries {
		if e.BaseSHA256 != "" {
			return e.BaseSHA256
		}
	}
	return ""
}

// reusablePendingBackup returns the live marker covering this exact
// pause (same original snapshot path AND same snapshot file identity,
// staged copies still present), so a control-plane retry of the pause
// reuses the first copy instead of staging a second. The identity check
// is load-bearing: a VM's snapshot path is fixed across pauses, so a
// resume-then-pause-again reuses the exact same pathname as a still-live
// marker from the earlier pause, and matching on path alone would treat
// that distinct pause as a retry and skip staging its actual disk state.
func (m *Manager) reusablePendingBackup(vmID, snapshotPath string) (PendingBackup, bool) {
	if m.state == nil {
		return PendingBackup{}, false
	}
	prev, ok, err := m.state.GetPendingBackup(vmID)
	if err != nil || !ok || prev.StagedDir == "" {
		return PendingBackup{}, false
	}
	if prev.OrigSnapshotPath != snapshotPath || fileMissing(prev.DiskPath) {
		return PendingBackup{}, false
	}
	id, err := baseIdentity(snapshotPath)
	if err != nil || prev.SnapshotIdentity == "" || id != prev.SnapshotIdentity {
		return PendingBackup{}, false
	}
	return prev, true
}

// resolveStagedLocation handles the crash window between the marker
// adopting final generation paths and the rename that creates them: if
// the marker's staged files are absent but the pause's pending-token
// directory still exists, the worker resumes from the pending location
// and re-runs the persist-then-rename sequence.
func (m *Manager) resolveStagedLocation(pb PendingBackup) PendingBackup {
	if !fileMissing(pb.DiskPath) || pb.Token == "" {
		return pb
	}
	pendingDir := filepath.Join(filepath.Dir(pb.StagedDir), "pending-"+pb.Token)
	if _, err := os.Stat(pendingDir); err != nil {
		return pb
	}
	pb.StagedDir = pendingDir
	pb.SnapshotPath = filepath.Join(pendingDir, "vmstate.snap")
	pb.DiskPath = filepath.Join(pendingDir, "rootfs.ext4")
	return pb
}

// dropStagedPending clears an unrecoverable staged marker and its
// pending directory (post-rename generation dirs are ack-owned).
func (m *Manager) dropStagedPending(pb PendingBackup, log zerolog.Logger) {
	// Only pending-token directories are marker-owned; a post-rename
	// generation directory may be referenced by a queued journal task
	// and belongs to ack cleanup and the sweep.
	if pb.StagedDir != "" && strings.HasPrefix(filepath.Base(pb.StagedDir), "pending-") {
		_ = os.RemoveAll(pb.StagedDir)
	}
	m.deletePendingBackupIf(pb, log)
}

// RenewPendingStaging refreshes the staging mtime of every durable
// pending-backup marker's staged directory. Call BEFORE the startup
// staging sweep, which runs synchronously ahead of reattach and thus
// ahead of RecoverPendingBackups: a marker that outlived the process by
// more than the sweep's orphan horizon is otherwise indistinguishable
// from an abandoned directory, and the sweep deletes it — discarding the
// only durable copy of an otherwise-recoverable pause. Needs only the
// BoltDB state (no instance map), so it's safe to call this early.
func (m *Manager) RenewPendingStaging(log zerolog.Logger) int {
	if m.state == nil {
		return 0
	}
	pending, err := m.state.ListPendingBackups()
	if err != nil {
		log.Warn().Err(err).Msg("renew pending staging: list failed")
		return 0
	}
	renewed := 0
	for _, pb := range pending {
		if pb.StagedDir == "" {
			continue
		}
		// A marker persisted with its final generation path just before a
		// crash prevented the rename that creates it (see
		// resolveStagedLocation) names a directory that does not exist
		// yet; renewing that path touches nothing, leaving the real
		// pending-token directory that still holds the artifacts
		// unrenewed and indistinguishable from an orphan to the sweep.
		resolved := m.resolveStagedLocation(pb)
		backup.RenewStaged(resolved.StagedDir)
		renewed++
	}
	return renewed
}

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

// backfillProgressEvery paces backfill progress logs: frequent enough to
// show liveness on a multi-hour pass, rare enough not to flood.
const backfillProgressEvery = 250

// BackfillPausedBackups walks the durable VM records and mints a
// pending-backup marker for every paused sandbox whose current snapshot
// has never been through the backup pipeline, then drains each marker
// through the existing rehash flow. It exists for fleets that predate
// the uploader: their sandboxes paused before backup was enabled and
// will never pause again on their own, so without this sweep their only
// copy stays on host-local disk forever.
//
// Safe to re-run: a durable per-VM ledger records the snapshot identity
// each mint covered, so reruns and later boots skip everything already
// handled and only pick up snapshots that changed (and a changed
// snapshot means a pause happened, whose own flow already covered it;
// the re-mint converges on the same content-addressed generation).
// Backfill work rides PriorityBestEffort in the journal and holds at
// most one shared rehash slot, so live pause backups always win both the
// hashing budget and the upload queue. Call after reattach for the same
// reason as RecoverPendingBackups: the at-rest verdict reads the
// instance map.
func (m *Manager) BackfillPausedBackups(ctx context.Context, log zerolog.Logger) {
	m.backfillCapturing.Store(true)
	defer func() {
		m.backfillCapturing.Store(false)
		m.lastSandboxEnqueue.Range(func(k, _ any) bool {
			m.lastSandboxEnqueue.Delete(k)
			return true
		})
	}()
	if m.backupEnqueue == nil || m.state == nil {
		return
	}
	m.ensureRehashSlots()
	recs, err := m.state.All()
	if err != nil {
		log.Error().Err(err).Msg("backup backfill: listing vm records failed")
		return
	}
	live := make(map[string]struct{}, len(recs))
	var minted, covered, unreadable, writeFailed int
	for _, rec := range recs {
		live[rec.ID] = struct{}{}
		if ctx.Err() != nil {
			return
		}
		if rec.Status != StatusPaused || rec.SnapshotPath == "" || rec.DiskPath == "" {
			continue
		}
		id, err := baseIdentity(rec.SnapshotPath)
		if err != nil {
			// Missing or unreadable snapshot: nothing to back up right now.
			// Deliberately not recorded in the ledger, so a rerun retries.
			unreadable++
			continue
		}
		if prev, gen, ok, err := m.state.GetBackfillMark(rec.ID); err == nil && ok && prev == id && gen != "" {
			// The mark binds the snapshot to the exact generation its
			// mint enqueued, so the probe is a point lookup: pending or
			// completed for THAT generation. An older generation's
			// completion (even one still in flight when the mark was
			// written) can never satisfy it, and an abandoned upload
			// makes the mark stale and re-mints below. Probe errors keep
			// the skip (transient journal trouble must not stampede
			// re-hashing), and a nil probe trusts the ledger as before.
			stale := false
			if m.backupCovered != nil {
				probe := backup.Task{SandboxID: rec.ID, Generation: gen}
				if cov, err := m.backupCovered(probe); err == nil && !cov {
					stale = true
				}
			}
			if !stale {
				covered++
				continue
			}
		}
		pb := newPendingBackup(rec.ID, rec.SnapshotPath, rec.DiskPath, rec.BasePath, "")
		pb.BestEffort = true
		wrote, err := m.state.PutPendingBackupIfAbsent(pb)
		if err != nil {
			log.Warn().Err(err).Str("vm_id", rec.ID).Msg("backup backfill: marker write failed")
			writeFailed++
			continue
		}
		if !wrote {
			// A marker already owns this VM's coverage (a live pause's, or
			// one retained on a transient failure); the sweep retries it on
			// its own cadence.
			covered++
			continue
		}
		minted++
		select {
		case m.rehashSlots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		gen, ran := m.rehashPendingBackup(ctx, pb, log)
		<-m.rehashSlots
		// Ledger AFTER the mint's synchronous rehash, bound to the
		// generation the guarded flow itself returned: the capture is
		// read while the per-VM guard is still held, so it cannot belong
		// to any other worker. A yielded run (ran=false) or a mint that
		// enqueued nothing writes no mark; the marker machinery owns the
		// outcome and the next pass re-evaluates.
		if ran && gen != "" {
			if err := m.state.PutBackfillMark(rec.ID, id, gen); err != nil {
				log.Warn().Err(err).Str("vm_id", rec.ID).Msg("backup backfill: ledger write failed")
			}
		}
		if minted%backfillProgressEvery == 0 {
			log.Info().Int("minted", minted).Int("already_covered", covered).
				Msg("backup backfill progress")
		}
	}
	if err := m.state.PruneBackfillMarks(live); err != nil {
		log.Warn().Err(err).Msg("backup backfill: ledger prune failed")
	}
	log.Info().Int("minted", minted).Int("already_covered", covered).
		Int("snapshot_unreadable", unreadable).Int("marker_write_failed", writeFailed).
		Msg("backup backfill pass complete")
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
		ok, s, _ := m.enqueueBackup(pb.VMID, manifest, pb.backupPriority(), pb.PauseToken)
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
// the overlay base's and the snapshot's stat identity at creation so the
// rehash can prove it is hashing the pause-time base and not a
// same-path replacement, and so a later pause of the same VM (fixed
// snapshot pathname) can be told apart from a retry of this one.
func newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath, pauseToken string) PendingBackup {
	pb := PendingBackup{
		VMID: vmID, SnapshotPath: snapshotPath, DiskPath: diskPath, DiskBasePath: diskBasePath,
		Token: newPendingToken(), PauseToken: pauseToken,
	}
	if diskBasePath != "" {
		if id, err := baseIdentity(diskBasePath); err == nil {
			pb.BaseIdentity = id
		}
	}
	if id, err := baseIdentity(snapshotPath); err == nil {
		pb.SnapshotIdentity = id
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
	return m.pausedAt(vmID, snapshotPath) && m.vmConfirmedAtRest(ctx, vmID)
}

// vmConfirmedAtRest reports whether the sandbox's Firecracker is fully
// stopped so its artifacts are byte-stable — the at-rest proof every backup
// gates on. It requires BOTH possible supervisors quiet, deliberately NOT
// dispatching on the recorded mode: a crash between a launch and its persist
// leaves the record's mode behind reality (a scope-gone fallback starts a
// unit over a cgroup record; an armed resume starts a cgroup FC over a unit
// record), and the recorded mode's oracle then answers vacuously while the
// other supervisor's guest is still writing. The unit claim is TERMINAL
// (unitFullyDown, not the weaker "not active" that calls a deactivating unit
// dead while it may still flush guest writes); the cgroup claim is a
// conclusively empty-or-absent group (populated or unreadable is not at
// rest, and no delegated subtree means no cgroup FC can exist). Overridable
// for tests via the unitDead seam, which stands in for the whole probe.
func (m *Manager) vmConfirmedAtRest(ctx context.Context, vmID string) bool {
	if m.unitDead != nil {
		return m.unitDead(ctx, vmID)
	}
	if !knownSupervision(m.supervisionForVM(vmID)) {
		// A mode this binary predates may supervise through a mechanism
		// neither oracle below can see — never at rest.
		return false
	}
	if m.cgroupStillLive(vmID) {
		return false
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

// backupPriority is the journal tier a marker's generation uploads at:
// best-effort for backfill-minted markers, pause priority for markers a
// real pause minted.
func (pb PendingBackup) backupPriority() backup.Priority {
	if pb.BestEffort {
		return backup.PriorityBestEffort
	}
	return backup.PriorityPause
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
func (m *Manager) enqueueBackup(vmID string, manifest []ManifestEntry, prio backup.Priority, pauseToken string) (bool, bool, string) {
	if m.backupEnqueue == nil || len(manifest) == 0 {
		return false, false, ""
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
		return false, false, ""
	}
	task := backup.Task{
		SandboxID: vmID,
		// Keyed on every artifact digest: any changed artifact means a new
		// generation, so create-only dedupe can never mix old and new
		// objects under one prefix.
		Generation: backup.GenerationKey(files),
		Files:      files,
		Priority:   prio,
		PauseToken: pauseToken,
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
			stageStart := time.Now()
			stageErr := backup.StageTask(m.backupStaging, &task)
			m.backupMetrics.RecordStageDuration(context.Background(), time.Since(stageStart))
			if stageErr != nil {
				m.log.Warn().Err(stageErr).Str("vm_id", vmID).
					Msg("backup staging failed; uploading from original paths")
			} else if after, err := os.Stat(diskPath); err == nil &&
				os.SameFile(before, after) &&
				before.ModTime().Equal(after.ModTime()) && before.Size() == after.Size() &&
				m.atRest(probeCtx(), vmID, snapPath) {
				staged = true
			} else {
				m.log.Warn().Str("vm_id", vmID).
					Msg("sandbox left at-rest during staging; uploading from original paths")
				task = rebuildTask(vmID, manifest, prio, pauseToken)
			}
		}
	}
	task.Staged = staged && m.backupStaging != ""
	if err := m.backupEnqueue(task); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).
			Msg("backup enqueue failed; pause not journaled")
		return false, false, ""
	}
	if m.backfillCapturing.Load() {
		m.lastSandboxEnqueue.Store(vmID, task.Generation)
	}
	return true, staged, task.Generation
}

// probeCtx bounds a systemd liveness probe: these run on detached
// workers whose own contexts are generous, and an unresponsive systemd
// must fail the probe (inconclusive) rather than hang the worker.
func probeCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = cancel // bounded by the deadline; the probe is short-lived
	return ctx
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
func rebuildTask(vmID string, manifest []ManifestEntry, prio backup.Priority, pauseToken string) backup.Task {
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
		Priority:   prio,
		PauseToken: pauseToken,
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
