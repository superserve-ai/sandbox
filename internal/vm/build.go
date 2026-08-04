package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// BuildTemplateRequest is the input to Manager.BuildTemplate.
type BuildTemplateRequest struct {
	// TemplateID is the key under which the produced snapshot is registered
	// in the templates map. Typically the template_id from the DB row.
	TemplateID string

	// Spec is the canonical build specification (what to build).
	Spec builder.BuildSpec

	// VCPU / MemoryMiB / DiskMiB define the build VM shape. The produced
	// snapshot inherits this shape — it IS the sandbox shape, since
	// Firecracker can't restore a snapshot at a different memory size.
	VCPU      uint32
	MemoryMiB uint32
	DiskMiB   uint32

	// BuildVMID overrides the default "build-<template_id>" record key.
	BuildVMID string
}

// BuildTemplateResult is returned on success.
type BuildTemplateResult struct {
	SnapshotPath   string
	MemFilePath    string
	RootfsPath     string
	BasePath       string // overlay-mode templates only
	DeltaPath      string // overlay-mode templates only
	ResolvedDigest string // sha256:... of the resolved base image
	SizeBytes      int64  // on-disk rootfs size
}

// BuildTemplate starts a template build asynchronously and returns the
// build VM id immediately. Use GetBuildStatus(build_vm_id) to poll progress
// and CancelBuild(build_vm_id) to abort.
//
// The actual work (pull + boot + steps + snapshot + register) runs in a
// detached goroutine with a fresh context so the caller's HTTP request
// cancellation doesn't kill an in-flight build — the supervisor polls via
// GetBuildStatus instead.
func (m *Manager) BuildTemplate(ctx context.Context, req BuildTemplateRequest) (string, error) {
	if req.TemplateID == "" {
		return "", fmt.Errorf("template_id is required")
	}
	if req.Spec.From == "" {
		return "", fmt.Errorf("spec.from is required")
	}
	if m.cfg.TemplateBuilderBin == "" {
		return "", fmt.Errorf("template-builder binary not configured (set ManagerConfig.TemplateBuilderBin)")
	}
	if req.VCPU == 0 {
		req.VCPU = 1
	}
	if req.MemoryMiB == 0 {
		req.MemoryMiB = 1024
	}
	if req.DiskMiB == 0 {
		req.DiskMiB = 4096
	}

	buildVMID := req.BuildVMID
	if buildVMID == "" {
		buildVMID = "build-" + req.TemplateID
	}

	// Fresh context so the build survives the caller's HTTP request
	// ending. CancelBuild is what stops it.
	buildCtx, cancel := context.WithCancel(context.Background())

	if _, err := m.registerBuild(buildVMID, req.TemplateID, cancel); err != nil {
		cancel()
		return "", err
	}

	go func() { defer sentrylog.Recover("build-worker"); m.buildTemplateWorker(buildCtx, buildVMID, req) }()

	return buildVMID, nil
}

// buildTemplateWorker is the goroutine body. Runs one build end-to-end and
// records the outcome in the registry. Never returns an error — all failures
// are logged and surfaced via completeBuild so GetBuildStatus sees them.
func (m *Manager) buildTemplateWorker(ctx context.Context, buildVMID string, req BuildTemplateRequest) {
	result, err := m.buildTemplateSync(ctx, buildVMID, req)
	m.completeBuild(buildVMID, result, err)
}

// buildTemplateSync delegates the build to the template-builder subprocess.
// The subprocess owns its own network, Firecracker process, and boxd
// connection — completely isolated from vmd's sandbox state.
func (m *Manager) buildTemplateSync(ctx context.Context, buildVMID string, req BuildTemplateRequest) (*BuildTemplateResult, error) {
	log := m.log.With().Str("template_id", req.TemplateID).Str("build_vm_id", buildVMID).Str("from", req.Spec.From).Logger()
	log.Info().Msg("starting template build (subprocess)")
	buildStart := time.Now()

	specJSON, err := json.Marshal(req.Spec)
	if err != nil {
		return nil, fmt.Errorf("marshal spec: %w", err)
	}

	// Claim a slot from vmd's authoritative allocator so the subprocess's
	// ns-<idx>/veth-<idx> can't collide with a sandbox slot, and release it (with
	// any kernel residue) when the build exits — success, failure, or panic.
	slotIndex, err := m.netMgr.ClaimFreshSlot(buildVMID)
	if err != nil {
		return nil, fmt.Errorf("reserve build network slot: %w", err)
	}
	slotReleased := false
	releaseSlot := func() {
		if !slotReleased {
			slotReleased = true
			m.netMgr.ReleaseSlot(buildVMID, slotIndex)
		}
	}
	defer releaseSlot()

	cmd := exec.CommandContext(ctx, m.cfg.TemplateBuilderBin,
		"--template-id", req.TemplateID,
		"--build-id", buildVMID,
		"--spec", string(specJSON),
		"--vcpu", fmt.Sprint(req.VCPU),
		"--memory", fmt.Sprint(req.MemoryMiB),
		"--disk", fmt.Sprint(req.DiskMiB),
		"--run-dir", m.cfg.RunDir,
		"--snapshot-dir", m.cfg.SnapshotDir,
		"--kernel", m.cfg.KernelPath,
		"--firecracker", m.cfg.FirecrackerBin,
		"--boxd", m.cfg.BoxdBinaryPath,
		"--host-interface", m.cfg.HostInterface,
		"--slot-index", fmt.Sprint(slotIndex),
	)

	// Stdout carries structured NDJSON build events — parse and forward
	// to the build log buffer so SSE subscribers see real-time progress.
	pipe := &buildLogPipe{buildVMID: buildVMID, mgr: m}
	cmd.Stdout = pipe
	cmd.Stderr = os.Stderr

	// Graceful cancel: SIGTERM lets template-builder's cleanup defers run;
	// WaitDelay escalates to SIGKILL if it hangs past 30s.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second

	// Build VM's working dir. template-builder names it "build-<templateID>"
	// (not vmd's buildVMID), so we clean that exact path. Done here because
	// template-builder's own defer can't run on SIGKILL.
	defer os.RemoveAll(filepath.Join(m.cfg.RunDir, "build-"+req.TemplateID))

	if err := cmd.Run(); err != nil {
		// Prefer the structured reason the subprocess emitted on its way
		// out ("image_pull_failed: ...", "step_failed: ...", etc.) over
		// the opaque "exit status 1" from os/exec.
		if pipe.lastError != "" {
			return nil, fmt.Errorf("%s", pipe.lastError)
		}
		return nil, fmt.Errorf("template-builder exited: %w", err)
	}

	// Read result from disk. build.meta.json + on-disk snapshot files are
	// the source of truth; no in-memory registration needed because the
	// sandbox create path reads snapshot paths from the control plane DB
	// and calls RestoreSnapshot with those paths directly.
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, req.TemplateID, buildVMID)
	result, err := readBuildMetaJSON(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("read build meta: %w", err)
	}

	// Best-effort: a missing access.log just means sandboxes fall back
	// to sequential prefetch. The "build-" prefix must remain so isBuildVM
	// skips persistence + reconciler for this throwaway VM.
	if m.cfg.UffdEnabled && m.cfg.UffdPrefetchEnabled {
		recordingVMID := "build-record-" + req.TemplateID
		accessLogPath := filepath.Join(snapshotDir, accessLogFilename)
		recCfg := VMConfig{
			VCPU:      req.VCPU,
			MemoryMiB: req.MemoryMiB,
			BasePath:  result.BasePath,
			DeltaDir:  snapshotDir,
		}
		if recErr := m.RecordAccessPattern(ctx, recordingVMID, result.SnapshotPath, result.MemFilePath, accessLogPath, recCfg, nil); recErr != nil {
			log.Warn().Err(recErr).Msg("access-pattern recording failed (sandbox will fall back to sequential prefetch)")
		}
	}

	// The subprocess is gone and the recording VM claims its own slot, so
	// the build's ns-<idx>/veth-<idx> reservation guards nothing anymore.
	// Release it before the hashing below: holding a network slot through
	// minutes of disk reads would shrink sandbox capacity for no reason.
	releaseSlot()

	// Durability: hash the finished artifact set (access.log included when
	// recorded above), stamp the digests into build.meta.json, and enqueue
	// the build for backup. Best-effort by design: the artifacts on disk
	// are valid regardless, so nothing in here fails the build.
	//
	// Deliberately synchronous: the build is reported ready only after its
	// integrity record exists, at the cost of the completion (and any
	// supervisor timeout budget) covering up to the hash budget for large
	// artifact sets. The duration is logged so that tradeoff stays visible.
	hashStart := time.Now()
	m.backupBuildArtifacts(ctx, req.TemplateID, buildVMID, snapshotDir, result.BasePath, nil, log)
	log.Info().Dur("backup_hash", time.Since(hashStart)).Msg("build backup pass finished")

	log.Info().Dur("total", time.Since(buildStart)).Msg("template build complete")
	return result, nil
}

// backupBuildArtifacts makes a finished build's artifact set durable: hash
// the snapshot directory plus the base image build.meta.json references
// (it lives in the run dir but the template is not restorable without it),
// record the digests into build.meta.json so the on-host artifacts carry
// their integrity data the way pause artifacts do, then enqueue the set
// (build.meta.json included) into the backup journal.
//
// Fails closed on completeness: the manifest object's presence in the
// bucket means "restorable", so a set missing even one artifact is never
// enqueued. The build itself still succeeds; the gap is surfaced by the
// warn log and coverage monitoring, then retried by the template sweep.
//
// guard, when non-nil, is consulted before any mutation (the digest stamp
// and the enqueue): reconcile workers run concurrently with new builds
// that can reuse the same build id and directory, and a guard that
// returns false drops the work silently because the newer build covers
// itself. The completion path passes nil (it IS the newest build).
func (m *Manager) backupBuildArtifacts(ctx context.Context, templateID, buildVMID, snapshotDir, basePath string, guard func() bool, log zerolog.Logger) {
	// No enqueue hook means backup is disabled on this host (BACKUP_BUCKET
	// unset). Bail before any hashing: the digests exist to feed the backup
	// journal, and with no consumer the only effect would be delaying every
	// successful build by up to buildHashBudget plus the metadata hash.
	// Same gate as the pause path, just hoisted ahead of the hashing
	// instead of inside the enqueue.
	if m.backupEnqueue == nil {
		return
	}
	entries, complete := collectBuildManifest(ctx, snapshotDir, []string{basePath}, log)
	if len(entries) == 0 {
		log.Warn().Str("dir", snapshotDir).
			Msg("build manifest hashed no artifacts; build not enqueued for backup")
		return
	}
	if !complete {
		log.Warn().Str("dir", snapshotDir).
			Msg("build artifact set hashed incompletely; build not enqueued for backup")
		return
	}
	// Directory enumeration only proves what exists, not what should: an
	// artifact that was never written (or already deleted) never reaches
	// the hasher, so `complete` alone would bless the gap. Judge the set
	// against the paths build.meta.json declares before publishing.
	meta, err := readBuildMetaJSON(snapshotDir)
	if err != nil {
		log.Warn().Err(err).Msg("build manifest: reread build.meta.json failed; build not enqueued for backup")
		return
	}
	hashed := make(map[string]bool, len(entries))
	for _, e := range entries {
		hashed[e.FileName] = true
	}
	for _, p := range meta.declaredArtifactPaths() {
		if p == "" || hashed[filepath.Base(p)] {
			continue
		}
		log.Warn().Str("artifact", filepath.Base(p)).
			Msg("required build artifact missing from hashed set; build not enqueued for backup")
		return
	}
	if guard != nil && !guard() {
		return
	}
	if err := writeBuildDigests(snapshotDir, entries); err != nil {
		log.Warn().Err(err).Msg("recording artifact digests into build.meta.json failed")
	}
	// The stamp above legitimately changed the meta's identity, so a
	// guard pinning it would now always fail against our own write. From
	// here the only rebuild-race signal left is an active registration.
	postStamp := guard
	if guard != nil {
		postStamp = func() bool { return !m.buildActive(buildVMID) }
	}
	m.finishBuildBackupEnqueue(ctx, templateID, buildVMID, snapshotDir, entries, postStamp, log)
}

// finishBuildBackupEnqueue hashes build.meta.json last so the backed-up
// copy is the one carrying the digests it was given by writeBuildDigests;
// its own digest travels in the task (and the generation manifest), never
// inside itself. Then the whole set goes to the journal. guard has the
// same contract as in backupBuildArtifacts: consulted right before the
// enqueue, false drops the work silently.
func (m *Manager) finishBuildBackupEnqueue(ctx context.Context, templateID, buildVMID, snapshotDir string, entries []ManifestEntry, guard func() bool, log zerolog.Logger) {
	metaPath := filepath.Join(snapshotDir, buildMetaFilename)
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	sum, size, err := hashFile(hctx, metaPath)
	if err != nil {
		log.Warn().Err(err).Msg("hashing build.meta.json failed; build not enqueued for backup")
		return
	}
	entries = append(entries, ManifestEntry{
		FileName:  buildMetaFilename,
		Path:      metaPath,
		SizeBytes: size,
		SHA256:    sum,
	})
	if guard != nil && !guard() {
		return
	}
	if m.enqueueTemplateBackup(templateID, buildVMID, entries) {
		return
	}
	// Only the journal write failed; the digests in hand describe the
	// finished artifacts and are already stamped into build.meta.json, so
	// the retry needs no rehash. Async so neither build completion nor a
	// status poll ever blocks on journal recovery, mirroring the pause
	// path's retryEnqueue. Unlike pause, no pending marker is persisted:
	// the stamped meta IS the durable retry state, and the template sweep
	// (this process or the next) rebuilds this exact task from it.
	log.Warn().Msg("template backup journal write failed; retrying enqueue")
	go m.retryTemplateEnqueue(templateID, buildVMID, entries, log)
}

// retryTemplateEnqueue re-attempts a template build's journal write with
// bounded backoff. Exhausted retries are logged at error level and left
// to the periodic template sweep, which re-reconciles every uncovered
// ready build from its stamped meta, in this process and after restarts.
func (m *Manager) retryTemplateEnqueue(templateID, buildVMID string, entries []ManifestEntry, log zerolog.Logger) {
	if retryWithBackoff(func() bool { return m.enqueueTemplateBackup(templateID, buildVMID, entries) }) {
		log.Info().Msg("template backup enqueued after retry")
		return
	}
	log.Error().Str("template_id", templateID).Str("build_vm_id", buildVMID).
		Msg("template backup journal writes kept failing; template sweep owns the retry")
}

// readStampedBuildDigests returns the artifact digests writeBuildDigests
// previously stamped into build.meta.json; nil when the build never got
// that far (crash before or during hashing).
func readStampedBuildDigests(snapshotDir string) ([]buildArtifactDigest, error) {
	data, err := os.ReadFile(filepath.Join(snapshotDir, buildMetaFilename))
	if err != nil {
		return nil, err
	}
	var meta struct {
		Artifacts []buildArtifactDigest `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return meta.Artifacts, nil
}

// buildActive reports whether a NON-terminal registration exists for this
// build id: a new build is currently producing artifacts in the same
// directory a reconcile worker would stamp.
func (m *Manager) buildActive(buildVMID string) bool {
	m.buildsMu.RLock()
	defer m.buildsMu.RUnlock()
	rec, ok := m.builds[buildVMID]
	return ok && !rec.Status.IsTerminal()
}

// reconcileAdoptedBuildBackup re-enters an adopted completed build into the
// backup pipeline. A vmd exit between template-builder writing
// build.meta.json and the enqueue (a window as long as the hash budget)
// leaves a durable, adoptable build with no journal record; without this,
// such a template would stay unbacked until rebuilt. One in-flight worker
// per build id, asynchronous so adoption (a status read path) is never
// serialized behind hash budgets, and routed through the shared rehash
// slots so a backlog of adopted builds cannot saturate disk bandwidth
// (skipped workers are retried by the periodic template sweep).
//
// Rebuilds can legitimately reuse a build id (the default id is
// build-<templateID>) and therefore the same directory. A worker that
// raced such a rebuild must not stamp stale digests over the new build's
// meta, so before any mutation it verifies no non-terminal registration
// exists for the id AND that build.meta.json is still the exact file it
// read (stat identity, the same pin the pause path uses for bases);
// either failing drops the reconcile silently, because the newer build
// covers its own backup.
//
// Two cases, keyed on whether writeBuildDigests already stamped the meta:
//
//   - no stamped digests: the crash predates hashing, so run the full
//     pipeline (hash, stamp, enqueue) exactly as build completion would.
//   - stamped digests whose sizes still match the files on disk: rebuild
//     the task from the record instead of re-hashing multi-GiB artifacts.
//     The journal dedupes by owner + generation (and the completions
//     record blocks re-uploads after ack), and the uploader re-verifies
//     streamed bytes against these digests, so divergence fails closed.
//   - stamped digests whose size does NOT match the disk (truncation,
//     partial restore): the record is provably stale, so fall through to
//     the full re-hash, which stamps fresh digests and enqueues a correct
//     new generation instead of abandoning the stale one forever.
func (m *Manager) reconcileAdoptedBuildBackup(snap BuildStatusSnapshot) {
	m.reconcileAdoptedBuildBackupMode(snap, false)
}

// reconcileAdoptedBuildBackupMode reconciles with the caller's choice of
// slot policy. The sweep passes waitForSlot=true: its glob order is
// deterministic, so a non-blocking drop would let the same early-sorted
// builds consume the slots every pass and starve a later build forever;
// blocking guarantees every match is processed each sweep, still bounded
// by the slot count (covered builds hold a slot for milliseconds). The
// request-path caller keeps the non-blocking drop, since an API call
// must not park behind multi-GB hash work; the sweep covers whatever it
// drops.
func (m *Manager) reconcileAdoptedBuildBackupMode(snap BuildStatusSnapshot, waitForSlot bool) {
	if m.backupEnqueue == nil || snap.Status != BuildStatusReady || snap.Result == nil {
		return
	}
	// Keyed by template AND build id: build ids are reusable across
	// templates, and a buildVMID-only key would let one template's
	// in-flight reconcile permanently starve another's same-named build.
	inflightKey := snap.TemplateID + "\x00" + snap.BuildVMID
	handle := &reconcileHandle{done: make(chan struct{})}
	rctx, rcancel := context.WithCancel(context.Background())
	handle.cancel = rcancel
	if _, busy := m.adoptedBuildBackups.LoadOrStore(inflightKey, handle); busy {
		rcancel()
		return
	}
	slots := m.ensureRehashSlots()
	if waitForSlot {
		slots <- struct{}{}
	} else {
		select {
		case slots <- struct{}{}:
		default:
			// All rehash slots busy: drop this attempt rather than
			// queueing unbounded hash work; the sweep retries uncovered
			// builds.
			close(handle.done)
			rcancel()
			m.adoptedBuildBackups.Delete(inflightKey)
			return
		}
	}
	templateID, buildVMID, res := snap.TemplateID, snap.BuildVMID, snap.Result
	dir := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, templateID, buildVMID)
	metaPath := filepath.Join(dir, buildMetaFilename)
	log := m.log.With().Str("template_id", templateID).Str("build_vm_id", buildVMID).Logger()
	go func() {
		defer func() {
			<-slots
			close(handle.done)
			rcancel()
			m.adoptedBuildBackups.Delete(inflightKey)
		}()
		metaID, err := baseIdentity(metaPath)
		if err != nil {
			log.Warn().Err(err).Msg("adopted build meta unreadable; reconcile skipped")
			return
		}
		guard := func() bool {
			// A registration for this build id cancels rctx and AWAITS
			// this goroutine's exit, so a guard that honors cancellation
			// makes the check-and-write atomic with respect to rebuilds:
			// no stamp or enqueue can land after a new build has been
			// admitted for the same directory.
			if rctx.Err() != nil {
				return false
			}
			if m.buildActive(buildVMID) {
				return false
			}
			cur, err := baseIdentity(metaPath)
			return err == nil && cur == metaID
		}
		if !guard() {
			return
		}
		stamped, err := readStampedBuildDigests(dir)
		if err != nil || len(stamped) == 0 {
			log.Info().Err(err).
				Msg("adopted build has no stamped digests; running backup hashing")
			m.backupBuildArtifacts(rctx, templateID, buildVMID, dir, res.BasePath, guard, log)
			return
		}
		entries := make([]ManifestEntry, 0, len(stamped)+1)
		for _, d := range stamped {
			path := filepath.Join(dir, d.Name)
			fi, statErr := os.Stat(path)
			if statErr != nil {
				// The base image lives in the run dir, not the snapshot
				// dir; anything else unresolvable means the stamp no
				// longer matches the disk, so re-hash from scratch.
				if res.BasePath != "" && d.Name == filepath.Base(res.BasePath) {
					path = res.BasePath
					fi, statErr = os.Stat(path)
				}
				if statErr != nil {
					log.Warn().Str("artifact", d.Name).
						Msg("stamped artifact not on disk; running backup hashing")
					m.backupBuildArtifacts(rctx, templateID, buildVMID, dir, res.BasePath, guard, log)
					return
				}
			}
			if fi.Size() != d.SizeBytes {
				log.Warn().Str("artifact", d.Name).
					Int64("stamped", d.SizeBytes).Int64("on_disk", fi.Size()).
					Msg("stamped artifact size diverged; running backup hashing")
				m.backupBuildArtifacts(rctx, templateID, buildVMID, dir, res.BasePath, guard, log)
				return
			}
			entries = append(entries, ManifestEntry{
				FileName:  d.Name,
				Path:      path,
				SizeBytes: d.SizeBytes,
				SHA256:    d.SHA256,
			})
		}
		log.Info().Int("files", len(entries)).
			Msg("adopted build re-enqueued for backup from stamped digests")
		m.finishBuildBackupEnqueue(rctx, templateID, buildVMID, dir, entries, guard, log)
	}()
}

// reconcileHandle lets a rebuild registration cancel an in-flight
// adoption reconcile for the same template+build and await its exit.
type reconcileHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// RecoverTemplateBackups reconciles every ready on-disk build whose
// current generation is neither pending in the journal nor recorded as
// completed, then keeps sweeping periodically. This is the durable-retry
// trigger the in-memory paths cannot provide: once a build's registry row
// is terminal the supervisor stops polling, so exhausted enqueue retries,
// process death during an async retry, or a fail-closed refusal at
// completion would otherwise drop the template's backup with only a log.
// Call alongside RecoverPendingBackups; no-op when backup is disabled.
func (m *Manager) RecoverTemplateBackups(ctx context.Context, log zerolog.Logger) {
	if m.backupEnqueue == nil {
		return
	}
	m.runTemplateBackupSweep(log)
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
				m.runTemplateBackupSweep(log)
			}
		}
	}()
}

// runTemplateBackupSweep scans SnapshotDir/templates/<tpl>/<build>/ for
// adoptable completed builds and hands each to the reconcile flow, which
// owns the covered check (via the enqueue), the rebuild-race guard, the
// in-flight dedupe, and the shared hash bound.
func (m *Manager) runTemplateBackupSweep(log zerolog.Logger) {
	pattern := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, "*", "*", buildMetaFilename)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Error().Err(err).Msg("template backup sweep: glob failed")
		return
	}
	for _, metaPath := range matches {
		dir := filepath.Dir(metaPath)
		buildVMID := filepath.Base(dir)
		templateID := filepath.Base(filepath.Dir(dir))
		// An active rebuild owns the directory; its completion path owns
		// the backup. Checked again under the reconcile guard, this early
		// skip just avoids pointless worker churn.
		if m.buildActive(buildVMID) {
			continue
		}
		res, err := readBuildMetaJSON(dir)
		if err != nil || !buildArtifactsPresent(res) {
			continue // half-written or partially deleted build: not adoptable
		}
		m.reconcileAdoptedBuildBackupMode(BuildStatusSnapshot{
			BuildVMID:  buildVMID,
			TemplateID: templateID,
			Status:     BuildStatusReady,
			Result:     res,
		}, true)
	}
}

// buildLogPipe parses NDJSON lines from template-builder's stdout and
// forwards them to the build log buffer for SSE streaming.
//
// Stream "error" events are also captured in lastError so
// buildTemplateSync can report the real cause of a non-zero exit instead
// of the generic "template-builder exited: exit status 1".
type buildLogPipe struct {
	buildVMID string
	mgr       *Manager
	buf       []byte
	lastError string
}

func (p *buildLogPipe) Write(data []byte) (int, error) {
	p.buf = append(p.buf, data...)
	for {
		idx := bytes.IndexByte(p.buf, '\n')
		if idx < 0 {
			break
		}
		line := p.buf[:idx]
		p.buf = p.buf[idx+1:]
		var evt struct {
			Visibility string `json:"visibility"`
			Stream     string `json:"stream"`
			Text       string `json:"text"`
		}
		if json.Unmarshal(line, &evt) != nil || evt.Text == "" {
			continue
		}
		// Internal events stay in the operator journal so we can diagnose
		// production issues without leaking platform plumbing into the
		// customer-visible build log stream.
		if evt.Visibility == "internal" {
			p.mgr.log.Info().
				Str("build_vm_id", p.buildVMID).
				Str("stream", evt.Stream).
				Msg(evt.Text)
			continue
		}
		if evt.Stream == "error" {
			p.lastError = evt.Text
		}
		p.mgr.appendBuildLog(p.buildVMID, BuildLogEvent{
			Stream: LogStream(evt.Stream),
			Text:   evt.Text,
		})
	}
	return len(data), nil
}

// buildMetaFilename is the metadata file template-builder writes into the
// build's snapshot directory; vmd later stamps artifact digests into it
// (writeBuildDigests).
const buildMetaFilename = "build.meta.json"

// readBuildMetaJSON reads the build.meta.json written by template-builder.
func readBuildMetaJSON(snapshotDir string) (*BuildTemplateResult, error) {
	data, err := os.ReadFile(filepath.Join(snapshotDir, buildMetaFilename))
	if err != nil {
		return nil, err
	}
	var meta struct {
		SnapshotPath   string `json:"snapshot_path"`
		MemPath        string `json:"mem_path"`
		RootfsPath     string `json:"rootfs_path"`
		BasePath       string `json:"base_path"`
		DeltaPath      string `json:"delta_path"`
		ResolvedDigest string `json:"resolved_digest"`
		SizeBytes      int64  `json:"size_bytes"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &BuildTemplateResult{
		SnapshotPath:   meta.SnapshotPath,
		MemFilePath:    meta.MemPath,
		RootfsPath:     meta.RootfsPath,
		BasePath:       meta.BasePath,
		DeltaPath:      meta.DeltaPath,
		ResolvedDigest: meta.ResolvedDigest,
		SizeBytes:      meta.SizeBytes,
	}, nil
}

// declaredArtifactPaths lists every artifact file build.meta.json
// declares (empty entries for modes that lack them). The single source
// for both the adoption presence check and the backup completeness
// check, so a future artifact field cannot be added to one and silently
// escape the other.
func (r *BuildTemplateResult) declaredArtifactPaths() []string {
	return []string{r.SnapshotPath, r.MemFilePath, r.RootfsPath, r.BasePath, r.DeltaPath}
}

// buildArtifactDigest is one artifact's integrity record inside
// build.meta.json's "artifacts" field.
type buildArtifactDigest struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// writeBuildDigests rewrites build.meta.json with an "artifacts" field
// carrying the hashed artifact set. The document is edited as raw JSON so
// every field template-builder wrote (including ones vmd does not model)
// survives the round trip, and the replace is atomic so readers
// (loadDurableBuild, the backup drain) never observe a torn file.
func writeBuildDigests(snapshotDir string, entries []ManifestEntry) error {
	path := filepath.Join(snapshotDir, buildMetaFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("parse %s: %w", buildMetaFilename, err)
	}
	digests := make([]buildArtifactDigest, 0, len(entries))
	for _, e := range entries {
		digests = append(digests, buildArtifactDigest{
			Name:      e.FileName,
			SHA256:    e.SHA256,
			SizeBytes: e.SizeBytes,
		})
	}
	raw, err := json.Marshal(digests)
	if err != nil {
		return err
	}
	meta["artifacts"] = raw
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp name (not a fixed <path>.tmp): a crash between write
	// and rename leaves residue behind, and a fixed name would let the
	// next stamping pass rename a STALE temp over a fresh meta. The
	// pattern keeps the .tmp suffix so collectBuildManifest excludes any
	// residue from the artifact set.
	f, err := os.CreateTemp(snapshotDir, buildMetaFilename+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(out); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncPath(snapshotDir)
}

// syncPath fsyncs a file or directory by path.
func syncPath(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
