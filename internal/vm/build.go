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
	defer m.netMgr.ReleaseSlot(buildVMID, slotIndex)

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

	// Durability: hash the finished artifact set (access.log included when
	// recorded above), stamp the digests into build.meta.json, and enqueue
	// the build for backup. Best-effort by design: the artifacts on disk
	// are valid regardless, so nothing in here fails the build.
	m.backupBuildArtifacts(ctx, req.TemplateID, buildVMID, snapshotDir, result.BasePath, log)

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
// warn log and coverage monitoring, never papered over.
func (m *Manager) backupBuildArtifacts(ctx context.Context, templateID, buildVMID, snapshotDir, basePath string, log zerolog.Logger) {
	// No enqueue hook means backup is disabled on this host (BACKUP_BUCKET
	// unset). Bail before any hashing: the digests exist to feed the backup
	// journal, and with no consumer the only effect would be delaying every
	// successful build by up to buildHashBudget plus the metadata hash while
	// the build's claimed network slot sits idle. Same gate as the pause
	// path, just hoisted ahead of the hashing instead of inside the enqueue.
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
	if err := writeBuildDigests(snapshotDir, entries); err != nil {
		log.Warn().Err(err).Msg("recording artifact digests into build.meta.json failed")
	}
	// Hash build.meta.json last so the backed-up copy is the one carrying
	// the digests it was just given; its own digest travels in the task
	// (and the generation manifest), never inside itself.
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
	m.enqueueTemplateBackup(templateID, buildVMID, entries)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := syncPath(tmp); err != nil {
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
