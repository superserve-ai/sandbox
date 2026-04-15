package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/superserve-ai/sandbox/internal/builder"
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
}

// BuildTemplateResult is returned on success.
type BuildTemplateResult struct {
	SnapshotPath   string
	MemFilePath    string
	RootfsPath     string
	ResolvedDigest string // sha256:... of the resolved base image
	SizeBytes      int64  // on-disk rootfs size
}

// SetBuilder attaches a Builder used by BuildTemplate. Must be called before
// BuildTemplate fires. Separate from NewManager so the builder can be
// optional for vmd deployments that don't do builds (test envs, etc.).
func (m *Manager) SetBuilder(b builder.Builder) {
	m.builder = b
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
	if m.builder == nil {
		return "", fmt.Errorf("builder not configured on manager; call SetBuilder before BuildTemplate")
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

	buildVMID := "build-" + req.TemplateID

	// Fresh context so the build survives the caller's HTTP request
	// ending. CancelBuild is what stops it.
	buildCtx, cancel := context.WithCancel(context.Background())

	if _, err := m.registerBuild(buildVMID, req.TemplateID, cancel); err != nil {
		cancel()
		return "", err
	}

	go m.buildTemplateWorker(buildCtx, buildVMID, req)

	return buildVMID, nil
}

// buildTemplateWorker is the goroutine body. Runs one build end-to-end and
// records the outcome in the registry. Never returns an error — all failures
// are logged and surfaced via completeBuild so GetBuildStatus sees them.
func (m *Manager) buildTemplateWorker(ctx context.Context, buildVMID string, req BuildTemplateRequest) {
	result, err := m.buildTemplateSync(ctx, buildVMID, req)
	m.completeBuild(buildVMID, result, err)
}

// buildTemplateSync does the actual work. Called by the async worker, but
// separated so integration tests can exercise the pipeline without going
// through the registry + goroutine. Callers MUST pass a buildVMID unique
// on this host.
func (m *Manager) buildTemplateSync(ctx context.Context, buildVMID string, req BuildTemplateRequest) (*BuildTemplateResult, error) {
	log := m.log.With().Str("template_id", req.TemplateID).Str("build_vm_id", buildVMID).Str("from", req.Spec.From).Logger()
	log.Info().Msg("starting template build")
	buildStart := time.Now()

	// Layout on disk, mirroring InitDefaultTemplate's convention but under
	// a templates/<id>/ subtree so concurrent builds don't collide:
	//   ${RunDir}/templates/<id>/rootfs.ext4
	//   ${SnapshotDir}/templates/<id>/vmstate.snap
	//   ${SnapshotDir}/templates/<id>/mem.snap
	rootfsDir := filepath.Join(m.cfg.RunDir, "templates", req.TemplateID)
	rootfsPath := filepath.Join(rootfsDir, "rootfs.ext4")
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, "templates", req.TemplateID)

	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir rootfs dir: %w", err)
	}
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir snapshot dir: %w", err)
	}

	// Phase 1: produce the rootfs.ext4.
	br, err := m.builder.BuildRootfs(ctx, req.Spec, rootfsPath, req.DiskMiB)
	if err != nil {
		return nil, fmt.Errorf("build rootfs: %w", err)
	}
	log.Info().Str("digest", br.ResolvedDigest).Int64("size_bytes", br.SizeBytes).Dur("elapsed", time.Since(buildStart)).Msg("rootfs produced")

	// Phase 2: cold-boot a build VM from that rootfs.
	inst, err := m.coldBootFromRootfs(ctx, buildVMID, rootfsPath, req.VCPU, req.MemoryMiB)
	if err != nil {
		return nil, fmt.Errorf("boot build VM: %w", err)
	}

	// From here on, any failure must tear down the VM so it doesn't linger.
	cleanup := func(reason string) {
		log.Warn().Str("reason", reason).Msg("tearing down build VM after failure")
		_ = m.DestroyVM(context.Background(), buildVMID, true)
	}

	// Phase 3: wait for the injected boxd to come up.
	if err := m.waitForBoxd(ctx, inst.IP, 30*time.Second); err != nil {
		cleanup("boxd not ready")
		return nil, fmt.Errorf("boxd not ready on build VM: %w", err)
	}
	log.Info().Dur("elapsed", time.Since(buildStart)).Msg("build VM up and boxd ready")

	// Phase 4: execute build steps in order. On failure, tear down the
	// build VM and propagate the error — we don't snapshot a half-built
	// template.
	if err := m.executeBuildSteps(ctx, buildVMID, inst.IP, req.Spec, log); err != nil {
		cleanup("build steps failed")
		return nil, fmt.Errorf("execute build steps: %w", err)
	}

	// Phase 5: start_cmd — launch the long-lived process whose live state
	// we want the snapshot to capture. Fire-and-forget; we don't wait for
	// exit because the point is to keep it running.
	if err := m.runStartCmd(ctx, buildVMID, inst.IP, req.Spec, log); err != nil {
		cleanup("start_cmd failed")
		return nil, fmt.Errorf("launch start_cmd: %w", err)
	}

	// Phase 5b: ready_cmd — block until the start process is actually
	// serving, so the snapshot captures a useful state. No-op if unset.
	if err := m.pollReadyCmd(ctx, buildVMID, inst.IP, req.Spec, log); err != nil {
		cleanup("ready_cmd timed out")
		return nil, fmt.Errorf("ready_cmd: %w", err)
	}

	// Phase 6: snapshot the running VM. Memory + vmstate land on disk.
	// Flip the registry status so the supervisor (and SDK poller) can tell
	// when user-step execution ends and the pause/dump phase begins.
	m.setBuildStatus(buildVMID, BuildStatusSnapshotting)
	m.appendBuildLog(buildVMID, BuildLogEvent{Stream: LogStreamSystem, Text: "snapshotting"})
	snapPath, memPath, err := m.CreateVMSnapshot(ctx, buildVMID, snapshotDir)
	if err != nil {
		cleanup("snapshot failed")
		return nil, fmt.Errorf("snapshot build VM: %w", err)
	}
	log.Info().Str("snapshot", snapPath).Str("mem", memPath).Dur("elapsed", time.Since(buildStart)).Msg("snapshot captured")

	// Phase 7: kill the build VM, keep its rundir so the rootfs.ext4 stays
	// available for future sandbox creations (they copy from it on create).
	m.killVMKeepRunDir(buildVMID)

	// Persist the digest alongside the snapshot for audit / future cache
	// keying. Best-effort — failure is logged but not fatal.
	writeBuildMeta(snapshotDir, br)

	// Phase 8: register the template so CreateVM can use it.
	m.mu.Lock()
	m.templates[req.TemplateID] = &TemplateSnapshot{
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
		DiskPath:     rootfsPath,
		RunDir:       rootfsDir,
		VCPUCount:    req.VCPU,
		MemSizeMiB:   req.MemoryMiB,
	}
	m.mu.Unlock()

	log.Info().Dur("total_ms", time.Since(buildStart)).Msg("template build complete")

	return &BuildTemplateResult{
		SnapshotPath:   snapPath,
		MemFilePath:    memPath,
		RootfsPath:     rootfsPath,
		ResolvedDigest: br.ResolvedDigest,
		SizeBytes:      br.SizeBytes,
	}, nil
}

// writeBuildMeta persists the build metadata (digest, size, timestamp) next
// to the snapshot so it's discoverable on disk. Useful for post-mortem and
// for a future build cache that keys on digest.
func writeBuildMeta(dir string, br builder.BuildRootfsResult) {
	meta := struct {
		ResolvedDigest string `json:"resolved_digest"`
		SizeBytes      int64  `json:"size_bytes"`
		BuiltAt        string `json:"built_at"`
	}{
		ResolvedDigest: br.ResolvedDigest,
		SizeBytes:      br.SizeBytes,
		BuiltAt:        time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "build.meta.json"), data, 0o644)
}
