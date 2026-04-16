package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

	slotIndex := int(m.nextBuildSlot.Add(1)) + 199

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
	cmd.Stdout = &buildLogPipe{buildVMID: buildVMID, mgr: m}
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("template-builder exited: %w", err)
	}

	// Read result from disk.
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, "templates", req.TemplateID)
	rootfsDir := filepath.Join(m.cfg.RunDir, "templates", req.TemplateID)
	result, err := readBuildMetaJSON(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("read build meta: %w", err)
	}

	// Register the template so CreateVM / RestoreSnapshot can use it.
	m.mu.Lock()
	m.templates[req.TemplateID] = &TemplateSnapshot{
		SnapshotPath: result.SnapshotPath,
		MemFilePath:  result.MemFilePath,
		DiskPath:     result.RootfsPath,
		RunDir:       rootfsDir,
		VCPUCount:    req.VCPU,
		MemSizeMiB:   req.MemoryMiB,
	}
	m.mu.Unlock()

	log.Info().Dur("total", time.Since(buildStart)).Msg("template build complete")
	return result, nil
}

// buildLogPipe parses NDJSON lines from template-builder's stdout and
// forwards them to the build log buffer for SSE streaming.
type buildLogPipe struct {
	buildVMID string
	mgr       *Manager
	buf       []byte
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
			Stream string `json:"stream"`
			Text   string `json:"text"`
		}
		if json.Unmarshal(line, &evt) == nil && evt.Text != "" {
			p.mgr.appendBuildLog(p.buildVMID, BuildLogEvent{
				Stream: LogStream(evt.Stream),
				Text:   evt.Text,
			})
		}
	}
	return len(data), nil
}

// readBuildMetaJSON reads the build.meta.json written by template-builder.
func readBuildMetaJSON(snapshotDir string) (*BuildTemplateResult, error) {
	data, err := os.ReadFile(filepath.Join(snapshotDir, "build.meta.json"))
	if err != nil {
		return nil, err
	}
	var meta struct {
		SnapshotPath   string `json:"snapshot_path"`
		MemPath        string `json:"mem_path"`
		RootfsPath     string `json:"rootfs_path"`
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
		ResolvedDigest: meta.ResolvedDigest,
		SizeBytes:      meta.SizeBytes,
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
