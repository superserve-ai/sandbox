package vm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// templateDirName is the fixed directory name used for the template VM's
// rundir. The snapshot's path_on_host references this directory. Each new VM
// gets its own mount namespace where a tmpfs is mounted over this directory
// and the per-VM rootfs is symlinked in — so every Firecracker process sees
// its own files at the same fixed path.
const templateDirName = "template"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// VMStatus represents the lifecycle state of a microVM.
type VMStatus int

const (
	StatusCreating VMStatus = iota
	StatusRunning
	StatusPaused
	StatusStopped
	StatusError
)

func (s VMStatus) String() string {
	switch s {
	case StatusCreating:
		return "creating"
	case StatusRunning:
		return "running"
	case StatusPaused:
		return "paused"
	case StatusStopped:
		return "stopped"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// VMInstance holds the runtime state of a single microVM.
type VMInstance struct {
	ID           string
	PID          int
	SocketPath   string
	VsockPath    string
	IP           string
	TAPDevice    string
	MACAddress   string
	Status       VMStatus
	Config       VMConfig
	RunDirID     string // Directory name under RunDir for this VM's files.
	Namespace    string // Network namespace name.
	DiskPath     string
	SnapshotPath string
	MemFilePath  string
	CreatedAt    time.Time
	Metadata     map[string]string

	mu sync.RWMutex
}

// VMConfig describes the desired configuration for a VM.
type VMConfig struct {
	VCPU        uint32
	MemoryMiB   uint32
	DiskSizeMiB uint32
	KernelPath  string
	KernelArgs  string
	RootfsPath  string
}

// ManagerConfig holds paths and settings for the VM manager.
type ManagerConfig struct {
	FirecrackerBin     string
	JailerBin          string
	KernelPath         string
	BaseRootfsPath     string
	SnapshotDir        string
	RunDir             string
	MaxConcurrent      int    // Max concurrent CreateVM operations (0 = default 10).
	TemplateBuilderBin string // Path to template-builder binary.
	BoxdBinaryPath     string // Path to boxd binary (passed to template-builder).
	HostInterface      string // Host network interface (e.g. "ens4").
}

// TemplateSnapshot holds paths for a template snapshot created at startup.
type TemplateSnapshot struct {
	SnapshotPath string // e.g., snapshots/template/vmstate.snap
	MemFilePath  string // e.g., snapshots/template/mem.snap
	DiskPath     string // e.g., rundir/template/rootfs.ext4
	RunDir       string // e.g., rundir/template/
	VCPUCount    uint32 // actual vCPU count baked into the snapshot
	MemSizeMiB   uint32 // actual RAM in MiB baked into the snapshot
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager orchestrates the lifecycle of Firecracker microVMs.
type Manager struct {
	cfg         ManagerConfig
	netMgr      *network.Manager
	egressProxy *network.EgressProxy
	log         zerolog.Logger
	state       *StateStore // persistent local state (BoltDB); nil = no persistence

	mu        sync.RWMutex
	vms       map[string]*VMInstance
	// templates is keyed by template ID. The baked-in default template is
	// registered under "default" by InitDefaultTemplate. Build-produced
	// templates are registered here by BuildTemplate.
	templates map[string]*TemplateSnapshot
	createSem chan struct{}

	// builds tracks in-flight and completed template builds. Keyed by
	// build VM id (which is also "build-" + templateID). Entries survive
	// until process exit so late pollers can read terminal outcomes; a
	// V2 sweep can evict old records if memory becomes a concern.
	buildsMu sync.RWMutex
	builds   map[string]*buildRecord

	// nextBuildSlot assigns unique network slot indices to concurrent
	// template-builder subprocesses. Starts at 200 to avoid collision
	// with vmd's sandbox pool (indices 1-100).
	nextBuildSlot atomic.Int32
}

// DefaultTemplateID is the key under which the baked-in default template is
// registered in the templates map. CreateVM falls back to this when no
// template_id is provided.
const DefaultTemplateID = "default"

// NewManager creates a new VM manager.
func NewManager(cfg ManagerConfig, netMgr *network.Manager, log zerolog.Logger) (*Manager, error) {
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	return &Manager{
		cfg:       cfg,
		netMgr:    netMgr,
		log:       log.With().Str("component", "vm_manager").Logger(),
		vms:       make(map[string]*VMInstance),
		templates: make(map[string]*TemplateSnapshot),
		createSem: make(chan struct{}, maxConcurrent),
	}, nil
}

// SetStateStore attaches a BoltDB state store for durable persistence.
// Must be called before any VM operations.
func (m *Manager) SetStateStore(s *StateStore) {
	m.state = s
}

// SetEgressProxy sets the TCP egress proxy for domain-based filtering.
// Must be called before any VMs are created.
func (m *Manager) SetEgressProxy(proxy *network.EgressProxy) {
	m.egressProxy = proxy
}

// templateRunDir returns the fixed path where the template VM's files live.
func (m *Manager) templateRunDir() string {
	return filepath.Join(m.cfg.RunDir, templateDirName)
}

// ---------------------------------------------------------------------------
// InitDefaultTemplate — boot once, snapshot, reuse forever
// ---------------------------------------------------------------------------

// InitDefaultTemplate ensures a template snapshot is available for fast
// sandbox creation. If a valid cached template exists and the base rootfs
// hasn't changed since it was built, the cached template is reused —
// skipping the ~2-3s cold boot entirely. This makes VMD restarts fast
// when only the VMD binary changed (the common deploy case).
//
// The template is rebuilt only when:
//   - No cached snapshot exists on disk (first boot)
//   - The base rootfs hash changed (new boxd version baked in)
//   - The cached snapshot files are missing or corrupt
func (m *Manager) InitDefaultTemplate(ctx context.Context) error {
	templateID := templateDirName
	log := m.log.With().Str("template_id", templateID).Logger()

	snapshotDir := filepath.Join(m.cfg.SnapshotDir, templateDirName)
	snapPath := filepath.Join(snapshotDir, "vmstate.snap")
	memPath := filepath.Join(snapshotDir, "mem.snap")
	diskPath := filepath.Join(m.templateRunDir(), "rootfs.ext4")
	hashPath := filepath.Join(snapshotDir, "rootfs.sha256")

	// Check if we can reuse the cached template.
	currentHash, hashErr := fileHash(m.cfg.BaseRootfsPath)
	if hashErr != nil {
		log.Warn().Err(hashErr).Msg("could not hash base rootfs — will rebuild template")
	}

	metaPath := filepath.Join(snapshotDir, "template.meta")

	if hashErr == nil && m.canReuseTemplate(snapPath, memPath, diskPath, hashPath, currentHash) {
		vcpu, mem := readTemplateMeta(metaPath)
		log.Info().Uint32("vcpu", vcpu).Uint32("mem_mib", mem).Msg("base rootfs unchanged — reusing cached template snapshot")
		m.mu.Lock()
		m.templates[DefaultTemplateID] = &TemplateSnapshot{
			SnapshotPath: snapPath,
			MemFilePath:  memPath,
			DiskPath:     diskPath,
			RunDir:       m.templateRunDir(),
			VCPUCount:    vcpu,
			MemSizeMiB:   mem,
		}
		m.mu.Unlock()
		return nil
	}

	// Cache miss — cold boot a throwaway VM, snapshot it, kill it.
	log.Info().Msg("building new template — cold-booting throwaway VM")

	inst, err := m.coldBootVM(ctx, templateID)
	if err != nil {
		return fmt.Errorf("boot template VM: %w", err)
	}

	if err := m.waitForBoxd(ctx, inst.IP, 30*time.Second); err != nil {
		_ = m.DestroyVM(ctx, templateID, true)
		return fmt.Errorf("boxd not ready: %w", err)
	}
	log.Info().Msg("guest agent ready — creating template snapshot")

	snapPath, memPath, err = m.CreateVMSnapshot(ctx, templateID, snapshotDir)
	if err != nil {
		_ = m.DestroyVM(ctx, templateID, true)
		return fmt.Errorf("snapshot template VM: %w", err)
	}

	diskPath = inst.DiskPath
	m.killVMKeepRunDir(templateID)

	// Persist the rootfs hash and resource values so the next startup
	// can skip the cold boot and restore the correct template config.
	if currentHash != "" {
		_ = os.WriteFile(hashPath, []byte(currentHash), 0o644)
	}
	writeTemplateMeta(metaPath, inst.Config.VCPU, inst.Config.MemoryMiB)

	m.mu.Lock()
	m.templates[DefaultTemplateID] = &TemplateSnapshot{
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
		DiskPath:     diskPath,
		RunDir:       m.templateRunDir(),
		VCPUCount:    inst.Config.VCPU,
		MemSizeMiB:   inst.Config.MemoryMiB,
	}
	m.mu.Unlock()

	log.Info().
		Str("snapshot_path", snapPath).
		Str("disk_path", diskPath).
		Msg("default template ready")
	return nil
}

// getTemplate returns the snapshot registered under templateID, or the default
// template when templateID is empty. Returns nil if the requested template is
// not registered (caller should 404 or fall back).
func (m *Manager) getTemplate(templateID string) *TemplateSnapshot {
	if templateID == "" {
		templateID = DefaultTemplateID
	}
	m.mu.RLock()
	tmpl := m.templates[templateID]
	m.mu.RUnlock()
	return tmpl
}

// readTemplateMeta reads the vCPU and memory values persisted alongside
// the template snapshot. Returns safe defaults (1 vCPU, 1024 MiB) if the
// file is missing or unreadable.
func readTemplateMeta(path string) (vcpu, memMiB uint32) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 1, 1024
	}
	var v, m uint32
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d %d", &v, &m); err != nil {
		return 1, 1024
	}
	return v, m
}

func writeTemplateMeta(path string, vcpu, memMiB uint32) {
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d %d", vcpu, memMiB)), 0o644)
}

// canReuseTemplate returns true when all template files exist on disk and
// the stored rootfs hash matches the current base image.
func (m *Manager) canReuseTemplate(snapPath, memPath, diskPath, hashPath, currentHash string) bool {
	for _, p := range []string{snapPath, memPath, diskPath} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	stored, err := os.ReadFile(hashPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(stored)) == currentHash
}

// fileHash returns the SHA-256 hex digest of a file.
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// CreateVM — single code path via template snapshot restore
// ---------------------------------------------------------------------------

// CreateVM provisions a new Firecracker microVM by restoring from a template
// snapshot. Each VM gets its own rootfs copy and runs in a mount namespace
// that maps the per-VM rootfs to the template's fixed path. When templateID
// is empty, falls back to the baked-in "default" template.
func (m *Manager) CreateVM(ctx context.Context, vmID string, templateID string, netCfg *network.Config, metadata map[string]string,
) (*VMInstance, error) {
	if vmID == "" {
		vmID = uuid.New().String()
	}

	tmpl := m.getTemplate(templateID)

	// If no template is ready (e.g., during InitDefaultTemplate itself and
	// templateID is empty), fall through to cold boot. For a non-empty
	// templateID that isn't registered, return an explicit NotFound so the
	// caller can surface a clear error.
	if tmpl == nil {
		if templateID == "" || templateID == DefaultTemplateID {
			return m.coldBootVM(ctx, vmID)
		}
		return nil, status.Errorf(codes.NotFound, "template %s not registered on this host", templateID)
	}

	// Verify template snapshot files are still intact.
	if err := m.checkTemplateHealth(tmpl); err != nil {
		return nil, fmt.Errorf("template unhealthy: %w", err)
	}

	// Limit concurrent CreateVM operations to prevent host overload.
	select {
	case m.createSem <- struct{}{}:
		defer func() { <-m.createSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	createStart := time.Now()
	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Msg("creating VM from template snapshot")

	m.mu.Lock()
	if _, exists := m.vms[vmID]; exists {
		m.mu.Unlock()
		return nil, status.Errorf(codes.AlreadyExists, "vm %s already exists", vmID)
	}

	inst := &VMInstance{
		ID:        vmID,
		Status:    StatusCreating,
		CreatedAt: time.Now(),
		Metadata:  metadata,
		RunDirID:  vmID,
		Config: VMConfig{
			VCPU:      tmpl.VCPUCount,
			MemoryMiB: tmpl.MemSizeMiB,
		},
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	cleanup := func() {
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		m.removeVM(vmID)
	}

	// Steps 1 and 2 — copying the rootfs and setting up the network
	// namespace — are independent. Run them in parallel so the total
	// wall-clock for the pair is max(rootfs, netns) instead of their sum.
	// On typical hardware this shaves ~10-30ms off create latency.
	parallelStart := time.Now()

	type rootfsResult struct {
		path string
		err  error
	}
	type netResult struct {
		info *network.VMNetInfo
		err  error
	}
	rootfsCh := make(chan rootfsResult, 1)
	netCh := make(chan netResult, 1)

	go func() {
		p, err := m.copyRootfs(ctx, vmID, tmpl.DiskPath)
		rootfsCh <- rootfsResult{path: p, err: err}
	}()
	go func() {
		info, err := m.netMgr.SetupVM(ctx, vmID, netCfg)
		netCh <- netResult{info: info, err: err}
	}()

	rfs := <-rootfsCh
	nr := <-netCh

	// Both goroutines always run to completion so we know exactly which
	// side(s) succeeded and need unwinding. Tear them down in reverse
	// order of resource ownership: network first (it's tied to kernel
	// state), rundir last (it's just files, handled by cleanup()).
	if rfs.err != nil || nr.err != nil {
		// If the network came up but the rootfs did not, the kernel
		// namespace/veth/firewall state must be explicitly freed; the
		// shared cleanup() only removes the rundir.
		if nr.err == nil {
			m.netMgr.CleanupVM(vmID)
		}
		cleanup()
		switch {
		case rfs.err != nil && nr.err != nil:
			return nil, fmt.Errorf("copy rootfs: %w; setup network: %v", rfs.err, nr.err)
		case rfs.err != nil:
			return nil, fmt.Errorf("copy rootfs: %w", rfs.err)
		default:
			return nil, fmt.Errorf("setup network: %w", nr.err)
		}
	}

	perVMRootfs := rfs.path
	netInfo := nr.info
	// Take inst.mu to write — concurrent readers via ExecCommand /
	// LookupInstance / persistState take RLock.
	inst.mu.Lock()
	inst.DiskPath = perVMRootfs
	inst.IP = netInfo.HostIP
	inst.TAPDevice = netInfo.TAPDevice
	inst.MACAddress = netInfo.MACAddress
	inst.Namespace = netInfo.Namespace
	inst.mu.Unlock()
	log.Debug().Dur("duration_ms", time.Since(parallelStart)).Msg("step: copy rootfs + setup network (parallel)")

	// 3. Start Firecracker in a mount + network namespace.
	startStep := time.Now()
	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	var (
		pid      int
		startErr error
	)
	pid, startErr = m.startFirecrackerViaSystemd(ctx, vmID, socketPath, perVMRootfs, netInfo.Namespace)
	if startErr != nil {
		m.netMgr.CleanupVM(vmID)
		cleanup()
		return nil, fmt.Errorf("start firecracker: %w", startErr)
	}
	inst.mu.Lock()
	inst.SocketPath = socketPath
	inst.PID = pid
	inst.mu.Unlock()
	log.Debug().Dur("duration_ms", time.Since(startStep)).Msg("step: start firecracker")

	// 4. Restore from the original (unpatched) template snapshot.
	// No IP reconfig needed — the VM uses a fixed internal IP (169.254.0.21)
	// and the network namespace provides isolation.
	restoreStep := time.Now()
	if err := RestoreSnapshotWithOverrides(
		socketPath, tmpl.SnapshotPath, tmpl.MemFilePath,
		"eth0", netInfo.TAPDevice,
	); err != nil {
		m.netMgr.CleanupVM(vmID)
		cleanup()
		return nil, fmt.Errorf("restore template snapshot: %w", err)
	}
	log.Debug().Dur("duration_ms", time.Since(restoreStep)).Msg("step: restore snapshot")

	m.setStatus(vmID, StatusRunning)
	// Persist again now that PID, IP, and socket are set.
	m.persistState(inst)
	log.Info().
		Int("pid", pid).
		Str("host_ip", inst.IP).
		Dur("total_ms", time.Since(createStart)).
		Msg("VM created from template snapshot")
	return inst, nil
}

// ---------------------------------------------------------------------------
// coldBootVM — used only for InitDefaultTemplate and as fallback
// ---------------------------------------------------------------------------

// waitForPIDExit polls until the process at pid is gone (kill(pid, 0)
// returns ESRCH) or the deadline expires. Best-effort: returns silently
// either way. Used after SIGKILL to ensure the kernel has actually
// reaped the process and released its fds before we reuse its resources.
func waitForPIDExit(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// syscall.Kill(pid, 0) returns ESRCH when the process is gone.
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// coldBootVM is a thin shim that uses the baked-in BaseRootfsPath and default
// 1-vCPU / 1024-MiB config. Existing callers (InitDefaultTemplate, CreateVM
// fallback) hit this path; BuildTemplate uses coldBootFromRootfs below.
func (m *Manager) coldBootVM(ctx context.Context, vmID string) (*VMInstance, error) {
	return m.coldBootFromRootfs(ctx, vmID, m.cfg.BaseRootfsPath, 1, 1024)
}

// coldBootFromRootfs is the parameterized form: boot a VM from a specific
// rootfs at the requested vcpu/memory. Used by BuildTemplate to boot the
// build VM from a freshly-produced rootfs at the template's target shape.
func (m *Manager) coldBootFromRootfs(ctx context.Context, vmID, rootfsPath string, vcpu, memMiB uint32) (*VMInstance, error) {
	if vmID == "" {
		vmID = uuid.New().String()
	}
	if rootfsPath == "" {
		return nil, fmt.Errorf("rootfsPath is required")
	}
	if vcpu == 0 {
		vcpu = 1
	}
	if memMiB == 0 {
		memMiB = 1024
	}

	m.mu.Lock()
	if _, exists := m.vms[vmID]; exists {
		m.mu.Unlock()
		return nil, status.Errorf(codes.AlreadyExists, "vm %s already exists", vmID)
	}

	inst := &VMInstance{
		ID:        vmID,
		Status:    StatusCreating,
		CreatedAt: time.Now(),
		RunDirID:  vmID,
		Config: VMConfig{
			VCPU:       vcpu,
			MemoryMiB:  memMiB,
			KernelPath: m.cfg.KernelPath,
			RootfsPath: rootfsPath,
		},
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Str("rootfs", rootfsPath).Uint32("vcpu", vcpu).Uint32("mem_mib", memMiB).Msg("cold-booting VM")

	// 1. Copy the rootfs for this VM.
	diskPath, err := m.copyRootfs(ctx, vmID, rootfsPath)
	if err != nil {
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("copy rootfs: %w", err)
	}

	// 2. Set up networking.
	netInfo, err := m.netMgr.SetupVM(ctx, vmID, nil)
	if err != nil {
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("setup network: %w", err)
	}

	// inst is already visible via m.vms; take inst.mu for writes so
	// concurrent readers (ExecCommand, LookupInstance, persistState)
	// see a consistent view.
	inst.mu.Lock()
	inst.DiskPath = diskPath
	inst.IP = netInfo.HostIP
	inst.TAPDevice = netInfo.TAPDevice
	inst.MACAddress = netInfo.MACAddress
	inst.Namespace = netInfo.Namespace
	mac := inst.MACAddress
	inst.mu.Unlock()

	// 3. Build Firecracker machine configuration.
	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	fcCfg := FirecrackerConfig{
		SocketPath: socketPath,
		KernelPath: m.cfg.KernelPath,
		KernelArgs: "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0 random.trust_cpu=on",
		RootfsPath: diskPath,
		VCPUCount:  int(vcpu),
		MemSizeMiB: int(memMiB),
		TAPDevice:  network.TAPName,
		MACAddress: mac,
		VMID:       vmID,
		VMIP:       network.VMInternalIP,
		GatewayIP:  network.VMGatewayIP,
	}

	// 4. Start Firecracker inside the network namespace, configure, and boot.
	pid, err := m.startFirecrackerColdBoot(ctx, vmID, socketPath, fcCfg, netInfo.Namespace)
	if err != nil {
		m.netMgr.CleanupVM(vmID)
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("start firecracker: %w", err)
	}

	inst.mu.Lock()
	inst.SocketPath = socketPath
	inst.PID = pid
	inst.mu.Unlock()

	m.setStatus(vmID, StatusRunning)
	log.Info().Int("pid", pid).Str("host_ip", netInfo.HostIP).Msg("VM cold-booted")
	return inst, nil
}

// ---------------------------------------------------------------------------
// DestroyVM
// ---------------------------------------------------------------------------

// DestroyVM terminates a VM and cleans up all its resources.
func (m *Manager) DestroyVM(ctx context.Context, vmID string, force bool) error {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return err
	}

	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Bool("force", force).Msg("destroying VM")

	// Stop the systemd unit if one exists — this is the path for sandbox
	// VMs launched via startFirecrackerViaSystemd.
	if err := stopUnit(ctx, systemdUnitName(vmID)); err != nil {
		log.Warn().Err(err).Msg("systemctl stop failed (unit may not exist — trying PID-based kill)")
	}
	removeUnitDropIn(vmID)

	// Fallback: cold-booted VMs (template build VMs from startFirecrackerColdBoot
	// and the default-template cold boot) aren't systemd-managed — they run as
	// plain child processes of vmd. stopUnit is a no-op for them, so we have
	// to SIGKILL by PID or Firecracker keeps holding its TAP fd, causing the
	// network pool to hand out a "reusable" slot whose tap0 is still in use.
	// Next VM that claims the slot fails with EBUSY ("Open tap device failed:
	// Resource busy"). See internal/network/manager.go:344 for the pool
	// return path that assumes the previous owner is dead.
	inst.mu.RLock()
	pid := inst.PID
	inst.mu.RUnlock()
	if pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			// SIGKILL is safe here: we're tearing down, no graceful shutdown
			// is expected. For systemd-managed VMs this is a no-op because
			// stopUnit already killed the process.
			_ = proc.Signal(syscall.SIGKILL)
			// Give the kernel a moment to actually release fds before we
			// hand the namespace + TAP back to the pool. 100ms is enough
			// in practice — Linux process teardown is fast once all fds
			// are dropped.
			waitForPIDExit(pid, 500*time.Millisecond)
		}
	}

	if inst.SocketPath != "" {
		_ = os.Remove(inst.SocketPath)
	}

	m.netMgr.CleanupVM(vmID)

	rundirKey := vmID
	if inst.RunDirID != "" {
		rundirKey = inst.RunDirID
	}
	m.cleanupRunDir(rundirKey)
	m.removeVM(vmID)

	log.Info().Msg("VM destroyed")
	return nil
}

// ---------------------------------------------------------------------------
// PauseVM (snapshot + stop)
// ---------------------------------------------------------------------------

// PauseVM snapshots the VM state and then stops the process.
func (m *Manager) PauseVM(ctx context.Context, vmID, snapshotDir string) (snapshotPath, memPath string, err error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", "", err
	}

	log := m.log.With().Str("vm_id", vmID).Logger()

	if snapshotDir == "" {
		snapshotDir = filepath.Join(m.cfg.SnapshotDir, vmID)
	}
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create snapshot dir: %w", err)
	}

	snapshotPath = filepath.Join(snapshotDir, "vmstate.snap")
	memPath = filepath.Join(snapshotDir, "mem.snap")

	log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating snapshot")
	if err := CreateSnapshot(inst.SocketPath, snapshotPath, memPath); err != nil {
		return "", "", m.handleVMError(vmID, fmt.Errorf("create snapshot: %w", err))
	}

	// Stop the Firecracker process — snapshot is already on disk.
	if err := stopUnit(ctx, systemdUnitName(vmID)); err != nil {
		log.Warn().Err(err).Msg("systemctl stop failed during pause")
	}

	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.mu.Unlock()

	m.persistState(inst)
	log.Info().Msg("VM paused")
	return snapshotPath, memPath, nil
}

// ---------------------------------------------------------------------------
// ResumeVM (restore from snapshot)
// ---------------------------------------------------------------------------

// ResumeVM restores a paused VM from its snapshot using a mount namespace.
func (m *Manager) ResumeVM(ctx context.Context, vmID, snapshotPath, memPath string) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()

	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}

	if snapshotPath == "" {
		snapshotPath = inst.SnapshotPath
	}
	if memPath == "" {
		memPath = inst.MemFilePath
	}
	if snapshotPath == "" || memPath == "" {
		return nil, status.Errorf(codes.InvalidArgument, "snapshot_path and mem_file_path are required")
	}

	// Verify the snapshot files actually exist on disk. DB can claim
	// "ready" but the files be missing — common scenarios:
	//   - vmd host replaced; new host has no cached snapshots
	//   - operator manually deleted files for disk recovery
	//   - snapshot directory not mounted
	//
	// Return FailedPrecondition so the caller can distinguish "ops
	// action required" from "transient error" and surface a clear
	// message to the user instead of a generic 500. The caller (control
	// plane) adds context about whether this was a template-sourced or
	// pause-sourced restore.
	if _, err := os.Stat(snapshotPath); err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.FailedPrecondition, "snapshot file missing on host: %s", snapshotPath)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "stat snapshot %s: %v", snapshotPath, err)
	}
	if _, err := os.Stat(memPath); err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.FailedPrecondition, "memory file missing on host: %s", memPath)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "stat mem file %s: %v", memPath, err)
	}

	rundirKey := vmID
	if inst.RunDirID != "" {
		rundirKey = inst.RunDirID
	}

	// The VM's rootfs is at its rundir. Start Firecracker in a mount namespace
	// that maps this rootfs to the template's fixed path (which the snapshot
	// references).
	rootfsPath := inst.DiskPath
	if rootfsPath == "" {
		rootfsPath = filepath.Join(m.cfg.RunDir, rundirKey, "rootfs.ext4")
	}

	vmDir := filepath.Join(m.cfg.RunDir, rundirKey)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	pid, err := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, rootfsPath, inst.Namespace)
	if err != nil {
		return nil, fmt.Errorf("start firecracker for restore: %w", err)
	}

	log.Info().Str("snapshot_path", snapshotPath).Msg("restoring VM from snapshot")
	if err := RestoreSnapshot(socketPath, snapshotPath, memPath); err != nil {
		return nil, fmt.Errorf("restore snapshot: %w", err)
	}

	inst.mu.Lock()
	inst.PID = pid
	inst.SocketPath = socketPath
	inst.Status = StatusRunning
	inst.mu.Unlock()

	m.persistState(inst)
	log.Info().Int("pid", pid).Msg("VM resumed from snapshot")
	return inst, nil
}

// ---------------------------------------------------------------------------
// Snapshot management
// ---------------------------------------------------------------------------

// CreateVMSnapshot captures a point-in-time snapshot of a running VM.
func (m *Manager) CreateVMSnapshot(ctx context.Context, vmID, snapshotDir string) (snapshotPath, memPath string, err error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", "", err
	}

	if snapshotDir == "" {
		snapshotDir = filepath.Join(m.cfg.SnapshotDir, vmID, fmt.Sprintf("snap-%d", time.Now().Unix()))
	}
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create snapshot dir: %w", err)
	}

	snapshotPath = filepath.Join(snapshotDir, "vmstate.snap")
	memPath = filepath.Join(snapshotDir, "mem.snap")

	if err := CreateSnapshot(inst.SocketPath, snapshotPath, memPath); err != nil {
		return "", "", fmt.Errorf("create snapshot: %w", err)
	}

	if err := UnpauseVM(inst.SocketPath); err != nil {
		return snapshotPath, memPath, fmt.Errorf("resume after snapshot: %w", err)
	}

	return snapshotPath, memPath, nil
}

// DeleteSnapshotFiles removes a snapshot's on-disk artifacts (vmstate + memory
// file). Both paths must resolve to locations under the configured snapshot
// directory — arbitrary paths are rejected as InvalidArgument to prevent the
// control plane from accidentally (or maliciously) unlinking unrelated files.
//
// The operation is idempotent: missing files are not an error. The enclosing
// directory is removed on a best-effort basis once both files are gone and it
// is empty; a non-empty directory is left alone.
//
// Callers are responsible for ensuring the snapshot is no longer referenced
// by any running VM. This method does not inspect instance state.
func (m *Manager) DeleteSnapshotFiles(snapshotPath, memPath string) error {
	if snapshotPath == "" && memPath == "" {
		return status.Error(codes.InvalidArgument, "at least one of snapshot_path/mem_file_path is required")
	}
	for _, p := range []string{snapshotPath, memPath} {
		if p == "" {
			continue
		}
		if err := m.assertUnderSnapshotDir(p); err != nil {
			return err
		}
	}

	for _, p := range []string{snapshotPath, memPath} {
		if p == "" {
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	// Best-effort: if the parent directory is now empty, clean it up. Any
	// error here is swallowed — a non-empty or missing directory is fine.
	for _, p := range []string{snapshotPath, memPath} {
		if p == "" {
			continue
		}
		dir := filepath.Dir(p)
		// Only attempt to remove directories under SnapshotDir — never the
		// root itself.
		if dir == "" || dir == m.cfg.SnapshotDir {
			continue
		}
		_ = os.Remove(dir) // removes only if empty
	}
	return nil
}

// assertUnderSnapshotDir returns nil iff `p` is an absolute path that, after
// cleaning, lies under m.cfg.SnapshotDir. This is the guard that keeps
// DeleteSnapshotFiles from being used to unlink arbitrary files on the host.
func (m *Manager) assertUnderSnapshotDir(p string) error {
	if m.cfg.SnapshotDir == "" {
		return status.Error(codes.FailedPrecondition, "snapshot_dir not configured")
	}
	if !filepath.IsAbs(p) {
		return status.Errorf(codes.InvalidArgument, "path must be absolute: %s", p)
	}
	cleaned := filepath.Clean(p)
	root := filepath.Clean(m.cfg.SnapshotDir)
	rel, err := filepath.Rel(root, cleaned)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return status.Errorf(codes.InvalidArgument, "path is outside snapshot directory: %s", p)
	}
	return nil
}

// RestoreVMSnapshot boots a VM from a previously captured snapshot.
func (m *Manager) RestoreVMSnapshot(ctx context.Context, vmID, snapshotPath, memPath, diskPath string,
	resourceLimits VMConfig, netCfg *network.Config,
) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()

	if vmID == "" {
		vmID = uuid.New().String()
	}

	m.mu.Lock()
	_, inPlace := m.vms[vmID]
	if inPlace {
		delete(m.vms, vmID)
		m.mu.Unlock()
		_ = stopUnit(ctx, systemdUnitName(vmID))
		m.mu.Lock()
	}

	inst := &VMInstance{
		ID:           vmID,
		Status:       StatusCreating,
		CreatedAt:    time.Now(),
		RunDirID:     vmID,
		Config:       resourceLimits,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	if diskPath == "" {
		var err error
		diskPath, err = m.copyRootfs(ctx, vmID, m.cfg.BaseRootfsPath)
		if err != nil {
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("copy rootfs for restore: %w", err)
		}
		log.Debug().Str("disk_path", diskPath).Msg("created rootfs copy for restored VM")
	}

	var tapDevice, macAddr, hostIP, nsName string

	if inPlace {
		existingNet := m.netMgr.GetVMNetInfo(vmID)
		if existingNet != nil {
			tapDevice = existingNet.TAPDevice
			macAddr = existingNet.MACAddress
			hostIP = existingNet.HostIP
			nsName = existingNet.Namespace
		}
	}

	if tapDevice == "" {
		netInfo, netErr := m.netMgr.SetupVM(ctx, vmID, netCfg)
		if netErr != nil {
			m.cleanupRunDir(vmID)
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("setup network: %w", netErr)
		}
		tapDevice = netInfo.TAPDevice
		macAddr = netInfo.MACAddress
		hostIP = netInfo.HostIP
		nsName = netInfo.Namespace
	}

	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	// Publish all the network/disk/socket fields before starting
	// Firecracker so the in-memory view is consistent for concurrent
	// readers. Lock once for the batch.
	inst.mu.Lock()
	inst.DiskPath = diskPath
	inst.IP = hostIP
	inst.TAPDevice = tapDevice
	inst.MACAddress = macAddr
	inst.Namespace = nsName
	inst.SocketPath = socketPath
	inst.mu.Unlock()

	pid, startErr := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, diskPath, nsName)
	if startErr != nil {
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("start firecracker: %w", startErr)
	}
	inst.mu.Lock()
	inst.PID = pid
	inst.mu.Unlock()

	log.Info().Msg("restoring snapshot")

	var restoreErr error
	if inPlace {
		restoreErr = RestoreSnapshot(socketPath, snapshotPath, memPath)
	} else {
		restoreErr = RestoreSnapshotWithOverrides(socketPath, snapshotPath, memPath, "eth0", tapDevice)
	}
	if restoreErr != nil {
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("restore snapshot: %w", restoreErr)
	}

	if err := m.waitForBoxd(ctx, hostIP, 5*time.Second); err != nil {
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("boxd not ready after restore: %w", err)
	}

	m.setStatus(vmID, StatusRunning)
	m.persistState(inst)
	log.Info().Int("pid", pid).Msg("VM restored from snapshot")
	return inst, nil
}

// ---------------------------------------------------------------------------
// GetVMInfo
// ---------------------------------------------------------------------------

func (m *Manager) GetVMInfo(_ context.Context, vmID string) (*VMInstance, error) {
	return m.getInstance(vmID)
}

// ---------------------------------------------------------------------------
// ShutdownAll
// ---------------------------------------------------------------------------

// ShutdownAll is a no-op — VMs are owned by systemd and outlive VMD.
func (m *Manager) ShutdownAll() {
	m.log.Info().Msg("VMs are systemd-managed — they will continue running after VMD shutdown")
}

// ---------------------------------------------------------------------------
// ReattachAll — startup recovery
// ---------------------------------------------------------------------------

// ReattachAll reconstructs the in-memory VM map on startup from two sources:
//
//  1. BoltDB — VMD's own cache from the previous lifetime.
//  2. Systemd — ground truth for which Firecracker units are actually running.
//
// For each VM in BoltDB that systemd confirms is alive AND whose Firecracker
// API socket is reachable, VMD reattaches. Stale BoltDB entries (dead process)
// are cleaned up. Orphan systemd units (running but not in BoltDB) are logged
// so the Phase 3 reconciler can handle them.
func (m *Manager) ReattachAll(ctx context.Context) (reattached, stale int) {
	if m.state == nil {
		m.log.Warn().Msg("no state store configured — skipping reattach")
		return 0, 0
	}

	records, err := m.state.All()
	if err != nil {
		m.log.Error().Err(err).Msg("failed to read BoltDB state — skipping reattach")
		return 0, 0
	}

	// Build a set of BoltDB-known IDs for orphan detection.
	knownIDs := make(map[string]bool, len(records))
	for _, rec := range records {
		knownIDs[rec.ID] = true
	}

	if len(records) == 0 {
		m.log.Info().Msg("no VMs in BoltDB — checking systemd for orphans")
	} else {
		m.log.Info().Int("count", len(records)).Msg("reattaching VMs from BoltDB")
	}

	// Phase A: reattach from BoltDB.
	for _, rec := range records {
		log := m.log.With().Str("vm_id", rec.ID).Logger()

		// Paused VMs legitimately have no running systemd unit — they
		// were stopped during pause and are waiting for a resume via
		// their snapshot. Reattach them with their paused status so the
		// resume path can find them.
		if rec.Status == StatusPaused {
			inst := toInstance(rec)
			m.mu.Lock()
			m.vms[rec.ID] = inst
			m.mu.Unlock()
			log.Info().Msg("reattached paused VM")
			reattached++
			continue
		}

		// For running VMs, verify the systemd unit is still active.
		if !isUnitActive(ctx, systemdUnitName(rec.ID)) {
			log.Warn().Msg("VM in BoltDB but not running — cleaning up stale record")
			m.state.Delete(rec.ID)
			stale++
			continue
		}

		// Verify the Firecracker API socket is actually reachable.
		if rec.SocketPath != "" {
			if _, statErr := os.Stat(rec.SocketPath); statErr != nil {
				log.Warn().Str("socket", rec.SocketPath).Msg("VM unit active but socket missing — cleaning up")
				m.state.Delete(rec.ID)
				stale++
				continue
			}
		}

		// Reattach: add to in-memory map.
		inst := toInstance(rec)

		m.mu.Lock()
		m.vms[rec.ID] = inst
		m.mu.Unlock()

		m.persistState(inst)
		log.Info().Int("pid", inst.PID).Str("ip", inst.IP).Msg("reattached to running VM")
		reattached++
	}

	// Phase B: detect orphan systemd units not in BoltDB.
	activeIDs, err := listActiveFirecrackerUnits(ctx)
	if err != nil {
		m.log.Warn().Err(err).Msg("failed to list active firecracker units — orphan detection skipped")
	} else {
		for _, id := range activeIDs {
			if !knownIDs[id] {
				m.log.Warn().Str("vm_id", id).Msg("orphan systemd unit detected (not in BoltDB) — will be handled by reconciler")
			}
		}
	}

	return reattached, stale
}

// ---------------------------------------------------------------------------
// ExecCommand
// ---------------------------------------------------------------------------

func (m *Manager) ExecCommand(ctx context.Context, vmID, command string, timeout time.Duration, opts *ExecOptions) (*ExecResult, error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}

	inst.mu.RLock()
	vmStatus := inst.Status
	vmIP := inst.IP
	inst.mu.RUnlock()

	if vmStatus != StatusRunning {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s is not running (status: %s)", vmID, vmStatus)
	}
	if vmIP == "" {
		return nil, status.Errorf(codes.Internal, "vm %s has no IP address", vmID)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := httpExec(ctx, vmIP, command, timeout, opts)
	if err != nil {
		return nil, m.handleVMError(vmID, err)
	}
	return result, nil
}

func (m *Manager) ExecCommandStream(ctx context.Context, vmID, command string, timeout time.Duration, opts *ExecOptions,
	onChunk func(stdout, stderr []byte, exitCode int32, finished bool),
) error {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return err
	}

	inst.mu.RLock()
	vmStatus := inst.Status
	vmIP := inst.IP
	inst.mu.RUnlock()

	if vmStatus != StatusRunning {
		return status.Errorf(codes.FailedPrecondition, "vm %s is not running (status: %s)", vmID, vmStatus)
	}
	if vmIP == "" {
		return status.Errorf(codes.Internal, "vm %s has no IP address", vmID)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := httpExecStream(ctx, vmIP, command, timeout, opts, onChunk); err != nil {
		return m.handleVMError(vmID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// File operations (Connect RPC for metadata only; byte transfer lives
// on the edge proxy's /files endpoint.)
// ---------------------------------------------------------------------------

// DeleteFile removes a file or directory inside a running VM via Connect RPC.
func (m *Manager) DeleteFile(ctx context.Context, vmID, filePath string) error {
	vmIP, err := m.getRunningVMIP(vmID)
	if err != nil {
		return err
	}
	client := boxdFilesystemClient(vmIP)
	_, rpcErr := client.Remove(ctx, connect.NewRequest(&pb.RemoveRequest{Path: filePath}))
	return rpcErr
}

func (m *Manager) getRunningVMIP(vmID string) (string, error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", err
	}
	inst.mu.RLock()
	vmStatus := inst.Status
	vmIP := inst.IP
	inst.mu.RUnlock()

	if vmStatus != StatusRunning {
		return "", status.Errorf(codes.FailedPrecondition, "vm %s is not running (status: %s)", vmID, vmStatus)
	}
	if vmIP == "" {
		return "", status.Errorf(codes.Internal, "vm %s has no IP", vmID)
	}
	return vmIP, nil
}

// handleVMError checks whether a connection error to a VM means the VM is
// dead. If the systemd unit is no longer active, it marks the VM as failed
// in BoltDB, removes it from the in-memory map, and returns NotFound so
// the control plane returns 410 Gone. If the unit is still active (transient
// error), it returns the original error unchanged.
func (m *Manager) handleVMError(vmID string, origErr error) error {
	if origErr == nil {
		return nil
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer checkCancel()
	if isUnitActive(checkCtx, systemdUnitName(vmID)) {
		return origErr
	}

	// Single lock acquisition for both status update and removal so
	// concurrent callers can't race on the same VM.
	m.mu.Lock()
	inst, ok := m.vms[vmID]
	if !ok {
		m.mu.Unlock()
		// Already cleaned up by another goroutine.
		return status.Errorf(codes.NotFound, "vm %s is no longer running", vmID)
	}
	inst.mu.Lock()
	inst.Status = StatusStopped
	inst.mu.Unlock()
	delete(m.vms, vmID)
	m.mu.Unlock()

	m.log.Warn().Str("vm_id", vmID).Err(origErr).
		Msg("VM process is dead — cleaning up and returning NotFound")
	m.persistState(inst)
	m.deleteState(vmID)
	return status.Errorf(codes.NotFound, "vm %s is no longer running", vmID)
}

// InstanceInfo is a snapshot of a VM's address and status for proxy lookups.
type InstanceInfo struct {
	VMIP      string
	Status    VMStatus
	CreatedAt time.Time
}

// LookupInstance returns the address, status, and creation time of a VM.
// CreatedAt acts as a lifecycle key — it changes if the VM is replaced, allowing
// the proxy to detect stale transports and close them before reuse.
// Returns false if the instance is not known to this VMD.
func (m *Manager) LookupInstance(vmID string) (InstanceInfo, bool) {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return InstanceInfo{}, false
	}
	inst.mu.RLock()
	info := InstanceInfo{
		VMIP:      inst.IP,
		Status:    inst.Status,
		CreatedAt: inst.CreatedAt,
	}
	inst.mu.RUnlock()
	return info, true
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (m *Manager) getInstance(vmID string) (*VMInstance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	inst, ok := m.vms[vmID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "vm %s not found", vmID)
	}
	return inst, nil
}

func (m *Manager) setStatus(vmID string, s VMStatus) {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return
	}
	inst.mu.Lock()
	inst.Status = s
	inst.mu.Unlock()
	m.persistState(inst)
}

// persistState writes the current VM state to BoltDB. No-op if no state
// store is configured. Errors are logged but not returned — BoltDB is a
// cache, not a source of truth.
func (m *Manager) persistState(inst *VMInstance) {
	if m.state == nil {
		return
	}
	if isBuildVM(inst.ID) {
		return
	}
	if err := m.state.Put(toRecord(inst)); err != nil {
		m.log.Error().Err(err).Str("vm_id", inst.ID).Msg("failed to persist VM state to BoltDB")
	}
}

// deleteState removes a VM record from BoltDB.
func (m *Manager) deleteState(vmID string) {
	if m.state == nil {
		return
	}
	if isBuildVM(vmID) {
		return
	}
	if err := m.state.Delete(vmID); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).Msg("failed to delete VM state from BoltDB")
	}
}

func (m *Manager) removeVM(vmID string) {
	m.mu.Lock()
	delete(m.vms, vmID)
	m.mu.Unlock()
	m.deleteState(vmID)
}

// copyRootfs creates a per-VM rootfs by copying the source image.
func (m *Manager) copyRootfs(ctx context.Context, dirName, srcRootfs string) (string, error) {
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir vm dir: %w", err)
	}

	diskPath := filepath.Join(vmDir, "rootfs.ext4")
	cmd := exec.CommandContext(ctx, "cp", "--reflink=auto", srcRootfs, diskPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("copy rootfs: %s: %w", string(out), err)
	}

	return diskPath, nil
}

func (m *Manager) cleanupRunDir(dirName string) {
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	if err := os.RemoveAll(vmDir); err != nil {
		m.log.Warn().Err(err).Str("dir", dirName).Msg("failed to remove rundir")
	}
}

// startFirecrackerColdBoot launches Firecracker inside a network namespace,
// configures it, and boots the kernel. Used only for InitDefaultTemplate.
func (m *Manager) startFirecrackerColdBoot(ctx context.Context, vmID, socketPath string, fcCfg FirecrackerConfig, netNS string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	cmd := exec.Command("ip", "netns", "exec", netNS,
		m.cfg.FirecrackerBin, "--api-sock", socketPath, "--id", vmID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("exec firecracker: %w", err)
	}

	pid := cmd.Process.Pid

	if err := waitForSocket(socketPath, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("wait for socket: %w", err)
	}

	if err := ConfigureMachine(socketPath, fcCfg); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("configure machine: %w", err)
	}

	if err := StartInstance(socketPath); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("start instance: %w", err)
	}

	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// startFirecrackerViaSystemd writes the start script and launches Firecracker
// as a standalone systemd unit. The VM survives VMD restarts because systemd
// owns the process, not VMD.
func (m *Manager) startFirecrackerViaSystemd(ctx context.Context, vmID, socketPath, perVMRootfs, netNS string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	templateDir := m.templateRunDir()
	rootfsLink := filepath.Join(templateDir, "rootfs.ext4")

	// Write the start script that the systemd unit's ExecStart calls.
	scriptPath := filepath.Join(filepath.Dir(socketPath), "start.sh")
	scriptContent := fmt.Sprintf("#!/bin/sh\nexec ip netns exec %s unshare -m -- sh -c 'mount --make-rprivate / && mount -t tmpfs tmpfs %q && ln -s %q %q && exec %q --api-sock %q --id %q'\n",
		netNS, templateDir, perVMRootfs, rootfsLink, m.cfg.FirecrackerBin, socketPath, vmID)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
		return 0, fmt.Errorf("write start script: %w", err)
	}

	// Start the systemd unit.
	if err := startUnit(ctx, systemdUnitName(vmID)); err != nil {
		return 0, fmt.Errorf("start systemd unit: %w", err)
	}

	// Wait for the Firecracker API socket.
	if err := waitForSocket(socketPath, 5*time.Second); err != nil {
		_ = stopUnit(ctx, systemdUnitName(vmID))
		return 0, fmt.Errorf("wait for socket: %w", err)
	}

	// Read the PID asynchronously so the create path isn't slowed down
	// by the ~15ms dbus roundtrip. The PID is populated in the instance
	// shortly after create returns and persisted to BoltDB.
	go m.resolveAndSetPID(vmID)

	return 0, nil
}

func (m *Manager) resolveAndSetPID(vmID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property=MainPID", "--value", systemdUnitName(vmID))
	out, err := cmd.Output()
	if err != nil {
		return
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pid); err != nil || pid == 0 {
		return
	}

	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	inst.mu.Lock()
	inst.PID = pid
	inst.mu.Unlock()

	m.persistState(inst)
	m.log.Debug().Str("vm_id", vmID).Int("pid", pid).Msg("resolved systemd MainPID")
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

// killVMKeepRunDir terminates the VM process and releases networking but
// leaves the rundir intact on disk. Used only for the throwaway template
// VM (which is cold-booted as a direct child, not a systemd unit).
func (m *Manager) killVMKeepRunDir(vmID string) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return
	}

	// Template VMs run as direct child processes (cold boot path).
	// Regular VMs run as systemd units — stop the unit if it exists.
	if inst.PID > 0 {
		if proc, e := os.FindProcess(inst.PID); e == nil {
			_ = proc.Signal(syscall.SIGKILL)
			go proc.Wait() //nolint:errcheck
		}
	} else {
		_ = stopUnit(context.Background(), systemdUnitName(vmID))
	}

	if inst.SocketPath != "" {
		_ = os.Remove(inst.SocketPath)
	}
	m.netMgr.CleanupVM(vmID)

	m.mu.Lock()
	delete(m.vms, vmID)
	m.mu.Unlock()
}

func (m *Manager) waitForBoxd(ctx context.Context, vmIP string, timeout time.Duration) error {
	return waitForHTTPHealth(ctx, vmIP, timeout)
}

// checkTemplateHealth verifies the given template's snapshot files exist on disk.
func (m *Manager) checkTemplateHealth(tmpl *TemplateSnapshot) error {
	if tmpl == nil {
		return fmt.Errorf("no template initialized")
	}
	for _, path := range []string{
		tmpl.SnapshotPath,
		tmpl.MemFilePath,
		tmpl.DiskPath,
	} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("template file missing: %s: %w", path, err)
		}
	}
	return nil
}

// CleanupTemplate removes the named template's rundir and snapshot files and
// drops it from the templates map. Pass DefaultTemplateID to remove the
// baked-in default. No-op for unknown template IDs.
func (m *Manager) CleanupTemplate(templateID string) {
	if templateID == "" {
		templateID = DefaultTemplateID
	}
	m.mu.Lock()
	tmpl := m.templates[templateID]
	delete(m.templates, templateID)
	m.mu.Unlock()
	if tmpl == nil {
		return
	}

	if tmpl.RunDir != "" {
		if err := os.RemoveAll(tmpl.RunDir); err != nil {
			m.log.Warn().Err(err).Str("dir", tmpl.RunDir).Msg("failed to remove template rundir")
		}
	}
	snapshotDir := filepath.Dir(tmpl.SnapshotPath)
	if snapshotDir != "" && snapshotDir != "." {
		if err := os.RemoveAll(snapshotDir); err != nil {
			m.log.Warn().Err(err).Str("dir", snapshotDir).Msg("failed to remove template snapshot")
		}
	}
	m.log.Info().Str("template_id", templateID).Msg("template files cleaned up")
}

