package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	FirecrackerBin string
	JailerBin      string
	KernelPath     string
	BaseRootfsPath string
	SnapshotDir    string
	RunDir         string
	MaxConcurrent  int  // Max concurrent CreateVM operations (0 = default 10).
	UseSystemd     bool // When true, VMs run as standalone systemd units.
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

	mu              sync.RWMutex
	vms             map[string]*VMInstance
	defaultTemplate *TemplateSnapshot
	createSem       chan struct{}

	// useSystemd controls whether VMs are started via systemd units
	// (true) or as direct child processes (false). Defaults to false
	// for backward compatibility; set to true via ManagerConfig.
	useSystemd bool
}

// NewManager creates a new VM manager.
func NewManager(cfg ManagerConfig, netMgr *network.Manager, log zerolog.Logger) (*Manager, error) {
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	return &Manager{
		cfg:        cfg,
		netMgr:     netMgr,
		log:        log.With().Str("component", "vm_manager").Logger(),
		vms:        make(map[string]*VMInstance),
		createSem:  make(chan struct{}, maxConcurrent),
		useSystemd: cfg.UseSystemd,
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

// InitDefaultTemplate cold-boots a throwaway VM from the base image, waits
// for the guest agent, snapshots the running state, and kills the VM — keeping
// the rundir and snapshot files on disk. Every subsequent CreateVM restores
// from this template snapshot instead of cold-booting.
//
// The template VM uses a fixed directory name ("template") so the snapshot's
// hardcoded path_on_host is always rundir/template/rootfs.ext4. Each new VM
// gets mount namespace isolation to present its own rootfs at that path.
func (m *Manager) InitDefaultTemplate(ctx context.Context) error {
	// Use a fixed ID so the rundir is always "template".
	templateID := templateDirName
	log := m.log.With().Str("template_id", templateID).Logger()
	log.Info().Msg("initializing default template — cold-booting throwaway VM")

	// Cold-boot a throwaway VM from the base image.
	inst, err := m.coldBootVM(ctx, templateID)
	if err != nil {
		return fmt.Errorf("boot template VM: %w", err)
	}

	// Wait for boxd to be reachable via HTTP.
	if err := m.waitForBoxd(ctx, inst.IP, 30*time.Second); err != nil {
		_ = m.DestroyVM(ctx, templateID, true)
		return fmt.Errorf("boxd not ready: %w", err)
	}
	log.Info().Msg("guest agent ready — creating template snapshot")

	// Snapshot the live VM.
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, templateDirName)
	snapPath, memPath, err := m.CreateVMSnapshot(ctx, templateID, snapshotDir)
	if err != nil {
		_ = m.DestroyVM(ctx, templateID, true)
		return fmt.Errorf("snapshot template VM: %w", err)
	}

	// Kill the VM process but keep the rundir on disk — the snapshot's
	// path_on_host references these files.
	diskPath := inst.DiskPath
	m.killVMKeepRunDir(templateID)

	m.defaultTemplate = &TemplateSnapshot{
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
		DiskPath:     diskPath,
		RunDir:       m.templateRunDir(),
		VCPUCount:    inst.Config.VCPU,
		MemSizeMiB:   inst.Config.MemoryMiB,
	}

	log.Info().
		Str("snapshot_path", snapPath).
		Str("disk_path", diskPath).
		Msg("default template ready")
	return nil
}

// ---------------------------------------------------------------------------
// CreateVM — single code path via template snapshot restore
// ---------------------------------------------------------------------------

// CreateVM provisions a new Firecracker microVM by restoring from the default
// template snapshot. Each VM gets its own rootfs copy and runs in a mount
// namespace that maps the per-VM rootfs to the template's fixed path.
func (m *Manager) CreateVM(ctx context.Context, vmID string, vcpu, memMiB, diskMiB uint32,
	kernelPath, kernelArgs, rootfsPath string, netCfg *network.Config, metadata map[string]string,
) (*VMInstance, error) {
	if vmID == "" {
		vmID = uuid.New().String()
	}

	// If the template isn't ready (e.g., during InitDefaultTemplate itself),
	// fall through to cold boot.
	if m.defaultTemplate == nil {
		return m.coldBootVM(ctx, vmID)
	}

	// Verify template snapshot files are still intact.
	if err := m.checkTemplateHealth(); err != nil {
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

	rundirID := uuid.New().String()
	inst := &VMInstance{
		ID:        vmID,
		Status:    StatusCreating,
		CreatedAt: time.Now(),
		Metadata:  metadata,
		RunDirID:  rundirID,
		Config: VMConfig{
			VCPU:      m.defaultTemplate.VCPUCount,
			MemoryMiB: m.defaultTemplate.MemSizeMiB,
		},
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	cleanup := func() {
		m.cleanupRunDir(rundirID)
		m.setStatus(vmID, StatusError)
		m.removeVM(vmID)
	}

	// 1. Copy the template rootfs for this VM.
	stepStart := time.Now()
	perVMRootfs, err := m.copyRootfs(ctx, rundirID, m.defaultTemplate.DiskPath)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("copy rootfs: %w", err)
	}
	inst.DiskPath = perVMRootfs
	log.Debug().Dur("duration_ms", time.Since(stepStart)).Msg("step: copy rootfs")

	// 2. Set up networking.
	stepStart = time.Now()
	netInfo, err := m.netMgr.SetupVM(ctx, vmID, netCfg)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("setup network: %w", err)
	}
	inst.IP = netInfo.HostIP
	inst.TAPDevice = netInfo.TAPDevice
	inst.MACAddress = netInfo.MACAddress
	inst.Namespace = netInfo.Namespace
	log.Debug().Dur("duration_ms", time.Since(stepStart)).Msg("step: setup network")

	// 3. Start Firecracker in a mount + network namespace.
	stepStart = time.Now()
	vmDir := filepath.Join(m.cfg.RunDir, rundirID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")
	inst.SocketPath = socketPath

	var pid int
	if m.useSystemd {
		pid, err = m.startFirecrackerViaSystemd(ctx, vmID, socketPath, perVMRootfs, netInfo.Namespace)
	} else {
		pid, err = m.startFirecrackerInNamespace(vmID, socketPath, perVMRootfs, netInfo.Namespace)
	}
	if err != nil {
		m.netMgr.CleanupVM(vmID)
		cleanup()
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	inst.PID = pid
	log.Debug().Dur("duration_ms", time.Since(stepStart)).Msg("step: start firecracker")

	// 4. Restore from the original (unpatched) template snapshot.
	// No IP reconfig needed — the VM uses a fixed internal IP (169.254.0.21)
	// and the network namespace provides isolation.
	stepStart = time.Now()
	if err := RestoreSnapshotWithOverrides(
		socketPath, m.defaultTemplate.SnapshotPath, m.defaultTemplate.MemFilePath,
		"eth0", netInfo.TAPDevice,
	); err != nil {
		m.netMgr.CleanupVM(vmID)
		cleanup()
		return nil, fmt.Errorf("restore template snapshot: %w", err)
	}
	log.Debug().Dur("duration_ms", time.Since(stepStart)).Msg("step: restore snapshot")

	m.setStatus(vmID, StatusRunning)
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

// coldBootVM provisions a VM the slow way: copy rootfs, set up networking,
// start Firecracker, configure machine, and boot the kernel.
func (m *Manager) coldBootVM(ctx context.Context, vmID string) (*VMInstance, error) {
	if vmID == "" {
		vmID = uuid.New().String()
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
			VCPU:       1,
			MemoryMiB:  1024,
			KernelPath: m.cfg.KernelPath,
			RootfsPath: m.cfg.BaseRootfsPath,
		},
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Msg("cold-booting VM")

	// 1. Copy the base rootfs for this VM.
	diskPath, err := m.copyRootfs(ctx, vmID, m.cfg.BaseRootfsPath)
	if err != nil {
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("copy rootfs: %w", err)
	}
	inst.DiskPath = diskPath

	// 2. Set up networking.
	netInfo, err := m.netMgr.SetupVM(ctx, vmID, nil)
	if err != nil {
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("setup network: %w", err)
	}
	inst.IP = netInfo.HostIP
	inst.TAPDevice = netInfo.TAPDevice
	inst.MACAddress = netInfo.MACAddress
	inst.Namespace = netInfo.Namespace

	// 3. Build Firecracker machine configuration.
	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")
	inst.SocketPath = socketPath

	fcCfg := FirecrackerConfig{
		SocketPath: socketPath,
		KernelPath: m.cfg.KernelPath,
		KernelArgs: "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0",
		RootfsPath: diskPath,
		VCPUCount:  1,
		MemSizeMiB: 1024,
		TAPDevice:  network.TAPName,
		MACAddress: inst.MACAddress,
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
	inst.PID = pid

	m.setStatus(vmID, StatusRunning)
	log.Info().Int("pid", pid).Str("host_ip", inst.IP).Msg("VM cold-booted")
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

	if m.useSystemd {
		// Stop the systemd unit — this kills Firecracker and runs ExecStopPost cleanup.
		// The netns unit is also stopped since firecracker@ Requires= it.
		if err := stopUnit(ctx, systemdUnitName(vmID)); err != nil {
			log.Warn().Err(err).Msg("systemctl stop failed (unit may already be stopped)")
		}
		removeUnitDropIn(vmID)
	} else {
		if inst.PID > 0 {
			proc, findErr := os.FindProcess(inst.PID)
			if findErr == nil {
				if force {
					_ = proc.Signal(syscall.SIGKILL)
				} else {
					_ = proc.Signal(syscall.SIGTERM)
					done := make(chan error, 1)
					go func() { _, e := proc.Wait(); done <- e }()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						log.Warn().Msg("SIGTERM timed out, sending SIGKILL")
						_ = proc.Signal(syscall.SIGKILL)
					}
				}
			}
		}
	}

	if inst.SocketPath != "" {
		_ = os.Remove(inst.SocketPath)
	}

	if !m.useSystemd {
		// In systemd mode, the netns unit handles network cleanup.
		m.netMgr.CleanupVM(vmID)
	}

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
		return "", "", fmt.Errorf("create snapshot: %w", err)
	}

	if inst.PID > 0 {
		if proc, e := os.FindProcess(inst.PID); e == nil {
			_ = proc.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { proc.Wait(); close(done) }() //nolint:errcheck
			select {
			case <-done:
			case <-time.After(500 * time.Millisecond):
				_ = proc.Signal(syscall.SIGKILL)
				<-done
			}
		}
	}

	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.mu.Unlock()

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

	pid, err := m.startFirecrackerInNamespace(vmID, socketPath, rootfsPath, inst.Namespace)
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

// RestoreVMSnapshot boots a VM from a previously captured snapshot.
func (m *Manager) RestoreVMSnapshot(ctx context.Context, vmID, snapshotPath, memPath, diskPath string,
	resourceLimits VMConfig, netCfg *network.Config,
) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()

	if vmID == "" {
		vmID = uuid.New().String()
	}

	m.mu.Lock()
	existingInst, inPlace := m.vms[vmID]
	if inPlace {
		if existingInst.PID > 0 {
			if proc, e := os.FindProcess(existingInst.PID); e == nil {
				_ = proc.Signal(syscall.SIGTERM)
				// Wait for process to exit instead of sleeping.
				done := make(chan struct{})
				go func() { proc.Wait(); close(done) }() //nolint:errcheck
				select {
				case <-done:
				case <-time.After(500 * time.Millisecond):
					_ = proc.Signal(syscall.SIGKILL)
					<-done
				}
			}
		}
		delete(m.vms, vmID)
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
	inst.DiskPath = diskPath

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
	inst.IP = hostIP
	inst.TAPDevice = tapDevice
	inst.MACAddress = macAddr
	inst.Namespace = nsName

	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")
	inst.SocketPath = socketPath

	pid, err := m.startFirecrackerInNamespace(vmID, socketPath, diskPath, nsName)
	if err != nil {
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	inst.PID = pid

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

	m.setStatus(vmID, StatusRunning)
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

// ShutdownAll destroys all VMs. In systemd mode this is a no-op — the VMs
// are owned by systemd and should outlive VMD.
func (m *Manager) ShutdownAll() {
	if m.useSystemd {
		m.log.Info().Msg("systemd mode: VMs will continue running after VMD shutdown")
		return
	}

	m.mu.RLock()
	ids := make([]string, 0, len(m.vms))
	for id := range m.vms {
		ids = append(ids, id)
	}
	m.mu.RUnlock()

	for _, id := range ids {
		if err := m.DestroyVM(context.Background(), id, true); err != nil {
			m.log.Error().Err(err).Str("vm_id", id).Msg("failed to destroy VM during shutdown")
		}
	}
}

// ---------------------------------------------------------------------------
// ReattachAll — startup recovery
// ---------------------------------------------------------------------------

// ReattachAll reconstructs the in-memory VM map from BoltDB + systemd on
// startup. For each VM that BoltDB knows about AND systemd reports as active,
// VMD reattaches by connecting to the existing Firecracker API socket.
// VMs in BoltDB that are no longer running in systemd are marked as stopped.
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
	if len(records) == 0 {
		m.log.Info().Msg("no VMs in BoltDB — nothing to reattach")
		return 0, 0
	}

	m.log.Info().Int("count", len(records)).Msg("reattaching VMs from BoltDB")

	for _, rec := range records {
		log := m.log.With().Str("vm_id", rec.ID).Logger()

		// Check if the systemd unit is still active.
		alive := isUnitActive(ctx, systemdUnitName(rec.ID))
		if !alive {
			// Also check if the socket exists (non-systemd mode compatibility).
			if rec.SocketPath != "" {
				if _, err := os.Stat(rec.SocketPath); err == nil {
					alive = true
				}
			}
		}

		if !alive {
			log.Warn().Msg("VM in BoltDB but not running — marking stale")
			m.state.Delete(rec.ID)
			stale++
			continue
		}

		// Reattach: add to in-memory map.
		inst := toInstance(rec)
		inst.Status = StatusRunning

		m.mu.Lock()
		m.vms[rec.ID] = inst
		m.mu.Unlock()

		m.persistState(inst)
		log.Info().Int("pid", inst.PID).Str("ip", inst.IP).Msg("reattached to running VM")
		reattached++
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

	return httpExec(ctx, vmIP, command, timeout, opts)
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

	return httpExecStream(ctx, vmIP, command, timeout, opts, onChunk)
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
	if err := m.state.Put(toRecord(inst)); err != nil {
		m.log.Error().Err(err).Str("vm_id", inst.ID).Msg("failed to persist VM state to BoltDB")
	}
}

// deleteState removes a VM record from BoltDB.
func (m *Manager) deleteState(vmID string) {
	if m.state == nil {
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

	if err := configureMachine(socketPath, fcCfg); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("configure machine: %w", err)
	}

	if err := startInstance(socketPath); err != nil {
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

	// Ensure log directory exists.
	os.MkdirAll("/var/lib/sandbox/logs", 0o755)

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

	// Read the PID from systemd.
	pid, err := m.getUnitMainPID(ctx, vmID)
	if err != nil {
		m.log.Warn().Err(err).Str("vm_id", vmID).Msg("could not read unit PID, using 0")
	}
	return pid, nil
}

// getUnitMainPID queries systemd for the main PID of a firecracker@ unit.
func (m *Manager) getUnitMainPID(ctx context.Context, vmID string) (int, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property=MainPID", "--value", systemdUnitName(vmID))
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

// startFirecrackerInNamespace launches Firecracker in its own mount namespace
// AND inside the given network namespace. The mount namespace provides rootfs
// isolation (tmpfs + symlink to per-VM rootfs), and the network namespace
// provides network isolation (each VM uses the same internal IP).
func (m *Manager) startFirecrackerInNamespace(vmID, socketPath, perVMRootfs, netNS string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	templateDir := m.templateRunDir()
	rootfsLink := filepath.Join(templateDir, "rootfs.ext4")

	// Write a temporary shell script to avoid shell injection from config values.
	// The script sets up mount namespace isolation, then exec's Firecracker.
	scriptPath := filepath.Join(filepath.Dir(socketPath), "start.sh")
	scriptContent := fmt.Sprintf("#!/bin/sh\nmount --make-rprivate / && mount -t tmpfs tmpfs %q && ln -s %q %q && exec %q --api-sock %q --id %q\n",
		templateDir, perVMRootfs, rootfsLink, m.cfg.FirecrackerBin, socketPath, vmID)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
		return 0, fmt.Errorf("write start script: %w", err)
	}

	// Run inside the network namespace with a private mount namespace.
	cmd := exec.Command("ip", "netns", "exec", netNS,
		"unshare", "-m", "--", "sh", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("exec firecracker in namespace: %w", err)
	}

	if err := waitForSocket(socketPath, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("wait for socket: %w", err)
	}

	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
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
// leaves the rundir intact on disk.
func (m *Manager) killVMKeepRunDir(vmID string) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return
	}

	if inst.PID > 0 {
		if proc, e := os.FindProcess(inst.PID); e == nil {
			_ = proc.Signal(syscall.SIGKILL)
			go proc.Wait() //nolint:errcheck
		}
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

// checkTemplateHealth verifies the default template snapshot files are readable.
func (m *Manager) checkTemplateHealth() error {
	if m.defaultTemplate == nil {
		return fmt.Errorf("no default template initialized")
	}
	for _, path := range []string{
		m.defaultTemplate.SnapshotPath,
		m.defaultTemplate.MemFilePath,
		m.defaultTemplate.DiskPath,
	} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("template file missing: %s: %w", path, err)
		}
	}
	return nil
}


// CleanupTemplate removes the default template's rundir and snapshot files.
func (m *Manager) CleanupTemplate() {
	if m.defaultTemplate == nil {
		return
	}
	tmpl := m.defaultTemplate
	m.defaultTemplate = nil

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
	m.log.Info().Msg("template files cleaned up")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
