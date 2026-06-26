package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/fsnotify/fsnotify"
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

// templateDirName is the fixed directory name that every template snapshot's
// `path_on_host` references. Each new VM gets its own mount namespace where a
// tmpfs is mounted over this directory and the per-VM rootfs is symlinked in
// — so every Firecracker process sees its own files at the same fixed path.
const templateDirName = "template"

// TemplatesDirName is the layout directory under RunDir / SnapshotDir that
// holds per-template artifacts (rootfs at build time, snapshot files).
const TemplatesDirName = "templates"

// accessLogFilename is the on-disk name of the recorded page-access trace that
// lives alongside a template's snapshot files. RecordAccessPattern writes here
// and restoreVMSnapshot reads from here as the prefetch input — both sites must
// stay in sync, so the literal lives here only.
const accessLogFilename = "access.log"

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
	TeamID       string // owning team; carried for data-plane usage attribution
	OwnerID      string // creating user; empty when unknown

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
	// Non-empty BasePath switches the VM into overlay mode: RootfsPath
	// becomes a sparse per-VM file backed by this shared read-only base.
	BasePath string
	// DeltaDir hydrates a fresh per-VM overlay from <dir>/rootfs.delta on
	// restore. Empty for in-place resume of an already-populated overlay.
	DeltaDir string
}

// ManagerConfig holds paths and settings for the VM manager.
type ManagerConfig struct {
	FirecrackerBin     string
	JailerBin          string
	KernelPath         string
	BaseRootfsPath     string
	SnapshotDir        string
	RunDir             string
	TemplateBuilderBin string // Path to template-builder binary.
	BoxdBinaryPath     string // Path to boxd binary (passed to template-builder).
	HostInterface      string // Host network interface (e.g. "ens4").
	// MaxConcurrentRestores caps parallel RestoreVMSnapshot operations to
	// prevent a spike of concurrent sandbox creates from saturating host
	// file I/O, netns setup, and Firecracker boots. 0 → default 100.
	MaxConcurrentRestores int

	// UffdEnabled gates the UFFD lazy-restore path. false → fresh
	// restores fall back to the File memory backend (synchronous CRC64),
	// same as in-place resume. Default true; flip to false as an ops
	// circuit breaker without redeploying.
	UffdEnabled bool

	// UffdPrefetchEnabled turns on background prefetch in the UFFD
	// handler. When true, the handler walks mem.snap after the handshake
	// and pre-copies pages into guest memory so the first exec doesn't
	// stall on cold pages. Ignored when UffdEnabled is false.
	UffdPrefetchEnabled bool

	// UffdRecordMaxSeconds caps how long RecordAccessPattern waits for the
	// guest's fault rate to settle before giving up. 0 → 10s default.
	UffdRecordMaxSeconds int

	// ResumeUffdEnabled routes resume-from-pause through the UFFD backend
	// instead of File, reusing the existing tap. Requires UffdEnabled;
	// default false, with File as the fallback.
	ResumeUffdEnabled bool

	// VerifySnapshotEnabled exposes the debug POST /verify-snapshot/{id} endpoint
	// (re-snapshot a paused VM for bit-identical checks). Default false; intended
	// for staging gate runs, not production.
	VerifySnapshotEnabled bool
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

	mu  sync.RWMutex
	vms map[string]*VMInstance

	// restoreSem bounds concurrent RestoreVMSnapshot operations. Buffered
	// channel; capacity = effective MaxConcurrentRestores.
	restoreSem chan struct{}

	// builds tracks in-flight and completed template builds. Keyed by
	// build VM id (which is also "build-" + templateID). Entries survive
	// until process exit so late pollers can read terminal outcomes.
	buildsMu sync.RWMutex
	builds   map[string]*buildRecord

	// nextBuildSlot assigns unique network slot indices to concurrent
	// template-builder subprocesses. Starts at 200 to avoid collision
	// with vmd's sandbox pool (indices 1-100).
	nextBuildSlot atomic.Int32
}

// NewManager creates a new VM manager.
func NewManager(cfg ManagerConfig, netMgr *network.Manager, log zerolog.Logger) (*Manager, error) {
	maxRestores := cfg.MaxConcurrentRestores
	if maxRestores <= 0 {
		maxRestores = 100
	}
	// Magic mount target — every per-VM start script mounts tmpfs over it.
	// Missing → "mount: failed" → opaque "wait for socket" timeout. Create
	// at startup so an aggressive ops cleanup can't break sandbox/build paths.
	if cfg.RunDir != "" {
		if err := os.MkdirAll(filepath.Join(cfg.RunDir, templateDirName), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir template magic dir: %w", err)
		}
	}
	return &Manager{
		cfg:        cfg,
		netMgr:     netMgr,
		log:        log.With().Str("component", "vm_manager").Logger(),
		vms:        make(map[string]*VMInstance),
		restoreSem: make(chan struct{}, maxRestores),
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

// templateRunDir returns the fixed path where every template's rootfs lives
// at restore time. Each VM mounts a per-instance tmpfs over this path and
// symlinks its own rootfs in; every Firecracker snapshot references this
// exact path via its embedded `path_on_host`, so one snapshot works for
// many VMs.
func (m *Manager) templateRunDir() string {
	return filepath.Join(m.cfg.RunDir, templateDirName)
}

// TemplateMagicDir is the per-process tmpfs mountpoint both build and
// restore use; divergence here re-introduces the shared-rootfs bug.
func TemplateMagicDir(runDir string) string {
	return filepath.Join(runDir, templateDirName)
}

// TemplateMagicRootfsPath is the `path_on_host` baked into legacy snapshots.
func TemplateMagicRootfsPath(runDir string) string {
	return filepath.Join(TemplateMagicDir(runDir), "rootfs.ext4")
}

// TemplateMagicBasePath is the `base_path` baked into overlay-mode snapshots.
func TemplateMagicBasePath(runDir string) string {
	return filepath.Join(TemplateMagicDir(runDir), "base.ext4")
}

// TemplateMagicOverlayPath is the `path_on_host` baked into overlay-mode
// snapshots — symlinked per-VM at restore time.
func TemplateMagicOverlayPath(runDir string) string {
	return filepath.Join(TemplateMagicDir(runDir), "overlay.ext4")
}

// restoreDiskAction is the disk-resolution mode picked by planRestore.
type restoreDiskAction int

const (
	restoreCreateOverlay restoreDiskAction = iota // overlay clone of a template
	restoreReuseOverlay                           // existing per-VM overlay (resume)
	restoreLegacyResolve                          // legacy non-overlay path
)

// restorePlan is planRestore's output — pure decision, no I/O.
type restorePlan struct {
	action   restoreDiskAction
	deltaDir string
}

// planRestore picks the disk action + delta_dir for a restore. createOverlay
// requires ALL of {basePath, deltaDir, !inPlace} — anything missing means
// we'd be cloning over an existing per-VM file, so fall back to reuse.
func planRestore(basePath, deltaDir string, inPlace bool) restorePlan {
	p := restorePlan{deltaDir: deltaDir}
	if inPlace {
		// fc's delta-apply truncates the overlay; force empty to stop a
		// caller mistake from clobbering per-VM state.
		p.deltaDir = ""
	}
	switch {
	case basePath != "" && deltaDir != "" && !inPlace:
		p.action = restoreCreateOverlay
	case basePath != "":
		p.action = restoreReuseOverlay
	default:
		p.action = restoreLegacyResolve
	}
	return p
}

// resolveRestoreDisk picks the disk file for a restored VM when the caller
// didn't supply one. Two legitimate cases:
//
//   - Template restore (snapshot path looks like .../templates/<id>/...) —
//     copy the template's rootfs to a fresh per-VM file.
//   - Sandbox resume after vmd cold restart — the per-VM rootfs already
//     exists at <runDir>/<vmID>/rootfs.ext4 from when the sandbox was first
//     created; reuse it.
//
// Anything else is an error: silently falling back to BaseRootfsPath would
// put the wrong disk under the snapshot's memory view.
func (m *Manager) resolveRestoreDisk(ctx context.Context, vmID, snapshotPath string) (string, error) {
	if src, srcErr := templateRootfsForSnapshot(m.cfg.RunDir, snapshotPath); srcErr == nil {
		dst, err := m.copyRootfs(ctx, vmID, src)
		if err != nil {
			return "", fmt.Errorf("copy rootfs for restore: %w", err)
		}
		return dst, nil
	} else {
		existing := filepath.Join(m.cfg.RunDir, vmID, "rootfs.ext4")
		if _, statErr := os.Stat(existing); statErr != nil {
			return "", fmt.Errorf(
				"resolve rootfs for vm %s: snapshot %q is not a template snapshot (%v) and per-VM rootfs %q is missing (%v)",
				vmID, snapshotPath, srcErr, existing, statErr,
			)
		}
		return existing, nil
	}
}

// templateRootfsForSnapshot maps .../templates/<id>/<file>.snap →
// <runDir>/templates/<id>/rootfs.ext4. Lets vmd find the template's rootfs
// without needing controlplane to pass it.
func templateRootfsForSnapshot(runDir, snapshotPath string) (string, error) {
	parent := filepath.Dir(snapshotPath) // .../templates/<templateID>
	templateID := filepath.Base(parent)  // <templateID>
	if filepath.Base(filepath.Dir(parent)) != TemplatesDirName {
		return "", fmt.Errorf("snapshot path %q does not look like .../templates/<id>/<file>", snapshotPath)
	}
	if templateID == "" || templateID == "." || templateID == string(filepath.Separator) {
		return "", fmt.Errorf("snapshot path %q has an empty template id segment", snapshotPath)
	}
	return filepath.Join(runDir, TemplatesDirName, templateID, "rootfs.ext4"), nil
}

// ---------------------------------------------------------------------------
// Cold boot — only used by the template build pipeline
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
	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Bool("force", force).Msg("destroying VM")

	// Cleanup runs even without an in-memory instance, so a malformed or reserved
	// vmID could escape RunDir or wipe a shared dir.
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}

	// A paused or post-restart VM may be absent from m.vms. Don't early-return on
	// that: unit stop and rundir removal are derivable from vmID and must run, or
	// destroying a paused sandbox leaks its rundir. Process/socket teardown needs
	// the instance, so it's gated below. Destroy is idempotent.
	inst, instErr := m.getInstance(vmID)

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
	if instErr == nil {
		inst.mu.RLock()
		pid := inst.PID
		sockPath := inst.SocketPath
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
		if sockPath != "" {
			_ = os.Remove(sockPath)
		}
	}

	// Reclaim the network slot even if the VM isn't tracked in the devices
	// map (e.g. a paused VM reattached without network state) — pass the
	// known namespace so the slot isn't leaked.
	ns := ""
	if instErr == nil {
		ns = inst.Namespace
	}
	m.netMgr.CleanupVMOrNamespace(vmID, ns)

	// Fall back to vmID when the instance is absent (RunDirID == vmID anyway).
	rundirKey := vmID
	if instErr == nil && inst.RunDirID != "" {
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
	if err := CreateSnapshot(inst.SocketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
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
		fname := "rootfs.ext4"
		if inst.Config.BasePath != "" {
			fname = "overlay.ext4"
		}
		rootfsPath = filepath.Join(m.cfg.RunDir, rundirKey, fname)
	}

	vmDir := filepath.Join(m.cfg.RunDir, rundirKey)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	var netInfo *network.VMNetInfo
	if inst.Namespace != "" {
		var nsErr error
		netInfo, nsErr = m.netMgr.EnsureVMSlot(ctx, vmID, inst.Namespace, inst.IP, inst.MACAddress)
		if nsErr != nil {
			return nil, fmt.Errorf("ensure network slot for resume: %w", nsErr)
		}
	}

	pid, err := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, inst.Namespace)
	if err != nil {
		return nil, fmt.Errorf("start firecracker for restore: %w", err)
	}

	log.Info().Str("snapshot_path", snapshotPath).Msg("restoring VM from snapshot")
	if err := m.restoreForResume(socketPath, snapshotPath, memPath, netInfo); err != nil {
		// Firecracker is already running; stop the unit before returning or it leaks.
		m.stopUnitDuringRestoreError(vmID)
		if errors.Is(err, ErrTornSnapshot) {
			return nil, status.Errorf(codes.DataLoss,
				"snapshot %q is torn (overlay side-car empty); re-snapshot from a healthy source: %v",
				snapshotPath, err)
		}
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

// restoreForResume picks the resume memory backend: UFFD (reusing the existing
// tap for the interface override) when enabled and a tap is present, else File,
// which is also the fallback when ResumeUffdEnabled is off.
func (m *Manager) restoreForResume(socketPath, snapshotPath, memPath string, netInfo *network.VMNetInfo) error {
	useUffd := m.cfg.ResumeUffdEnabled && m.cfg.UffdEnabled && netInfo != nil && netInfo.TAPDevice != ""
	if !useUffd {
		return RestoreSnapshot(socketPath, snapshotPath, memPath, "")
	}

	// No prefetch access log: only template builds record one (next to the template
	// snapshot), pause snapshots don't — so resume-side prefetch is future work.
	return RestoreSnapshotUffdInternalWithOverrides(
		socketPath, snapshotPath, memPath, "", "", "eth0", netInfo.TAPDevice, "",
	)
}

// VerifySnapshot loads vmID's snapshot without resuming, re-snapshots the frozen
// image to a temp file, and returns its path (compare with the original via
// snapcheck). Non-destructive: stops the throwaway FC, leaving the sandbox paused.
func (m *Manager) VerifySnapshot(ctx context.Context, vmID string) (string, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()

	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", err
	}
	// Only operate on a paused VM. Starting a throwaway Firecracker for a running
	// sandbox (and stopping it on the way out) would disrupt the live VM.
	if inst.Status != StatusPaused {
		return "", status.Errorf(codes.FailedPrecondition,
			"vm %s is not paused (status %s); verify only runs on paused snapshots", vmID, inst.Status)
	}
	snapshotPath, memPath := inst.SnapshotPath, inst.MemFilePath
	if snapshotPath == "" || memPath == "" {
		return "", status.Errorf(codes.InvalidArgument, "vm %s has no snapshot on record", vmID)
	}
	if _, err := os.Stat(memPath); err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "mem file missing on host: %s", memPath)
	}

	rundirKey := vmID
	if inst.RunDirID != "" {
		rundirKey = inst.RunDirID
	}
	rootfsPath := inst.DiskPath
	if rootfsPath == "" {
		fname := "rootfs.ext4"
		if inst.Config.BasePath != "" {
			fname = "overlay.ext4"
		}
		rootfsPath = filepath.Join(m.cfg.RunDir, rundirKey, fname)
	}
	socketPath := filepath.Join(m.cfg.RunDir, rundirKey, "firecracker.sock")

	var tapDevice string
	if inst.Namespace != "" {
		netInfo, nsErr := m.netMgr.EnsureVMSlot(ctx, vmID, inst.Namespace, inst.IP, inst.MACAddress)
		if nsErr != nil {
			return "", fmt.Errorf("ensure network slot for verify: %w", nsErr)
		}
		tapDevice = netInfo.TAPDevice
	}

	// Throwaway Firecracker in the sandbox's existing unit/rundir, stopped on the
	// way out. Safe because the VM is paused (no live FC to disrupt), but it must
	// not run concurrently with a resume of the same sandbox — fine for the
	// debug/staging use this endpoint is gated to.
	if _, err := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, inst.Namespace); err != nil {
		return "", fmt.Errorf("start firecracker for verify: %w", err)
	}
	defer func() { _ = stopUnit(context.Background(), systemdUnitName(vmID)) }()

	if err := LoadSnapshotNoResume(socketPath, snapshotPath, memPath, "eth0", tapDevice, ""); err != nil {
		return "", err
	}

	verifyDir := filepath.Join(filepath.Dir(memPath), "verify")
	if err := os.MkdirAll(verifyDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir verify dir: %w", err)
	}
	memBPath := filepath.Join(verifyDir, "mem.snap")
	if err := SnapshotPausedVM(socketPath, filepath.Join(verifyDir, "vmstate.snap"), memBPath); err != nil {
		return "", err
	}

	log.Info().Str("mem_b", memBPath).Msg("verify snapshot: re-snapshotted frozen image")
	return memBPath, nil
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

	if err := CreateSnapshot(inst.SocketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
		return "", "", fmt.Errorf("create snapshot: %w", err)
	}

	if err := UnpauseVM(inst.SocketPath); err != nil {
		return snapshotPath, memPath, fmt.Errorf("resume after snapshot: %w", err)
	}

	return snapshotPath, memPath, nil
}

// DeleteSnapshotFiles removes a snapshot's on-disk artifacts (vmstate + memory
// file). Both paths are required to lie strictly under <SnapshotDir>/<vmID>/ —
// any path outside that directory is rejected as InvalidArgument, so a call
// cannot unlink files belonging to another sandbox or the snapshot root itself.
//
// The operation is idempotent: missing files are not an error. The enclosing
// directory is removed on a best-effort basis once both files are gone and it
// is empty; a non-empty directory is left alone.
//
// Callers are responsible for ensuring the snapshot is no longer referenced
// by any running VM. This method does not inspect instance state.
func (m *Manager) DeleteSnapshotFiles(vmID, snapshotPath, memPath string) error {
	if vmID == "" {
		return status.Error(codes.InvalidArgument, "vm_id is required")
	}
	if snapshotPath == "" && memPath == "" {
		return status.Error(codes.InvalidArgument, "at least one of snapshot_path/mem_file_path is required")
	}
	for _, p := range []string{snapshotPath, memPath} {
		if p == "" {
			continue
		}
		if err := m.assertUnderVMSnapshotDir(vmID, p); err != nil {
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

	// Side-car (overlay-mode only). Missing is expected for legacy;
	// any other error is logged — leftover side-cars caused fork bugs.
	if snapshotPath != "" {
		sidecar := snapshotPath + ".overlay"
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			m.log.Warn().Err(err).Str("path", sidecar).Msg("remove overlay side-car")
		}
	}

	// Best-effort: if the parent directory is now empty, clean it up. Only
	// remove directories that are strict descendants of the vm's snapshot
	// root — never the vm root itself or anything above it. Any error is
	// swallowed; a non-empty or missing directory is fine.
	vmRoot := filepath.Clean(filepath.Join(m.cfg.SnapshotDir, vmID))
	sep := string(filepath.Separator)
	for _, p := range []string{snapshotPath, memPath} {
		if p == "" {
			continue
		}
		dir := filepath.Dir(filepath.Clean(p))
		if dir == vmRoot || !strings.HasPrefix(dir+sep, vmRoot+sep) {
			continue
		}
		_ = os.Remove(dir)
	}
	return nil
}

// DeleteSandboxSnapshots removes a sandbox's entire snapshot directory
// (<SnapshotDir>/<vmID>/). Path-based and idempotent — a missing directory is
// not an error — so it reclaims pause artifacts even when no snapshot row
// exists or the per-file delete was missed. The leaf/reserved guard prevents a
// stray vmID from escaping the snapshot root or removing the shared template
// tree. Only call this for a sandbox being deleted; it does not inspect
// instance state, so the caller must ensure the snapshot can't be resumed.
func (m *Manager) DeleteSandboxSnapshots(vmID string) error {
	if m.cfg.SnapshotDir == "" {
		return status.Error(codes.InvalidArgument, "snapshot dir not configured")
	}
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	dir := filepath.Join(m.cfg.SnapshotDir, vmID)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}

// assertUnderVMSnapshotDir returns nil iff `p` is an absolute path that, after
// cleaning, lies strictly under <SnapshotDir>/<vmID>/. This is the guard that
// keeps DeleteSnapshotFiles from being used to unlink another sandbox's files
// or the snapshot root itself.
func (m *Manager) assertUnderVMSnapshotDir(vmID, p string) error {
	if m.cfg.SnapshotDir == "" {
		return status.Error(codes.FailedPrecondition, "snapshot_dir not configured")
	}
	if !filepath.IsAbs(p) {
		return status.Errorf(codes.InvalidArgument, "path must be absolute: %s", p)
	}
	cleaned := filepath.Clean(p)
	root := filepath.Clean(filepath.Join(m.cfg.SnapshotDir, vmID))
	rel, err := filepath.Rel(root, cleaned)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return status.Errorf(codes.InvalidArgument, "path is outside snapshot directory for vm %s: %s", vmID, p)
	}
	return nil
}

// RestoreVMSnapshot boots a VM from a previously captured snapshot.
func (m *Manager) RestoreVMSnapshot(ctx context.Context, vmID, snapshotPath, memPath string,
	resourceLimits VMConfig, netCfg *network.Config, teamID, ownerID string,
) (*VMInstance, error) {
	return m.restoreVMSnapshot(ctx, vmID, snapshotPath, memPath, resourceLimits, netCfg, teamID, ownerID, "")
}

// restoreVMSnapshot is the implementation. recordToPath is empty for normal
// restores; set to a writable file path by template-build access-pattern
// recording, in which case the in-firecracker UFFD handler writes each served
// page offset to that file on VM shutdown.
func (m *Manager) restoreVMSnapshot(ctx context.Context, vmID, snapshotPath, memPath string,
	resourceLimits VMConfig, netCfg *network.Config, teamID, ownerID, recordToPath string,
) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()
	tEntry := time.Now()

	// Bound concurrent restores so a burst of sandbox creates doesn't
	// saturate host file I/O, netns setup, tmpfs, and Firecracker boots.
	// Fail fast with ctx.Err() if the caller's deadline fires while we
	// wait — the sandbox create has its own upstream deadline.
	select {
	case m.restoreSem <- struct{}{}:
		defer func() { <-m.restoreSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	tSemAcquired := time.Now()

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
		TeamID:       teamID,
		OwnerID:      ownerID,
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	// Side-car == overlay-mode marker. Fail clean if BasePath is missing
	// rather than fall through and risk opening an unrelated rootfs.
	if resourceLimits.BasePath == "" && snapshotPath != "" {
		if _, err := os.Stat(snapshotPath + ".overlay"); err == nil {
			m.setStatus(vmID, StatusError)
			return nil, status.Errorf(codes.FailedPrecondition,
				"snapshot %q is overlay-mode but no base_path was provided to restore", snapshotPath)
		}
	}

	plan := planRestore(resourceLimits.BasePath, resourceLimits.DeltaDir, inPlace)
	var diskPath string
	var diskErr error
	switch plan.action {
	case restoreCreateOverlay:
		diskPath, diskErr = m.createOverlay(vmID, resourceLimits.BasePath)
	case restoreReuseOverlay:
		existing := filepath.Join(m.cfg.RunDir, vmID, "overlay.ext4")
		if _, statErr := os.Stat(existing); statErr != nil {
			diskErr = fmt.Errorf("overlay-mode restore for vm %s: per-VM overlay missing at %q: %v", vmID, existing, statErr)
		} else {
			diskPath = existing
		}
	case restoreLegacyResolve:
		diskPath, diskErr = m.resolveRestoreDisk(ctx, vmID, snapshotPath)
	}
	if diskErr != nil {
		m.setStatus(vmID, StatusError)
		return nil, diskErr
	}
	tDiskReady := time.Now()

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
	tNetReady := time.Now()

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

	// inPlace resume always uses the File backend; UffdEnabled=false is the
	// ops circuit breaker that forces fresh restores onto File too.
	useUffd := !inPlace && m.cfg.UffdEnabled

	pid, startErr := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, diskPath, resourceLimits.BasePath, nsName)
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
	tFcReady := time.Now()

	log.Info().
		Int64("entry_to_sem_ms", tSemAcquired.Sub(tEntry).Milliseconds()).
		Int64("sem_to_disk_ms", tDiskReady.Sub(tSemAcquired).Milliseconds()).
		Int64("disk_to_net_ms", tNetReady.Sub(tDiskReady).Milliseconds()).
		Int64("net_to_fc_ms", tFcReady.Sub(tNetReady).Milliseconds()).
		Int64("entry_to_fc_ready_ms", tFcReady.Sub(tEntry).Milliseconds()).
		Msg("restoring snapshot")

	var restoreErr error
	switch {
	case useUffd:
		// Skip prefetch trace when recording so the captured order reflects
		// guest-driven access, not pages pulled in by the prefetcher.
		// Firecracker enforces this same invariant on its side (record_to set
		// ⇒ no prefetch regardless of access_log_path); this branch is the
		// stat-avoidance optimisation that keeps us from probing the disk for
		// a file we already know we won't pass through.
		accessLogPath := ""
		if recordToPath == "" && m.cfg.UffdPrefetchEnabled {
			candidate := filepath.Join(filepath.Dir(memPath), accessLogFilename)
			if _, err := os.Stat(candidate); err == nil {
				accessLogPath = candidate
			}
		}
		restoreErr = RestoreSnapshotUffdInternalWithOverrides(
			socketPath, snapshotPath, memPath, accessLogPath, recordToPath, "eth0", tapDevice, plan.deltaDir,
		)
	case inPlace:
		restoreErr = RestoreSnapshot(socketPath, snapshotPath, memPath, plan.deltaDir)
	default:
		// UFFD disabled but fresh restore — File backend with network overrides.
		restoreErr = RestoreSnapshotWithOverrides(socketPath, snapshotPath, memPath, "eth0", tapDevice, plan.deltaDir)
	}
	log.Info().
		Int64("load_snapshot_ms", time.Since(tFcReady).Milliseconds()).
		Bool("ok", restoreErr == nil).
		Msg("snapshot loaded")
	if restoreErr != nil {
		// Firecracker is already running; stop the unit before other
		// cleanup or it leaks. See stopUnitDuringRestoreError comment.
		m.stopUnitDuringRestoreError(vmID)
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		if errors.Is(restoreErr, ErrTornSnapshot) {
			return nil, status.Errorf(codes.DataLoss,
				"snapshot %q is torn (overlay side-car empty); re-snapshot from a healthy source: %v",
				snapshotPath, restoreErr)
		}
		return nil, fmt.Errorf("restore snapshot: %w", restoreErr)
	}

	tBoxdStart := time.Now()
	if err := m.waitForBoxd(ctx, hostIP, 5*time.Second); err != nil {
		m.stopUnitDuringRestoreError(vmID)
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("boxd not ready after restore: %w", err)
	}
	tBoxdReady := time.Now()

	m.setStatus(vmID, StatusRunning)
	m.persistState(inst)
	tPersisted := time.Now()

	log.Info().
		Int("pid", pid).
		Int64("wait_boxd_ms", tBoxdReady.Sub(tBoxdStart).Milliseconds()).
		Int64("persist_state_ms", tPersisted.Sub(tBoxdReady).Milliseconds()).
		Msg("VM restored from snapshot")
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
			// Repopulate the network slot like running VMs do, so a paused
			// sandbox deleted before its next resume can reclaim its slot.
			// Resume's EnsureVMSlot is idempotent, so this is safe.
			if inst.Namespace != "" && inst.IP != "" {
				if err := m.netMgr.ReattachVM(rec.ID, inst.Namespace, inst.IP, inst.MACAddress); err != nil {
					log.Error().Err(err).Msg("reattach: restore paused VM network state failed")
				}
			}
			log.Info().Msg("reattached paused VM")
			reattached++
			continue
		}

		// For running VMs, verify the systemd unit is still active.
		if !isUnitActive(ctx, systemdUnitName(rec.ID)) {
			log.Warn().Msg("VM in BoltDB but not running — cleaning up stale record")
			// Kill the orphaned Firecracker process if it's still alive.
			// Cold-booted VMs (from the old build path) were launched with
			// Setsid: true and no systemd unit, so they survive vmd restarts
			// as orphans holding TAP fds and contaminating the network pool.
			if rec.PID > 0 {
				if proc, err := os.FindProcess(rec.PID); err == nil {
					if killErr := proc.Signal(syscall.SIGKILL); killErr == nil {
						log.Info().Int("pid", rec.PID).Msg("killed orphan Firecracker process")
					}
				}
			}
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

		// Restore network manager state for this VM: slot tracking,
		// devices map, host firewall rules (re-installed via idempotent
		// AddVM in case the kernel rules were lost).
		if inst.Namespace != "" && inst.IP != "" {
			if err := m.netMgr.ReattachVM(rec.ID, inst.Namespace, inst.IP, inst.MACAddress); err != nil {
				log.Error().Err(err).Msg("reattach: restore network state failed")
			}
		}

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

	// Phase C: sweep host network namespaces (ns-N / veth-N) that do not
	// correspond to any live BoltDB record. Template builds never touch
	// BoltDB, so a crashed build always leaks; sandbox teardown can also
	// race the kernel-level delete. Without this sweep the pre-allocated
	// pool wastes startup retrying colliding slots and kernel state degrades
	// over time. Re-reading records reflects Phase A's stale deletions.
	keepNs := make(map[string]bool)
	if freshRecords, readErr := m.state.All(); readErr == nil {
		for _, rec := range freshRecords {
			if rec.Namespace != "" {
				keepNs[rec.Namespace] = true
			}
		}
	}
	if swept := m.netMgr.SweepOrphanNamespaces(keepNs); swept > 0 {
		m.log.Info().Int("swept", swept).Msg("sweep: removed orphan namespaces")
	}

	return reattached, stale
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

// DirEntry is one entry returned by ListDir. ModifiedUnix is 0 when the
// sandbox's boxd predates that field; the console renders it as "—".
type DirEntry struct {
	Name         string
	IsDir        bool
	Size         int64
	ModifiedUnix int64
}

// ListDir returns a one-level listing of dirPath inside a running VM via boxd's
// FilesystemService.ListDir — the metadata-over-Connect-RPC counterpart to the
// data plane's byte-transfer /files endpoint. It works on every sandbox: boxd
// has answered ListDir since long before the data-plane ?format=json handler,
// so existing sandboxes list without a template reseed.
//
// boxd's filesystem errors are translated to gRPC status codes here so the API
// never confuses a missing directory (NotFound) with a gone VM — boxd replying
// at all means the VM is alive. A gone VM is caught by getRunningVMIP above or
// surfaces as a connection error, not NotFound.
func (m *Manager) ListDir(ctx context.Context, vmID, dirPath string) ([]DirEntry, error) {
	vmIP, err := m.getRunningVMIP(vmID)
	if err != nil {
		return nil, err
	}
	client := boxdFilesystemClient(vmIP)
	resp, rpcErr := client.ListDir(ctx, connect.NewRequest(&pb.ListDirRequest{Path: dirPath}))
	if rpcErr != nil {
		switch connect.CodeOf(rpcErr) {
		case connect.CodeNotFound:
			return nil, status.Error(codes.NotFound, "directory not found")
		case connect.CodeInvalidArgument:
			return nil, status.Error(codes.InvalidArgument, "path is not a listable directory")
		default:
			return nil, rpcErr
		}
	}
	entries := resp.Msg.GetEntries()
	out := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, DirEntry{
			Name:         e.GetName(),
			IsDir:        e.GetIsDir(),
			Size:         e.GetSize(),
			ModifiedUnix: e.GetModifiedUnix(),
		})
	}
	return out, nil
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
	TeamID    string
	OwnerID   string
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
		TeamID:    inst.TeamID,
		OwnerID:   inst.OwnerID,
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

// copyRootfs creates a per-VM rootfs by copying the source image. Legacy
// non-overlay path; overlay mode uses createOverlay instead.
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

// createOverlay creates a sparse per-VM overlay file pre-sized to the base
// — explicit size avoids relying on fc's open-time set_len contract.
func (m *Manager) createOverlay(dirName, basePath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("createOverlay: basePath required")
	}
	baseInfo, err := os.Stat(basePath)
	if err != nil {
		return "", fmt.Errorf("stat base %q: %w", basePath, err)
	}
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir vm dir: %w", err)
	}
	overlayPath := filepath.Join(vmDir, "overlay.ext4")
	f, err := os.Create(overlayPath)
	if err != nil {
		return "", fmt.Errorf("create overlay: %w", err)
	}
	if err := f.Truncate(baseInfo.Size()); err != nil {
		f.Close()
		return "", fmt.Errorf("size overlay to base: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close overlay: %w", err)
	}
	return overlayPath, nil
}

func (m *Manager) cleanupRunDir(dirName string) {
	if !isLeafName(dirName) || isReservedRunDirName(dirName) {
		m.log.Error().Str("dir", dirName).Msg("refusing to remove unsafe or reserved rundir name")
		return
	}
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	if err := os.RemoveAll(vmDir); err != nil {
		m.log.Warn().Err(err).Str("dir", dirName).Msg("failed to remove rundir")
	}
}

// isLeafName reports whether s is safe as a single path element under a managed
// directory — non-empty, not "."/"..", and free of separators — so callers
// cannot escape that directory via filepath.Join + os.RemoveAll.
func isLeafName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

// isReservedRunDirName reports whether name is a shared dir under RunDir
// (template mount target, build tree) rather than a per-VM dir.
func isReservedRunDirName(name string) bool {
	return name == templateDirName || name == TemplatesDirName
}

// stopUnitDuringRestoreError stops the per-VM systemd unit when a restore
// aborts after Firecracker started. Uses a fresh context because the
// caller's gRPC ctx is often already cancelled (deadline exceeded under
// load). Without this, the firecracker process leaks.
func (m *Manager) stopUnitDuringRestoreError(vmID string) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := stopUnit(cleanupCtx, systemdUnitName(vmID)); err != nil {
		m.log.Warn().Err(err).Str("vm_id", vmID).Msg("systemctl stop failed during restore error cleanup")
	}
	removeUnitDropIn(vmID)
}

// RecordAccessPattern restores the snapshot in recording mode, waits a fixed
// warmup window for the guest to fault its working set, then destroys the VM.
// The Firecracker-side handler writes each unique offset to outputPath as it
// serves the fault, so the trace is durable on disk independent of how the VM
// process exits.
//
// The pre-flatten settle-on-fault-quiescence logic relied on reading
// FaultsServed from the Go-side handler. The in-firecracker handler keeps the
// same counters but does not yet expose them to vmd, so we currently use a
// fixed warmup of UffdRecordMaxSeconds. Refining this back to settle-based —
// along with restoring the lost `settled`, `elapsed`, and `total_faults`
// signals in the post-recording log — depends on a follow-up that surfaces
// per-VM UFFD metrics out of Firecracker.
func (m *Manager) RecordAccessPattern(ctx context.Context, vmID, snapshotPath, memPath, outputPath string,
	resourceLimits VMConfig, netCfg *network.Config,
) error {
	if _, err := os.Stat(outputPath); err == nil {
		m.log.Info().Str("path", outputPath).Msg("access log already exists, skipping recording")
		return nil
	}

	inst, err := m.restoreVMSnapshot(ctx, vmID, snapshotPath, memPath, resourceLimits, netCfg, "", "", outputPath)
	if err != nil {
		return fmt.Errorf("restore for recording: %w", err)
	}

	warmup := 10 * time.Second
	if m.cfg.UffdRecordMaxSeconds > 0 {
		warmup = time.Duration(m.cfg.UffdRecordMaxSeconds) * time.Second
	}

	if recordWarmup(ctx, warmup) == warmupCancelled {
		if err := m.DestroyVM(context.Background(), inst.ID, true); err != nil {
			m.log.Warn().Err(err).Str("template_vm", vmID).
				Msg("destroy after cancelled recording warmup failed; reconciler will clean up")
		}
		return ctx.Err()
	}

	if err := m.DestroyVM(context.Background(), inst.ID, true); err != nil {
		return fmt.Errorf("destroy recording VM: %w", err)
	}

	pages, exists := inspectRecordedTrace(outputPath)
	switch {
	case !exists:
		m.log.Warn().Str("template_vm", vmID).Str("path", outputPath).
			Msg("recorder produced no access log; restores will fall back to sequential prefetch")
	case pages == 0:
		m.log.Warn().Str("template_vm", vmID).Str("path", outputPath).
			Msg("recorder produced an empty access log; restores will fall back to sequential prefetch")
	default:
		m.log.Info().Str("template_vm", vmID).Str("path", outputPath).Int("pages", pages).
			Msg("access pattern recorded")
	}
	return nil
}

// warmupResult is the outcome of a recording warmup wait.
type warmupResult int

const (
	warmupCompleted warmupResult = iota
	warmupCancelled
)

// recordWarmup blocks until either the warmup window elapses or ctx is
// cancelled. Extracted so the cancellation path is unit-testable without
// having to mock the rest of the VM lifecycle.
func recordWarmup(ctx context.Context, warmup time.Duration) warmupResult {
	timer := time.NewTimer(warmup)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return warmupCancelled
	case <-timer.C:
		return warmupCompleted
	}
}

// inspectRecordedTrace returns the number of recorded offsets in the trace
// file at `path`. exists=false means the recorder never opened the file
// (typically because the restore failed before the handler started).
// pages=0 with exists=true means the file was opened but no faults arrived
// before destroy.
func inspectRecordedTrace(path string) (pages int, exists bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	// The recorder writes one decimal offset per line terminated with '\n'.
	// Counting newlines is a faithful page count without requiring a parse.
	return bytes.Count(content, []byte{'\n'}), true
}

// startFirecrackerColdBoot launches Firecracker inside a network namespace,
// configures it, and boots the kernel. Used by the template build pipeline
// (coldBootFromRootfs) to boot the throwaway VM that we snapshot into a
// new template.
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
// owns the process, not VMD. Non-empty basePath switches the start script to
// the dual-symlink overlay layout.
func (m *Manager) startFirecrackerViaSystemd(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	templateDir := m.templateRunDir()

	var setupCmds string
	if basePath != "" {
		baseLink := filepath.Join(templateDir, "base.ext4")
		overlayLink := filepath.Join(templateDir, "overlay.ext4")
		setupCmds = fmt.Sprintf("mount --make-rprivate / && mount -t tmpfs tmpfs %q && ln -s %q %q && ln -s %q %q",
			templateDir, basePath, baseLink, perVMRootfs, overlayLink)
	} else {
		rootfsLink := filepath.Join(templateDir, "rootfs.ext4")
		setupCmds = fmt.Sprintf("mount --make-rprivate / && mount -t tmpfs tmpfs %q && ln -s %q %q",
			templateDir, perVMRootfs, rootfsLink)
	}

	scriptPath := filepath.Join(filepath.Dir(socketPath), "start.sh")
	scriptContent := fmt.Sprintf("#!/bin/sh\nexec ip netns exec %s unshare -m -- sh -c '%s && exec %q --api-sock %q --id %q'\n",
		netNS, setupCmds, m.cfg.FirecrackerBin, socketPath, vmID)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
		return 0, fmt.Errorf("write start script: %w", err)
	}

	tStartUnit := time.Now()
	if err := startUnit(ctx, systemdUnitName(vmID)); err != nil {
		return 0, fmt.Errorf("start systemd unit: %w", err)
	}
	tStartUnitDone := time.Now()

	if err := waitForSocket(socketPath, 5*time.Second); err != nil {
		status := unitFailureSummary(ctx, systemdUnitName(vmID))
		_ = stopUnit(ctx, systemdUnitName(vmID))
		return 0, fmt.Errorf("wait for socket (unit %s): %w", status, err)
	}
	tSocketReady := time.Now()

	m.log.Info().
		Str("vm_id", vmID).
		Int64("start_unit_ms", tStartUnitDone.Sub(tStartUnit).Milliseconds()).
		Int64("wait_socket_ms", tSocketReady.Sub(tStartUnitDone).Milliseconds()).
		Msg("fc startup phases")

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

// waitForSocket blocks until the given socket path appears or the timeout
// elapses. Falls back to polling if inotify setup fails.
func waitForSocket(path string, timeout time.Duration) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return waitForSocketPolling(path, timeout)
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return waitForSocketPolling(path, timeout)
	}

	// Recheck after the watch is active: the socket could have appeared
	// in the race window between the stat above and watcher.Add returning.
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	name := filepath.Base(path)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return waitForSocketPolling(path, timeout)
			}
			if (ev.Op&fsnotify.Create) != 0 && filepath.Base(ev.Name) == name {
				return nil
			}
		case err, ok := <-watcher.Errors:
			if !ok || err != nil {
				return waitForSocketPolling(path, timeout)
			}
		case <-deadline.C:
			return fmt.Errorf("socket %s did not appear within %s", path, timeout)
		}
	}
}

func waitForSocketPolling(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

func (m *Manager) waitForBoxd(ctx context.Context, vmIP string, timeout time.Duration) error {
	return waitForHTTPHealth(ctx, vmIP, timeout)
}
