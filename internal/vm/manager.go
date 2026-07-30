package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/shellquote"
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

	// PreviewAccess and PreviewPorts are the data-plane publication policy.
	// Empty/legacy_public preserves historical all-port routing; strict modes
	// require membership in the allowlist. The revision rejects stale pushes.
	PreviewAccess         string
	PreviewPorts          map[int32]PreviewPortPolicy
	PreviewPolicyRevision int64
	// PreviewTokenPolicyRevision must exactly match PreviewPolicyRevision for
	// any per-port token generation to be active. A mismatched watermark is a
	// durable signal that an older writer advanced the policy without the
	// current token-carrier semantics.
	PreviewTokenPolicyRevision int64

	// BaseMemPath is the immutable base (template) memory file for a layered
	// snapshot. Set at create-from-template; non-empty ⇒ this VM's pauses write a
	// Diff overlay (mem.diff) against this base, and resume loads layered
	// (overlay + base). Cleared when a pause falls back to a standalone Full.
	BaseMemPath string

	// DirtyTracked is true when the current Firecracker run was loaded with
	// dirty-page tracking armed (set on incremental UFFD resume). Gates whether
	// the next pause may write a Diff snapshot. Not persisted: it describes the
	// live FC process, which a fresh resume re-establishes.
	DirtyTracked bool

	mu sync.RWMutex
}

// PreviewPortPolicy is the VMD representation of one published port. Access
// is empty for a Phase 1 sender and then inherits PreviewAccess. TokenVersion
// is meaningful only for a tokenized wire sentinel.
type PreviewPortPolicy struct {
	Access       string
	TokenVersion int64
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
	// file I/O, netns setup, and Firecracker boots. 0 → default 500.
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

	// IncrementalSnapshotEnabled makes a UFFD resume arm dirty-page tracking so the
	// next pause writes an incremental (Diff) snapshot — only the dirtied pages,
	// merged into the existing mem.snap — instead of a Full one. Requires
	// ResumeUffdEnabled. Default false.
	IncrementalSnapshotEnabled bool

	// HandlerDeathAbortEnabled tells the in-process UFFD handler to abort Firecracker
	// on an unexpected handler death (instead of letting the guest freeze on its next
	// page fault). The dead VM then surfaces via the unit-inactive → reconciler path
	// rather than hanging silently. Independent of the snapshot flags. Default false.
	HandlerDeathAbortEnabled bool

	// RequirePresenceSidecar controls refusing a layered UFFD restore whose
	// overlay has no .presence side-car next to it. Without the side-car,
	// Firecracker falls back to inferring page presence from the overlay's
	// extent map — only sound if the file was never copied by a tool that
	// rewrites sparse extents.
	//
	// Modes: "auto" (default) enforces once the host's convergence sweep has
	// given every layered overlay a side-car — enforcement engages only when
	// it provably affects nothing that exists; "always" enforces immediately
	// (fresh migration-target hosts, which start converged by construction);
	// "never" is the break-glass off switch.
	RequirePresenceSidecar string

	// LaunchViaLauncherNS routes the Firecracker launch through a long-lived,
	// pruned "launcher" mount namespace (pinned at LauncherNSPath); see
	// fcStartScript for the mechanism. Keeps per-VM launch cost independent of
	// fleet size. Default false; the legacy `ip netns exec` path is the fallback.
	LaunchViaLauncherNS bool

	// LauncherNSPath is where the launcher mount namespace is pinned (persisted
	// via `unshare --mount`). Only used when LaunchViaLauncherNS is true.
	// Empty → defaultLauncherNSPath.
	LauncherNSPath string
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

	// launcherReady gates the launcher launch path: false → launches use the
	// legacy path. Set when the namespace is built/validated; kept in sync by
	// revalidateLauncher.
	launcherReady atomic.Bool
	// launcherBuilt is true only after a successful build THIS boot; gates
	// revalidateLauncher's re-enable so a stale previous-boot pin can't resurrect
	// the launcher path.
	launcherBuilt atomic.Bool

	// orphanScanDone gates the fresh-unit linger skip: it is set only after
	// startup reattach successfully listed active units and registered the
	// BoltDB-missing ones as unconfirmed stops. Until then (or forever, if
	// the listing failed) a predecessor-era unit could be alive with no
	// bookkeeping, so every launch must run the linger query.
	orphanScanDone atomic.Bool

	// presenceConverged mirrors the on-disk converged marker: every layered
	// overlay on this host has a presence side-car, so strict enforcement can
	// engage (in "auto" mode) without affecting anything that exists. Set at
	// startup from the marker file and by the convergence sweep when it wins.
	presenceConverged atomic.Bool

	mu  sync.RWMutex
	vms map[string]*VMInstance

	// reattachSF dedups concurrent on-demand reattach of the same VM, so a
	// request that arrives before the background startup pass has reached its
	// VM loads it once from BoltDB instead of racing.
	reattachSF singleflight.Group

	// restoreSem bounds concurrent RestoreVMSnapshot operations. Buffered
	// channel; capacity = effective MaxConcurrentRestores.
	restoreSem chan struct{}

	// tplLastRestore: last restore time per template mem file, for the
	// secs_since_template_restore phase tag (a page-cache warmth proxy).
	tplMu          sync.Mutex
	tplLastRestore map[string]time.Time

	// builds tracks in-flight and completed template builds. Keyed by
	// build VM id (which is also "build-" + templateID). Entries survive
	// until process exit so late pollers can read terminal outcomes.
	buildsMu sync.RWMutex
	builds   map[string]*buildRecord

	// vmOpLocks serializes lifecycle operations (restore, resume, pause) for
	// a single vmID, so a retry or a concurrent actor can't stomp an
	// in-flight launch (kill a still-booting VM, re-diff a consumed dirty
	// bitmap). Keyed by vmID → chan struct{}{} used as a capacity-1
	// semaphore, so acquisition can honor the caller's context. Entries are
	// never deleted: vmIDs are unique UUIDs so they don't collide, and
	// deleting on destroy would let a same-vmID retry acquire a fresh lock
	// and lose mutual exclusion. DestroyVM deliberately does NOT take these
	// locks — it must interrupt a wedged op (a hung firecracker socket call
	// holds the lock until destroy SIGKILLs the process), so blocking it
	// would turn a recoverable wedge into a permanent hang.
	vmOpLocks sync.Map
}

// instanceRunning reports whether vmID's tracked instance is Running — the
// authoritative signal that a resume/restore completed, used by the
// reconciler to avoid stopping a just-relaunched unit.
func (m *Manager) instanceRunning(vmID string) bool {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.Status == StatusRunning
}

// vmOpCh returns vmID's capacity-1 lock channel, creating it once.
func (m *Manager) vmOpCh(vmID string) chan struct{} {
	if v, ok := m.vmOpLocks.Load(vmID); ok {
		return v.(chan struct{})
	}
	v, _ := m.vmOpLocks.LoadOrStore(vmID, make(chan struct{}, 1))
	return v.(chan struct{})
}

// lockVMOp acquires vmID's lifecycle lock, honoring ctx while it waits — a
// caller whose deadline expires in the queue behind another op returns
// ctx.Err() instead of running abandoned pause/restore work. The returned
// func releases it. Never called from a read/reattach path (not reentrant)
// or from DestroyVM (see vmOpLocks).
func (m *Manager) lockVMOp(ctx context.Context, vmID string) (func(), error) {
	ch := m.vmOpCh(vmID)
	select {
	case ch <- struct{}{}:
		// select picks a ready case at random, so an already-cancelled
		// caller can win the send even though ctx is done. Re-check and
		// release rather than run abandoned work.
		if err := ctx.Err(); err != nil {
			<-ch
			return nil, err
		}
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tryLockVMOp acquires vmID's lifecycle lock without blocking. ok=false
// means an operation is in flight for this vmID and the caller must not act.
func (m *Manager) tryLockVMOp(vmID string) (unlock func(), ok bool) {
	ch := m.vmOpCh(vmID)
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return nil, false
	}
}

// NewManager creates a new VM manager.
func NewManager(cfg ManagerConfig, netMgr *network.Manager, log zerolog.Logger) (*Manager, error) {
	maxRestores := cfg.MaxConcurrentRestores
	if maxRestores <= 0 {
		maxRestores = 500
	}
	// Magic mount target — every per-VM start script mounts tmpfs over it.
	// Missing → "mount: failed" → opaque "wait for socket" timeout. Create
	// at startup so an aggressive ops cleanup can't break sandbox/build paths.
	if cfg.RunDir != "" {
		if err := os.MkdirAll(filepath.Join(cfg.RunDir, templateDirName), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir template magic dir: %w", err)
		}
	}
	m := &Manager{
		cfg:            cfg,
		netMgr:         netMgr,
		log:            log.With().Str("component", "vm_manager").Logger(),
		vms:            make(map[string]*VMInstance),
		restoreSem:     make(chan struct{}, maxRestores),
		tplLastRestore: make(map[string]time.Time),
	}
	m.loadPresenceConverged()
	return m, nil
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
// returns ESRCH) or the deadline expires. Returns true when the process is
// gone. Used after SIGKILL to ensure the kernel has actually reaped the
// process and released its fds before we reuse its resources.
func waitForPIDExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// syscall.Kill(pid, 0) returns ESRCH when the process is gone.
		if err := syscall.Kill(pid, 0); err != nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// sigkillPID SIGKILLs pid and waits up to wait for the kernel to reap it, so
// its fds (including a tap device) are released before the caller reuses the
// process's resources. The single kill path for orphan Firecrackers.
func sigkillPID(pid int, wait time.Duration) {
	if pid <= 0 {
		return
	}
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Signal(syscall.SIGKILL)
		if wait > 0 {
			waitForPIDExit(pid, wait)
		}
	}
}

// pidIsVMFirecracker reports whether pid is this VM's Firecracker. A stored
// PID can be stale (paused VMs keep the PID of a process that died at pause)
// and reused by an unrelated process, so kills fed by stored state verify
// identity first — the exact `--id <vmID>` argv token plus the firecracker
// binary, not a substring match.
func pidIsVMFirecracker(pid int, vmID string) bool {
	if pid <= 0 || vmID == "" {
		return false
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return firecrackerCmdlineMatches(cmdline, vmID)
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

	// Recover the PID, socket, and namespace to tear down. A tracked VM has them
	// in memory; an untracked one (paused or post-restart, absent from m.vms) has
	// them only in the record. Without the record fallback a cold-boot VM's
	// Firecracker is never killed (stopUnit is a no-op for it) and its slot is
	// never reclaimed (ns is "").
	var pid int
	var sockPath, ns string
	if instErr == nil {
		inst.mu.RLock()
		pid = inst.PID
		sockPath = inst.SocketPath
		ns = inst.Namespace
		inst.mu.RUnlock()
	} else if m.state != nil {
		if rec, err := m.state.Get(vmID); err == nil && rec != nil {
			pid = rec.PID
			sockPath = rec.SocketPath
			ns = rec.Namespace
		}
	}

	// No-op for systemd VMs (stopUnit already killed them); the real kill for
	// cold-boot VMs and record orphans. Identity-gated regardless of source —
	// a paused VM's PID is stale whether it came from memory or the record.
	if pidIsVMFirecracker(pid, vmID) {
		sigkillPID(pid, 500*time.Millisecond)
	}
	if sockPath != "" {
		_ = os.Remove(sockPath)
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
	// Serialize same-vmID lifecycle ops (see lockVMOp): a duplicate pause
	// waits, then hits the already-paused guard.
	unlockOp, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return "", "", err
	}
	defer unlockOp()

	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", "", err
	}

	log := m.log.With().Str("vm_id", vmID).Logger()

	// Retried pause (response lost mid-RPC): re-snapshotting a stopped VM
	// dials a dead socket and ends with the record deleted. Return the
	// recorded artifacts instead — after confirming they still exist, like
	// ResumeVM does before acting on a record.
	inst.mu.RLock()
	if inst.Status == StatusPaused && inst.SnapshotPath != "" && inst.MemFilePath != "" {
		snapshotPath, memPath = inst.SnapshotPath, inst.MemFilePath
		inst.mu.RUnlock()
		if !fileExists(snapshotPath) || !fileExists(memPath) {
			return "", "", status.Errorf(codes.FailedPrecondition, "paused VM artifacts missing on host: %s", memPath)
		}
		log.Info().Msg("pause: VM already paused, returning existing snapshot")
		return snapshotPath, memPath, nil
	}
	inst.mu.RUnlock()

	if snapshotDir == "" {
		snapshotDir = filepath.Join(m.cfg.SnapshotDir, vmID)
	}
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create snapshot dir: %w", err)
	}

	snapshotPath = filepath.Join(snapshotDir, "vmstate.snap")

	// Read the fields that select Full vs in-place-diff vs layered together under the
	// lock, so the decision can't see a torn mix written by a concurrent resume.
	inst.mu.RLock()
	socketPath := inst.SocketPath
	dirtyTracked := inst.DirtyTracked
	instBaseMem := inst.BaseMemPath
	instMemFile := inst.MemFilePath
	inst.mu.RUnlock()

	// Layered incremental: a template-created, dirty-tracked VM writes a diff overlay
	// (mem.diff) holding only the pages changed vs its template base. The base is a
	// distinct file from the overlay, so the merge never touches the template the
	// handler still faults from; resume loads overlay+base lazily.
	//
	// Only layer when this overlay is the one the VM accumulates into: the first
	// pause after a template create (resumed from the base directly), or a later
	// pause writing the exact overlay the VM resumed from. Otherwise (custom dir,
	// explicit-override resume) the diff would capture only this run's changes and
	// drop the prior overlay's pages, so fall back to a Full (complete) image.
	overlayPath := filepath.Join(snapshotDir, "mem.diff")
	fullPath := filepath.Join(snapshotDir, "mem.snap")
	layered := m.cfg.IncrementalSnapshotEnabled && dirtyTracked && instBaseMem != "" &&
		(instMemFile == instBaseMem || overlayPath == instMemFile)
	baseMemPath := ""
	// CreateDiffSnapshot merges in place: an interrupted diff has no surviving copy
	// of the file it overwrites (for layered, only the session delta — the template
	// base is untouched; for in-place, the VM's own mem.snap). Crash-atomicity of the
	// diff is the durability-boundary work, intentionally out of scope here.
	switch {
	case layered:
		memPath = overlayPath
		baseMemPath = instBaseMem
		// A first layered pass (VM loaded straight from the template base, not from
		// this overlay) must start from a fresh overlay: its dirty set is the whole
		// overlay, so any leftover mem.diff from a failed/un-finalized earlier pause
		// would survive as stale page extents — CreateDiffSnapshot writes only
		// dirtied pages in place and never truncates — and override the base on the
		// next layered restore, corrupting guest memory. Remove it; if it can't be
		// removed, fall back to Full. An accumulating pass (resumed from this same
		// overlay) must instead keep it, so this only runs for the first pass.
		usable := true
		if instMemFile == instBaseMem {
			if rerr := freshenFirstPassOverlay(overlayPath); rerr != nil {
				log.Warn().Err(rerr).Str("path", overlayPath).Msg("pause: stale overlay/side-car removal failed; falling back to Full")
				usable = false
			}
		}
		// Write the base sidecar BEFORE the diff so an overlay never exists on disk
		// without its base record (a stateless cross-host restore relies on it). If
		// the sidecar can't be written, fall back to a Full rather than produce an
		// unrecoverable overlay.
		if usable {
			if serr := os.WriteFile(layeredBaseSidecarPath(memPath), []byte(baseMemPath), 0o644); serr != nil {
				log.Warn().Err(serr).Msg("pause: layered base sidecar write failed; falling back to Full")
				usable = false
			}
		}
		if usable {
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating layered diff snapshot")
			saveStart := time.Now()
			if err := CreateDiffSnapshot(socketPath, snapshotPath, memPath); err != nil {
				// A failed diff may have left a partial overlay. Drop the .base sidecar
				// so a later restore can't treat that partial data as a valid layered
				// overlay — without the sidecar it's refused (overlay-without-base),
				// failing loud instead of loading corrupt memory. The overlay file
				// itself is left in place: handleVMError keeps a still-running VM, which
				// may still have it mmap'd. (True crash-atomicity is out of scope.)
				// The presence side-car goes too — it describes the pre-failure
				// overlay. Racing a still-running Firecracker is benign: a side-car it
				// rewrites after this remove matches the completed dump, and with
				// .base gone the restore is refused regardless.
				_ = os.Remove(layeredBaseSidecarPath(memPath))
				_ = os.Remove(presence.SidecarPath(memPath))
				return "", "", m.handleVMError(vmID, fmt.Errorf("create layered diff snapshot: %w", err))
			}
			m.verifyPresenceRefreshed(memPath, saveStart, log)
		} else {
			memPath, baseMemPath = fullPath, ""
			if err := CreateSnapshot(socketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
				return "", "", m.handleVMError(vmID, fmt.Errorf("create snapshot: %w", err))
			}
		}
	default:
		memPath = fullPath
		// In-place diff (no template base): merge dirtied pages into the VM's own
		// mem.snap when tracking was armed this run and mem.snap is the resume base —
		// dirtied offsets are resident/never re-faulted, disjoint from clean reads.
		if shouldWriteDiff(m.cfg.IncrementalSnapshotEnabled, dirtyTracked, memPath, instMemFile, fileExists(memPath)) {
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating diff snapshot")
			if err := CreateDiffSnapshot(socketPath, snapshotPath, memPath); err != nil {
				return "", "", m.handleVMError(vmID, fmt.Errorf("create diff snapshot: %w", err))
			}
		} else {
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating snapshot")
			if err := CreateSnapshot(socketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
				return "", "", m.handleVMError(vmID, fmt.Errorf("create snapshot: %w", err))
			}
		}
	}

	// Stop the Firecracker process — snapshot is already on disk. A stop
	// that fails must NOT fail the pause: the artifacts are valid and the
	// record must reach Paused (a retry against a Running record would
	// re-diff an already-consumed dirty bitmap and destroy the overlay).
	//
	// Bound the stop path (both attempts + dead-check) to the caller's
	// deadline so the handler can't run long past the ~30s pause RPC cap
	// (stopUnit's expiry settle may probe ≤2s past it — bounded, and it only
	// affects the log below, never what gets persisted). A timed-out pause
	// converges anyway: the control plane retries pause to paused rather than
	// reverting, and a straggler unit is reclaimed by the reconciler.
	unit := systemdUnitName(vmID)
	stopCtx, stopCancel := context.WithTimeout(ctx, stopUnitBudget)
	if err := stopUnit(stopCtx, unit); err != nil {
		log.Warn().Err(err).Msg("systemctl stop failed during pause; retrying")
		if serr := stopUnit(stopCtx, unit); serr != nil && !unitDefinitelyDead(stopCtx, unit) {
			log.Error().Err(serr).Msg("unit still running after pause; reconciler will reclaim it")
		}
	}
	stopCancel()

	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.BaseMemPath = baseMemPath // template base for a layered overlay; "" when standalone
	inst.DirtyTracked = false      // FC process is stopping; a fresh resume re-arms tracking.
	inst.mu.Unlock()

	m.persistState(inst)
	log.Info().Msg("VM paused")
	return snapshotPath, memPath, nil
}

// shouldWriteDiff reports whether a pause may write a Diff instead of a Full.
// Diff is correct only when tracking was armed this run AND memPath is the exact
// mem file this VM resumed from AND that file exists; any miss falls back to Full.
// Diff onto a non-resume-file or untracked run would silently corrupt the snapshot.
// memFileExists is the on-disk presence of memPath itself (the VM's own mem.snap),
// not a template/layered base — the in-place diff merges into that resume file.
func shouldWriteDiff(incremental, dirtyTracked bool, memPath, resumeMemPath string, memFileExists bool) bool {
	return incremental && dirtyTracked && memPath == resumeMemPath && memFileExists
}

// layeredBaseSidecarPath is where the layered base (template) path is recorded
// next to an overlay mem file, so a restore that has only the on-disk artifact
// (no in-memory/BoltDB instance — e.g. a stateless RestoreVMSnapshot after host
// loss) can still reconstruct the base instead of loading the sparse overlay
// standalone (which would read the base's pages as zero holes).
func layeredBaseSidecarPath(memPath string) string { return memPath + ".base" }

// ErrPresenceSidecarMissing marks a layered restore refused because the overlay
// has no presence side-car on a host that requires one (RequirePresenceSidecar).
// Deterministic and permanent until the artifact pair is re-copied, so callers
// must map it to FailedPrecondition — surfacing it as a generic (retryable)
// error turns one bad transfer into an indefinite boot/teardown retry loop.
var ErrPresenceSidecarMissing = errors.New("overlay presence side-car missing")

// gateOverlayPresence enforces RequirePresenceSidecar before a layered restore
// of memPath. Without the side-car Firecracker infers presence from the
// overlay's extent map, which transfers can silently rewrite: refuse when this
// host requires the side-car (transferred-artifact hosts), warn otherwise
// (pre-side-car local snapshots restore fine from extents). Only confirmed
// absence gates; a side-car that exists but can't be stat'ed or parsed is left
// to Firecracker's own read, which fails loudly with the real error. Every
// layered restore entry point must call this — fresh restores and resumes
// alike — and it needs only memPath, so call it before any side effects.
func (m *Manager) gateOverlayPresence(memPath string, log zerolog.Logger) error {
	if _, err := os.Stat(presence.SidecarPath(memPath)); !os.IsNotExist(err) {
		return nil
	}
	if m.presenceStrict() {
		return fmt.Errorf(
			"layered overlay %q has no presence side-car and this host requires one; "+
				"re-copy the overlay and side-car as a pair: %w",
			memPath, ErrPresenceSidecarMissing)
	}
	log.Warn().Str("path", presence.SidecarPath(memPath)).
		Msg("layered overlay has no presence side-car; Firecracker will infer presence from extents")
	return nil
}

// freshenFirstPassOverlay removes any leftover overlay so a first layered pass starts
// from a clean file (its dirty set is the whole overlay, so a stale one would leave
// non-dirtied stale pages that override the base on restore). A missing overlay is the
// normal case (nil); a real overlay that can't be removed returns an error so the
// caller falls back to a Full snapshot rather than diff onto stale data.
func freshenFirstPassOverlay(overlayPath string) error {
	if err := os.Remove(overlayPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// The presence side-car pairs with the overlay just removed. Firecracker
	// rewrites it on the upcoming save, so this mainly keeps the fallback-to-Full
	// path from leaving a bitmap that describes a file that no longer exists.
	if err := os.Remove(presence.SidecarPath(overlayPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// readLayeredBase returns the recorded base for an overlay mem file and whether
// the sidecar is present and non-empty.
func readLayeredBase(memPath string) (string, bool) {
	b, err := os.ReadFile(layeredBaseSidecarPath(memPath))
	if err != nil {
		return "", false
	}
	base := strings.TrimSpace(string(b))
	return base, base != ""
}

// isOverlayMemFile reports whether memPath names a layered diff overlay (which
// must be restored over a base, never standalone).
func isOverlayMemFile(memPath string) bool {
	return filepath.Base(memPath) == "mem.diff"
}

// isTemplateMemPath reports whether memPath is an immutable template memory
// artifact (under <SnapshotDir>/templates/...), making it a valid layered base.
// Covers both system and user-built templates and any nesting (e.g. the
// build-<id> subdir the build pipeline writes), unlike the strict-shape
// templateRootfsForSnapshot used for legacy disk resolution.
func (m *Manager) isTemplateMemPath(memPath string) bool {
	if m.cfg.SnapshotDir == "" || memPath == "" {
		return false
	}
	root := filepath.Clean(filepath.Join(m.cfg.SnapshotDir, TemplatesDirName)) + string(filepath.Separator)
	return strings.HasPrefix(filepath.Clean(memPath), root)
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ---------------------------------------------------------------------------
// ResumeVM (restore from snapshot)
// ---------------------------------------------------------------------------

// ResumeVM restores a paused VM from its snapshot using a mount namespace.
func (m *Manager) ResumeVM(ctx context.Context, vmID, snapshotPath, memPath string) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()
	tEntry := time.Now()

	// Serialize same-vmID lifecycle ops (see lockVMOp): a duplicate resume
	// waits, then is recognized as a retry rather than relaunching.
	unlockOp, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlockOp()

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

	// Retried resume (response lost mid-RPC): the VM may already be up from
	// the prior attempt. Relaunching would kill it and roll the guest back
	// to the snapshot, so return the live instance — same guard as the
	// stateless restore path.
	if existing := m.retriedLaunchTarget(vmID, snapshotPath, memPath); existing != nil {
		log.Info().Msg("resume: VM already running and healthy, returning it")
		return existing, nil
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
	// Presence gate for layered overlays. Deterministic from a stat, so it
	// belongs here with the other precondition checks — a post-boot refusal
	// would start and tear down a Firecracker unit and network slot on every
	// auto-resume retry of a sandbox whose side-car was lost in transfer.
	if isOverlayMemFile(memPath) {
		if gerr := m.gateOverlayPresence(memPath, log); gerr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", gerr)
		}
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

	tSlot := time.Now()
	var netInfo *network.VMNetInfo
	if inst.Namespace != "" {
		var nsErr error
		netInfo, nsErr = m.netMgr.EnsureVMSlot(ctx, vmID, inst.Namespace, inst.IP, inst.MACAddress)
		if nsErr != nil {
			return nil, fmt.Errorf("ensure network slot for resume: %w", nsErr)
		}
	}

	tFcStart := time.Now()
	pid, err := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, inst.Namespace, false)
	if err != nil {
		return nil, fmt.Errorf("start firecracker for restore: %w", err)
	}
	tFcDone := time.Now()

	log.Info().Str("snapshot_path", snapshotPath).Msg("restoring VM from snapshot")
	// A base is needed only when memPath is itself a diff overlay. Keying on memPath
	// (not the cached BaseMemPath) means a standalone/override resume clears any
	// stale base, so the next pause won't wrongly diff against the old template.
	//
	// The .base sidecar is authoritative for THIS overlay, so prefer it — the cached
	// BaseMemPath only matches the cached overlay (inst.MemFilePath) and would supply
	// the wrong base for an explicit override of a different mem.diff. Fall back to
	// the cached base only when the sidecar is missing and this is the cached overlay.
	basePath := ""
	if isOverlayMemFile(memPath) {
		if b, ok := readLayeredBase(memPath); ok {
			basePath = b
		} else if memPath == inst.MemFilePath {
			basePath = inst.BaseMemPath
		}
		if basePath == "" {
			m.stopUnitDuringRestoreError(vmID)
			return nil, status.Errorf(codes.FailedPrecondition,
				"layered overlay %q has no recoverable base; refusing standalone restore", memPath)
		}
	}
	tRestore := time.Now()
	dirtyTracked, err := m.restoreForResume(socketPath, snapshotPath, memPath, basePath, netInfo)
	tRestoreDone := time.Now()
	if err != nil {
		// Firecracker is already running; stop the unit before returning or it leaks.
		m.stopUnitDuringRestoreError(vmID)
		if errors.Is(err, ErrTornSnapshot) {
			return nil, status.Errorf(codes.DataLoss,
				"snapshot %q is torn (overlay side-car empty); re-snapshot from a healthy source: %v",
				snapshotPath, err)
		}
		if errors.Is(err, ErrLayeredInvalidSnapshot) {
			// Permanent: the overlay/base pairing is structurally invalid, so retrying
			// the layered restore can't succeed. FailedPrecondition tells the caller not
			// to retry (vs the generic Internal below, which it may).
			return nil, status.Errorf(codes.FailedPrecondition,
				"snapshot %q has an invalid layered overlay/base pairing; do not retry: %v",
				snapshotPath, err)
		}
		return nil, fmt.Errorf("restore snapshot: %w", err)
	}

	inst.mu.Lock()
	inst.PID = pid
	inst.SocketPath = socketPath
	inst.Status = StatusRunning
	inst.DirtyTracked = dirtyTracked
	// Record the file actually resumed from (callers may pass an explicit path
	// that differs from the cached one) so the next pause's diff baseline matches
	// what Firecracker's dirty bitmap is relative to.
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.BaseMemPath = basePath // re-cache (may have come from the on-disk sidecar)
	inst.mu.Unlock()

	m.persistState(inst)
	// Resume-side phase parity with the create path's "restoring snapshot"
	// line; wait_boxd_ms arrives async on the probe log below. prep spans
	// the op-lock wait plus the precondition gates, so a duplicate-resume
	// queue shows up here rather than hiding in the total.
	log.Info().Int("pid", pid).
		Int64("prep_ms", tSlot.Sub(tEntry).Milliseconds()).
		Int64("ensure_slot_ms", tFcStart.Sub(tSlot).Milliseconds()).
		Int64("fc_start_ms", tFcDone.Sub(tFcStart).Milliseconds()).
		Int64("restore_ms", tRestoreDone.Sub(tRestore).Milliseconds()).
		Int64("total_ms", time.Since(tEntry).Milliseconds()).
		Msg("VM resumed from snapshot")

	// Telemetry only: measure how long boxd takes to become reachable after
	// the vCPUs resume. Detached — status is already running and the probe
	// mutates nothing, so a slow or dead boxd can't affect the resume. The
	// field name matches the restore path's wait_boxd_ms so both are
	// queryable the same way; resume readiness was the blind spot in the
	// exec-503 incidents.
	probeStart := time.Now()
	vmIP := inst.IP
	go func() {
		defer sentrylog.Recover("resume-boxd-probe")
		probeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.waitForBoxd(probeCtx, vmIP, 30*time.Second); err != nil {
			log.Warn().Err(err).
				Int64("wait_boxd_ms", time.Since(probeStart).Milliseconds()).
				Msg("boxd not reachable after resume")
			return
		}
		log.Info().
			Int64("wait_boxd_ms", time.Since(probeStart).Milliseconds()).
			Msg("boxd reachable after resume")
	}()
	return inst, nil
}

// restoreForResume picks the resume memory backend: UFFD (reusing the existing tap
// for the interface override, optionally layered over basePath) when enabled and a
// tap is present, else File. A layered overlay (basePath set) requires UFFD. Reports
// whether dirty-page tracking was armed so the caller can decide if the next pause
// may write a Diff.
func (m *Manager) restoreForResume(socketPath, snapshotPath, memPath, basePath string, netInfo *network.VMNetInfo) (dirtyTracked bool, err error) {
	useUffd := m.cfg.ResumeUffdEnabled && m.cfg.UffdEnabled && netInfo != nil && netInfo.TAPDevice != ""
	if !useUffd {
		// A layered overlay can only be served by the UFFD layered backend. If this
		// host can't take that path (resume-UFFD/UFFD off, or no tap), refuse rather
		// than load the sparse overlay via the File backend, which would read the
		// base's pages as zero holes.
		if basePath != "" {
			return false, fmt.Errorf("layered overlay %q requires UFFD resume (resume-uffd + uffd + tap); refusing File-backend restore", memPath)
		}
		return false, RestoreSnapshot(socketPath, snapshotPath, memPath, "")
	}

	// No prefetch access log: only template builds record one (next to the template
	// snapshot), pause snapshots don't — so resume-side prefetch is future work.
	// basePath non-empty ⇒ layered restore (memPath is the diff overlay over basePath).
	trackDirty := m.cfg.IncrementalSnapshotEnabled
	return trackDirty, RestoreSnapshotUffdInternalWithOverrides(
		socketPath, snapshotPath, memPath, basePath, "", "", "eth0", netInfo.TAPDevice, "", trackDirty,
		m.cfg.HandlerDeathAbortEnabled,
	)
}

// VerifySnapshot loads vmID's snapshot without resuming, re-snapshots the frozen
// image to a temp file, and returns its path (compare with the original via
// snapcheck). Non-destructive: stops the throwaway FC, leaving the sandbox paused.
func (m *Manager) VerifySnapshot(ctx context.Context, vmID string) (string, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()

	// Serialize same-vmID lifecycle ops (see lockVMOp): the throwaway
	// firecracker must not race a concurrent resume onto the same unit.
	unlockOp, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return "", err
	}
	defer unlockOp()

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
	// This gate loads via the File backend (no base), so it can only verify a
	// standalone image. A layered diff overlay would load with its base's pages as
	// zero holes and produce a meaningless comparison — refuse instead.
	if isOverlayMemFile(memPath) || inst.BaseMemPath != "" {
		return "", status.Errorf(codes.FailedPrecondition,
			"vm %s is a layered (diff-overlay) snapshot; the verify gate only supports standalone images", vmID)
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
	if _, err := m.startFirecrackerViaSystemd(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, inst.Namespace, false); err != nil {
		return "", fmt.Errorf("start firecracker for verify: %w", err)
	}
	defer func() { _ = stopUnitWithBudget(context.Background(), systemdUnitName(vmID)) }()

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

	// This Full snapshot reset Firecracker's dirty bitmap, so the diff baseline
	// relative to the resume base is gone. Clear the flag now — before the unpause,
	// which can fail and return early — so a later pause can't take the Diff path
	// against the stale baseline and miss pages dirtied between resume and this
	// ad-hoc snapshot. Forces the next pause back to Full.
	inst.mu.Lock()
	inst.DirtyTracked = false
	inst.mu.Unlock()
	m.persistState(inst)

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

	// Side-cars. Missing is expected for legacy; any other error is logged —
	// leftover side-cars caused fork bugs. The .overlay record sits next to the
	// vmstate snapshot; the layered .base record sits next to the mem overlay
	// (mem.diff.base). A stray .base would make a later restore treat a
	// non-layered mem file as a layered overlay, so it must go with the mem file.
	if snapshotPath != "" {
		sidecar := snapshotPath + ".overlay"
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			m.log.Warn().Err(err).Str("path", sidecar).Msg("remove overlay side-car")
		}
	}
	if memPath != "" {
		// The .presence bitmap must go with the mem file for the same reason as
		// .base: VMD reuses mem paths, and a stale bitmap next to a future
		// same-size overlay passes Firecracker's geometry checks and silently
		// resolves pages against the wrong layer.
		for _, sidecar := range []string{layeredBaseSidecarPath(memPath), presence.SidecarPath(memPath)} {
			if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
				m.log.Warn().Err(err).Str("path", sidecar).Msg("remove mem side-car")
			}
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
	previewAccess string, previewPorts map[int32]PreviewPortPolicy, previewPolicyRevision int64,
) (*VMInstance, error) {
	return m.restoreVMSnapshot(ctx, vmID, snapshotPath, memPath, resourceLimits, netCfg, teamID, ownerID, previewAccess, previewPorts, previewPolicyRevision, "")
}

// templateRestoreAge returns seconds since this host last completed a restore of
// the given template mem file (i.e. last warmed its page cache), or -1 if
// untracked or first-seen. Read-only — markTemplateRestored does the recording,
// so a restore that fails before the load can't stamp a false-warm reading.
func (m *Manager) templateRestoreAge(memPath string) int64 {
	if !m.isTemplateMemPath(memPath) {
		return -1
	}
	m.tplMu.Lock()
	prev, seen := m.tplLastRestore[filepath.Clean(memPath)]
	m.tplMu.Unlock()
	if !seen {
		return -1
	}
	return int64(time.Since(prev).Seconds())
}

// markTemplateRestored records that a restore of the given template mem file
// completed (guest booted → working set now cached). Only template mem paths
// are tracked (per-VM resume snapshots are keyed by vmID and would grow the map
// unbounded), so those are a no-op.
func (m *Manager) markTemplateRestored(memPath string) {
	if !m.isTemplateMemPath(memPath) {
		return
	}
	m.tplMu.Lock()
	m.tplLastRestore[filepath.Clean(memPath)] = time.Now()
	m.tplMu.Unlock()
}

// psiSomeAvg10 returns the "some avg10" pressure-stall figure from a PSI file
// (e.g. /proc/pressure/cpu), or -1 if unavailable. Best-effort.
func psiSomeAvg10(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				n, perr := strconv.ParseFloat(v, 64)
				if perr != nil {
					return -1
				}
				return n
			}
		}
	}
	return -1
}

// restoreVMSnapshot is the implementation. recordToPath is empty for normal
// restores; set to a writable file path by template-build access-pattern
// recording, in which case the in-firecracker UFFD handler writes each served
// page offset to that file on VM shutdown.
func (m *Manager) restoreVMSnapshot(ctx context.Context, vmID, snapshotPath, memPath string,
	resourceLimits VMConfig, netCfg *network.Config, teamID, ownerID string,
	previewAccess string, previewPorts map[int32]PreviewPortPolicy, previewPolicyRevision int64, recordToPath string,
) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()
	tEntry := time.Now()

	if vmID == "" {
		vmID = uuid.New().String()
	}

	// Serialize same-vmID lifecycle ops (see lockVMOp): a duplicate restore
	// waits for the in-flight attempt, then retriedLaunchTarget recognizes
	// it — instead of racing into the inPlace block and stopping it. Taken
	// BEFORE restoreSem so a retry storm for one vmID blocks on the lock
	// without holding scarce restore slots, which would starve other VMs.
	unlockOp, lerr := m.lockVMOp(ctx, vmID)
	if lerr != nil {
		return nil, lerr
	}
	defer unlockOp()

	// Retried restore (response lost mid-RPC): re-restoring a VM the prior
	// attempt brought up would roll the guest back to the snapshot. A live
	// unit proves the prior restore completed — return that VM instead.
	// Checked BEFORE restoreSem so a no-op retry never consumes a scarce
	// restore slot (or fails on the semaphore when all slots are busy).
	// lazyReattach loads a paused VM the background reattach hasn't reached.
	m.lazyReattach(vmID)
	if existing := m.retriedLaunchTarget(vmID, snapshotPath, memPath); existing != nil {
		log.Info().Msg("restore: VM already running and healthy, returning it")
		return existing, nil
	}

	// A control plane from before preview publication sends the zero-value
	// policy on restore. Preserve an existing in-memory or sidecar-backed policy
	// whenever its revision is at least as new, including strict revision zero;
	// otherwise rolling back and forward could reopen every port in memory even
	// though StateStore correctly retained the durable sidecar.
	previewAccess, previewPorts, previewPolicyRevision, policyErr := m.previewPolicyForRestore(
		vmID, previewAccess, previewPorts, previewPolicyRevision,
	)
	if policyErr != nil {
		return nil, status.Errorf(codes.Internal, "load existing preview policy for restore: %v", policyErr)
	}

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
	// Cold/hot segmentation tags for the phase log, sampled once (not per
	// attempt): concurrency, template-cache age, and host CPU/mem pressure.
	// warmthPath is the file that actually drives fault-in — for a layered
	// overlay it's the recorded template base (memPath is then a per-VM diff),
	// else memPath itself — so layered restores segment by the base they use.
	//
	// inflight = other restores in flight (we already hold a slot, so subtract
	// it); an uncontended restore reads 0. len >= 1 here, so no underflow.
	inflight := len(m.restoreSem) - 1
	warmthPath := memPath
	if base, ok := readLayeredBase(memPath); ok {
		warmthPath = base
	}
	tplAgeSecs := m.templateRestoreAge(warmthPath)
	cpuPSI := psiSomeAvg10("/proc/pressure/cpu")
	memPSI := psiSomeAvg10("/proc/pressure/memory")

	// Deterministic artifact/config preconditions, checked before ANY state
	// changes: no provisional instance published (a refusal must not leave a
	// phantom StatusError record for retries to trip over as inPlace), no
	// existing same-ID VM stopped, no disk/network/Firecracker setup.
	//
	// Side-car == overlay-mode marker. Fail clean if BasePath is missing
	// rather than fall through and risk opening an unrelated rootfs.
	if resourceLimits.BasePath == "" && snapshotPath != "" {
		if _, err := os.Stat(snapshotPath + ".overlay"); err == nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"snapshot %q is overlay-mode but no base_path was provided to restore", snapshotPath)
		}
	}
	// Presence gate for layered overlays (same predicate the layered backend
	// selection uses below).
	if _, hasBase := readLayeredBase(memPath); hasBase || isOverlayMemFile(memPath) {
		if gerr := m.gateOverlayPresence(memPath, log); gerr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", gerr)
		}
	}

	// Sampled before this attempt creates the rundir: a pre-existing rundir
	// means a prior attempt on this host reached start.sh (and possibly
	// started the unit) even if it died before persisting any state, so the
	// unit name is not provably fresh. Only a definitive not-exist proves
	// absence — any other stat error reads as prior.
	_, rdErr := os.Stat(filepath.Join(m.cfg.RunDir, vmID))
	priorRunDir := !errors.Is(rdErr, os.ErrNotExist)

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

		PreviewAccess:              previewAccess,
		PreviewPorts:               clonePreviewPorts(previewPorts),
		PreviewPolicyRevision:      previewPolicyRevision,
		PreviewTokenPolicyRevision: inferPreviewTokenPolicyRevision(previewPorts, previewPolicyRevision),
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	// A provably-fresh unit name — no known instance (lazyReattach already
	// folded BoltDB into the map), no prior rundir, and no stop attempt this
	// process could still be winding down from — cannot be lingering, so the
	// launch may skip the systemd linger query. The winding-down term covers
	// cleanup paths that delete the other evidence after an unconfirmed stop
	// (destroy, reattach stale-cleanup). Build VMs never qualify: their
	// deterministic reused IDs are exempt from persistence and invisible to
	// the reconciler, so no bookkeeping can ever rule out a prior unit.
	// orphanScanDone gates everything: until startup reattach has listed
	// active units, a predecessor-era orphan may exist with no bookkeeping.
	// Only the first attempt qualifies: any retry follows a start of the
	// same unit name.
	freshUnit := m.orphanScanDone.Load() && !inPlace && !priorRunDir &&
		!isBuildVM(vmID) && !unitMaybeWindingDown(systemdUnitName(vmID))

	plan := planRestore(resourceLimits.BasePath, resourceLimits.DeltaDir, inPlace)
	// Failure cleanup must not delete an overlay this attempt didn't create:
	// see cleanupRunDirKeepOverlay.
	cleanupAfterRestoreFailure := func() {
		if plan.action == restoreReuseOverlay {
			m.cleanupRunDirKeepOverlay(vmID)
		} else {
			m.cleanupRunDir(vmID)
		}
	}
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

	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	// inPlace resume always uses the File backend; UffdEnabled=false is the
	// ops circuit breaker that forces fresh restores onto File too.
	useUffd := !inPlace && m.cfg.UffdEnabled

	// Loop-carried across restore attempts: only what the post-loop code reads.
	var (
		hostIP     string
		pid        int
		restoreErr error
	)

	// A fresh restore that fails with a still-held tap0 (isTapDeviceBusyErr) is
	// retried on a different slot; the failed slot is torn down. inPlace resumes
	// reuse a specific VM's own slot and never retry.
	const maxRestoreAttempts = 3
	for attempt := 1; ; attempt++ {
		tAttemptStart := time.Now()
		var tapDevice, macAddr, nsName string
		hostIP = ""
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
				cleanupAfterRestoreFailure()
				m.setStatus(vmID, StatusError)
				return nil, fmt.Errorf("setup network: %w", netErr)
			}
			tapDevice = netInfo.TAPDevice
			macAddr = netInfo.MACAddress
			hostIP = netInfo.HostIP
			nsName = netInfo.Namespace
		}
		tNetReady := time.Now()

		// Publish all the network/disk/socket fields before starting Firecracker
		// so the in-memory view is consistent for concurrent readers.
		inst.mu.Lock()
		inst.DiskPath = diskPath
		inst.IP = hostIP
		inst.TAPDevice = tapDevice
		inst.MACAddress = macAddr
		inst.Namespace = nsName
		inst.SocketPath = socketPath
		inst.mu.Unlock()

		var startErr error
		pid, startErr = m.startFirecrackerViaSystemd(ctx, vmID, socketPath, diskPath, resourceLimits.BasePath, nsName, freshUnit && attempt == 1)
		if startErr != nil {
			if !inPlace {
				m.netMgr.CleanupVM(vmID)
			}
			cleanupAfterRestoreFailure()
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("start firecracker: %w", startErr)
		}
		inst.mu.Lock()
		inst.PID = pid
		inst.mu.Unlock()
		tFcReady := time.Now()

		// Attempts after the first measure from the attempt start, so a retry's
		// disk_to_net_ms doesn't absorb the whole failed previous attempt.
		netBase := tDiskReady
		if attempt > 1 {
			netBase = tAttemptStart
		}
		log.Info().
			Int64("entry_to_sem_ms", tSemAcquired.Sub(tEntry).Milliseconds()).
			Int64("sem_to_disk_ms", tDiskReady.Sub(tSemAcquired).Milliseconds()).
			Int64("disk_to_net_ms", tNetReady.Sub(netBase).Milliseconds()).
			Int64("net_to_fc_ms", tFcReady.Sub(tNetReady).Milliseconds()).
			Int64("entry_to_fc_ready_ms", tFcReady.Sub(tEntry).Milliseconds()).
			Int("inflight", inflight).
			Int64("secs_since_template_restore", tplAgeSecs).
			Bool("inplace", inPlace).
			Bool("uffd", useUffd).
			Float64("cpu_psi_avg10", cpuPSI).
			Float64("mem_psi_avg10", memPSI).
			Int("attempt", attempt).
			Msg("restoring snapshot")

		// attemptErr is this attempt's result alone; it lands in restoreErr after
		// the load log so a stale prior-attempt error can never leak into the
		// UFFD branch's attemptErr==nil gate below.
		var attemptErr error
		// A diff overlay (mem.diff, or any file with a base sidecar) must be served by
		// the UFFD layered backend. Catch it before backend selection so that with UFFD
		// disabled / inPlace / resume-UFFD off it fails loud instead of falling to the
		// File backend, which would load the sparse overlay as a full image (the base's
		// pages read as zero holes).
		sidecarBase, hasSidecar := readLayeredBase(memPath)
		overlayNeedsLayered := isOverlayMemFile(memPath) || hasSidecar
		switch {
		case overlayNeedsLayered && !(useUffd && m.cfg.ResumeUffdEnabled):
			attemptErr = fmt.Errorf(
				"layered overlay %q requires UFFD layered restore (uffd + resume-uffd); refusing File-backend restore",
				memPath)
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
			// Decide the layered base for this UFFD restore. An overlay (mem.diff) needs
			// its base reconstructed from the sidecar (else refuse — loading it
			// standalone reads the base as zero holes); a template create instead arms
			// tracking and records the template as the base. Layered needs resume-UFFD.
			isTemplate := m.isTemplateMemPath(memPath)
			canLayered := m.cfg.UffdEnabled && m.cfg.ResumeUffdEnabled
			basePath := ""
			armLayered := false
			switch {
			case hasSidecar:
				// The outer overlayNeedsLayered guard already required resume-UFFD to reach
				// here, so canLayered holds — serve the overlay over its recorded base.
				basePath = sidecarBase
				armLayered = m.cfg.IncrementalSnapshotEnabled
				inst.mu.Lock()
				inst.BaseMemPath = sidecarBase
				inst.DirtyTracked = armLayered
				inst.mu.Unlock()
			case isOverlayMemFile(memPath):
				attemptErr = fmt.Errorf("layered overlay %q has no base sidecar; refusing standalone restore", memPath)
			case m.cfg.IncrementalSnapshotEnabled && canLayered && recordToPath == "" && isTemplate:
				armLayered = true
				inst.mu.Lock()
				inst.BaseMemPath = memPath // template mem file = the layered base
				inst.DirtyTracked = true
				inst.mu.Unlock()
			}
			if attemptErr == nil {
				attemptErr = RestoreSnapshotUffdInternalWithOverrides(
					socketPath, snapshotPath, memPath, basePath, accessLogPath, recordToPath, "eth0", tapDevice, plan.deltaDir, armLayered,
					m.cfg.HandlerDeathAbortEnabled,
				)
			}
		case inPlace:
			attemptErr = RestoreSnapshot(socketPath, snapshotPath, memPath, plan.deltaDir)
		default:
			// UFFD disabled but fresh restore — File backend with network overrides.
			attemptErr = RestoreSnapshotWithOverrides(socketPath, snapshotPath, memPath, "eth0", tapDevice, plan.deltaDir)
		}
		log.Info().
			Int64("load_snapshot_ms", time.Since(tFcReady).Milliseconds()).
			Bool("ok", attemptErr == nil).
			Int("attempt", attempt).
			Msg("snapshot loaded")
		restoreErr = attemptErr

		if restoreErr == nil {
			break
		}
		// Retriable only for a fresh-restore tap0 busy. The overlay and inst are
		// kept for the next attempt; terminal cleanup lives below the loop.
		if inPlace || attempt >= maxRestoreAttempts || !isTapDeviceBusyErr(restoreErr) {
			break
		}
		m.stopUnitDuringRestoreError(vmID)
		// Retry only when the unit is affirmatively dead — an inconclusive
		// answer reads as alive. Launches would replace a live leftover,
		// but "not confirmed dead" means systemctl itself is struggling;
		// kept conservative.
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 2*time.Second)
		dead := unitDefinitelyDead(checkCtx, systemdUnitName(vmID))
		checkCancel()
		if !dead {
			log.Warn().Int("attempt", attempt).
				Msg("unit not confirmed dead after stop — not retrying restore")
			break
		}
		log.Warn().Err(restoreErr).Int("attempt", attempt).
			Msg("restore failed with tap0 busy — retrying with a fresh slot")
		// Full teardown, not recycle: a fast recycle could return this same busy
		// slot to the pool and the next attempt could re-claim it.
		m.netMgr.TeardownVM(vmID)
		inst.mu.Lock()
		inst.DirtyTracked = false
		inst.mu.Unlock()
	}

	if restoreErr != nil {
		// Firecracker is already running; stop the unit before other
		// cleanup or it leaks. See stopUnitDuringRestoreError comment.
		m.stopUnitDuringRestoreError(vmID)
		if !inPlace {
			// A tap-busy slot is suspect — tear it down rather than recycle it,
			// so it isn't handed to another create with the same bad tap.
			if isTapDeviceBusyErr(restoreErr) {
				m.netMgr.TeardownVM(vmID)
			} else {
				m.netMgr.CleanupVM(vmID)
			}
		}
		cleanupAfterRestoreFailure()
		m.setStatus(vmID, StatusError)
		// armLayered may have set DirtyTracked=true on inst before the restore call;
		// clear it on failure so a lingering instance can't later take a Diff against a
		// baseline that never loaded. (The VM is StatusError + unit stopped, so this is
		// belt-and-suspenders, but it keeps the flag honest.)
		inst.mu.Lock()
		inst.DirtyTracked = false
		inst.mu.Unlock()
		if errors.Is(restoreErr, ErrTornSnapshot) {
			return nil, status.Errorf(codes.DataLoss,
				"snapshot %q is torn (overlay side-car empty); re-snapshot from a healthy source: %v",
				snapshotPath, restoreErr)
		}
		if errors.Is(restoreErr, ErrLayeredInvalidSnapshot) {
			// Permanent: the overlay/base pairing is structurally invalid, so retrying
			// the layered restore can't succeed. FailedPrecondition tells the caller not
			// to retry (vs the generic Internal below, which it may).
			return nil, status.Errorf(codes.FailedPrecondition,
				"snapshot %q has an invalid layered overlay/base pairing; do not retry: %v",
				snapshotPath, restoreErr)
		}
		if errors.Is(restoreErr, ErrPresenceSidecarMissing) {
			// Permanent until the side-car is re-copied next to the overlay. Nothing
			// sets restoreErr to this sentinel today (the gate runs in the
			// precondition block), but without this mapping a future gate call that
			// funnels through restoreErr would downgrade the refusal to retryable.
			return nil, status.Errorf(codes.FailedPrecondition, "%v", restoreErr)
		}
		return nil, fmt.Errorf("restore snapshot: %w", restoreErr)
	}

	tBoxdStart := time.Now()
	// Same window as first boot: a restore that has to fault its memory and
	// overlay from cold storage (first resume of a migrated VM, page cache
	// evicted) legitimately needs more than a warm same-host resume, and a
	// timeout here is destructive — the error path below tears down the VM.
	if err := m.waitForBoxd(ctx, hostIP, 30*time.Second); err != nil {
		m.stopUnitDuringRestoreError(vmID)
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		cleanupAfterRestoreFailure()
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("boxd not ready after restore: %w", err)
	}
	tBoxdReady := time.Now()

	// boxd is up → the guest has booted, so this template's working set is now
	// in page cache: read eagerly at load (File) or faulted in during boot
	// (UFFD). Stamp warmthPath (the layered base for an overlay restore, else
	// memPath) here (not at the load) so the next restore's
	// secs_since_template_restore reflects real warmth for either backend.
	m.markTemplateRestored(warmthPath)

	m.setStatus(vmID, StatusRunning)
	m.persistState(inst)
	// Persist-then-verify: checking AFTER the write leaves no window — a
	// concurrent DestroyVM either erased the record itself or is caught here,
	// and we erase our write and tear down instead of resurrecting it.
	m.mu.RLock()
	_, stillTracked := m.vms[vmID]
	m.mu.RUnlock()
	if !stillTracked {
		m.deleteState(vmID)
		m.stopUnitDuringRestoreError(vmID)
		if !inPlace {
			m.netMgr.CleanupVM(vmID)
		}
		cleanupAfterRestoreFailure()
		return nil, status.Errorf(codes.NotFound, "vm %s was destroyed during restore", vmID)
	}
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

	// Phase A: reattach from BoltDB. Routed through reattachByID (singleflight)
	// so this eager pass and any concurrent lazy request serialize per VM — a
	// lazy load can't run reattachRecord for a vmID while the eager pass is mid
	// stale-cleanup for the same one. reattachByID re-reads the record inside the
	// flight, so a DestroyVM between the snapshot and here can't resurrect it.
	for _, snap := range records {
		// Stop on shutdown: a cancelled ctx makes liveness checks fail, which
		// would otherwise misfire the stale-cleanup path against live VMs.
		if ctx.Err() != nil {
			break
		}
		if m.reattachByID(snap.ID, true) != nil {
			reattached++
		} else {
			stale++
		}
	}

	// Phase B: detect orphan systemd units not in BoltDB.
	activeIDs, err := listActiveFirecrackerUnits(ctx)
	if err != nil {
		m.log.Warn().Err(err).Msg("failed to list active firecracker units — orphan detection skipped")
	} else {
		for _, id := range activeIDs {
			if !knownIDs[id] {
				// Registered as an unconfirmed stop so a same-ID launch never
				// reads this orphan as fresh: without a control-plane DB the
				// reconciler never stops BoltDB-missing units, so this
				// observation may be the only bookkeeping the unit gets.
				recordUnitStop(systemdUnitName(id))
				m.log.Warn().Str("vm_id", id).Msg("orphan systemd unit detected (not in BoltDB) — will be handled by reconciler")
			}
		}
		// Orphans are accounted for — fresh-unit launches may skip the
		// linger query from here on. Stays unset on listing failure: an
		// unobserved orphan can't be ruled out by anything else.
		m.orphanScanDone.Store(true)
	}

	// No broad re-sweep here. Startup already swept once before StartPool filled
	// the pool; re-sweeping now would delete the pool's warm netns (which are not
	// BoltDB records). Stale records deleted in Phase A free their own namespace
	// inline (see reattachRecord), so a re-sweep isn't needed.

	return reattached, stale
}

// reattachRecord rebuilds one VM's in-memory and network state from its BoltDB
// reattachHook, when non-nil, is invoked at the start of every reattachRecord
// call. Test-only seam for asserting that concurrent reattaches of the same VM
// dedupe through the singleflight group. Always nil in production.
var reattachHook func(vmID string)

// record. Returns (nil, false) when cleanupStale deleted a dead record.
//
// cleanupStale must be false on the request path: the dead-VM check would SIGKILL
// and delete a live VM whenever systemctl is merely slow. Only the eager GC pass
// sets it. Concurrent-safe: the map write is double-checked under the lock.
func (m *Manager) reattachRecord(ctx context.Context, rec VMRecord, cleanupStale bool) (*VMInstance, bool) {
	if reattachHook != nil {
		reattachHook(rec.ID)
	}
	// Already present. A lazy load inserts optimistically (no liveness check), so
	// a dead record it inserted isn't GC'd here — that's the reconciler's job
	// (Drift 1/5 → markStale), deliberately, to avoid racing the request path.
	m.mu.RLock()
	if inst, ok := m.vms[rec.ID]; ok {
		m.mu.RUnlock()
		return inst, true
	}
	m.mu.RUnlock()

	log := m.log.With().Str("vm_id", rec.ID).Logger()

	// Running VMs must have a live systemd unit and a reachable API socket; a
	// dead one is a stale record. Paused VMs legitimately have no unit — they
	// were stopped at pause and wait for a resume — so they skip these checks.
	if cleanupStale && rec.Status != StatusPaused {
		if unitDefinitelyDead(ctx, systemdUnitName(rec.ID)) {
			log.Warn().Msg("VM in BoltDB but not running — cleaning up stale record")
			// Cold-booted VMs (old build path) ran with Setsid and no unit, so
			// they survive vmd restarts as orphans holding TAP fds — SIGKILL by
			// PID, but only after verifying the PID still names this VM (a stale
			// record PID may have been reused by an unrelated process). The wait
			// lets the kernel release the tap fd before the netns teardown below.
			if pidIsVMFirecracker(rec.PID, rec.ID) {
				sigkillPID(rec.PID, 500*time.Millisecond)
				log.Info().Int("pid", rec.PID).Msg("killed orphan Firecracker process")
			}
			m.state.Delete(rec.ID)
			// Free this record's namespace/slot directly instead of a broad
			// re-sweep (which would also delete the warm pool's netns).
			m.netMgr.CleanupVMOrNamespace(rec.ID, rec.Namespace)
			return nil, false
		}
		if rec.SocketPath != "" {
			if _, statErr := os.Stat(rec.SocketPath); statErr != nil {
				log.Warn().Str("socket", rec.SocketPath).Msg("VM unit active but socket missing — stopping and cleaning up")
				// The unit is still active, so stop Firecracker before we forget
				// the record and tear down its netns — otherwise it keeps running
				// as an orphan burning CPU/RAM and holding TAP fds in a namespace
				// we're about to delete out from under it.
				if err := stopUnit(ctx, systemdUnitName(rec.ID)); err != nil {
					log.Warn().Err(err).Msg("systemctl stop failed for socket-missing VM")
				}
				m.state.Delete(rec.ID)
				m.netMgr.CleanupVMOrNamespace(rec.ID, rec.Namespace)
				return nil, false
			}
		}
	}

	inst := toInstance(rec)

	// Bail early if another caller (a request, or the background pass) already
	// published this VM.
	m.mu.RLock()
	existing, present := m.vms[rec.ID]
	m.mu.RUnlock()
	if present {
		return existing, true
	}

	// Restore network state (slot tracking, devices map, host firewall rules)
	// BEFORE publishing to m.vms, so any concurrent getInstance that sees the
	// map entry is guaranteed devices[vmID] is already populated — otherwise its
	// UpdateSandboxNetwork/DestroyVM could race a half-restored VM. ReattachVM is
	// idempotent, so a rare double restore (background pass and a request both
	// reaching here) is harmless.
	if inst.Namespace != "" && inst.IP != "" {
		if err := m.netMgr.ReattachVM(rec.ID, inst.Namespace, inst.IP, inst.MACAddress); err != nil {
			log.Error().Err(err).Msg("reattach: restore network state failed")
		}
	}

	// Publish, re-checking under the write lock in case another caller won the
	// race while we restored network state; if so, keep theirs.
	m.mu.Lock()
	if existing, ok := m.vms[rec.ID]; ok {
		m.mu.Unlock()
		return existing, true
	}
	m.vms[rec.ID] = inst
	m.mu.Unlock()

	// Commit only if a concurrent DestroyVM didn't delete the record during
	// reattach (the gate is open, so deletes race the background pass); otherwise
	// undo the in-memory reattach.
	if rec.Status == StatusPaused {
		if m.recordDeleted(rec.ID) {
			m.undoReattach(rec.ID)
			return nil, false
		}
		log.Info().Msg("reattached paused VM")
	} else {
		if !m.persistStateIfPresent(inst) {
			m.undoReattach(rec.ID)
			return nil, false
		}
		log.Info().Int("pid", inst.PID).Str("ip", inst.IP).Msg("reattached to running VM")
	}
	return inst, true
}

// lazyReattach loads a VM's record from BoltDB and reattaches it on demand, so
// a request that arrives before the background startup pass has reached its VM
// resolves it here instead of getting a spurious NotFound. Deduped per VM by
// singleflight. Returns nil when the VM is unknown to this host (not in BoltDB).
func (m *Manager) lazyReattach(vmID string) *VMInstance {
	return m.reattachByID(vmID, false)
}

// reattachByID runs a single-flighted reattach for vmID. Routing BOTH the eager
// startup pass and lazy request loads through the same singleflight group
// serializes them per VM: only one reattachRecord runs for a given vmID at a
// time, so the eager pass's stale-cleanup can't free a slot back to the pool
// while a concurrent lazy load is mid-flight binding that VM's network state.
//
// cleanupStale is honored by whichever caller wins the flight; a joiner shares
// that result. The reattach uses a detached, bounded context so a caller's
// cancellation can't abort work another caller is waiting on. Returns nil when
// the VM is unknown to this host or was cleaned up as stale.
func (m *Manager) reattachByID(vmID string, cleanupStale bool) *VMInstance {
	if m.state == nil {
		return nil
	}
	v, _, _ := m.reattachSF.Do(vmID, func() (any, error) {
		m.mu.RLock()
		inst, ok := m.vms[vmID]
		m.mu.RUnlock()
		if ok {
			return inst, nil
		}
		rec, err := m.state.Get(vmID)
		if err != nil || rec == nil {
			return (*VMInstance)(nil), nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, _ := m.reattachRecord(ctx, *rec, cleanupStale)
		return got, nil
	})
	inst, _ := v.(*VMInstance)
	return inst
}

// SweepStartupOrphanNamespaces removes host network namespaces (ns-N / veth-N)
// that no live BoltDB record claims — leaked by crashed template builds or a
// teardown that raced the kernel delete. Reads BoltDB directly, so it is safe
// to run before the eager reattach and before the network pool fills.
func (m *Manager) SweepStartupOrphanNamespaces() {
	if m.state == nil {
		return
	}
	recs, err := m.state.All()
	if err != nil {
		// Sweeping with an empty keep-set would delete every live VM's
		// namespace — skip entirely when the records can't be read.
		m.log.Error().Err(err).Msg("sweep: cannot read state — skipping orphan namespace sweep")
		return
	}
	keepNs := make(map[string]bool)
	for _, rec := range recs {
		if rec.Namespace != "" {
			keepNs[rec.Namespace] = true
		}
	}
	if swept := m.netMgr.SweepOrphanNamespaces(keepNs); swept > 0 {
		m.log.Info().Int("swept", swept).Msg("sweep: removed orphan namespaces")
	}
}

// ReserveStartupSlots reserves every existing record's slot index in the network
// allocator's owned set (and bumps the high-water mark past it) so StartPool can
// run before the backgrounded per-VM reattach without the pool ever building on
// an index a record holds. Every record is reserved unconditionally — a dead
// record's slot is reclaimed later when the reattach cleans it up. Cheap: parses
// slot indices, no kernel work, no systemctl.
//
// Reports whether the reservation pass provably completed. Callers whose
// safety depends on record slots being reserved — pool adoption treats every
// unreserved namespace as claimable — must not proceed on false.
func (m *Manager) ReserveStartupSlots(context.Context) bool {
	if m.state == nil {
		return false
	}
	recs, err := m.state.All()
	if err != nil {
		m.log.Error().Err(err).Msg("failed to read state for startup slot reservation")
		return false
	}
	m.netMgr.ReserveSlotsAbove(collectStartupSlots(recs))
	return true
}

// collectStartupSlots returns vmID→namespace for every record that has one, so
// each slot is reserved under its owner. Pure — unit-testable without BoltDB.
func collectStartupSlots(recs []VMRecord) map[string]string {
	out := make(map[string]string, len(recs))
	for _, rec := range recs {
		if rec.Namespace != "" {
			out[rec.ID] = rec.Namespace
		}
	}
	return out
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

	PreviewAccess string
	PreviewPorts  map[int32]PreviewPortPolicy
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
		if inst = m.lazyReattach(vmID); inst == nil {
			return InstanceInfo{}, false
		}
	}
	inst.mu.RLock()
	previewPorts, _ := normalizePreviewTokenPolicy(
		inst.PreviewPorts, inst.PreviewPolicyRevision, inst.PreviewTokenPolicyRevision,
	)
	previewAccess := restrictivePreviewAccess(inst.PreviewAccess, previewPorts)
	info := InstanceInfo{
		VMIP:      inst.IP,
		Status:    inst.Status,
		CreatedAt: inst.CreatedAt,
		TeamID:    inst.TeamID,
		OwnerID:   inst.OwnerID,

		PreviewAccess: previewAccess,
		PreviewPorts:  previewPorts,
	}
	inst.mu.RUnlock()
	return info, true
}

func clonePreviewPorts(in map[int32]PreviewPortPolicy) map[int32]PreviewPortPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int32]PreviewPortPolicy, len(in))
	for port, policy := range in {
		out[port] = policy
	}
	return out
}

func normalizedPreviewAccess(access string) string {
	if access == "" {
		return preview.AccessLegacyPublic
	}
	return access
}

// inferPreviewTokenPolicyRevision marks one incoming full snapshot as
// tokenized only when every tokenized sentinel carries a positive generation.
// The policy revision itself becomes the durable watermark; there is no
// separate control-plane wire field that an older sender could accidentally
// replay.
func inferPreviewTokenPolicyRevision(ports map[int32]PreviewPortPolicy, revision int64) int64 {
	if revision <= 0 {
		return 0
	}
	foundTokenized := false
	for _, policy := range ports {
		if !preview.IsTokenizedAccess(policy.Access) {
			continue
		}
		foundTokenized = true
		if policy.TokenVersion <= 0 {
			return 0
		}
	}
	if !foundTokenized {
		return 0
	}
	return revision
}

// normalizePreviewTokenPolicy returns a detached map whose token generations
// are usable only for an exact, current tokenized snapshot. Raw private,
// public, legacy, and unknown modes always clear their generation. If one
// tokenized sentinel is malformed or the sidecar watermark is stale, all
// generations are cleared so no credential from a prior revision can be
// revived.
func normalizePreviewTokenPolicy(in map[int32]PreviewPortPolicy, revision, tokenPolicyRevision int64) (map[int32]PreviewPortPolicy, int64) {
	out := clonePreviewPorts(in)
	foundTokenized := false
	valid := revision > 0 && tokenPolicyRevision == revision
	for port, policy := range out {
		if preview.IsTokenizedAccess(policy.Access) {
			foundTokenized = true
			if policy.TokenVersion <= 0 {
				valid = false
			}
		} else {
			policy.TokenVersion = 0
			out[port] = policy
		}
	}
	if !foundTokenized || !valid {
		for port, policy := range out {
			policy.TokenVersion = 0
			out[port] = policy
		}
		return out, 0
	}
	return out, tokenPolicyRevision
}

// previewPolicyEqual compares the complete effective snapshot represented by
// one policy revision. Token state is normalized before comparison so stale
// generations on raw-private/public records never make two closed policies
// look different, while a live token watermark or generation disagreement is
// always rejected. Exact port membership is part of the snapshot identity.
func previewPolicyEqual(
	accessA string, portsA map[int32]PreviewPortPolicy, revisionA, tokenPolicyRevisionA int64,
	accessB string, portsB map[int32]PreviewPortPolicy, revisionB, tokenPolicyRevisionB int64,
) bool {
	portsA, tokenPolicyRevisionA = normalizePreviewTokenPolicy(portsA, revisionA, tokenPolicyRevisionA)
	portsB, tokenPolicyRevisionB = normalizePreviewTokenPolicy(portsB, revisionB, tokenPolicyRevisionB)
	accessA = normalizedPreviewAccess(restrictivePreviewAccess(accessA, portsA))
	accessB = normalizedPreviewAccess(restrictivePreviewAccess(accessB, portsB))
	if revisionA != revisionB || tokenPolicyRevisionA != tokenPolicyRevisionB ||
		accessA != accessB || len(portsA) != len(portsB) {
		return false
	}
	for port, policyA := range portsA {
		policyB, ok := portsB[port]
		if !ok || policyA.Access != policyB.Access || policyA.TokenVersion != policyB.TokenVersion {
			return false
		}
	}
	return true
}

// previewPolicyForRestore merges incoming wire policy with any policy already
// known for this VM. Revisions identify immutable snapshots, so existing state
// wins equality. The durable sidecar is considered after memory and therefore
// wins an equal-revision disagreement caused by an old VMD rewriting only the
// primary lifecycle JSON.
func (m *Manager) previewPolicyForRestore(vmID, incomingAccess string, incomingPorts map[int32]PreviewPortPolicy, incomingRevision int64) (string, map[int32]PreviewPortPolicy, int64, error) {
	incomingTokenRevision := inferPreviewTokenPolicyRevision(incomingPorts, incomingRevision)
	ports, _ := normalizePreviewTokenPolicy(incomingPorts, incomingRevision, incomingTokenRevision)
	access := restrictivePreviewAccess(incomingAccess, ports)
	revision := incomingRevision

	m.mu.RLock()
	inst := m.vms[vmID]
	m.mu.RUnlock()
	if inst != nil {
		inst.mu.RLock()
		existingPorts, _ := normalizePreviewTokenPolicy(
			inst.PreviewPorts, inst.PreviewPolicyRevision, inst.PreviewTokenPolicyRevision,
		)
		existingAccess := restrictivePreviewAccess(inst.PreviewAccess, existingPorts)
		existingRevision := inst.PreviewPolicyRevision
		inst.mu.RUnlock()
		if existingRevision >= revision {
			access, ports, revision = existingAccess, existingPorts, existingRevision
		}
	}

	if m.state != nil {
		rec, err := m.state.Get(vmID)
		if err != nil {
			return "", nil, 0, err
		}
		if rec != nil && rec.PreviewPolicyRevision >= revision {
			ports = previewPortsFromRecord(rec.PreviewPorts, rec.PreviewPortAccess, rec.PreviewPortTokenVersions)
			ports, _ = normalizePreviewTokenPolicy(ports, rec.PreviewPolicyRevision, rec.PreviewTokenPolicyRevision)
			access = restrictivePreviewAccess(rec.PreviewAccess, ports)
			revision = rec.PreviewPolicyRevision
		}
	}
	return access, ports, revision, nil
}

// UpdateSandboxPreviewPolicy replaces the policy persisted on the instance
// record. Revisions are monotonic; older snapshots are harmlessly ignored, and
// an equal revision is idempotent only when its complete policy is identical.
func (m *Manager) UpdateSandboxPreviewPolicy(vmID, previewAccess string, previewPorts map[int32]PreviewPortPolicy, revision int64) error {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return err
	}
	inst.mu.Lock()
	if revision < inst.PreviewPolicyRevision {
		inst.mu.Unlock()
		return nil
	}
	tokenPolicyRevision := inferPreviewTokenPolicyRevision(previewPorts, revision)
	if revision == inst.PreviewPolicyRevision {
		equal := previewPolicyEqual(
			inst.PreviewAccess, inst.PreviewPorts, inst.PreviewPolicyRevision, inst.PreviewTokenPolicyRevision,
			previewAccess, previewPorts, revision, tokenPolicyRevision,
		)
		inst.mu.Unlock()
		if equal {
			return nil
		}
		return status.Errorf(codes.FailedPrecondition,
			"preview policy revision %d conflicts with the policy already stored for vm %s", revision, vmID)
	}
	nextPorts, tokenPolicyRevision := normalizePreviewTokenPolicy(previewPorts, revision, tokenPolicyRevision)
	previewAccess = restrictivePreviewAccess(previewAccess, nextPorts)
	// Keep the instance lock through persistence. Otherwise two concurrent
	// RPCs can apply revisions in order but race their BoltDB writes in reverse,
	// resurrecting the stale policy after a vmd restart. Persist the intended
	// record before advancing memory so a failed write leaves the old revision
	// retryable instead of acknowledging a policy that a restart would lose.
	if m.state != nil && !isBuildVM(inst.ID) {
		record := toRecordLocked(inst)
		record.PreviewAccess = previewAccess
		record.PreviewPorts = previewPortsToRecord(nextPorts)
		record.PreviewPortAccess = previewPortAccessToRecord(nextPorts)
		record.PreviewPortTokenVersions = previewPortTokenVersionsToRecord(nextPorts)
		record.PreviewPolicyRevision = revision
		record.PreviewTokenPolicyRevision = tokenPolicyRevision
		if err := m.state.Put(record); err != nil {
			inst.mu.Unlock()
			return fmt.Errorf("persist preview policy: %w", err)
		}
	}
	inst.PreviewAccess = previewAccess
	inst.PreviewPorts = nextPorts
	inst.PreviewPolicyRevision = revision
	inst.PreviewTokenPolicyRevision = tokenPolicyRevision
	inst.mu.Unlock()
	return nil
}

func restrictivePreviewAccess(sandboxAccess string, ports map[int32]PreviewPortPolicy) string {
	accesses := make([]string, 0, len(ports))
	for _, policy := range ports {
		accesses = append(accesses, policy.Access)
	}
	return preview.RestrictiveFallback(sandboxAccess, accesses...)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (m *Manager) getInstance(vmID string) (*VMInstance, error) {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if ok {
		return inst, nil
	}
	// Not in the map — during the startup window it may not be reattached yet;
	// load it on demand before declaring it gone.
	if inst := m.lazyReattach(vmID); inst != nil {
		return inst, nil
	}
	return nil, status.Errorf(codes.NotFound, "vm %s not found", vmID)
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

// persistStateIfPresent persists inst only if its record still exists (atomic),
// returning false when a concurrent DestroyVM deleted it — so the caller undoes
// the reattach instead of resurrecting it. No store / write error → true.
func (m *Manager) persistStateIfPresent(inst *VMInstance) bool {
	if m.state == nil || isBuildVM(inst.ID) {
		return true
	}
	wrote, err := m.state.PutIfPresent(toRecord(inst))
	if err != nil {
		m.log.Error().Err(err).Str("vm_id", inst.ID).Msg("failed to persist VM state to BoltDB")
		return true
	}
	return wrote
}

// recordDeleted reports whether vmID's record is gone from the store (deleted
// concurrently). False when there's no store or the read errors.
func (m *Manager) recordDeleted(vmID string) bool {
	if m.state == nil || isBuildVM(vmID) {
		return false
	}
	present, err := m.state.Has(vmID)
	return err == nil && !present
}

// undoReattach reverses an in-memory reattach when the record turns out to have
// been deleted concurrently. It only forgets the in-memory entries: whoever
// deleted the record (DestroyVM or the reconciler's markStale) already tore down
// or recycled the slot, so a second physical teardown here would double-free it
// or clobber the new owner of a recycled ns/veth.
func (m *Manager) undoReattach(vmID string) {
	m.mu.Lock()
	delete(m.vms, vmID)
	m.mu.Unlock()
	m.netMgr.Forget(vmID)
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

// cleanupRunDirKeepOverlay removes the VM's rundir contents except
// overlay.ext4. Restore failures use it when the overlay pre-existed the
// attempt (restoreReuseOverlay): the overlay is the sandbox's persistent
// disk — for a VM whose artifacts were placed on this host by a migration,
// it may be the only local copy — and deleting it turns a transient restore
// failure (network claim, timeout) into data loss that poisons every retry.
func (m *Manager) cleanupRunDirKeepOverlay(dirName string) {
	if !isLeafName(dirName) || isReservedRunDirName(dirName) {
		m.log.Error().Str("dir", dirName).Msg("refusing to clean unsafe or reserved rundir name")
		return
	}
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	entries, err := os.ReadDir(vmDir)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Warn().Err(err).Str("dir", dirName).Msg("failed to read rundir for selective cleanup")
		}
		return
	}
	for _, e := range entries {
		if e.Name() == "overlay.ext4" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(vmDir, e.Name())); err != nil {
			m.log.Warn().Err(err).Str("dir", dirName).Str("entry", e.Name()).Msg("failed to remove rundir entry")
		}
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
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := stopUnit(stopCtx, systemdUnitName(vmID)); err != nil {
		m.log.Warn().Err(err).Str("vm_id", vmID).Msg("systemctl stop failed during restore error cleanup")
	}

	// Slot is recycled right after this returns; if stopUnit timed out the FC
	// may still hold tap0. Resolve the unit's live MainPID (inst.PID is set
	// asynchronously and often still 0 this early), SIGKILL, and wait for exit.
	killCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	sigkillPID(m.unitMainPID(killCtx, vmID), 500*time.Millisecond)

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

	inst, err := m.restoreVMSnapshot(ctx, vmID, snapshotPath, memPath, resourceLimits, netCfg, "", "", "", nil, 0, outputPath)
	if err != nil {
		return fmt.Errorf("restore for recording: %w", err)
	}

	warmup := 10 * time.Second
	if m.cfg.UffdRecordMaxSeconds > 0 {
		warmup = time.Duration(m.cfg.UffdRecordMaxSeconds) * time.Second
	}

	// Bounded, not Background: an unbounded destroy could pin the shared
	// systemd job lock behind a wedged PID1 and queue every stop on the host.
	// The clock starts at the destroy, not before the warmup sleep.
	destroyRecordingVM := func() error {
		dctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return m.DestroyVM(dctx, inst.ID, true)
	}

	if recordWarmup(ctx, warmup) == warmupCancelled {
		if err := destroyRecordingVM(); err != nil {
			m.log.Warn().Err(err).Str("template_vm", vmID).
				Msg("destroy after cancelled recording warmup failed; reconciler will clean up")
		}
		return ctx.Err()
	}

	if err := destroyRecordingVM(); err != nil {
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

// defaultLauncherNSPath is where the pruned launcher mount namespace is pinned
// when LaunchViaLauncherNS is enabled without an explicit LauncherNSPath.
const defaultLauncherNSPath = "/run/vmd/launcher.mntns"

// launcherNSPath returns the launcher mount-namespace pin path when the
// launcher launch mode is enabled, or "" to select the legacy launch path.
func (m *Manager) launcherNSPath() string {
	if !m.cfg.LaunchViaLauncherNS {
		return ""
	}
	if m.cfg.LauncherNSPath != "" {
		return m.cfg.LauncherNSPath
	}
	return defaultLauncherNSPath
}

// fcSetupCmds builds the rootfs-setup portion of the launch script — mount the
// per-VM tmpfs and symlink the rootfs into it. Caller-influenced paths
// (basePath, perVMRootfs) are single-quoted so they can't inject shell.
func fcSetupCmds(templateDir, basePath, perVMRootfs string) string {
	if basePath != "" {
		baseLink := filepath.Join(templateDir, "base.ext4")
		overlayLink := filepath.Join(templateDir, "overlay.ext4")
		return fmt.Sprintf("mount --make-rprivate / && mount -t tmpfs tmpfs %s && ln -s %s %s && ln -s %s %s",
			shellquote.Single(templateDir), shellquote.Single(basePath), shellquote.Single(baseLink),
			shellquote.Single(perVMRootfs), shellquote.Single(overlayLink))
	}
	rootfsLink := filepath.Join(templateDir, "rootfs.ext4")
	return fmt.Sprintf("mount --make-rprivate / && mount -t tmpfs tmpfs %s && ln -s %s %s",
		shellquote.Single(templateDir), shellquote.Single(perVMRootfs), shellquote.Single(rootfsLink))
}

// fcStartScript renders the per-VM start.sh that systemd's ExecStart runs.
//
// launcherNSPath == "" → legacy: `ip netns exec <ns> unshare -m …`.
// launcherNSPath != "" → launcher: `nsenter --net=<ns> --mount=<pin> -- unshare
// -m …`, so the per-VM clone copies the launcher's small table, not the full host
// table. nsenter opens both fds from the host mount view before setns, so the
// netns resolves even though the launcher has /run/netns pruned — which is why
// `ip netns exec` (resolves the netns from inside the mount ns) can't be used.
func fcStartScript(netNS, launcherNSPath, setupCmds, fcBin, socketPath, vmID string) string {
	prefix := fmt.Sprintf("ip netns exec %s", netNS)
	sysfs := ""
	if launcherNSPath != "" {
		prefix = fmt.Sprintf("nsenter --net=/run/netns/%s --mount=%s --", netNS, shellquote.Single(launcherNSPath))
		// nsenter, unlike `ip netns exec`, doesn't remount /sys, so /sys/class/net
		// would show the host's interfaces, not the VM's tap. Remount a netns-aware
		// sysfs inside the per-VM ns (after make-rprivate, so it can't reach the host).
		sysfs = " && mount -t sysfs sysfs /sys"
	}
	// Each value is single-quoted, then the whole inner script is single-quoted as
	// the `sh -c` arg — two shellquote.Single layers, so a caller-influenced path
	// (base_path, perVMRootfs) can't close a quote and inject shell as root.
	inner := fmt.Sprintf("%s%s && exec %s --api-sock %s --id %s",
		setupCmds, sysfs, shellquote.Single(fcBin), shellquote.Single(socketPath), shellquote.Single(vmID))
	return fmt.Sprintf("#!/bin/sh\nexec %s unshare -m -- sh -c %s\n", prefix, shellquote.Single(inner))
}

// startFirecrackerViaSystemd writes the start script and launches Firecracker
// as a standalone systemd unit. The VM survives VMD restarts because systemd
// owns the process, not VMD. Non-empty basePath switches the start script to
// the dual-symlink overlay layout.
func (m *Manager) startFirecrackerViaSystemd(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, freshUnit bool) (int, error) {
	tPrestart := time.Now()
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	templateDir := m.templateRunDir()

	setupCmds := fcSetupCmds(templateDir, basePath, perVMRootfs)

	scriptPath := filepath.Join(filepath.Dir(socketPath), "start.sh")
	// Re-check the pin here, not just launcherReady: a pin unmounted since the
	// last revalidation tick would otherwise bake a dead nsenter --mount into
	// start.sh and hard-fail. pinIsMounted is one statfs — no fork on the hot
	// path, no transient exec failure under burst load. On failure fall back to
	// legacy for THIS launch only; launcherReady stays with the sampler, so one
	// blip can't knock the whole fleet onto the O(fleet) legacy path for a tick.
	launcherPath := ""
	pin := m.launcherNSPath()
	switch {
	case pin == "":
		// Launcher mode disabled: legacy is the configured path.
	case !m.launcherReady.Load():
		// Every launch here copies the full host mount table, so concurrent
		// launches degrade with fleet size. launcherBuilt splits the causes:
		// a build still in progress resolves itself; a failed build or an
		// invalidated pin does not.
		if m.launcherBuilt.Load() {
			m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin invalidated — using legacy path for this launch")
		} else {
			m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin not built — using legacy path for this launch")
		}
	case pinIsMounted(pin):
		launcherPath = pin
	default:
		m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin not mounted at launch — using legacy path for this launch")
	}
	scriptContent := fcStartScript(netNS, launcherPath, setupCmds, m.cfg.FirecrackerBin, socketPath, vmID)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
		return 0, fmt.Errorf("write start script: %w", err)
	}

	// Replacing a live (or still winding down) stale unit spends the stop
	// phase (TimeoutStopSec 10s) before the fresh process can even fork, so
	// it needs a bigger socket budget. Decided up front: with Type=simple
	// the restart job clears at fork, before the socket exists, so no
	// at-timeout probe can tell a just-replaced unit from a stalled fresh
	// one. Timed separately: it is a per-launch systemd round trip, and
	// concurrent launches serialize on the shared D-Bus connection. A
	// fresh unit skips it with the identical outcome: never-existed reads
	// NotLoaded, i.e. not lingering.
	tLinger := time.Now()
	replacingLive := !freshUnit && unitLingering(ctx, systemdUnitName(vmID))
	lingerCheckMs := time.Since(tLinger).Milliseconds()

	tStartUnit := time.Now()
	if err := restartUnit(ctx, systemdUnitName(vmID)); err != nil {
		return 0, fmt.Errorf("start systemd unit: %w", err)
	}
	tStartUnitDone := time.Now()

	socketWait := 5 * time.Second
	if replacingLive {
		socketWait = 17 * time.Second // 5s + the stop-phase margin
	}
	// waitForSocket ignores ctx, so cap the TOTAL wait at the caller's
	// remaining deadline — otherwise it overruns, the ctx expires, and the
	// stopUnit cleanup below runs on a dead context and leaves the unit up.
	// Floor it so a launch reached late in the deadline still gets a real
	// chance: a ~0 cap would reap a healthy VM whose socket is milliseconds
	// away. A small overrun of a near-spent deadline is the lesser evil.
	if dl, ok := ctx.Deadline(); ok {
		socketWait = max(2*time.Second, min(socketWait, time.Until(dl)))
	}
	err := waitForSocket(socketPath, socketWait)
	if err != nil {
		status := unitFailureSummary(ctx, systemdUnitName(vmID))
		m.log.Warn().Str("vm_id", vmID).Str("unit_state", status).Err(err).
			Msg("firecracker socket missing after launch")
		// Detached budget: the caller's ctx may be at its deadline here, and
		// this stop must run or the just-launched unit leaks.
		_ = stopUnitWithBudget(ctx, systemdUnitName(vmID))
		return 0, fmt.Errorf("wait for socket (unit %s): %w", status, err)
	}
	tSocketReady := time.Now()

	m.log.Info().
		Str("vm_id", vmID).
		Int64("prestart_ms", tStartUnit.Sub(tPrestart).Milliseconds()).
		Int64("linger_check_ms", lingerCheckMs).
		Bool("linger_skipped", freshUnit).
		Int64("start_unit_ms", tStartUnitDone.Sub(tStartUnit).Milliseconds()).
		Int64("wait_socket_ms", tSocketReady.Sub(tStartUnitDone).Milliseconds()).
		Msg("fc startup phases")

	// Read the PID asynchronously so the create path isn't slowed down
	// by the ~15ms dbus roundtrip. The PID is populated in the instance
	// shortly after create returns and persisted to BoltDB.
	go m.resolveAndSetPID(vmID)

	return 0, nil
}

// unitMainPID returns the systemd MainPID for a VM's unit, or 0 when it can't
// be resolved or the unit has no running process.
func (m *Manager) unitMainPID(ctx context.Context, vmID string) int {
	if val, notLoaded, ok := sdbusUnitProperty(ctx, systemdUnitName(vmID), "Service", "MainPID"); ok {
		if notLoaded {
			return 0 // unit gone == no process, definitively
		}
		if pid, isU32 := val.(uint32); isU32 {
			return int(pid)
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=MainPID", "--value", systemdUnitName(vmID)).Output()
	if err != nil {
		return 0
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pid); err != nil {
		return 0
	}
	return pid
}

func (m *Manager) resolveAndSetPID(vmID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pid := m.unitMainPID(ctx, vmID)
	if pid == 0 {
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

// waitForSocket blocks until the socket at path ACCEPTS connections or the
// timeout elapses. File existence alone is not readiness: the file appears
// at bind(), and a connect() in the bind()→listen() gap is refused.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if err := waitForSocketFile(path, deadline, timeout); err != nil {
		return err
	}
	// The connect phase gets its own bounded window from file-appearance:
	// capped at 1s so a process that bound and then died fails fast (its
	// socket refuses just like the gap does), floored at 250ms so a socket
	// appearing at the edge of the file budget still gets a real chance to
	// reach listen() — a bounded overrun of the nominal timeout.
	connWindow := min(time.Until(deadline), time.Second)
	connWindow = max(connWindow, 250*time.Millisecond)
	return waitForSocketConnectable(path, time.Now().Add(connWindow))
}

// WaitForAPISocket is the exported readiness wait for a firecracker API
// socket: file existence AND accepting connections. For use by every
// spawn site, in and out of this package.
func WaitForAPISocket(path string, timeout time.Duration) error {
	return waitForSocket(path, timeout)
}

// waitForSocketFile waits for the socket file to exist — inotify with a
// polling fallback. timeout is only for the error message.
func waitForSocketFile(path string, deadline time.Time, timeout time.Duration) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return waitForSocketFilePolling(path, deadline, timeout)
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return waitForSocketFilePolling(path, deadline, timeout)
	}

	// Recheck after the watch is active: the socket could have appeared
	// in the race window between the stat above and watcher.Add returning.
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	name := filepath.Base(path)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return waitForSocketFilePolling(path, deadline, timeout)
			}
			if (ev.Op&fsnotify.Create) != 0 && filepath.Base(ev.Name) == name {
				return nil
			}
		case err, ok := <-watcher.Errors:
			if !ok || err != nil {
				return waitForSocketFilePolling(path, deadline, timeout)
			}
		case <-timer.C:
			return fmt.Errorf("socket %s did not appear within %s", path, timeout)
		}
	}
}

func waitForSocketFilePolling(path string, deadline time.Time, timeout time.Duration) error {
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

// waitForSocketConnectable dials until the socket accepts a connection.
// The bind()→listen() gap is normally sub-microsecond but scheduler
// pressure under a launch burst stretches it to milliseconds, and an
// immediate API call used to fail hard there. ONLY a refused connection
// (the gap, or a dead process's lingering socket) is worth waiting out;
// any other error — ENOENT from a teardown race, ENOTSOCK, EACCES — is
// surfaced immediately. Fast path: one successful connect+close (tens
// of µs).
func waitForSocketConnectable(path string, deadline time.Time) error {
	interval := time.Millisecond
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			c.Close()
			return nil
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("socket %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("socket %s not accepting connections: %w", path, err)
		}
		time.Sleep(interval)
		interval = min(interval*2, 10*time.Millisecond)
	}
}

func (m *Manager) waitForBoxd(ctx context.Context, vmIP string, timeout time.Duration) error {
	return waitForHTTPHealth(ctx, vmIP, timeout)
}

// retriedLaunchTarget returns the tracked instance for vmID when a resume or
// restore request is a retry of one that already completed: Running with the
// SAME artifacts (a different snapshot must replace the VM as before).
//
// Called while holding vmID's lifecycle lock, so Status is trustworthy: no
// concurrent op is mid-flight, and a Running instance is a finished prior
// attempt. Hence no boxd probe — it couldn't tell a slow-booting boxd (30s
// warmup) from a dead one, and a false negative relaunches over the live
// VM, rolling the guest back. DestroyVM bypasses the lock, so the recheck
// drops an instance a concurrent destroy removed.
//
// A reset-to-snapshot flow (none today) must not reuse these RPCs as-is.
// vmUnitDead reports a VM's systemd unit as definitively not-active;
// swappable in tests. Inconclusive answers read as alive (not dead).
var vmUnitDead = func(vmID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return unitDefinitelyDead(ctx, systemdUnitName(vmID))
}

func (m *Manager) retriedLaunchTarget(vmID, snapshotPath, memPath string) *VMInstance {
	m.mu.RLock()
	existing := m.vms[vmID]
	m.mu.RUnlock()
	if existing == nil {
		return nil
	}
	existing.mu.RLock()
	running := existing.Status == StatusRunning
	sameArtifacts := existing.SnapshotPath == snapshotPath && existing.MemFilePath == memPath
	existing.mu.RUnlock()
	if !running || !sameArtifacts {
		return nil
	}
	// Process-level liveness, not boxd readiness: a record can read Running
	// while the firecracker died (crash while vmd was down, then a
	// cleanupStale=false reattach loads it). A slow-booting VM's unit is
	// still active, so this catches a corpse without false-negativing a
	// warming one — the trap the removed boxd probe fell into. Inconclusive
	// (systemctl slow) reads as alive: never relaunch on doubt.
	if vmUnitDead(vmID) {
		return nil
	}
	m.mu.RLock()
	still := m.vms[vmID] == existing
	m.mu.RUnlock()
	if !still {
		return nil
	}
	return existing
}
