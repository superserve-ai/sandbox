package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/shellquote"
	"github.com/superserve-ai/sandbox/internal/telemetry"
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
	ID  string
	PID int
	// launchGen fences PID publication to the attempt that started it. A
	// retry reuses this instance, and the previous attempt's asynchronous
	// MainPID resolver can still be in flight — writing a stopped unit's PID
	// into the new attempt's record. Bumped under mu at each attempt start;
	// a resolver whose captured generation no longer matches drops its write.
	launchGen      uint64
	SocketPath     string
	VsockPath      string
	IP             string
	TAPDevice      string
	MACAddress     string
	Status         VMStatus
	Unverified     bool   // Running persisted before boxd readiness (see VMRecord)
	RevivalPending bool   // revival attempt in flight (see VMRecord)
	RevivedDisk    string // resolved salvage path of a completed revival (see VMRecord)
	Config         VMConfig
	RunDirID       string // Directory name under RunDir for this VM's files.
	Namespace      string // Network namespace name.
	DiskPath       string
	SnapshotPath   string
	MemFilePath    string
	CreatedAt      time.Time
	Metadata       map[string]string
	TeamID         string // owning team; carried for data-plane usage attribution
	OwnerID        string // creating user; empty when unknown
	// PausedAt records when this VM last entered the paused state. It drives
	// oldest-first pressure reclamation. Zero means the field is unset on a
	// legacy record; callers fall back to CreatedAt and then place any fully
	// timestampless records last.
	PausedAt time.Time

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

	// TeardownPending, when non-empty, records that a failed lifecycle op
	// deliberately RETAINED this VM's resources (rundir, network slot)
	// because its process could not be proven dead — and names the owner of
	// the residual teardown. Persisted, so the parked state explains itself
	// after a restart; cleared by a successful relaunch, and retired with
	// the record when the reconciler completes the release.
	TeardownPending string

	// Supervision records how the current Firecracker run is supervised —
	// SupervisionUnit (systemd service, the empty string so legacy records
	// stay canonical) or SupervisionCgroup (direct-spawned under vmd's
	// delegated subtree). Persisted: liveness, stop, and reattach all
	// dispatch on it, and it must survive a vmd restart. A resume decides
	// the mode for the NEW run and must set it before the post-launch
	// persist.
	Supervision Supervision

	mu sync.RWMutex
}

// vmNetworkManager captures the network operations the VM manager uses.
// Keeping this narrow lets tests stub teardown/rebuild behavior without
// running real namespace commands.
type vmNetworkManager interface {
	CleanupVM(vmID string)
	CleanupVMOrNamespace(vmID, fallbackNamespace string)
	ClaimFreshSlot(owner string) (int, error)
	EnsureVMSlot(ctx context.Context, vmID, namespace, hostIP, macAddress string) (*network.VMNetInfo, error)
	Forget(vmID string)
	GetVMNetInfo(vmID string) *network.VMNetInfo
	NetnsStats() (netnsTotal, ownedSlots, orphaned int)
	NamespaceForPID(pid int) string
	ReattachVM(vmID, namespace, hostIP, macAddress string) error
	ReclaimUnusedSlots() int
	ReleaseSlot(owner string, idx int)
	ReserveSlotsAbove(reservations map[string]string)
	SetupVM(ctx context.Context, vmID string, cfg *network.Config) (*network.VMNetInfo, error)
	PoolStats() (fresh, recycled int, enabled bool)
	DrainWarmPool(max int) int
	SweepOrphanNamespaces(keep map[string]bool) int
	UpdateFirewallRules(vmID string, allowedCIDRs, deniedCIDRs []string) error
	TeardownVMOrNamespace(vmID, fallbackNamespace string)
	TeardownVM(vmID string)
}

type sandboxNetworkRules struct {
	allowedCIDRs   []string
	deniedCIDRs    []string
	allowedDomains []string
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

	// PausedNetworkSlotHeadroomPercent is the percentage-based free-slot
	// cushion the controller tries to maintain. Zero disables the percentage
	// component and relies on the absolute reserve.
	PausedNetworkSlotHeadroomPercent int
	// PausedNetworkSlotHeadroomReserve is the absolute free-slot cushion the
	// controller tries to maintain. The controller uses the larger of the
	// reserve and the percentage-derived target.
	PausedNetworkSlotHeadroomReserve int
	// PausedNetworkSlotHeadroomHysteresis is the extra free-slot margin used
	// to stop reclaiming only after healthy headroom is restored.
	PausedNetworkSlotHeadroomHysteresis int
	// PausedNetworkNetnsThreshold is the maximum number of netns entries the
	// host should tolerate before the controller switches into inventory-shrink
	// mode.
	PausedNetworkNetnsThreshold int
	// PausedNetworkNetnsHysteresis is the stop margin below the netns pressure
	// threshold.
	PausedNetworkNetnsHysteresis int
	// PausedNetworkMountThreshold is the maximum number of host mount entries
	// the controller should tolerate before it switches into inventory-shrink
	// mode.
	PausedNetworkMountThreshold int
	// PausedNetworkMountHysteresis is the stop margin below the mount pressure
	// threshold.
	PausedNetworkMountHysteresis int
	// PausedNetworkMinWarmAge keeps freshly paused VMs out of pressure-driven
	// reclamation so they can remain warm briefly.
	PausedNetworkMinWarmAge time.Duration
	// PausedNetworkReclaimEnabled gates the pressure controller.
	PausedNetworkReclaimEnabled bool
	// PausedNetworkMaxReclaims bounds how many paused sandboxes one controller
	// pass may reclaim.
	PausedNetworkMaxReclaims int
	// PausedNetworkReclaimCooldown adds hysteresis between reclamation passes.
	PausedNetworkReclaimCooldown time.Duration
	// TelemetryRecorder receives bounded host metrics for paused-network
	// pressure and reclaim activity. Nil disables export.
	TelemetryRecorder telemetry.Recorder

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

	// DirectSpawn requests the cgroup-supervised launch path for new VMs:
	// vmd forks Firecracker into a per-VM cgroup instead of starting a
	// systemd unit, removing PID 1's serial per-unit dispatch from launch.
	// Arming additionally requires ArmDirectSpawn to succeed (delegated
	// subtree present, unit configured KillMode=process) — a request
	// without the preconditions degrades to the unit path with a loud
	// error, never to a fleet that dies on the next vmd deploy.
	DirectSpawn bool
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager orchestrates the lifecycle of Firecracker microVMs.
type Manager struct {
	cfg         ManagerConfig
	netMgr      vmNetworkManager
	egressProxy *network.EgressProxy
	log         zerolog.Logger
	state       *StateStore // persistent local state (BoltDB); nil = no persistence
	recorder    telemetry.Recorder
	// backupEnqueue hands finalized pause manifests to the durability
	// pipeline; nil when backup is disabled. See SetBackupEnqueue.
	backupEnqueue func(backup.Task) error
	// backupStaging is the uploader's hard-link staging tree; empty
	// means artifacts upload from their original paths.
	backupStaging string
	// unitDead overrides the systemd unit-dead probe in tests; nil means
	// the real probe. See vmConfirmedAtRest.
	unitDead func(ctx context.Context, vmID string) bool
	// rehashDone, when set, is called as the detached pending-backup worker
	// returns. The worker deliberately outlives backupPause, so a test whose
	// staging tree is a t.TempDir() otherwise races its own cleanup against
	// the worker's writes. Nil in production.
	rehashDone func()
	// pendingInFlight guards one pending-backup worker per VM across the
	// startup recovery and the periodic sweep.
	pendingInFlight sync.Map
	// pendingSweepInterval overrides the pending-backup sweep pace in
	// tests; 0 means pendingBackupSweepInterval.
	pendingSweepInterval time.Duration
	// rehashSlots bounds concurrent recovery/sweep rehash workers,
	// shared by the pause recovery and the template-build sweep; created
	// lazily via ensureRehashSlots.
	rehashSlots     chan struct{}
	rehashSlotsOnce sync.Once
	// backupCovered probes the journal for whether an owner+generation is
	// already pending or completed; nil means never covered. See
	// SetBackupCovered.
	backupCovered func(backup.Task) (bool, error)
	// lastSandboxEnqueue records the generation of each sandbox's most
	// recent successful backup enqueue, captured ONLY while a backfill
	// pass runs (backfillCapturing): the pass is the map's only reader,
	// it clears the map when it ends, and gating the writes keeps a
	// long-lived host's churn from growing the map with sandboxes no
	// pass will ever read.
	lastSandboxEnqueue sync.Map
	backfillCapturing  atomic.Bool
	// backupMetrics optionally observes backup hook timings; nil (metrics
	// disabled) is safe at every call site. See SetBackupMetrics.
	backupMetrics *telemetry.BackupRecorder
	// launchFirecrackerHook is a test seam. When set, launchFirecracker
	// delegates to it instead of the platform-specific implementation.
	launchFirecrackerHook func(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, existing Supervision, hadPriorLife, freshUnit bool) (pid int, supervision Supervision, err error)
	// restoreForResumeHook is a test seam for the snapshot restore step.
	restoreForResumeHook func(socketPath, snapshotPath, memPath, basePath string, netInfo *network.VMNetInfo) (dirtyTracked bool, err error)
	// pausedNetworkControllerState bounds pause-network reclamation cadence.
	pausedNetworkControllerMu      sync.Mutex
	pausedNetworkControllerLastRun time.Time
	pausedNetworkControllerActive  bool
	// adoptedBuildBackups guards backup reconciliation of completed
	// builds adopted from disk: one IN-FLIGHT reconcile per build id.
	// Cross-process and cross-attempt dedupe is the journal's job (owner
	// + generation index and the completions record); this map only keeps
	// repeated status polls and overlapping sweeps from spawning
	// concurrent workers for one build. See reconcileAdoptedBuildBackup.
	adoptedBuildBackups sync.Map

	// launcherReady gates the launcher launch path: false → launches use the
	// legacy path. Set when the namespace is built/validated; kept in sync by
	// revalidateLauncher.
	launcherReady atomic.Bool
	// launcherBuilt is true only after a successful build THIS boot; gates
	// revalidateLauncher's re-enable so a stale previous-boot pin can't resurrect
	// the launcher path.
	launcherBuilt atomic.Bool
	// launcherBuilding admits one pin build at a time, so the boot build and a
	// sampler-driven retry can't run concurrently and prune the same paths.
	launcherBuilding atomic.Bool
	// launcherNextRetry is the earliest wall-clock (unix nanos) at which a failed
	// pin build may be retried. Zero means retry immediately.
	launcherNextRetry atomic.Int64

	// cgroups is the delegated subtree for direct-spawned VMs; nil until
	// ArmDirectSpawn succeeds. directSpawnArmed gates NEW launches onto the
	// cgroup path — existing VMs always follow their record's Supervision
	// regardless of the flag, so both modes coexist through the migration.
	// launchPathValidated reports the launch validations passed this boot;
	// every cgroup launch (fresh or relaunch) requires it — see
	// validateDirectLaunchPath.
	cgroups             *cgroupTree
	directSpawnArmed    atomic.Bool
	launchPathValidated atomic.Bool
	// reapers holds the per-VM exit channel for direct-spawned children this
	// process owns (vmID → chan directSpawnResult, buffered 1). Kill paths
	// wait on the channel, never on kill(0) polls — zombies answer polls.
	reapers sync.Map
	// survivorNS preserves vmID → netns for a protected recordless survivor
	// whose startup kill could not be confirmed. Once that process exits on
	// its own, its pid — the only other route to the namespace — is gone, so
	// the empty-group reap must spend this mapping to release the reserved
	// slot and veth. In-memory only: a restart rebuilds reservations from
	// scratch and the startup sweep reclaims unprotected namespaces.
	survivorNS sync.Map
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

	// forensicsOK gates console quarantine: false when the root-only
	// forensics directory could not be created or secured at startup.
	forensicsOK bool

	// destroying holds the vmIDs currently inside DestroyVM, from just before
	// the slot is freed until teardown completes. A lazy getInstance skips
	// reattaching a listed VM: without this, a request that misses m.vms
	// mid-destroy (exec, preview, inject) would reattach the record, rebind
	// the freed slot, and hand a live pointer to an IP the pool is recycling.
	// Keyed vmID → struct{}{}; entries are always removed when destroy returns.
	destroying sync.Map
	// destroyEpochs counts completed DestroyVM calls per vmID (bumped on
	// every exit, before the tombstone clears). A rollback that must
	// distinguish its own teardowns from an external destroy that
	// completed in between compares this against its expected count: the
	// tombstone alone only spans an in-flight destroy, not a finished
	// one.
	destroyEpochs sync.Map // vmID -> *uint64
	// recordOwnerMus serializes DestroyVM against revival's rollback:
	// DestroyVM holds vmID's mutex from before the tombstone through the
	// epoch bump and tombstone clear, so a rollback that acquires it and
	// then checks the epoch cannot interleave with a destroy completing
	// between its check and its restore write.
	recordOwnerMus sync.Map // vmID -> *sync.Mutex
	// preserveRecordOnDestroy converts record deletion into an overwrite
	// with the stored pending anchor while a revival is in flight:
	// revival refuses unknown sandboxes, so any delete-then-rewrite gap
	// (its own residue clear most of all) would brick the retry if vmd
	// crashed inside it. Revival's destroy-wins paths bypass it with
	// deleteStateForce once an external destroy is detected.
	preserveRecordOnDestroy sync.Map // vmID -> VMRecord
	// reattachStopDeadline bounds the aggregate time the eager reattach
	// pass may spend stopping interrupted-revival residue: the pass is
	// serial, and per-record stop budgets would otherwise stack into
	// minutes of postponed reconciliation.
	reattachStopDeadline atomic.Value // time.Time
}

// trackedInstance returns vmID's in-memory instance, or nil — WITHOUT the
// lazy reattach getInstance performs on a miss. Delivery gates (credential
// injects) must use this: a lazy reattach inside DestroyVM's window between
// the map delete and the record delete would resurrect the instance AND
// rebind its freed network slot, making the gate's own lookup certify an
// ownership the destroy just revoked.
func (m *Manager) trackedInstance(vmID string) *VMInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.vms[vmID]
}

// vmOwnsIP reports whether vmID is still the live owner of ip: tracked,
// Running, IP-matched, AND holding the network slot per the net manager's
// device table (the authoritative owner ledger). The tracked instance alone
// is not enough — DestroyVM frees the slot before it removes the instance, and
// it takes no lifecycle lock, so a concurrent destroy can recycle ip to
// another VM while the record still reads Running. Every path that acts on an
// IP a lock-free destroy could have revoked — credential delivery AND the
// resume readiness gate — checks this before trusting the answer.
func (m *Manager) vmOwnsIP(vmID, ip string) bool {
	inst := m.trackedInstance(vmID)
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	ok := inst.IP == ip && inst.Status == StatusRunning
	inst.mu.RUnlock()
	return ok && m.netMgr.GetVMNetInfo(vmID) != nil
}

// instanceUnverifiedRunning reports whether vmID's tracked instance claims
// Running but never proved boxd readiness — a crash-window record (see
// VMRecord.Unverified). Such a record is NOT evidence of a live serving VM,
// which is what lets the reconciler's orphan rule act on it where the
// blanket "defer to Running" guard would otherwise protect it forever.
func (m *Manager) instanceUnverifiedRunning(vmID string) bool {
	inst := m.trackedInstance(vmID)
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.Status == StatusRunning && inst.Unverified
}

// instanceRunning reports whether vmID's tracked instance is Running — the
// authoritative signal that a resume/restore completed, used by the
// reconciler to avoid stopping a just-relaunched unit.
func (m *Manager) instanceRunning(vmID string) bool {
	inst := m.trackedInstance(vmID)
	if inst == nil {
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
	forensicsQuarantineOK := false
	if cfg.RunDir != "" {
		if err := os.MkdirAll(filepath.Join(cfg.RunDir, templateDirName), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir template magic dir: %w", err)
		}
		// Pre-created so the readiness-timeout verdict path only renames
		// into it — even first-stall metadata I/O must not spend the
		// reserve. Best-effort: if an ops cleanup removes it, the rename
		// fails and forensics degrade to the journald summary.
		forensicsDir := filepath.Join(cfg.RunDir, stallForensicsDirName)
		// MkdirAll leaves a PRE-EXISTING directory's mode alone, and
		// consoles land in it as 0644 before the deferred file chmod — the
		// directory mode is what actually fences other accounts, so an
		// unsecurable directory disables file quarantine entirely (the
		// content-free summary and journald fallback still work).
		if err := os.MkdirAll(forensicsDir, 0o700); err != nil {
			log.Warn().Err(err).Msg("stall-forensics dir unavailable; console quarantine disabled")
		} else if err := os.Chmod(forensicsDir, 0o700); err != nil {
			log.Warn().Err(err).Msg("stall-forensics dir not securable; console quarantine disabled")
		} else {
			forensicsQuarantineOK = true
		}
	}
	m := &Manager{
		forensicsOK:    forensicsQuarantineOK,
		cfg:            cfg,
		netMgr:         netMgr,
		recorder:       cfg.TelemetryRecorder,
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

// recordPhases emits one latency histogram sample per named phase (plane
// "vmd"); the host label comes from the recorder's construction. Nil-safe
// and negative durations are dropped, so call sites stay one-liners.
func (m *Manager) recordPhases(op, mode string, phases map[string]time.Duration) {
	if m.recorder == nil {
		return
	}
	for phase, d := range phases {
		if d < 0 {
			continue
		}
		m.recorder.RecordLatencyPhase(context.Background(), telemetry.LatencyPhase{
			Plane: "vmd", Op: op, Phase: phase, Mode: mode, Duration: d,
		})
	}
}

func (m *Manager) SetStateStore(s *StateStore) {
	m.state = s
}

// SetEgressProxy sets the TCP egress proxy for domain-based filtering.
// Must be called before any VMs are created.
func (m *Manager) SetEgressProxy(proxy *network.EgressProxy) {
	m.egressProxy = proxy
}

func (m *Manager) applySandboxNetworkRules(vmID string, netInfo *network.VMNetInfo, rules *sandboxNetworkRules) error {
	if rules == nil {
		return nil
	}
	if err := m.netMgr.UpdateFirewallRules(vmID, rules.allowedCIDRs, rules.deniedCIDRs); err != nil {
		return fmt.Errorf("update firewall rules: %w", err)
	}
	if m.egressProxy != nil && netInfo != nil {
		m.egressProxy.SetRules(netInfo.HostIP, &network.EgressRules{
			AllowedCIDRs:   rules.allowedCIDRs,
			DeniedCIDRs:    rules.deniedCIDRs,
			AllowedDomains: rules.allowedDomains,
			SandboxID:      vmID,
		})
	}
	return nil
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
// basePath, when non-empty, boots the rootfs as a sparse overlay backed
// by that shared read-only base (the fork's overlay drive mode); the
// per-VM copy must then be hole-exact, so it reflinks strictly rather
// than falling back to a heuristic sparse copy that could turn
// guest-written zeros into holes exposing base content.
// supervised spawns the VM under the fleet's real lifecycle supervision
// (systemd unit or validated cgroup, seeded by `supervision`) through
// the same dispatcher resume uses, so auto-pause's mode-directed stop
// and every at-rest oracle see the VM the way they see any sandbox.
// The flag is explicit because SupervisionUnit is the zero value: a
// sentinel on the mode alone cannot distinguish "unit mode" from the
// legacy unsupervised spawn kept for throwaway template-build VMs.
func (m *Manager) coldBootFromRootfs(ctx context.Context, vmID, rootfsPath, basePath string, rules *sandboxNetworkRules, seed func(*VMInstance), preLaunch func() error, supervised bool, supervision Supervision, vcpu, memMiB uint32) (*VMInstance, error) {
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
			BasePath:   basePath,
		},
	}
	// The seed runs before the instance is visible or persisted, so
	// every intermediate durable write during the boot (each setStatus
	// persists synchronously) already carries the caller's metadata; a
	// crash mid-boot must not leave a record with empty ownership or
	// preview policy, or one that claims a verified guest.
	if seed != nil {
		seed(inst)
	}
	m.vms[vmID] = inst
	m.mu.Unlock()

	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Str("rootfs", rootfsPath).Str("base", basePath).Uint32("vcpu", vcpu).Uint32("mem_mib", memMiB).Msg("cold-booting VM")

	// 1. Copy the rootfs for this VM. Overlay sources demand a
	// hole-exact copy (reflink, no heuristic fallback): every hole is a
	// window to the base, and a guest-written zero run misdetected as a
	// hole would silently resurface base content.
	var diskPath string
	var err error
	if basePath != "" {
		diskPath, err = m.copyRootfsExact(ctx, vmID, rootfsPath)
	} else {
		diskPath, err = m.copyRootfs(ctx, vmID, rootfsPath)
	}
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

	// Egress policy installs before the guest can execute a single
	// instruction: resume's discipline (rules land before
	// launchFirecracker), because a policied workload's startup services
	// must never see the fresh slot's permissive defaults.
	if err := m.applySandboxNetworkRules(vmID, netInfo, rules); err != nil {
		m.netMgr.CleanupVM(vmID)
		m.cleanupRunDir(vmID)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("apply network rules: %w", err)
	}

	// A caller-supplied gate right before Firecracker starts: revival's
	// last chance to notice an external destroy that completed after
	// network setup began (network setup blocks, so the epoch check at
	// prep time is already stale by the time execution reaches here).
	// Without this, revival could launch onto a slot/TAP a destroy
	// already handed back to the pool.
	if preLaunch != nil {
		if perr := preLaunch(); perr != nil {
			m.netMgr.CleanupVM(vmID)
			m.cleanupRunDir(vmID)
			m.setStatus(vmID, StatusError)
			return nil, perr
		}
	}

	// 3. Build Firecracker machine configuration.
	vmDir := filepath.Join(m.cfg.RunDir, vmID)
	socketPath := filepath.Join(vmDir, "firecracker.sock")

	fcCfg := FirecrackerConfig{
		SocketPath: socketPath,
		KernelPath: m.cfg.KernelPath,
		KernelArgs: "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0 random.trust_cpu=on",
		RootfsPath: diskPath,
		BasePath:   basePath,
		VCPUCount:  int(vcpu),
		MemSizeMiB: int(memMiB),
		TAPDevice:  network.TAPName,
		MACAddress: mac,
		VMID:       vmID,
		VMIP:       network.VMInternalIP,
		GatewayIP:  network.VMGatewayIP,
	}

	// 4. Start Firecracker inside the network namespace, configure, and boot.
	var pid int
	if supervised {
		spawnedPID, actual, lerr := m.launchFirecracker(ctx, vmID, socketPath, diskPath, basePath, netInfo.Namespace, supervision, true, false)
		// Stamp before the error branch too: a cgroup launch that forked
		// Firecracker but failed confirmation leaves a live process, so
		// the instance must say cgroup for stops to target it rather
		// than no-op a unit.
		inst.mu.Lock()
		inst.Supervision = actual
		inst.mu.Unlock()
		// The mandatory stop must not run under the RPC's possibly-
		// expired context: a canceled stop leaves a live supervised
		// Firecracker, and freeing its slot and run directory
		// underneath it is the wedge the stop exists to prevent.
		stopFailed := false
		stopSpawned := func() {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), coldBootStopBudget)
			defer cancel()
			if serr := m.stopVM(sctx, vmID, actual); serr != nil {
				stopFailed = true
				log.Error().Err(serr).Msg("stop spawned VM after failed cold boot; residue left for forced teardown")
				return
			}
			// A nil stop can still mean a deactivating unit (the expired
			// stop wait settles those as complete while the process may
			// hold its socket): release requires the terminal claim,
			// exactly as every stale-cleanup path holds it.
			var down bool
			if cgroupSupervised(actual) {
				down = m.cgroupDefinitelyDead(vmID) && vmUnitFullyDown(vmID)
			} else {
				down = vmUnitFullyDown(vmID)
			}
			if !down {
				stopFailed = true
				log.Error().Msg("spawned VM not terminally down after stop; residue left for forced teardown")
			}
		}
		if lerr != nil {
			// A failed launch can itself leave a live process (a cgroup
			// spawn whose internal kill was unconfirmed), so the
			// confirmed stop runs here too before anything is freed.
			stopSpawned()
		} else if lerr = waitForSocket(socketPath, 10*time.Second); lerr != nil {
			stopSpawned()
		} else if lerr = ConfigureMachine(socketPath, fcCfg); lerr != nil {
			stopSpawned()
		} else if lerr = StartInstance(socketPath); lerr != nil {
			stopSpawned()
		}
		if lerr == nil {
			pid = spawnedPID
		}
		if lerr != nil {
			// A failed stop forbids freeing resources: the slot and run
			// directory may still be under a live Firecracker, so leave
			// the residue for a forced DestroyVM to clear.
			if !stopFailed {
				m.netMgr.CleanupVM(vmID)
				m.cleanupRunDir(vmID)
			}
			m.setStatus(vmID, StatusError)
			if stopFailed {
				// Callers that roll back durable state must know the
				// spawned VM may still be alive: the StatusError record
				// above is the truthful one to keep.
				return nil, fmt.Errorf("start firecracker (supervised): %w: %w", lerr, errSpawnedStopUnconfirmed)
			}
			return nil, fmt.Errorf("start firecracker (supervised): %w", lerr)
		}
	} else {
		var serr error
		pid, serr = m.startFirecrackerColdBoot(ctx, vmID, socketPath, fcCfg, netInfo.Namespace)
		if serr != nil {
			m.netMgr.CleanupVM(vmID)
			m.cleanupRunDir(vmID)
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("start firecracker: %w", serr)
		}
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
func (m *Manager) DestroyVM(ctx context.Context, vmID string, force bool) (err error) {
	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Bool("force", force).Msg("destroying VM")

	// Cleanup runs even without an in-memory instance, so a malformed or reserved
	// vmID could escape RunDir or wipe a shared dir.
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}

	// Tombstone the whole teardown so a concurrent lazy getInstance can't
	// resurrect this VM onto the slot we're about to free (see the destroying
	// field). A tracked VM still resolves from m.vms below — this gates only
	// reattach; an untracked one takes the record fallback, which carries all
	// teardown needs.
	unlockOwner := m.lockRecordOwner(vmID)
	defer unlockOwner() // registered first: releases after the epoch bump and tombstone clear
	// An external destroy retires any revival anchor: its success must
	// mean the record is durably gone, not preserved until an in-flight
	// revival's cleanup happens to run. Revival's own teardowns mark
	// their context and keep the preserve (their record deletion is the
	// crash gap the preserve exists to close).
	if v := ctx.Value(reviveTeardownCtxKey{}); v == nil {
		m.preserveRecordOnDestroy.Delete(vmID)
	}
	m.destroying.Store(vmID, struct{}{})
	defer m.destroying.Delete(vmID)
	// Only a SUCCESSFUL destroy advances the epoch (LIFO: before the
	// tombstone clears): revival treats an epoch step as an
	// authoritative deletion and force-deletes the anchor, but a failed
	// destroy deliberately left residue and record for a forced retry,
	// and counting it would destroy the only durable record.
	defer func() {
		if err == nil {
			m.bumpDestroyEpoch(vmID)
		}
	}()

	// A paused or post-restart VM may be absent from m.vms. Don't early-return on
	// that: unit stop and rundir removal are derivable from vmID and must run, or
	// destroying a paused sandbox leaks its rundir. Process/socket teardown needs
	// the instance, so it's gated below. Destroy is idempotent.
	inst, instErr := m.getInstance(vmID)

	// Stop by supervision mode: cgroup kill+rmdir for direct-spawned VMs, the
	// systemd stop for unit VMs. Derived from instance-or-record so a paused
	// or post-restart VM (absent from m.vms) still stops correctly.
	destroySupervision := SupervisionUnit
	if instErr == nil {
		inst.mu.RLock()
		destroySupervision = inst.Supervision
		inst.mu.RUnlock()
	} else {
		destroySupervision = m.supervisionForVM(vmID)
	}
	if err := m.stopVM(ctx, vmID, destroySupervision); err != nil {
		log.Warn().Err(err).Msg("stop failed (VM may not exist — trying PID-based kill)")
	}
	// Mode-agnostic safety gate, BEFORE any destructive cleanup. Neither the stop
	// error nor destroySupervision can be trusted to prove death here: the record's
	// supervision can be stale (a verify throwaway can leak a cgroup FC onto a unit
	// record), and a no-op unit stop returns nil — so a stale unit record would
	// sail past a mode-conditioned check and free the tap under a live FC, handing
	// it to the next tenant. Consult the cgroup directly instead: if this vmID's
	// group is still live (populated, or unreadable == inconclusive == alive),
	// keep the record+slot and let the reconciler reclaim once it empties; a retry
	// then completes. cgroup.kill for a wedged FC (uninterruptible I/O) is exactly
	// this case, but so is any record/reality drift.
	if m.cgroupStillLive(vmID) {
		// Stop what the probe found: the record's mode can be stale (a
		// verify throwaway's failed cleanup leaves a cgroup FC on a
		// unit-mode record), destroy's intent is death in either mode, and
		// in BoltDB-only mode no drift rule reclaims a live group behind an
		// existing record. stopVM's cgroup arm kills, reaps, and removes on
		// its own detached budget; only a group that still won't die
		// refuses.
		_ = m.stopVM(ctx, vmID, SupervisionCgroup)
		if m.cgroupStillLive(vmID) {
			return status.Errorf(codes.Unavailable, "vm %s stop unconfirmed (cgroup process still live); retry after it exits", vmID)
		}
	}
	// The mirror ambiguity: a scope-gone fallback can leave a cgroup record
	// over a live firecracker@ unit (crash before the mode persisted), and
	// the recorded-mode stop above never touched it. Stop the unit too and
	// require it terminal before any cleanup — a no-op round trip when no
	// unit exists.
	if cgroupSupervised(destroySupervision) {
		_ = stopUnit(ctx, systemdUnitName(vmID))
		if !unitFullyDown(ctx, systemdUnitName(vmID)) {
			return status.Errorf(codes.Unavailable, "vm %s stop unconfirmed (fallback unit still active); retry after it exits", vmID)
		}
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

// PauseVM snapshots the VM state and then stops the process. The returned
// manifest carries integrity metadata (sha256 + size) for the pause's
// durable artifacts (disk state + vmstate); see collectPauseManifest for
// what is included and why memory files are not.
func (m *Manager) PauseVM(ctx context.Context, vmID, snapshotDir, pauseToken string) (snapshotPath, memPath string, manifest []ManifestEntry, err error) {
	// Timed from BEFORE the op lock so pause_ms includes lock queueing —
	// a duplicate-pause pile-up shows here rather than hiding.
	tPause := time.Now()
	var snapshotType string
	var tSnapshot time.Time
	var snapshotDur, stopDur time.Duration
	// Deferred, gated on snapshot work having begun: a CreateSnapshot that
	// burns seconds and then fails must land in the pause distributions —
	// those are among the slowest pauses. The already-paused retry guard
	// (before tSnapshot) still deliberately emits nothing.
	defer func() {
		if tSnapshot.IsZero() {
			return
		}
		phases := map[string]time.Duration{"total": time.Since(tPause)}
		if snapshotDur > 0 {
			phases["snapshot"] = snapshotDur
		} else {
			phases["snapshot"] = time.Since(tSnapshot)
		}
		if stopDur > 0 {
			phases["stop"] = stopDur
		}
		m.recordPhases("pause", snapshotType, phases)
	}()
	// Serialize same-vmID lifecycle ops (see lockVMOp): a duplicate pause
	// waits, then hits the already-paused guard.
	unlockOp, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return "", "", nil, err
	}
	defer unlockOp()

	inst, err := m.getInstance(vmID)
	if err != nil {
		return "", "", nil, err
	}

	log := m.log.With().Str("vm_id", vmID).Logger()

	// Retried pause (response lost mid-RPC): re-snapshotting a stopped VM
	// dials a dead socket and ends with the record deleted. Return the
	// recorded artifacts instead — after confirming they still exist, like
	// ResumeVM does before acting on a record. The manifest is recomputed
	// from the on-disk files (retries are rare; correctness over cost).
	inst.mu.RLock()
	if inst.Status == StatusPaused && inst.SnapshotPath != "" && inst.MemFilePath != "" {
		snapshotPath, memPath = inst.SnapshotPath, inst.MemFilePath
		retryDiskPath, retryDiskBase := inst.DiskPath, inst.Config.BasePath
		inst.mu.RUnlock()
		if !fileExists(snapshotPath) || !fileExists(memPath) {
			return "", "", nil, status.Errorf(codes.FailedPrecondition, "paused VM artifacts missing on host: %s", memPath)
		}
		// The paused status may only exist in memory: the original pause sets it
		// before persisting, so a failed write leaves the durable record reading
		// Running behind a stopped unit — which the next reattach cleans up as
		// stale, taking the record with it. Re-record before reporting success,
		// or this retry launders that loss into a completed pause.
		switch wrote, perr := m.persistStateIfPresent(inst); {
		case perr != nil:
			return "", "", nil, fmt.Errorf("record paused state for vm %s: %w", vmID, perr)
		case !wrote:
			return "", "", nil, status.Errorf(codes.NotFound, "vm %s destroyed during pause", vmID)
		}
		log.Info().Msg("pause: VM already paused, returning existing snapshot")
		// The recorded StatusPaused is not proof the unit stopped: the
		// original pause records it even when both stop attempts failed
		// (skipping that attempt's backup). This retry must not launder
		// that skip through a status the at-rest checks trust, so it
		// backs up only once the unit is confirmed dead.
		var manifest []ManifestEntry
		if m.vmConfirmedAtRest(ctx, vmID) {
			manifest = m.backupPause(ctx, vmID, snapshotPath, retryDiskPath, retryDiskBase, pauseToken, log)
		} else {
			log.Warn().Msg("pause backup skipped on retry: unit not confirmed dead")
		}
		return snapshotPath, memPath, manifest, nil
	}
	if inst.Status == StatusError {
		// A parked Error VM (socket gone, stop unconfirmed) cannot be
		// snapshotted — fail fast instead of dialing the dead socket and
		// returning a generic error. Drift 8 owns the cleanup.
		inst.mu.RUnlock()
		return "", "", nil, status.Errorf(codes.FailedPrecondition, "vm %s is in error state and cannot be paused", vmID)
	}
	inst.mu.RUnlock()

	if snapshotDir == "" {
		snapshotDir = filepath.Join(m.cfg.SnapshotDir, vmID)
	}
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return "", "", nil, fmt.Errorf("create snapshot dir: %w", err)
	}

	snapshotPath = filepath.Join(snapshotDir, "vmstate.snap")

	// Read the fields that select Full vs in-place-diff vs layered together under the
	// lock, so the decision can't see a torn mix written by a concurrent resume.
	inst.mu.RLock()
	socketPath := inst.SocketPath
	dirtyTracked := inst.DirtyTracked
	instBaseMem := inst.BaseMemPath
	instMemFile := inst.MemFilePath
	diskPath := inst.DiskPath
	diskBasePath := inst.Config.BasePath
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
	// Which memory image this pause writes — the field that makes a slow
	// full-snapshot pause visible at a glance. Bounded: layered|diff|full.
	snapshotType = "full"
	tSnapshot = time.Now()
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
			snapshotType = "layered"
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating layered diff snapshot")
			saveStart := time.Now()
			if err := CreateDiffSnapshot(socketPath, snapshotPath, memPath); err != nil {
				snapshotDur = time.Since(tSnapshot)
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
				return "", "", nil, m.handleVMError(vmID, fmt.Errorf("create layered diff snapshot: %w", err))
			}
			m.verifyPresenceRefreshed(memPath, saveStart, log)
		} else {
			memPath, baseMemPath = fullPath, ""
			if err := CreateSnapshot(socketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
				snapshotDur = time.Since(tSnapshot)
				return "", "", nil, m.handleVMError(vmID, fmt.Errorf("create snapshot: %w", err))
			}
		}
	default:
		memPath = fullPath
		// In-place diff (no template base): merge dirtied pages into the VM's own
		// mem.snap when tracking was armed this run and mem.snap is the resume base —
		// dirtied offsets are resident/never re-faulted, disjoint from clean reads.
		if shouldWriteDiff(m.cfg.IncrementalSnapshotEnabled, dirtyTracked, memPath, instMemFile, fileExists(memPath)) {
			snapshotType = "diff"
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating diff snapshot")
			if err := CreateDiffSnapshot(socketPath, snapshotPath, memPath); err != nil {
				snapshotDur = time.Since(tSnapshot)
				return "", "", nil, m.handleVMError(vmID, fmt.Errorf("create diff snapshot: %w", err))
			}
		} else {
			log.Info().Str("snapshot_path", snapshotPath).Msg("pausing VM — creating snapshot")
			if err := CreateSnapshot(socketPath, snapshotPath, memPath, "", SnapshotNormal); err != nil {
				snapshotDur = time.Since(tSnapshot)
				return "", "", nil, m.handleVMError(vmID, fmt.Errorf("create snapshot: %w", err))
			}
		}
	}

	// Stop the Firecracker process — snapshot is already on disk. A stop
	// that fails must NOT fail the pause: the artifacts are valid and the
	// record must reach Paused (a retry against a Running record would
	// re-diff an already-consumed dirty bitmap and destroy the overlay).
	//
	// Run the stop path (both attempts + dead-check) on a detached context
	// with its own budget: a slow snapshot may have spent the caller's entire
	// deadline, and inheriting it would kill the stop before it starts. The
	// snapshot is durable and the record reaches Paused either way; the
	// budget only bounds how long this handler lingers past the RPC, and a
	// straggler VM is still reclaimed by the reconciler.
	snapshotDur = time.Since(tSnapshot)
	inst.mu.RLock()
	pauseSupervision := inst.Supervision
	inst.mu.RUnlock()
	stopConfirmed := true
	tStop := time.Now()
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), stopUnitBudget)
	stopErr := m.stopVM(stopCtx, vmID, pauseSupervision)
	if stopErr != nil {
		log.Warn().Err(stopErr).Msg("stop failed during pause")
		// Retry only the unit path (a transient systemctl failure). The cgroup
		// kill already SIGKILLs and waits the group empty on its own detached
		// budget, so a second call is a redundant kill that spends a second
		// full budget past the RPC without reviving a wedged FC.
		if !cgroupSupervised(pauseSupervision) {
			stopErr = m.stopVM(stopCtx, vmID, pauseSupervision)
		}
		if stopErr != nil && !m.vmDefinitelyDead(stopCtx, vmID, pauseSupervision) {
			stopConfirmed = false
			log.Error().Err(stopErr).Msg("VM still running after pause; reconciler will reclaim it")
		}
	}
	stopCancel()
	stopDur = time.Since(tStop)

	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.BaseMemPath = baseMemPath // template base for a layered overlay; "" when standalone
	inst.DirtyTracked = false      // FC process is stopping; a fresh resume re-arms tracking.
	inst.PausedAt = time.Now()
	// The crash-window marker describes a RUNNING record persisted before
	// readiness was proven; a successful pause proves the guest was live and
	// snapshots fresh artifacts, and its resume relaunches from them anyway.
	// Carrying the marker into Paused would make every future resume of this
	// sandbox take the destructive relaunch gate for no reason.
	inst.Unverified = false
	inst.mu.Unlock()

	// If-present, not Put: DestroyVM takes no vm-op lock (by design), and
	// the detached stop widened the window where a destroy can land
	// mid-pause — a plain Put would resurrect the deleted record.
	//
	// A write failure is not a deletion, and must not report a completed
	// pause: the retry above re-records the state instead.
	switch wrote, perr := m.persistStateIfPresent(inst); {
	case perr != nil:
		return "", "", nil, fmt.Errorf("record paused state for vm %s: %w", vmID, perr)
	case !wrote:
		log.Warn().Msg("record deleted during pause stop — destroy owns the teardown")
		return "", "", nil, status.Errorf(codes.NotFound, "vm %s destroyed during pause", vmID)
	}

	// Hash the durable artifacts once the unit is stopped and the files are
	// at rest. Runs under its own budget derived from the RPC deadline (see
	// collectPauseManifest): large disks must not pin this handler past the
	// pause RPC cap, or the control plane times out and retries against an
	// already-stopped unit; a budget-exhausted hash just yields a partial
	// manifest, never a late response. Runs AFTER the paused status is
	// recorded: the async rehash proves at-rest bytes against that status,
	// and hashing before the flip would make it drop every retry. Skipped
	// entirely when the unit is not confirmed stopped: a still-running
	// Firecracker keeps writing the overlay, and the recorded StatusPaused
	// would satisfy the rehash's at-rest proof while the bytes are live. A
	// later retry pause backs the artifacts up once the unit is truly dead.
	// stopConfirmed alone is the RPC's notion of a finished stop, which
	// deliberately includes a still-deactivating unit; hashing needs the
	// stronger fully-down claim, so the gate reconfirms with the same
	// probe the at-rest proof uses — on a detached probe ctx, since the
	// caller's may be spent (the stop above detached for exactly that).
	if stopConfirmed && m.vmConfirmedAtRest(probeCtx(), vmID) {
		manifest = m.backupPause(ctx, vmID, snapshotPath, diskPath, diskBasePath, pauseToken, log)
	} else if m.backupEnqueue != nil {
		log.Warn().Msg("pause backup deferred: unit not confirmed fully down, bytes may still be changing")
		// The pause still owes its backup. Leave a pending marker AND a
		// worker: the worker's first act re-persists the marker (healing
		// a transiently failed write here), its at-rest proof holds the
		// backup off until the unit is truly down, and the periodic
		// sweep keeps retrying after the worker gives up.
		pb := newPendingBackup(vmID, snapshotPath, diskPath, diskBasePath, pauseToken)
		m.persistPendingBackup(pb, log)
		go m.rehashPendingBackup(ctx, pb, log)
	}

	log.Info().
		Str("snapshot_type", snapshotType).
		Int64("snapshot_ms", snapshotDur.Milliseconds()).
		Int64("stop_ms", stopDur.Milliseconds()).
		Int64("pause_ms", time.Since(tPause).Milliseconds()).
		Msg("VM paused")
	return snapshotPath, memPath, manifest, nil
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

// resumeVMLocked restores a paused VM from its snapshot using a mount
// namespace. The caller must hold vmID's lifecycle lock (see lockVMOp) and
// keep it held across the post-restore steps — readiness gate, env injection,
// abort-on-failure — so a concurrent retry can't adopt the instance between
// this returning and those steps acting on it. The gRPC adapter is the sole
// caller and owns that lock scope; there is deliberately no self-locking
// wrapper, which would release the lock before those steps and reopen the race.
func (m *Manager) resumeVMLocked(ctx context.Context, vmID, snapshotPath, memPath string, networkRules *sandboxNetworkRules) (*VMInstance, error) {
	log := m.log.With().Str("vm_id", vmID).Logger()
	tEntry := time.Now()
	var tSlot, tVerify, tFcStart, tFcDone, tRestore, tRestoreDone time.Time
	var verifyDur time.Duration
	needsNetworkCleanup := false
	defer func() {
		if needsNetworkCleanup {
			m.netMgr.TeardownVM(vmID)
		}
	}()
	// Deferred, gated on real resume work having begun (tSlot): failed
	// resumes must land in the phase distributions with whichever stages
	// they reached — success-only emission hides the slowest failures.
	// Precondition rejections before the slot claim emit nothing.
	// Registered after the network-cleanup defer so it runs BEFORE
	// TeardownVM: the elapsed-time fallbacks must not absorb teardown.
	defer func() {
		if !tVerify.IsZero() {
			// Died mid-probe; count the elapsed verification time.
			verifyDur += time.Since(tVerify)
		}
		if tSlot.IsZero() && verifyDur == 0 {
			return
		}
		phases := map[string]time.Duration{
			"total": time.Since(tEntry),
		}
		// Synchronous readiness verification — the pre-slot adoption gate
		// and the post-restore gate for relaunched unverified records — is
		// real resume work (each a bounded multi-second wait); a slow probe
		// must not vanish from the distributions.
		if verifyDur > 0 {
			phases["verify"] = verifyDur
		}
		if tSlot.IsZero() {
			m.recordPhases("resume", "", phases)
			return
		}
		phases["prep"] = tSlot.Sub(tEntry)
		switch {
		case !tFcDone.IsZero():
			phases["fc_start"] = tFcDone.Sub(tFcStart)
		case !tFcStart.IsZero():
			phases["fc_start"] = time.Since(tFcStart)
		}
		if !tFcStart.IsZero() {
			phases["ensure_slot"] = tFcStart.Sub(tSlot)
		} else {
			// Slot/network preparation died mid-stage — report its elapsed
			// time, or slow failed preparation stays invisible in the phase
			// meant to identify it.
			phases["ensure_slot"] = time.Since(tSlot)
		}
		switch {
		case !tRestoreDone.IsZero():
			phases["restore"] = tRestoreDone.Sub(tRestore)
		case !tRestore.IsZero():
			phases["restore"] = time.Since(tRestore)
		}
		m.recordPhases("resume", "", phases)
	}()

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
	if existing, needsVerify := m.retriedLaunchTarget(vmID, snapshotPath, memPath); existing != nil {
		if !needsVerify {
			// Resume's contract never blocks on boxd (the readiness probe is
			// detached telemetry), so adoption matches: record + live unit
			// suffice.
			log.Info().Msg("resume: VM already running and healthy, returning it")
			return existing, nil
		}
		// An unverified target is the one case where blindness is unsafe in
		// BOTH directions: blind adoption hands back a corpse, blind refusal
		// relaunches over a possibly-live guest. Evidence decides, with the
		// gate restore adoption uses; success heals the marker durably.
		tVerify = time.Now()
		verr := m.verifyBoxdReady(ctx, existing.IP)
		verifyDur += time.Since(tVerify)
		tVerify = time.Time{}
		if verr != nil {
			// A genuine verdict (see verifyBoxdReady): the record is a corpse.
			// Record it before relaunching: the relaunch can still fail a
			// precondition, and those paths return without touching status
			// (they assume a Paused input), leaving the record advertising a
			// VM that never came back. The marker stays set — readiness is
			// still unproven, and the relaunch below reads it to verify.
			existing.mu.Lock()
			existing.Status = StatusPaused
			existing.mu.Unlock()
			// The verdict has to be durable BEFORE relaunching: the relaunch
			// below can fail on a precondition and return, and an undurable
			// verdict would leave the record still claiming Running. Refuse
			// instead — the next attempt re-derives the verdict.
			switch wrote, perr := m.persistStateIfPresent(existing); {
			case perr != nil:
				return nil, fmt.Errorf("record readiness verdict for vm %s: %w", vmID, perr)
			case !wrote:
				return nil, status.Errorf(codes.NotFound, "vm %s was destroyed during resume", vmID)
			}
			log.Warn().Err(verr).Msg("resume: unverified VM failed readiness — relaunching")
		} else {
			if cerr := m.commitVerifiedAdoption(existing); cerr != nil {
				return nil, cerr
			}
			log.Info().Msg("resume: unverified VM verified and adopted")
			return existing, nil
		}
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

	tSlot = time.Now()
	var netInfo *network.VMNetInfo
	nsName := inst.Namespace
	if nsName != "" {
		var nsErr error
		netInfo, nsErr = m.netMgr.EnsureVMSlot(ctx, vmID, nsName, inst.IP, inst.MACAddress)
		if nsErr != nil {
			return nil, fmt.Errorf("ensure network slot for resume: %w", nsErr)
		}
	} else {
		var netErr error
		netInfo, netErr = m.netMgr.SetupVM(ctx, vmID, nil)
		if netErr != nil {
			return nil, fmt.Errorf("setup network for resume: %w", netErr)
		}
		nsName = netInfo.Namespace
		needsNetworkCleanup = true
	}
	if err := m.applySandboxNetworkRules(vmID, netInfo, networkRules); err != nil {
		return nil, err
	}

	tFcStart = time.Now()
	inst.mu.RLock()
	resumeExisting := inst.Supervision
	inst.mu.RUnlock()
	// freshUnit=false: a resume replaces a paused VM's slot, never a brand-new
	// unit, so it must always run the linger query.
	pid, resumeSupervision, err := m.launchFirecracker(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, nsName, resumeExisting, true, false)
	// Stamp before the error branch too: a cgroup launch that forked FC but
	// failed socket-readiness (kill unconfirmed) leaves a live process, so the
	// instance must say cgroup for a later destroy to kill it, not no-op a unit.
	inst.mu.Lock()
	inst.Supervision = resumeSupervision
	inst.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("start firecracker for restore: %w", err)
	}
	tFcDone = time.Now()

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
	tRestore = time.Now()
	var dirtyTracked bool
	var restoreErr error
	if m.restoreForResumeHook != nil {
		dirtyTracked, restoreErr = m.restoreForResumeHook(socketPath, snapshotPath, memPath, basePath, netInfo)
	} else {
		dirtyTracked, restoreErr = m.restoreForResume(socketPath, snapshotPath, memPath, basePath, netInfo)
	}
	tRestoreDone = time.Now()
	if restoreErr != nil {
		// Firecracker is already running; stop the unit before returning or it leaks.
		m.stopUnitDuringRestoreError(vmID)
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
		return nil, fmt.Errorf("restore snapshot: %w", restoreErr)
	}

	inst.mu.RLock()
	wasUnverified := inst.Unverified
	inst.mu.RUnlock()
	if wasUnverified {
		// The relaunch of an unverified crash-window record verifies readiness
		// synchronously (as its adoption above does): clearing the marker
		// blind would let a same-artifact restore retry adopt an unready VM without
		// its gate, and leaving it set would make every resume retry relaunch
		// and roll the guest back again. Normal resumes stay readiness-blind
		// (detached probe below). The guest was just relaunched from its
		// snapshot, so this teardown discards nothing of value — but only a
		// GENUINE verdict may reach it; see verifyBoxdReady.
		tVerify = time.Now()
		verr := m.verifyBoxdReady(ctx, netInfo.HostIP)
		verifyDur += time.Since(tVerify)
		tVerify = time.Time{}
		if verr != nil {
			m.stopUnitDuringRestoreError(vmID)
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("boxd not ready after relaunch of unverified vm %s: %w", vmID, verr)
		}
	}

	inst.mu.Lock()
	inst.PID = pid
	inst.SocketPath = socketPath
	inst.IP = netInfo.HostIP
	inst.TAPDevice = netInfo.TAPDevice
	inst.MACAddress = netInfo.MACAddress
	inst.Namespace = nsName
	inst.Status = StatusRunning
	inst.Unverified = false
	inst.DirtyTracked = dirtyTracked
	inst.PausedAt = time.Time{}
	// Record the file actually resumed from (callers may pass an explicit path
	// that differs from the cached one) so the next pause's diff baseline matches
	// what Firecracker's dirty bitmap is relative to.
	inst.SnapshotPath = snapshotPath
	inst.MemFilePath = memPath
	inst.BaseMemPath = basePath // re-cache (may have come from the on-disk sidecar)
	inst.mu.Unlock()

	if cerr := m.commitResumeState(inst); cerr != nil {
		return nil, cerr
	}
	needsNetworkCleanup = false
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
	probe := boxdHealthProbe
	go func() {
		defer sentrylog.Recover("resume-boxd-probe")
		probeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := probe(probeCtx, vmIP, 30*time.Second); err != nil {
			log.Warn().Err(err).
				Int64("wait_boxd_ms", time.Since(probeStart).Milliseconds()).
				Msg("boxd not reachable after resume")
			// Emit the timeout sample too: dropping it would censor exactly
			// the exec-unavailable incidents this series exists to reveal —
			// they'd appear as missing observations instead of a ~30s mode.
			m.recordPhases("resume", "", map[string]time.Duration{"wait_boxd": time.Since(probeStart)})
			return
		}
		log.Info().
			Int64("wait_boxd_ms", time.Since(probeStart).Milliseconds()).
			Msg("boxd reachable after resume")
		m.recordPhases("resume", "", map[string]time.Duration{"wait_boxd": time.Since(probeStart)})
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

	var (
		tapDevice string
		nsName    string
	)
	if inst.Namespace != "" {
		netInfo, nsErr := m.netMgr.EnsureVMSlot(ctx, vmID, inst.Namespace, inst.IP, inst.MACAddress)
		if nsErr != nil {
			return "", fmt.Errorf("ensure network slot for verify: %w", nsErr)
		}
		tapDevice = netInfo.TAPDevice
		nsName = netInfo.Namespace
	} else {
		netInfo, netErr := m.netMgr.SetupVM(ctx, vmID, nil)
		if netErr != nil {
			return "", fmt.Errorf("setup network for verify: %w", netErr)
		}
		tapDevice = netInfo.TAPDevice
		nsName = netInfo.Namespace
		defer m.netMgr.TeardownVM(vmID)
	}

	// Throwaway Firecracker in the sandbox's existing rundir, stopped on the
	// way out. Safe because the VM is paused (no live FC to disrupt), but it must
	// not run concurrently with a resume of the same sandbox — fine for the
	// debug/staging use this endpoint is gated to. The deferred stop uses the
	// mode this launch ACTUALLY chose (arming can put a legacy VM's throwaway
	// on the cgroup path), or the FC and its cgroup outlive the verify.
	// freshUnit=false: a verify throwaway reuses the VM's id, so the linger
	// query must run.
	inst.mu.RLock()
	verifyExisting := inst.Supervision
	inst.mu.RUnlock()
	_, verifySupervision, err := m.launchFirecracker(ctx, vmID, socketPath, rootfsPath, inst.Config.BasePath, nsName, verifyExisting, true, false)
	// Register the mode-aware stop BEFORE the error branch: a cgroup launch that
	// forked FC but failed socket-readiness (kill unconfirmed) returns cgroup
	// mode with an error and leaves a live throwaway, so the deferred stop must
	// run to kill it — or the FC and its tap outlive the verify. A no-op when
	// nothing spawned (stopVM is idempotent on a missing group or unit).
	defer func() {
		sctx, scancel := context.WithTimeout(context.Background(), stopUnitBudget)
		_ = m.stopVM(sctx, vmID, verifySupervision)
		scancel()
	}()
	if err != nil {
		return "", fmt.Errorf("start firecracker for verify: %w", err)
	}

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
	//
	// Not persisted, deliberately: DirtyTracked is not in VMRecord, so a write
	// here would duplicate the durable record while clobbering fields a
	// concurrent lifecycle op just changed — this path holds no vm-op lock.
	// Persisting from here needs that lock; see TestToRecordIgnoresDirtyTracked.
	inst.mu.Lock()
	inst.DirtyTracked = false
	inst.mu.Unlock()

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
	// A caller-supplied vmID becomes a filesystem path component (rundir and,
	// under direct spawn, the per-VM cgroup dir). Reject a non-leaf or
	// reserved name before it can escape those trees — e.g. "../daemon" would
	// resolve a cgroup onto vmd's own group and a later kill would take the
	// daemon down with the VM.
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Errorf(codes.InvalidArgument, "vm_id %q must be a valid per-VM identifier", vmID)
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
	// The success path nils unlockOp after handing the release to its
	// background persist goroutine.
	defer func() {
		if unlockOp != nil {
			unlockOp()
		}
	}()

	// Retried restore (response lost mid-RPC): re-restoring a VM the prior
	// attempt brought up would roll the guest back to the snapshot. A live
	// unit proves the prior restore completed — return that VM instead.
	// Checked BEFORE restoreSem so a no-op retry never consumes a scarce
	// restore slot (or fails on the semaphore when all slots are busy).
	// lazyReattach loads a paused VM the background reattach hasn't reached.
	m.lazyReattach(vmID)
	if existing, needsVerify := m.retriedLaunchTarget(vmID, snapshotPath, memPath); existing != nil {
		// The adopted VM keeps its stamped policy without re-validation, and
		// the response still attests it: sound only while every vmd generation
		// that could have served the prior attempt stamps the request's policy
		// itself. A generation that changes stamping must add a
		// request-vs-stamped comparison here.
		if needsVerify {
			// An unverified record never proved boxd readiness (crash between
			// the optimistic persist and the verified one), so verify before
			// adopting — a bounded WAIT, not a single probe, so a warming VM
			// passes. Verified records adopt without this gate: readiness was
			// proven once, and a wedged boxd here must not demote a live VM.
			tVerify := time.Now()
			err := m.verifyBoxdReady(ctx, existing.IP)
			// Emitted here, success and failure alike: this branch returns
			// before the phase defer below is registered, and a crash-window
			// adoption can wait out the whole probe budget.
			m.recordPhases("restore", "", map[string]time.Duration{"verify": time.Since(tVerify)})
			if err != nil {
				// A destroy racing the wait is the one thing that says nothing
				// about the VM; match the sibling destroyed-paths.
				m.mu.RLock()
				still := m.vms[vmID] == existing
				m.mu.RUnlock()
				if !still {
					return nil, status.Errorf(codes.NotFound, "vm %s was destroyed during restore", vmID)
				}
				// Definitive exhaustion, a genuine verdict (see
				// verifyBoxdReady): flip out of Running. That forces the
				// retry to relaunch — the only escape from a wedged agent,
				// since re-adopting one loops forever — and unblocks cleanup,
				// because the reconciler's live-unit rules defer to a Running
				// record. No unit stop here: boxd-dead does not prove
				// guest-dead, and the relaunch replaces the unit anyway.
				// If-present, so a racing destroy's deletion still wins.
				existing.mu.Lock()
				existing.Status = StatusError
				existing.mu.Unlock()
				// Best-effort: the returned error is the useful one, and an
				// undurable flip is re-derived by the next attempt's gate.
				_, _ = m.persistStateIfPresent(existing)
				return nil, fmt.Errorf("adopted VM %s boxd not ready: %w", vmID, err)
			}
			// Readiness is now proven; make that durable so the next restart
			// reattaches a verified record instead of re-gating it forever.
			if cerr := m.commitVerifiedAdoption(existing); cerr != nil {
				return nil, cerr
			}
		}
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
		// The full-deadline queue wait is the worst restore-queue latency —
		// emit it, or saturation incidents vanish from entry_to_sem.
		m.recordPhases("restore", "", map[string]time.Duration{"entry_to_sem": time.Since(tEntry)})
		return nil, ctx.Err()
	}
	tSemAcquired := time.Now()
	// Failed restores return before the first-attempt success block below
	// records the setup phases; emit whichever stages completed (elapsed for
	// the in-flight one) so failed attempts — which can consume most of the
	// restore deadline — form the phase tails instead of vanishing.
	restorePhasesRecorded := false
	var attempt int
	var tDiskReady, tNetReady, tFcReady, tAttemptStart, tFailBoundary time.Time
	defer func() {
		if restorePhasesRecorded {
			return
		}
		// The failure branches stamp tFailBoundary before their cleanup so
		// the in-flight stage's elapsed time excludes teardown/persistence.
		end := time.Now()
		if !tFailBoundary.IsZero() {
			end = tFailBoundary
		}
		phases := map[string]time.Duration{}
		if attempt <= 1 {
			phases["entry_to_sem"] = tSemAcquired.Sub(tEntry)
			switch {
			case tDiskReady.IsZero():
				phases["sem_to_disk"] = end.Sub(tSemAcquired)
			case tNetReady.IsZero():
				phases["sem_to_disk"] = tDiskReady.Sub(tSemAcquired)
				phases["disk_to_net"] = end.Sub(tDiskReady)
			default:
				phases["sem_to_disk"] = tDiskReady.Sub(tSemAcquired)
				phases["disk_to_net"] = tNetReady.Sub(tDiskReady)
				phases["net_to_fc"] = end.Sub(tNetReady)
			}
		} else {
			// Retry attempt died mid-setup: the pre-loop phases went out with
			// attempt 1, so measure this attempt's setup from its own start.
			switch {
			case tNetReady.IsZero():
				phases["disk_to_net"] = end.Sub(tAttemptStart)
			default:
				phases["disk_to_net"] = tNetReady.Sub(tAttemptStart)
				phases["net_to_fc"] = end.Sub(tNetReady)
			}
		}
		m.recordPhases("restore", "", phases)
	}()
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
	cpuPSI, memPSI, ioPSI := cachedPSI()

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
	prevInst, inPlace := m.vms[vmID]
	prevSupervision := SupervisionUnit
	if inPlace {
		prevInst.mu.RLock()
		prevSupervision = prevInst.Supervision
		prevInst.mu.RUnlock()
		delete(m.vms, vmID)
		m.mu.Unlock()
		_ = m.stopVM(ctx, vmID, prevSupervision)
		m.mu.Lock()
	}

	inst := &VMInstance{
		ID:        vmID,
		Status:    StatusCreating,
		CreatedAt: time.Now(),
		RunDirID:  vmID,
		Config:    resourceLimits,
		// Carry the replaced VM's supervision so the launch relaunches in the
		// same mode and its preamble clears the stale process — an in-place
		// replace whose stop above failed/timed out must not start a new
		// process in a different mode alongside the surviving old one (same
		// ID, disk, netns, tap). Fresh (non-inPlace) creates keep "" and the
		// launch chooses by the armed flag.
		Supervision:  prevSupervision,
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
		tFailBoundary = time.Now()
		m.setStatus(vmID, StatusError)
		return nil, diskErr
	}
	tDiskReady = time.Now()

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
	for attempt = 1; ; attempt++ {
		tAttemptStart = time.Now()
		if attempt > 1 {
			restorePhasesRecorded = false
			tNetReady, tFcReady = time.Time{}, time.Time{}
		}
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
				tFailBoundary = time.Now()
				cleanupAfterRestoreFailure()
				m.setStatus(vmID, StatusError)
				return nil, fmt.Errorf("setup network: %w", netErr)
			}
			tapDevice = netInfo.TAPDevice
			macAddr = netInfo.MACAddress
			hostIP = netInfo.HostIP
			nsName = netInfo.Namespace
		}
		tNetReady = time.Now()

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
		var supervision Supervision
		inst.mu.RLock()
		existingSupervision := inst.Supervision
		inst.mu.RUnlock()
		// hadPriorLife = inPlace || priorRunDir: a leftover rundir means a
		// crashed prior life whose recordless systemd unit may still be running
		// (record never persisted, so inPlace is false). The cgroup path must run
		// its legacy-unit stop before spawning, or an armed retry starts a second
		// Firecracker over the live unit on the same id/disk/tap. Matches the same
		// !inPlace && !priorRunDir the freshUnit gate above uses.
		// freshUnit && attempt == 1: only a first-attempt fresh unit may skip
		// the linger query; a retry replaces the prior attempt's unit. The
		// dispatcher threads it to the systemd path (irrelevant to cgroup).
		// Forget the previous attempt's PID BEFORE this launch can spawn its
		// own MainPID resolver: a retry reuses `inst`, and a stale PID that
		// survives into the new attempt points at a stopped (possibly
		// recycled) process — which stall capture would then inspect and
		// report as this VM's.
		beginLaunchAttempt(inst)
		pid, supervision, startErr = m.launchFirecracker(ctx, vmID, socketPath, diskPath, resourceLimits.BasePath, nsName, existingSupervision, inPlace || priorRunDir, freshUnit && attempt == 1)
		// Stamp the chosen mode NOW, before the error branch: a launch that
		// forked a cgroup FC but failed socket-readiness (and whose own kill
		// couldn't confirm the group empty) leaves a live process. The record
		// must say cgroup so a later destroy dispatches the cgroup kill/rmdir
		// instead of a no-op unit stop.
		inst.mu.Lock()
		inst.Supervision = supervision
		inst.mu.Unlock()
		if startErr != nil {
			tFailBoundary = time.Now()
			m.releaseFailedRestore(vmID, inPlace, false, cleanupAfterRestoreFailure)
			m.setStatus(vmID, StatusError)
			return nil, fmt.Errorf("start firecracker: %w", startErr)
		}
		publishLaunchPID(inst, pid, supervision)
		tFcReady = time.Now()

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
			Float64("io_psi_avg10", ioPSI).
			Int("attempt", attempt).
			Msg("restoring snapshot")
		restorePhasesRecorded = true
		attemptPhases := map[string]time.Duration{
			"disk_to_net": tNetReady.Sub(netBase),
			"net_to_fc":   tFcReady.Sub(tNetReady),
		}
		if attempt == 1 {
			attemptPhases["entry_to_sem"] = tSemAcquired.Sub(tEntry)
			attemptPhases["sem_to_disk"] = tDiskReady.Sub(tSemAcquired)
		}
		m.recordPhases("restore", "", attemptPhases)

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
		// Failed attempts included: a slow failing load (tap-busy retry,
		// terminal failure) must appear in the distribution, not vanish.
		m.recordPhases("restore", "", map[string]time.Duration{"load_snapshot": time.Since(tFcReady)})
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
		dead := m.vmDefinitelyDead(checkCtx, vmID, m.supervisionForVM(vmID))
		checkCancel()
		if !dead {
			log.Warn().Int("attempt", attempt).
				Msg("VM not confirmed dead after stop — not retrying restore")
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
		m.releaseFailedRestore(vmID, inPlace, isTapDeviceBusyErr(restoreErr), cleanupAfterRestoreFailure)
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

	// Running means the vCPUs are live, which is what lets the persist overlap
	// the wait below; readiness is still verified there and still fails the
	// restore. This deliberately adopts the resume path's weaker guarantee —
	// resume has always published Running before readiness (its probe is
	// detached telemetry) — where restore previously published only after.
	// The window itself is not routable: the control plane hands out no usable
	// sandbox until this RPC returns and it activates the row. What the marker
	// bounds is the durable case — a crash here leaves a Running record whose
	// readiness was never proven, and both restore and resume adoption
	// re-verify such records before adopting them.
	// The status is set directly — setStatus would
	// persist synchronously, serializing the very fsync the goroutine
	// overlaps with the boxd wait.
	inst.mu.Lock()
	inst.Status = StatusRunning
	inst.Unverified = true
	inst.PausedAt = time.Time{}
	inst.mu.Unlock()
	persistDone := make(chan struct{})
	optimisticOK := false
	go func() {
		defer sentrylog.Recover("restore-persist")
		defer close(persistDone)
		optimisticOK = m.persistState(inst)
	}()

	tBoxdStart := time.Now()
	// Same window as first boot: a restore that has to fault its memory and
	// overlay from cold storage (first resume of a migrated VM, page cache
	// evicted) legitimately needs more than a warm same-host resume, and a
	// timeout here is destructive — the error path below tears down the VM.
	//
	// The window is clamped to the RPC deadline less the WORST-CASE error
	// path — the verdict returns only after teardown, so the reserve must
	// cover it: the 10s bounded unit stop, the 2s surviving-unit resolve,
	// and a reply margin. Then the DEFINITIVE verdict always reaches the
	// caller in-band even when setup ate into the budget and the stop is
	// stuck at its bound: an honest early error beats letting the caller's
	// deadline win the race — a bare DeadlineExceeded reads as transient
	// and gets retried into this VM's torn-down state.
	readiness := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl) - bootVerdictReserve; remaining < readiness {
			readiness = remaining
		}
	}
	if err := m.waitForBoxd(ctx, hostIP, readiness); err != nil {
		// Emit the exhausted readiness wait immediately, before teardown, so
		// the sample measures the probe (not unit stop + resource release +
		// persist join) and the concurrent-destroy return below can't skip it.
		m.recordPhases("restore", "", map[string]time.Duration{"wait_boxd": time.Since(tBoxdStart)})
		// The console (FC log + guest serial) is the only witness to where
		// the guest stalled between vCPU resume and first output; the
		// teardown below deletes it, so capture it now. Only for a genuine
		// readiness timeout: a caller disconnect also lands here via ctx,
		// and that aborting restore should neither pay the file read nor
		// pollute the stall signal.
		if ctx.Err() == nil {
			m.captureStallForensics(vmID, m.resolveFCPID(vmID, pid), time.Since(tBoxdStart), tAttemptStart)
		}
		// Teardown first — none of it touches BoltDB, so a stalled persist
		// cannot keep the failed restore's unit and network alive.
		m.stopUnitDuringRestoreError(vmID)
		m.releaseFailedRestore(vmID, inPlace, false, cleanupAfterRestoreFailure)
		// Durable-state convergence is unbounded fsync work (the persist
		// join, then another synchronous Put) and BoltDB is slow under
		// exactly the host pressure that stalls readiness — it must not
		// spend the verdict reserve. The ordering the join protects
		// (Running must not land after Error; a destroyed record must not
		// be resurrected) moves intact into a detached worker: join, then
		// re-check tracking, then write. The reply needs only a map read
		// to pick its error; a destroy that lands during the persist join
		// now returns the generic error instead of NotFound in that narrow
		// race — the worker still converges the durable state either way.
		m.mu.RLock()
		_, stillTracked := m.vms[vmID]
		m.mu.RUnlock()
		if stillTracked {
			// Mark the failure in-memory BEFORE returning: only the durable
			// write may be deferred. A same-ID retry that wins the lifecycle
			// lock right after this RPC returns must see Error — a lingering
			// Running/Unverified corpse would route it into re-verifying a
			// stopped VM instead of relaunching.
			inst.mu.Lock()
			inst.Status = StatusError
			inst.mu.Unlock()
		}
		go func() {
			defer sentrylog.Recover("restore-error-persist")
			<-persistDone
			// The identity check and the Error write must be atomic against
			// a same-ID retry, which serializes on the lifecycle lock: held
			// here, the map entry cannot be replaced between check and
			// write (only DestroyVM bypasses the lock, and its record
			// delete makes setStatus a no-op — the safe direction).
			unlock, lockErr := m.lockVMOp(context.Background(), vmID)
			if lockErr != nil {
				return
			}
			defer unlock()
			m.mu.RLock()
			cur, tracked := m.vms[vmID]
			m.mu.RUnlock()
			if !tracked {
				m.deleteState(vmID)
				return
			}
			if cur != inst {
				// A same-ID retry replaced the entry while the persist was
				// blocked. The stale optimistic write joined above may have
				// landed AFTER the replacement's own durable write, leaving
				// this torn-down instance as the last BoltDB value — a vmd
				// restart would reattach stale PID/network state. Repair by
				// re-persisting the replacement: it is stable under the
				// lifecycle lock held here (a live retry would still hold
				// it), and this write lands after the stale one by
				// construction.
				m.persistState(cur)
			} else {
				m.setStatus(vmID, StatusError)
			}
			// DestroyVM bypasses the lifecycle lock, so its record delete
			// can interleave anywhere around EITHER write above and be
			// resurrected by it. Converge by compensation: if the VM is
			// gone now, delete what we may have just written; a destroy
			// landing after this check deletes it itself. Every
			// interleaving ends with the record absent. (Under the held
			// lifecycle lock a destroy is the only possible map mutation,
			// so an untracked entry here can mean nothing else.)
			m.mu.RLock()
			_, still := m.vms[vmID]
			m.mu.RUnlock()
			if !still {
				m.deleteState(vmID)
			}
		}()
		if !stillTracked {
			// The destroy owns the teardown; report it as such, like every
			// sibling destroy-race path. A generic error here reads as
			// transient and the control plane retries a destroyed sandbox.
			return nil, status.Errorf(codes.NotFound, "vm %s was destroyed during restore", vmID)
		}
		return nil, fmt.Errorf("boxd not ready after restore: %w", err)
	}
	tBoxdReady := time.Now()

	// boxd is up → the guest has booted, so this template's working set is now
	// in page cache: read eagerly at load (File) or faulted in during boot
	// (UFFD). Stamp warmthPath (the layered base for an overlay restore, else
	// memPath) here (not at the load) so the next restore's
	// secs_since_template_restore reflects real warmth for either backend.
	m.markTemplateRestored(warmthPath)

	<-persistDone
	if !optimisticOK && !m.persistState(inst) {
		// The record could not be made durable, so the VM would be invisible
		// to the next reattach — a zombie unit after any vmd restart. Fail
		// the restore; the retry only costs latency when the store is
		// already broken.
		m.stopUnitDuringRestoreError(vmID)
		m.releaseFailedRestore(vmID, inPlace, false, cleanupAfterRestoreFailure)
		m.setStatus(vmID, StatusError)
		return nil, fmt.Errorf("vm %s restored but its state could not be persisted", vmID)
	}
	inst.mu.Lock()
	inst.Unverified = false
	inst.mu.Unlock()
	// Persist-then-verify: checking AFTER the write leaves no window — a
	// concurrent DestroyVM either erased the record itself or is caught here,
	// and we erase our write and tear down instead of resurrecting it. The
	// join above keeps the write happened-before this check.
	m.mu.RLock()
	_, stillTracked := m.vms[vmID]
	m.mu.RUnlock()
	if !stillTracked {
		m.deleteState(vmID)
		m.stopUnitDuringRestoreError(vmID)
		m.releaseFailedRestore(vmID, inPlace, false, cleanupAfterRestoreFailure)
		return nil, status.Errorf(codes.NotFound, "vm %s was destroyed during restore", vmID)
	}
	tPersisted := time.Now()

	// The cleared flag must land durably: a vmd restart would otherwise
	// reattach this verified VM as unverified, and a duplicate delivery
	// would relaunch it, rolling the guest back. Off the response path, but
	// the unlock handoff keeps the write inside the vm op critical section,
	// so a lifecycle op arriving right after the response cannot have its
	// persist overwritten by this one. Destroy bypasses the op lock;
	// PutIfPresent refuses to resurrect its record deletion.
	handoff := unlockOp
	unlockOp = nil
	go func() {
		defer sentrylog.Recover("restore-verified-persist")
		defer handoff()
		// Best-effort: an undurable clear leaves the marker set, which the
		// next adoption re-verifies and heals.
		_, _ = m.persistStateIfPresent(inst)
	}()

	log.Info().
		Int("pid", pid).
		Int64("wait_boxd_ms", tBoxdReady.Sub(tBoxdStart).Milliseconds()).
		Int64("persist_state_ms", tPersisted.Sub(tBoxdReady).Milliseconds()).
		Msg("VM restored from snapshot")
	m.recordPhases("restore", "", map[string]time.Duration{
		"wait_boxd": tBoxdReady.Sub(tBoxdStart),
		"persist":   tPersisted.Sub(tBoxdReady),
	})
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
// so the reconciler can handle them.
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

	// Reattach from BoltDB, routed through reattachByID (singleflight)
	// so this eager pass and any concurrent lazy request serialize per VM — a
	// lazy load can't run reattachRecord for a vmID while the eager pass is mid
	// stale-cleanup for the same one. reattachByID re-reads the record inside the
	// flight, so a DestroyVM between the snapshot and here can't resurrect it.
	m.reattachStopDeadline.Store(time.Now().Add(reattachStopPassBudget))
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

	// Detect orphan units not in BoltDB, both supervision modes.
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
	// Detect orphan per-VM cgroups not in BoltDB — LOG ONLY,
	// symmetric with the unit path. Killing here would race an in-flight
	// restore (this runs in a background goroutine; a create past the
	// startup gate can have its cgroup before its record). The reconciler
	// owns destruction, with a grace period and the op lock.
	if m.cgroups != nil {
		if cgIDs, cerr := m.cgroups.scanVMCgroups(); cerr == nil {
			for _, id := range cgIDs {
				if knownIDs[id] || isBuildVM(id) {
					continue
				}
				m.log.Warn().Str("vm_id", id).Msg("orphan vm cgroup detected (not in BoltDB) — will be handled by reconciler")
			}
		} else {
			m.log.Warn().Err(cerr).Msg("failed to scan vm cgroups — cgroup orphan detection skipped")
		}
	}

	// No broad re-sweep here. Startup already swept once before StartPool filled
	// the pool; re-sweeping now would delete the pool's warm netns (which are not
	// BoltDB records). Stale records deleted above free their own namespace
	// inline (see reattachRecord), so a re-sweep isn't needed.

	return reattached, stale
}

// reattachRecord rebuilds one VM's in-memory and network state from its BoltDB
// reattachHook, when non-nil, is invoked at the start of every reattachRecord
// call. Test-only seam for asserting that concurrent reattaches of the same VM
// dedupe through the singleflight group. Always nil in production.
var reattachHook func(vmID string)

// staleUnitStopConfirmed stops a stale record's still-active unit on a
// detached budget (the reattach ctx may be nearly spent) and reports whether
// it is confirmed down; a var for the same test seam vmDeadForRetry uses. The
// terminal probe decides regardless of the stop's reported outcome: a nil
// stop can still mean a deactivating unit (the expired-wait settle reports
// those complete), and the caller releases the record and namespace on
// true. The probe detaches — the budgeted stop can outlast the reattach
// ctx, and probing on a spent ctx would read a finished stop as alive.
var staleUnitStopConfirmed = func(ctx context.Context, unit string) bool {
	_ = stopUnitWithBudget(ctx, unit)
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return unitFullyDown(pctx, unit)
}

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

	// A revival interrupted by a restart must keep its record: it is the
	// retry's anchor (revive refuses unknown sandboxes), and the stale
	// cleanup below would delete it as a dead non-paused record. Park it
	// as Error without adopting; the retry's at-rest probe gates any
	// residue before a new boot, and the retry clears the mark.
	// No status exclusion: a pending marker can ride a still-Paused
	// record (revival of an unresumable paused zombie anchors before the
	// first status write), and a crash there leaves the same possibly-
	// live residue as any other interrupted attempt.
	if rec.RevivalPending {
		// A revival in flight holds vmID's op lock (ReviveVM's very
		// first step) and already owns this record's fate; stopping its
		// newly launched replacement or overwriting its state out from
		// under it would be exactly the corruption this cleanup exists
		// to prevent for a CRASHED attempt. The lock is held through the
		// WHOLE cleanup below (stop and park), not just checked and
		// released, or a fresh revive could start the instant it
		// released and race the rest of this block exactly as if the
		// check had never happened. Non-blocking: this pass must not
		// stall on a live revival, so a held lock skips cleanup entirely
		// and leaves that attempt's own commit or rollback to resolve
		// the record.
		unlockTry, ok := m.tryLockVMOp(rec.ID)
		if !ok {
			log.Info().Msg("revival in flight (op lock held) — leaving pending record for that attempt to resolve")
			return nil, false
		}
		defer unlockTry()
		log.Warn().Msg("revival interrupted by restart — stopping residue and parking record for retry")
		// The interrupted attempt may have left a live replacement, and
		// the retry's at-rest probe would refuse while it runs; without a
		// stop here (the reaper exempts pending records) recovery would
		// wedge until a manual destroy. Bounded and best-effort: an
		// unconfirmed stop still parks, the probe keeps refusing, and
		// the operator's forced destroy resolves.
		// Both supervisors stop, not just the recorded mode: a cgroup
		// launch can fall back to a unit mid-crash (errScopeGone), so the
		// record's mode may not name the residue's real supervisor. The
		// budget is the per-record cap clipped to the pass-wide deadline,
		// so many pending records cannot stack stops into minutes of
		// postponed reconciliation; past the deadline the stop is
		// skipped, the record still parks, and the retry's at-rest probe
		// keeps refusing until the operator resolves.
		budget := coldBootStopBudget
		if d, ok := m.reattachStopDeadline.Load().(time.Time); ok && !d.IsZero() {
			if rem := time.Until(d); rem < budget {
				budget = rem
			}
		}
		// The pass deadline bounds stop STARTS, not stop internals: some
		// stop branches strip cancellation and run their own internal
		// budgets, so the deadline is rechecked between the two stops
		// and the overshoot is bounded by at most one internal budget.
		if budget > 0 {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
			_ = m.stopVM(sctx, rec.ID, SupervisionUnit)
			remaining := true
			if d, ok := m.reattachStopDeadline.Load().(time.Time); ok && !d.IsZero() && time.Until(d) <= 0 {
				remaining = false
			}
			if remaining {
				_ = m.stopVM(sctx, rec.ID, SupervisionCgroup)
			} else {
				log.Warn().Msg("reattach stop budget exhausted after unit stop; skipping cgroup stop")
			}
			cancel()
		} else {
			log.Warn().Msg("reattach stop budget exhausted; parking without residue stop")
		}
		rec.Status = StatusError
		// Presence-conditional parking, deliberately WITHOUT the
		// record-owner mutex: a concurrent DestroyVM holds that mutex
		// while joining this very reattach flight through getInstance,
		// so taking it here would deadlock both. PutIfPresent is a
		// single Bolt transaction, which is discrimination enough: a
		// destroy's delete landing first makes this a no-op, and one
		// landing after deletes the parked record. The destroy wins
		// both orderings.
		if wrote, err := m.state.PutIfPresent(rec); err != nil {
			log.Error().Err(err).Msg("park interrupted-revival record")
		} else if !wrote {
			log.Info().Msg("interrupted-revival record deleted by a destroy; leaving it deleted")
		}
		return nil, false
	}

	// A live cgroup is ground truth for supervision, reconciled before we
	// trust the record's mode or status. Two crash windows produce a
	// disagreement: a crash mid unit→cgroup flip leaves the record still
	// saying unit over a live cgroup; a crash mid-resume leaves a Paused
	// record with a live half-restored FC.
	supervisionCorrected := false
	if m.cgroups != nil {
		// An unreadable cgroup.events reads as populated (fail-closed): falling
		// through to the stale unit mode would free networking under a live
		// cgroup FC that the unit liveness check reads as dead.
		if pop, perr := m.cgroups.vmCgroupPopulated(rec.ID); perr != nil || pop {
			// Stamp cgroup mode FIRST, unconditionally: even if the kill
			// below fails (host contention), the published record must never
			// say unit over a live cgroup, or a later destroy stops a
			// nonexistent unit and a resume launches a unit alongside it. This
			// is a no-op when the record already says cgroup (the common clean
			// reattach), so capture the disagreement before overwriting it —
			// only an ACTUAL correction is worth a WARN, not every reattach.
			wasNonCgroup := !cgroupSupervised(rec.Supervision)
			supervisionCorrected = wasNonCgroup
			rec.Supervision = SupervisionCgroup
			if rec.Status == StatusPaused {
				// A paused VM has no live process — this is a mid-resume
				// orphan. Kill it and keep the record Paused so a fresh
				// resume retries cleanly. On kill failure the reconciler
				// backstops (the record is now cgroup-mode).
				log.Warn().Msg("live cgroup for a paused record — killing mid-resume orphan")
				_ = m.stopVM(ctx, rec.ID, SupervisionCgroup)
			} else if wasNonCgroup {
				// Only when the record actually disagreed with the live cgroup
				// (a crash mid unit→cgroup flip), never on a clean reattach.
				log.Warn().Msg("live cgroup with a non-cgroup record — corrected supervision to cgroup")
			}
		}
	}

	// An unknown supervision mode (store corruption, or a record written by a
	// NEWER binary) is unmanageable: the dispatchers refuse it, and the stale
	// cleanup below would probe the wrong oracle — a nonexistent unit reads
	// vacuously down, releasing record and network under a possibly-live FC.
	// Park it as Error instead (durable via the publish tail), preserving the
	// value for the binary that understands it. The live-cgroup correction
	// above already repaired the one case reality can prove.
	unmanageableMode := !knownSupervision(rec.Supervision)
	if unmanageableMode {
		log.Error().Str("supervision", string(rec.Supervision)).
			Msg("unknown supervision mode — parking as unmanageable")
		rec.Status = StatusError
	}

	// Running VMs must have a live systemd unit and a reachable API socket; a
	// dead one is a stale record. Paused VMs legitimately have no unit — they
	// were stopped at pause and wait for a resume — so they skip these checks.
	// Release requires the TERMINAL unit state, not vmDeadForRetry: deactivating
	// reads dead there while a wedged FC (a parked Error record's unconfirmed
	// stop, riding out a restart) may still be exiting — a transitional unit
	// falls through to the socket path below, which parks it instead.
	if cleanupStale && !unmanageableMode && rec.Status != StatusPaused {
		var fullyDown bool
		if cgroupSupervised(rec.Supervision) {
			// Both supervisors — the scope-gone fallback window (see
			// DestroyVM's fallback-unit gate); an empty group is already
			// terminal, the unit claim must be too.
			fullyDown = m.cgroupDefinitelyDead(rec.ID) && vmUnitFullyDown(rec.ID)
		} else {
			fullyDown = vmUnitFullyDown(rec.ID)
		}
		if fullyDown {
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
				// The VM is still live, so stop Firecracker before we forget
				// the record and tear down its netns — otherwise it keeps running
				// as an orphan burning CPU/RAM and holding TAP fds in a namespace
				// we're about to delete out from under it.
				var confirmed bool
				if cgroupSupervised(rec.Supervision) {
					// A cgroup FC that survived the stop still holds its tap;
					// deleting the record and reclaiming the slot now would recycle
					// it under a live process and discard the only handle to retry.
					// Keep both intact unless it's confirmed dead — the reconciler
					// reclaims it once the group empties.
					if err := m.stopVM(ctx, rec.ID, rec.Supervision); err != nil {
						log.Warn().Err(err).Msg("stop failed for socket-missing VM")
					}
					// Both supervisors — the scope-gone fallback window.
					_ = stopUnit(ctx, systemdUnitName(rec.ID))
					confirmed = m.cgroupDefinitelyDead(rec.ID) && vmUnitFullyDown(rec.ID)
					if !confirmed {
						return nil, false
					}
				} else {
					// An unconfirmed stop keeps the record — deleting it would
					// leave a live unit no record points to — but flipped to
					// Error: a socket-less VM can never be managed again, so no
					// retry may adopt it. A caller-driven relaunch or destroy
					// stops the unit on its own budget; failing that, the
					// reconciler's error-unit rule reaps it.
					confirmed = staleUnitStopConfirmed(ctx, systemdUnitName(rec.ID))
					if !confirmed {
						rec.Status = StatusError
						wrote, perr := m.state.PutIfPresent(rec)
						if perr == nil && !wrote {
							// Deleted while we waited on the stop (destroy or
							// markStale): whoever deleted it owns the teardown, and
							// recreating the row would resurrect it and rebind a
							// freed slot.
							return nil, false
						}
						if perr != nil {
							log.Error().Err(perr).Msg("failed to persist error status for unstopped VM")
							// Without a durable refusal, a restart could re-adopt
							// the Running row. Escalate instead of retrying the
							// broken store — kill by verified PID when possible,
							// then have systemd kill whatever remains — and let
							// one probe decide: SIGKILL delivery does not prove
							// exit (a D-state process survives it), and an
							// unconfirmed kill must not release the record.
							if pidIsVMFirecracker(rec.PID, rec.ID) {
								sigkillPID(rec.PID, 500*time.Millisecond)
							}
							confirmed = killUnitSIGKILL(ctx, systemdUnitName(rec.ID))
						}
					}
				}
				if confirmed {
					if derr := m.state.Delete(rec.ID); derr == nil {
						m.netMgr.CleanupVMOrNamespace(rec.ID, rec.Namespace)
						return nil, false
					} else {
						// The Running row survives with its unit dead;
						// untracked, a lazy reattach would re-adopt it onto a
						// slot this path was about to free — markStale retries
						// the delete on later passes.
						log.Error().Err(derr).Msg("failed to delete stale record; parking as error")
					}
				} else {
					log.Warn().Msg("unit not confirmed stopped; record kept as error")
				}
				// Park the refusal: fall through to the shared bind/publish/
				// commit tail with StatusError, so a lazy reattach can never
				// re-read the Running row and adopt it.
				rec.Status = StatusError
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
		// The paused branch is deliberately read-only (no mass rewrite of
		// every paused record at startup) — except a supervision correction,
		// which must land durably or a second restart resolves the record
		// back to unit.
		if supervisionCorrected {
			switch wrote, perr := m.persistStateIfPresent(inst); {
			case perr == nil && !wrote: // deleted by a concurrent destroy
				m.undoReattach(rec.ID)
				return nil, false
			case perr != nil:
				// Not a deletion: keep the VM published with the corrected mode
				// in memory (undoing would leave a live cgroup FC untracked). A
				// restart re-derives the correction from the live cgroup.
				log.Warn().Err(perr).Msg("supervision correction not durable; kept in memory")
			}
		} else if m.recordDeleted(rec.ID) {
			m.undoReattach(rec.ID)
			return nil, false
		} else if fresh, ferr := m.state.Get(rec.ID); ferr == nil && fresh != nil && fresh.Supervision != rec.Supervision {
			// The rollback demotion (reconciler, under the vm-op lock) may
			// have rewritten the durable mode while this lock-free reattach
			// was in flight; adopt it, or a resume acts on the stale mode and
			// re-promotes a demoted record. Skipped when the correction above
			// ran — that value is proven by the live cgroup, not the store.
			inst.mu.Lock()
			inst.Supervision = fresh.Supervision
			inst.mu.Unlock()
		}
		log.Info().Msg("reattached paused VM")
	} else {
		// Only a deletion undoes the reattach (see persistStateIfPresent).
		if wrote, perr := m.persistStateIfPresent(inst); perr == nil && !wrote {
			m.undoReattach(rec.ID)
			return nil, false
		}
		if inst.Status == StatusError {
			log.Warn().Msg("VM parked in error state — tracked so no retry adopts it")
		} else {
			log.Info().Int("pid", inst.PID).Str("ip", inst.IP).Msg("reattached to running VM")
		}
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
		// Being destroyed: don't resurrect from the record onto a freed slot
		// (see the destroying field).
		if _, destroying := m.destroying.Load(vmID); destroying {
			return (*VMInstance)(nil), nil
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
func (m *Manager) SweepStartupOrphanNamespaces(extraKeep ...string) {
	if m.state == nil {
		return
	}
	// Keep-set from the slot index — same content the record scan produced.
	nsByID, err := m.state.SlotNamespaces()
	if err != nil {
		// Sweeping with an empty keep-set would delete every live VM's
		// namespace — skip entirely when the index can't be read.
		m.log.Error().Err(err).Msg("sweep: cannot read slot index — skipping orphan namespace sweep")
		return
	}
	keepNs := make(map[string]bool, len(nsByID))
	for _, ns := range nsByID {
		keepNs[ns] = true
	}
	// Recordless cgroup survivors whose FC outlived the reap: keep their tap
	// intact so the slot isn't recycled under a live process. The reconciler
	// reclaims them once confirmed dead.
	for _, ns := range extraKeep {
		keepNs[ns] = true
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
	tLoad := time.Now()
	slots, err := m.state.SlotNamespaces()
	if err != nil {
		m.log.Error().Err(err).Msg("failed to read slot index for startup slot reservation")
		return false
	}
	loadMS := time.Since(tLoad)
	tReserve := time.Now()
	m.netMgr.ReserveSlotsAbove(slots)
	// Reservations pin the allocator above the highest record index, stranding
	// every unused index below it. Hand those back now, while records are the
	// only owners and "unowned with no namespace" provably means free.
	reclaimed := m.netMgr.ReclaimUnusedSlots()
	// Async: the write must not sit on the startup path.
	reserveDur := time.Since(tReserve)
	go func() {
		m.log.Info().Dur("slot_index_load_ms", loadMS).Dur("reserve_reclaim_ms", reserveDur).
			Int("reservations", len(slots)).Int("reclaimed", reclaimed).
			Msg("startup slot reservation breakdown")
	}()
	if reclaimed > 0 {
		m.log.Info().Int("slots", reclaimed).Msg("reclaimed unused network slot indexes")
	}
	return true
}

// ReapRecordlessCgroupVMs kills direct-spawn VMs that have a live cgroup but
// no BoltDB record — a crash between spawn and the first persist. It runs
// synchronously at startup, BEFORE the request gate opens, so every recordless
// cgroup is genuinely a previous-life survivor (no create has happened yet);
// the racy post-gate case is left to the reconciler under its op lock. No-op
// unless direct spawn is armed/managed and the state store is attached.
//
// A SIGKILL-immune FC (D-state, UFFD-wedged) survives the kill still holding
// its tap. For each such survivor this reserves the slot under its id — the
// same way a record protects its own, so the pool won't fresh-claim it and
// adoption skips owned slots — and returns its namespace so the non-adoption
// orphan sweep keeps it too. Either reclaim path recycling the slot under a
// live FC would break death-before-recycle. Drift-0 releases the reservation
// via CleanupVMOrNamespace once the FC is finally dead.
//
// sweepSafe is false when a possible live survivor's namespace could NOT be
// resolved (or its record read, or the cgroup scan, failed): the sweep can't
// be told which ns to spare, so the caller must skip it entirely rather than
// reclaim that live FC's tap.
func (m *Manager) ReapRecordlessCgroupVMs(ctx context.Context) (protected []string, sweepSafe bool) {
	if m.cgroups == nil || m.state == nil {
		return nil, true // not managing cgroup VMs — no survivors to spare
	}
	cgIDs, err := m.cgroups.scanVMCgroups()
	if err != nil {
		// Can't enumerate cgroups, so can't rule out a live survivor: the
		// sweep must not run this startup.
		m.log.Warn().Err(err).Msg("failed to scan vm cgroups for recordless reap — skipping startup orphan sweep")
		return nil, false
	}
	sweepSafe = true
	scanned := len(cgIDs)
	var recorded, recordless, reaped int
	for _, id := range cgIDs {
		// Build VMs ARE reaped here: pre-gate every cgroup is a previous-life
		// survivor, and a build's cgroup is recordless (persistState omits build
		// IDs), so nothing else would ever kill it. The build-VM skip belongs
		// only in the reconciler, which runs post-gate where a build may be
		// in-flight.
		if has, herr := m.state.Has(id); herr != nil || has {
			if herr != nil {
				// Unreadable: skip the kill (conservative), but this VM may be
				// a live recordless survivor whose slot and ns are now in NO
				// protected set — the sweep must not run on this startup.
				sweepSafe = false
				m.log.Warn().Err(herr).Str("vm_id", id).Msg("record lookup failed for cgroup survivor — skipping startup orphan sweep")
			} else {
				recorded++
			}
			continue // recorded (reattach owns it) or unreadable
		}
		recordless++
		m.log.Warn().Str("vm_id", id).Msg("recordless cgroup survivor at startup — reaping")
		// Capture the netns before the kill: an FC that survives it is still in
		// the group, but a clean kill removes it and firstPID would read empty.
		ns := m.netMgr.NamespaceForPID(m.cgroups.firstPID(id))
		serr := m.stopVM(ctx, id, SupervisionCgroup)
		if serr == nil {
			reaped++
		}
		if serr != nil {
			m.log.Error().Err(serr).Str("vm_id", id).Msg("failed to reap recordless cgroup")
			// Liveness decides first — populated or unreadable == maybe-alive.
			// A confirmed-empty group whose rmdir merely failed is dead, its
			// slot genuinely free to reclaim.
			if pop, perr := m.cgroups.vmCgroupPopulated(id); perr != nil || pop {
				if ns != "" {
					m.netMgr.ReserveSlotsAbove(map[string]string{id: ns})
					m.survivorNS.Store(id, ns)
					protected = append(protected, ns)
				} else {
					// Alive, but its namespace couldn't be resolved (a
					// transient /proc read), so this specific slot can't be
					// spared by name. The one-time sweep must not run, or it
					// would reclaim the live FC's tap; a later boot reclaims
					// genuine orphans once the read succeeds.
					sweepSafe = false
					m.log.Warn().Str("vm_id", id).Msg("live recordless survivor with unresolved netns — skipping startup orphan sweep")
				}
			}
		}
	}
	// Async: the write must not sit on the startup path.
	nProtected := len(protected)
	go func() {
		m.log.Info().Int("scanned", scanned).Int("recorded", recorded).Int("recordless", recordless).
			Int("reaped", reaped).Int("protected", nProtected).Msg("cgroup reap breakdown")
	}()
	return protected, sweepSafe
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
	// Only a definitive death lets the teardown proceed — a cgroup VM has no
	// unit, so the unit oracle would call it dead and reap a live VM on any
	// transient FC error. vmDefinitelyDead dispatches on mode and reads an
	// inconclusive answer as alive.
	if !m.vmDefinitelyDead(checkCtx, vmID, m.supervisionForVM(vmID)) {
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

// supervisionForVM resolves a VM's supervision mode from the in-memory
// instance, else the persisted record, else "" (unit — the safe legacy
// default). Cheap: an RLock and at most one BoltDB read. Every stop and
// liveness site that lacks an instance in hand uses this so a cgroup VM is
// never treated as a unit VM (which would leave its process unkilled and
// read it as dead).
func (m *Manager) supervisionForVM(vmID string) Supervision {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if ok {
		inst.mu.RLock()
		s := inst.Supervision
		inst.mu.RUnlock()
		return s
	}
	if m.state != nil {
		if rec, err := m.state.Get(vmID); err == nil && rec != nil {
			return rec.Supervision
		}
	}
	return SupervisionUnit
}

// instanceClaimsCgroup reports whether a tracked in-memory instance exists for
// vmID AND is cgroup-supervised. Unlike supervisionForVM it does NOT fall back
// to the record or default to unit; an absent instance reads as no claim.
func (m *Manager) instanceClaimsCgroup(vmID string) bool {
	m.mu.RLock()
	inst, ok := m.vms[vmID]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return cgroupSupervised(inst.Supervision)
}

// errSpawnedStopUnconfirmed marks a cold-boot failure whose spawned VM
// could not be confirmed stopped; its resources and error record were
// deliberately retained for a forced teardown.
var errSpawnedStopUnconfirmed = errors.New("spawned VM stop unconfirmed")

// reattachStopPassBudget bounds the aggregate residue-stop time of one
// eager reattach pass (see reattachStopDeadline).
const reattachStopPassBudget = 90 * time.Second

// coldBootStopBudget bounds the detached stop of a spawned VM after a
// failed cold boot: detachment protects the stop from the caller's spent
// deadline, but an unbounded stop would let a hung systemctl wedge the
// lifecycle path indefinitely (see stopUnitBudget for the same
// discipline).
const coldBootStopBudget = 30 * time.Second

// lockRecordOwner acquires vmID's record-ownership mutex (see
// recordOwnerMus) and returns its unlock.
func (m *Manager) lockRecordOwner(vmID string) func() {
	v, _ := m.recordOwnerMus.LoadOrStore(vmID, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// recordRevivalPending reports whether vmID's durable record is marked
// as an in-flight revival's retry anchor (see VMRecord.RevivalPending).
func (m *Manager) recordRevivalPending(vmID string) bool {
	if m.state == nil {
		return false
	}
	rec, err := m.state.Get(vmID)
	return err == nil && rec != nil && rec.RevivalPending
}

// destroyEpoch reads vmID's completed-destroy counter.
func (m *Manager) destroyEpoch(vmID string) uint64 {
	v, _ := m.destroyEpochs.LoadOrStore(vmID, new(uint64))
	return atomic.LoadUint64(v.(*uint64))
}

func (m *Manager) bumpDestroyEpoch(vmID string) {
	v, _ := m.destroyEpochs.LoadOrStore(vmID, new(uint64))
	atomic.AddUint64(v.(*uint64), 1)
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

type pausedNetworkPressureSnapshot struct {
	totalSlots    int
	freeSlots     int
	netnsTotal    int
	ownedSlots    int
	orphaned      int
	mountTotal    int
	mountNsfs     int
	freshPool     int
	recycledPool  int
	poolAvailable bool
}

func (m *Manager) pausedNetworkPressureSnapshot() pausedNetworkPressureSnapshot {
	snapshot := pausedNetworkPressureSnapshot{totalSlots: network.MaxSlots}
	if m.netMgr != nil {
		snapshot.netnsTotal, snapshot.ownedSlots, snapshot.orphaned = m.netMgr.NetnsStats()
		snapshot.freshPool, snapshot.recycledPool, snapshot.poolAvailable = m.netMgr.PoolStats()
	}
	snapshot.mountTotal, snapshot.mountNsfs = hostMountCounts()
	snapshot.freeSlots = snapshot.totalSlots - snapshot.ownedSlots
	if snapshot.poolAvailable {
		snapshot.freeSlots += snapshot.freshPool + snapshot.recycledPool
	}
	if snapshot.freeSlots > snapshot.totalSlots {
		snapshot.freeSlots = snapshot.totalSlots
	}
	if snapshot.freeSlots < 0 {
		snapshot.freeSlots = 0
	}
	return snapshot
}

func (m *Manager) pausedNetworkSlotWatermarks(totalSlots int) (low, high int) {
	low = m.cfg.PausedNetworkSlotHeadroomReserve
	if pct := (totalSlots * m.cfg.PausedNetworkSlotHeadroomPercent) / 100; pct > low {
		low = pct
	}
	if low < 0 {
		low = 0
	}
	if low > totalSlots {
		low = totalSlots
	}
	high = low + m.cfg.PausedNetworkSlotHeadroomHysteresis
	if high <= low {
		high = low + 1
	}
	if high > totalSlots {
		high = totalSlots
	}
	if high < low {
		high = low
	}
	return low, high
}

func (m *Manager) pausedNetworkCountWatermarks(threshold, hysteresis int) (low, high int, enabled bool) {
	if threshold <= 0 {
		return 0, 0, false
	}
	high = threshold
	low = high - hysteresis
	if hysteresis <= 0 {
		low = high - 1
	}
	if low < 0 {
		low = 0
	}
	if high <= low {
		high = low + 1
	}
	return low, high, true
}

func (m *Manager) pausedAtForOrder(rec VMRecord) time.Time {
	if !rec.PausedAt.IsZero() {
		return rec.PausedAt
	}
	if !rec.CreatedAt.IsZero() {
		return rec.CreatedAt
	}
	return time.Time{}
}

func (m *Manager) reclaimPausedNetworkInventory(now time.Time) int {
	if m.state == nil || m.netMgr == nil || !m.cfg.PausedNetworkReclaimEnabled {
		return 0
	}
	m.pausedNetworkControllerMu.Lock()
	active := m.pausedNetworkControllerActive
	last := m.pausedNetworkControllerLastRun
	m.pausedNetworkControllerMu.Unlock()
	if cooldown := m.cfg.PausedNetworkReclaimCooldown; cooldown > 0 {
		if !last.IsZero() && now.Sub(last) < cooldown {
			return 0
		}
	}

	snapshot := m.pausedNetworkPressureSnapshot()
	slotLow, slotHigh := m.pausedNetworkSlotWatermarks(snapshot.totalSlots)
	netnsLow, netnsHigh, netnsEnabled := m.pausedNetworkCountWatermarks(m.cfg.PausedNetworkNetnsThreshold, m.cfg.PausedNetworkNetnsHysteresis)
	mountLow, mountHigh, mountEnabled := m.pausedNetworkCountWatermarks(m.cfg.PausedNetworkMountThreshold, m.cfg.PausedNetworkMountHysteresis)

	slotPressure := snapshot.freeSlots < slotLow
	netnsPressure := netnsEnabled && snapshot.netnsTotal > netnsHigh
	mountPressure := mountEnabled && snapshot.mountTotal > mountHigh
	kernelPressure := netnsPressure || mountPressure
	pressureState := "idle"
	switch {
	case slotPressure && kernelPressure:
		pressureState = "both"
	case slotPressure:
		pressureState = "slot"
	case kernelPressure:
		pressureState = "kernel"
	}
	healthyNetns := !netnsEnabled || snapshot.netnsTotal <= netnsLow
	healthyMount := !mountEnabled || snapshot.mountTotal <= mountLow
	healthy := snapshot.freeSlots >= slotHigh && healthyNetns && healthyMount
	telemetrySnapshot := telemetry.PausedNetworkPressure{
		TotalSlots:     int64(snapshot.totalSlots),
		UsedSlots:      int64(snapshot.totalSlots - snapshot.freeSlots),
		AvailableSlots: int64(snapshot.freeSlots),
		FreshPool:      int64(snapshot.freshPool),
		RecycledPool:   int64(snapshot.recycledPool),
		NetnsTotal:     int64(snapshot.netnsTotal),
		MountTotal:     int64(snapshot.mountTotal),
		PressureState:  pressureState,
	}
	defer func() {
		if m.recorder != nil {
			m.recorder.RecordPausedNetworkPressure(context.Background(), telemetrySnapshot)
		}
	}()
	if active && healthy {
		m.pausedNetworkControllerMu.Lock()
		m.pausedNetworkControllerActive = false
		m.pausedNetworkControllerMu.Unlock()
		return 0
	}
	if !active && !slotPressure && !kernelPressure {
		return 0
	}
	m.pausedNetworkControllerMu.Lock()
	m.pausedNetworkControllerActive = true
	m.pausedNetworkControllerMu.Unlock()

	recs, err := m.state.All()
	if err != nil {
		m.log.Error().Err(err).Msg("failed to read VM state for paused network controller")
		return 0
	}
	type candidate struct {
		rec  VMRecord
		when time.Time
	}
	candidates := make([]candidate, 0, len(recs))
	for _, rec := range recs {
		if rec.Status != StatusPaused || rec.Namespace == "" {
			continue
		}
		candidates = append(candidates, candidate{rec: rec, when: m.pausedAtForOrder(rec)})
	}
	if len(candidates) == 0 {
		return 0
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].when.Equal(candidates[j].when) {
			return candidates[i].rec.ID < candidates[j].rec.ID
		}
		if candidates[i].when.IsZero() {
			return false
		}
		if candidates[j].when.IsZero() {
			return true
		}
		return candidates[i].when.Before(candidates[j].when)
	})

	maxReclaims := m.cfg.PausedNetworkMaxReclaims
	if maxReclaims <= 0 {
		maxReclaims = 1
	}
	reclaimed := 0
	for _, cand := range candidates {
		if reclaimed >= maxReclaims {
			break
		}
		// Warmth is protected under every pressure type. Gating this on slot
		// pressure alone made it dead in practice: slot headroom is measured
		// against the whole index range, so kernel pressure is what actually
		// fires, and a sandbox paused seconds ago was eligible immediately.
		// Skipping a too-fresh candidate costs nothing — the backlog supplies
		// older ones, and the next pass re-evaluates.
		if m.cfg.PausedNetworkMinWarmAge > 0 {
			age := now.Sub(m.pausedAtForOrder(cand.rec))
			if age < m.cfg.PausedNetworkMinWarmAge {
				continue
			}
		}
		if unlock, ok := m.tryLockVMOp(cand.rec.ID); ok {
			cur := cand.rec
			if inst := m.trackedInstance(cand.rec.ID); inst != nil {
				inst.mu.RLock()
				cur.Status = inst.Status
				cur.Namespace = inst.Namespace
				cur.IP = inst.IP
				cur.TAPDevice = inst.TAPDevice
				cur.MACAddress = inst.MACAddress
				cur.PausedAt = inst.PausedAt
				inst.mu.RUnlock()
			} else if m.state != nil {
				stored, gerr := m.state.Get(cand.rec.ID)
				if gerr != nil || stored == nil || stored.ID == "" {
					unlock()
					continue
				}
				cur = *stored
			}
			if cur.Status != StatusPaused || cur.Namespace == "" {
				unlock()
				continue
			}
			shrink := kernelPressure || !snapshot.poolAvailable
			released, relErr := m.releasePausedNetworkSlot(cur, shrink)
			if relErr != nil {
				m.log.Error().Err(relErr).Str("vm_id", cand.rec.ID).Bool("shrink", shrink).Msg("failed to release paused network slot")
				unlock()
				continue
			}
			if released {
				reclaimed++
				telemetrySnapshot.ReclaimedPaused++
				if shrink {
					telemetrySnapshot.ReclaimedTeardown++
				} else {
					telemetrySnapshot.ReclaimedRecycle++
				}
			}
			unlock()
			continue
		}
	}
	if kernelPressure && reclaimed < maxReclaims {
		drained := m.netMgr.DrainWarmPool(maxReclaims - reclaimed)
		reclaimed += drained
		telemetrySnapshot.ReclaimedTeardown += int64(drained)
	}
	// Stamp on any pass that got this far, not only ones that reclaimed. A
	// pressured host whose candidates are all lock-contended (or already
	// released) otherwise never arms the cooldown, and repeats the full record
	// scan, /proc/mounts read and netns readdir on every single tick.
	m.pausedNetworkControllerMu.Lock()
	m.pausedNetworkControllerLastRun = now
	m.pausedNetworkControllerMu.Unlock()
	return reclaimed
}

// releasePausedNetworkSlot tears down or recycles a paused sandbox's network
// namespace and clears the persisted network identity so the slot can be
// reclaimed.
func (m *Manager) releasePausedNetworkSlot(rec VMRecord, shrink bool) (bool, error) {
	if rec.Namespace == "" || m.netMgr == nil {
		return false, nil
	}

	if inst := m.trackedInstance(rec.ID); inst != nil {
		inst.mu.Lock()
		if inst.Status != StatusPaused {
			inst.mu.Unlock()
			return false, nil
		}
		ns := inst.Namespace
		if ns == "" {
			inst.mu.Unlock()
			return false, nil
		}
		inst.mu.Unlock()
		cleared := toRecord(inst)
		cleared.Namespace = ""
		cleared.IP = ""
		cleared.TAPDevice = ""
		cleared.MACAddress = ""
		if m.state != nil && !isBuildVM(inst.ID) {
			if wrote, err := m.state.PutIfPresent(cleared); err != nil {
				return false, fmt.Errorf("persist paused slot release for vm %s: %w", rec.ID, err)
			} else if !wrote {
				return false, nil
			}
		}
		inst.mu.Lock()
		inst.Namespace = ""
		inst.IP = ""
		inst.TAPDevice = ""
		inst.MACAddress = ""
		inst.mu.Unlock()
		// Name the namespace explicitly rather than relying on the net
		// manager's device table: a VM whose startup reattach failed is absent
		// from it, and the by-vmID calls silently no-op for those. The record's
		// namespace has already been cleared above, so a no-op here would strand
		// the netns, veth, tap and mount entries with nothing left naming them —
		// invisible to every sweep and reclaim until the next restart. These
		// variants take the same by-vmID path when the VM is tracked.
		if shrink {
			m.netMgr.TeardownVMOrNamespace(rec.ID, ns)
		} else {
			m.netMgr.CleanupVMOrNamespace(rec.ID, ns)
		}
		return true, nil
	}

	cleared := rec
	cleared.Namespace = ""
	cleared.IP = ""
	cleared.TAPDevice = ""
	cleared.MACAddress = ""
	if m.state != nil {
		if wrote, err := m.state.PutIfPresent(cleared); err != nil {
			return false, fmt.Errorf("persist paused slot release for vm %s: %w", rec.ID, err)
		} else if !wrote {
			return false, nil
		}
	}
	if shrink {
		m.netMgr.TeardownVMOrNamespace(rec.ID, rec.Namespace)
	} else {
		m.netMgr.CleanupVMOrNamespace(rec.ID, rec.Namespace)
	}
	return true, nil
}

// persistState writes the current VM state to BoltDB. No-op if no state
// store is configured. Errors are logged but not returned — BoltDB is a
// cache, not a source of truth.
func (m *Manager) persistState(inst *VMInstance) bool {
	if m.state == nil {
		return true
	}
	if isBuildVM(inst.ID) {
		return true
	}
	if err := m.state.Put(toRecord(inst)); err != nil {
		m.log.Error().Err(err).Str("vm_id", inst.ID).Msg("failed to persist VM state to BoltDB")
		return false
	}
	return true
}

// persistStateIfPresent persists inst only if its record still exists (atomic).
// wrote=false means a concurrent DestroyVM deleted the record: the caller must
// not resurrect it. A non-nil err means the write itself failed and the durable
// record is UNCHANGED — a different outcome that must never be read as either
// "stored" or "deleted", which is why the two travel separately.
func (m *Manager) persistStateIfPresent(inst *VMInstance) (wrote bool, err error) {
	if m.state == nil || isBuildVM(inst.ID) {
		return true, nil
	}
	wrote, err = m.state.PutIfPresent(toRecord(inst))
	if err != nil {
		m.log.Error().Err(err).Str("vm_id", inst.ID).Msg("failed to persist VM state to BoltDB")
		return false, err
	}
	return wrote, nil
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
	if v, ok := m.preserveRecordOnDestroy.Load(vmID); ok {
		// A revival is in flight: the record is its retry anchor, so
		// deletion becomes an overwrite with the pending-marked record.
		// There is no recordless instant for a crash to land in.
		rec := v.(VMRecord)
		if err := m.state.Put(rec); err != nil {
			m.log.Error().Err(err).Str("vm_id", vmID).Msg("failed to preserve revival anchor in BoltDB")
		}
		return
	}
	if err := m.state.Delete(vmID); err != nil {
		m.log.Error().Err(err).Str("vm_id", vmID).Msg("failed to delete VM state from BoltDB")
	}
}

// reviveTeardownCtxKey marks a context as belonging to revival's own
// teardown calls: DestroyVM preserves the revival anchor for those and
// retires it for every other caller.
type reviveTeardownCtxKey struct{}

// deleteStateForce removes the durable record even while a revival's
// preserve entry is active: revival's own destroy-wins paths call it
// once an external destroy is detected, because the deletion is then
// authoritative and the anchor must not survive it.
func (m *Manager) deleteStateForce(vmID string) {
	m.preserveRecordOnDestroy.Delete(vmID)
	m.deleteState(vmID)
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

// copyRootfsExact reflinks the source into the VM's run dir with no
// fallback: extent-exact or error, for overlay sources whose holes are
// semantically load-bearing.
func (m *Manager) copyRootfsExact(ctx context.Context, dirName, srcRootfs string) (string, error) {
	vmDir := filepath.Join(m.cfg.RunDir, dirName)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir vm dir: %w", err)
	}
	diskPath := filepath.Join(vmDir, "rootfs.ext4")
	cmd := exec.CommandContext(ctx, "cp", "--reflink=always", srcRootfs, diskPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("exact copy (source and run dir must share a reflink filesystem): %s: %w", string(out), err)
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
	return name == templateDirName || name == TemplatesDirName || name == stallForensicsDirName
}

// abortResumeLocked reverts a freshly-resumed VM back to Paused when a
// post-restore step fails; the caller must hold vmID's lifecycle lock,
// continuously since the resume it is aborting — that continuity is what
// guarantees no retry has adopted the instance in between. The VM is
// stopped and the record re-marked Paused so the host matches the caller's
// view of a failed resume. A restore never mutates the snapshot artifacts it
// resumed from, so a later resume simply restores them again.
//
// DestroyVM bypasses the lifecycle lock (see vmOpLocks), so a concurrent
// destroy is still possible; its deletions are handled by the guards below.
func (m *Manager) abortResumeLocked(vmID string) {
	// trackedInstance, never getInstance: in DestroyVM's delete window a
	// lazy reattach would resurrect the instance and rebind its freed slot
	// (see trackedInstance). Untracked means the destroy owns the teardown.
	inst := m.trackedInstance(vmID)
	if inst == nil {
		return
	}
	inst.mu.Lock()
	running := inst.Status == StatusRunning
	inst.mu.Unlock()
	if !running {
		return
	}
	m.stopUnitDuringRestoreError(vmID)
	inst.mu.Lock()
	inst.Status = StatusPaused
	inst.DirtyTracked = false // FC process stopped; a fresh resume re-arms tracking.
	inst.PausedAt = time.Now()
	inst.mu.Unlock()
	// Durable convergence is deferred: the write is unbounded fsync work
	// and this runs on reply paths whose deadline reserve covers only the
	// bounded stop. In-memory Paused above is what a same-ID retry reads.
	// The worker carries the standard protections: the lifecycle lock
	// serializes it against retries, a replacement's record is repaired
	// rather than clobbered by our stale instance, and the lock-bypassing
	// destroy is compensated after the write (an undurable revert is also
	// re-derived by the reconciler).
	m.deferStatePersist("resume-abort-persist", vmID, inst, true)
}

// releaseFailedRestore frees a failed restore's network slot and rundir —
// unless a cgroup FC survived the failure (or its death cannot be proven), in
// which case it still holds the tap and its disk, and freeing either would
// hand live resources to the next claimant. Ownership (record, rundir, slot)
// is then retained: the record reads Error with cgroup supervision, and the
// reconciler's error rules complete the stop and release. Unit-mode VMs are
// unaffected — cgroupStillLive consults the cgroup, not the record, and is
// false when no delegated subtree exists.
func (m *Manager) releaseFailedRestore(vmID string, inPlace, tapBusy bool, cleanupRunDir func()) {
	if m.cgroupStillLive(vmID) {
		m.log.Warn().Str("vm_id", vmID).
			Msg("restore failed with a live cgroup — keeping rundir and network until the reconciler confirms death")
		// Best-effort persist — the in-memory marker still guides this
		// life, and a restart re-parks via reattach either way.
		m.mu.RLock()
		inst := m.vms[vmID]
		m.mu.RUnlock()
		if inst != nil {
			inst.mu.Lock()
			inst.TeardownPending = "restore failed; cgroup process not proven dead; rundir and network retained; reconciler owns stop and release"
			inst.mu.Unlock()
			// SYNCHRONOUS on purpose, unlike this path's other durable
			// writes: the marker is crash-safety-critical (pinned by test).
			// A crash before it lands would lose the "reconciler owns stop
			// and release" instruction while a possibly-live Firecracker
			// still holds the tap and rundir. This branch fires only when a
			// cgroup is provably live or unprovable — rare enough that the
			// verdict reserve yields to resource safety here.
			_, _ = m.persistStateIfPresent(inst)
		}
		return
	}
	if !inPlace {
		// A tap-busy slot is suspect — tear it down rather than recycle it,
		// so it isn't handed to another create with the same bad tap.
		if tapBusy {
			m.netMgr.TeardownVM(vmID)
		} else {
			m.netMgr.CleanupVM(vmID)
		}
	}
	cleanupRunDir()
}

// stopUnitDuringRestoreError stops a VM when a restore aborts after
// Firecracker started. Uses a fresh context because the caller's gRPC ctx is
// often already cancelled (deadline exceeded under load). Without this, the
// firecracker process leaks. Mode-aware: cgroup mode's kill waits for the
// group to empty by construction (so the slot-recycle-races-tap concern the
// unit path handles with a MainPID SIGKILL is already covered).
func (m *Manager) stopUnitDuringRestoreError(vmID string) {
	supervision := m.supervisionForVM(vmID)
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stopErr := m.stopVM(stopCtx, vmID, supervision)
	if stopErr != nil {
		m.log.Warn().Err(stopErr).Str("vm_id", vmID).Msg("stop failed during restore error cleanup")
	}
	if cgroupSupervised(supervision) {
		// stopVM's cgroup path already sent cgroup.kill (SIGKILL to every
		// process) and waited for the group to empty; a nil error means it
		// is gone. On error the FC is wedged (e.g. uninterruptible I/O) —
		// there is no stronger signal than SIGKILL — so do NOT claim clean:
		// log it, and the slot stays safe because the pool recycles only
		// after verifyAndRecycle confirms the netns empty, with the
		// reconciler reaping the residual cgroup.
		if stopErr != nil {
			m.log.Error().Err(stopErr).Str("vm_id", vmID).
				Msg("cgroup VM not confirmed stopped; slot recycle gated on pool verification")
		}
		return
	}

	// Unit path: slot is recycled right after this returns; if stopUnit timed
	// out the FC may still hold tap0. Resolve the unit's live MainPID
	// (inst.PID is set asynchronously and often still 0 this early), SIGKILL,
	// and wait for exit.
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
	//
	// The date stamp right before the exec splits wait_socket into shell-chain
	// time and Firecracker-side time (see readFCExecStamp). Best-effort: a date
	// without %N or an unwritable dir must never block the launch. Cost: one
	// fork+exec and a one-line page-cache write, ~1ms inside a phase measured
	// in tens of ms — and it lands INSIDE wait_socket, so the split it buys is
	// also what would expose it if it ever grew. No fork-free alternative
	// exists here: POSIX sh has no sub-second clock builtin, and Firecracker's
	// own --start-time-us reporting lands in a metrics sink this fleet does
	// not run.
	inner := fmt.Sprintf("%s%s && { date +%%s%%N >%s 2>/dev/null || true; } && exec %s --api-sock %s --id %s",
		setupCmds, sysfs, shellquote.Single(fcExecStampPath(socketPath)),
		shellquote.Single(fcBin), shellquote.Single(socketPath), shellquote.Single(vmID))
	return fmt.Sprintf("#!/bin/sh\nexec %s unshare -m -- sh -c %s\n", prefix, shellquote.Single(inner))
}

// fcExecStampPath is the per-VM file the launch script writes (wall-clock
// nanoseconds) immediately before exec'ing Firecracker.
func fcExecStampPath(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), "fcexec.ts")
}

// readFCExecStamp returns the launch script's pre-exec timestamp, or false
// when it is missing, unparsable (a shell whose date lacks %N), or outside
// (notBefore, notAfter) — a stale stamp from a prior launch of the same VM
// must not be attributed to this one. Wall clock on both sides: the script's
// date and the phase timestamps compared against it.
func readFCExecStamp(socketPath string, notBefore, notAfter time.Time) (time.Time, bool) {
	data, err := os.ReadFile(fcExecStampPath(socketPath))
	if err != nil {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	ts := time.Unix(0, ns)
	if ts.Before(notBefore) || ts.After(notAfter) {
		return time.Time{}, false
	}
	return ts, true
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
	// Re-check the pin here (shared with the direct path via launchLauncherPath):
	// a pin unmounted since the last revalidation tick would otherwise bake a
	// dead nsenter --mount into start.sh and hard-fail. On failure it falls back
	// to legacy for THIS launch only; launcherReady stays with the sampler, so
	// one blip can't knock the whole fleet onto the O(fleet) legacy path.
	launcherPath := m.launchLauncherPath(vmID)
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
		// A failed unit start (D-Bus round trip or systemctl fallback eating
		// the deadline) can be the slowest part of a launch — sample it.
		m.recordPhases("launch", "unit", map[string]time.Duration{
			"prestart":   tStartUnit.Sub(tPrestart),
			"linger":     time.Duration(lingerCheckMs) * time.Millisecond,
			"start_unit": time.Since(tStartUnit),
		})
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
		// Emit the coarse phases with the exhausted wait: the slowest launch
		// incidents must form the histogram's tail, not vanish from it.
		m.recordPhases("launch", "unit", map[string]time.Duration{
			"prestart":    tStartUnit.Sub(tPrestart),
			"linger":      time.Duration(lingerCheckMs) * time.Millisecond,
			"start_unit":  tStartUnitDone.Sub(tStartUnit),
			"wait_socket": time.Since(tStartUnitDone),
		})
		// Detached budget: the caller's ctx may be at its deadline here, and
		// this stop must run or the just-launched unit leaks.
		_ = stopUnitWithBudget(ctx, systemdUnitName(vmID))
		return 0, fmt.Errorf("wait for socket (unit %s): %w", status, err)
	}
	tSocketReady := time.Now()

	ev := m.log.Info().
		Str("vm_id", vmID).
		Int64("prestart_ms", tStartUnit.Sub(tPrestart).Milliseconds()).
		Int64("linger_check_ms", lingerCheckMs).
		Bool("linger_skipped", freshUnit).
		Int64("start_unit_ms", tStartUnitDone.Sub(tStartUnit).Milliseconds()).
		Int64("wait_socket_ms", tSocketReady.Sub(tStartUnitDone).Milliseconds())
	// On the unit path chain also contains PID 1's dispatch of the unit;
	// fc_socket is Firecracker init plus our detection latency. Emitted to
	// both the log and the phase histogram when the stamp is usable.
	unitPhases := map[string]time.Duration{
		"prestart":    tStartUnit.Sub(tPrestart),
		"linger":      time.Duration(lingerCheckMs) * time.Millisecond,
		"start_unit":  tStartUnitDone.Sub(tStartUnit),
		"wait_socket": tSocketReady.Sub(tStartUnitDone),
	}
	// Window opens at tStartUnit (pre-enqueue): the unit's script can stamp
	// before the no-block start call returns. The split boundary is clamped
	// to tStartUnitDone so both sides use it: chain + fc_socket always
	// equals wait_socket exactly.
	if ts, ok := readFCExecStamp(socketPath, tStartUnit, tSocketReady); ok {
		boundary := ts
		if boundary.Before(tStartUnitDone) {
			boundary = tStartUnitDone
		}
		ev = ev.Int64("chain_ms", boundary.Sub(tStartUnitDone).Milliseconds()).
			Int64("fc_socket_ms", tSocketReady.Sub(boundary).Milliseconds())
		unitPhases["chain"] = boundary.Sub(tStartUnitDone)
		unitPhases["fc_socket"] = tSocketReady.Sub(boundary)
	}
	ev.Msg("fc startup phases")
	m.recordPhases("launch", "unit", unitPhases)

	// Read the PID asynchronously so the create path isn't slowed down
	// by the ~15ms dbus roundtrip. The PID is populated in the instance
	// shortly after create returns and persisted to BoltDB.
	go m.resolveAndSetPID(vmID, m.launchGenFor(vmID))

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

func (m *Manager) resolveAndSetPID(vmID string, gen uint64) {
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

	if !publishResolvedPID(inst, gen, pid) {
		// A newer launch attempt owns this record; publishing here would
		// point every later reader at a stopped unit.
		return
	}

	// The persist must join the vm op critical section: unserialized, its
	// snapshot could commit after the launching op's own writes (e.g. the
	// restore's verified persist) and regress them. The in-memory PID above
	// is set regardless — the launching op's persists carry it, and any
	// later persist repairs a skipped one. IfPresent because destroy
	// bypasses this lock and its record deletion must win.
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return
	}
	defer unlock()
	// Best-effort: a later lifecycle persist carries the PID.
	_, _ = m.persistStateIfPresent(inst)
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

// psiSample caches the three PSI gauges: avg10 moves on a ten-second
// window, so re-reading /proc on every semaphore-held restore buys nothing.
// A burst of restores shares one refresh; a lone restore pays at most three
// small /proc reads every cache period.
type psiSample struct {
	at            time.Time
	cpu, mem, io1 float64
}

var (
	psiCache      atomic.Pointer[psiSample]
	psiRefreshing atomic.Bool
)

func cachedPSI() (cpu, mem, io1 float64) {
	p := psiCache.Load()
	if p != nil && time.Since(p.at) < 2*time.Second {
		return p.cpu, p.mem, p.io1
	}
	// Exactly one caller refreshes; a concurrent burst on an expired cache
	// serves the stale sample instead of stacking /proc reads on the
	// semaphore-held path (avg10 moves on a ten-second window — staleness
	// is immaterial, per-restore syscalls are not).
	if !psiRefreshing.CompareAndSwap(false, true) {
		if p != nil {
			return p.cpu, p.mem, p.io1
		}
		return -1, -1, -1
	}
	defer psiRefreshing.Store(false)
	s := &psiSample{
		at:  time.Now(),
		cpu: psiSomeAvg10("/proc/pressure/cpu"),
		mem: psiSomeAvg10("/proc/pressure/memory"),
		io1: psiSomeAvg10("/proc/pressure/io"),
	}
	psiCache.Store(s)
	return s.cpu, s.mem, s.io1
}

// tailFile returns up to n trailing bytes of the file and its total size.
func tailFile(path string, n int64) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return "", st.Size(), err
	}
	return string(buf), st.Size(), nil
}

// stallJournalSem bounds concurrent journalctl fallbacks: a mass stall of
// unit-supervised restores must not spawn hundreds of five-second processes
// on an already pressured host. Saturated captures are skipped, not queued —
// the first few consoles tell a burst's story, and the journal keeps the
// rest for manual inspection.
var stallJournalSem = make(chan struct{}, 2)

// deferStatePersist converges an instance's durable record OFF the reply
// path — persistence is unbounded fsync work and BoltDB is slow under
// exactly the pressure that puts these paths in play. The in-memory state
// must already be correct before calling (that is what concurrent readers
// and same-ID retries see). The worker carries the standard protections:
// the lifecycle lock serializes it against retries, a replacement's record
// is repaired rather than clobbered by the stale instance, and the
// lock-bypassing destroy is compensated after the write.
func (m *Manager) deferStatePersist(scope, vmID string, inst *VMInstance, ifPresent bool) {
	go func() {
		defer sentrylog.Recover(scope)
		unlock, lockErr := m.lockVMOp(context.Background(), vmID)
		if lockErr != nil {
			return
		}
		defer unlock()
		m.mu.RLock()
		cur, tracked := m.vms[vmID]
		m.mu.RUnlock()
		if !tracked {
			return // the destroy owns teardown; nothing to write
		}
		if cur != inst {
			m.persistState(cur)
		} else if ifPresent {
			_, _ = m.persistStateIfPresent(inst)
		} else {
			m.persistState(inst)
		}
		m.mu.RLock()
		_, still := m.vms[vmID]
		m.mu.RUnlock()
		if !still {
			m.deleteState(vmID)
		}
	}()
}

// bootVerdictReserve is the deadline slice reserved for a boot's WORST-CASE
// error path so the definitive verdict still returns in-band: the 10s
// bounded unit stop, the 2s surviving-unit resolve, and a reply margin.
// Shared by the restore readiness clamp and the resume readiness clamp —
// both gates tear down on timeout before replying.
const bootVerdictReserve = 13 * time.Second

// stallForensicsDirName holds quarantined consoles from readiness-timeout
// teardowns, inside RunDir (dot-prefixed so it can never collide with a VM
// id). Files are root-only: guest serial is tenant-controlled data and must
// not reach service logs or wider-readable paths.
const stallForensicsDirName = ".stall-forensics"

// stallForensicsKeep caps the quarantine so a stall storm cannot grow it
// unbounded; oldest are dropped first (names sort by capture time).
const stallForensicsKeep = 20

// summarizeConsoleTail classifies console lines without exposing content:
// Firecracker's own lines (timestamp + [vmid:fc_*] prefix), boxd's lines,
// and anything else — which can only be guest output. That split answers
// the diagnostic question by itself: zero guest/boxd lines means the guest
// stalled before its first output (the resume/page-fault window), while
// boxd lines mean it reached userspace.
func summarizeConsoleTail(tail string) (fcLines, boxdLines, guestLines int, panicked bool) {
	for _, line := range strings.Split(tail, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "[boxd]"):
			boxdLines++
		case strings.Contains(line, ":fc_") && strings.HasPrefix(line, "20"):
			fcLines++
		default:
			guestLines++
		}
	}
	panicked = strings.Contains(tail, "Kernel panic")
	return
}

// captureStallForensics records a content-free summary of a VM's console
// after the guest failed to become ready, and quarantines the raw file
// (root-only, capped) for operator inspection — the failure teardown would
// otherwise delete the only evidence. An empty console is itself the
// strongest signal: the guest stalled before its first line.
//
// Two things run synchronously because the teardown destroys their subject:
// the console rename (the rundir is deleted) and the procfs read of the
// Firecracker process (the process is killed). Both are in-memory operations
// — a rename and a handful of procfs reads, no disk I/O — so the in-band
// verdict margin is preserved. Formatting, logging, quarantine writes, and
// the journald fallback all run detached.
func (m *Manager) captureStallForensics(vmID string, pid int, waited time.Duration, launchedAt time.Time) {
	failedAt := time.Now()

	src := filepath.Join(m.cfg.RunDir, vmID, "console.log")
	// The ONLY work that must beat the teardown's rundir delete is moving
	// the file out (direct-spawn mode; unit mode has no file, and its
	// journal survives on its own). Everything else — read, summary,
	// chmod, pruning, the journald fallback — runs detached, so the
	// verdict reserve is never spent on forensics.
	dir := filepath.Join(m.cfg.RunDir, stallForensicsDirName)
	dst := filepath.Join(dir, fmt.Sprintf("%d-%s.console.log", failedAt.Unix(), vmID))
	renamed := m.forensicsOK && os.Rename(src, dst) == nil // dir pre-created and secured at startup
	// Proc capture runs AFTER the rename: both are best-effort and race a
	// concurrent DestroyVM (which bypasses the lifecycle lock and deletes the
	// rundir), but the rename is microseconds while the capture may spend its
	// whole budget — doing the cheap one first keeps a slow capture from
	// costing us the console too.
	var proc *procStallState
	if pid > 0 {
		proc = captureProcState(pid, vmID)
	}
	go func() {
		defer sentrylog.Recover("stall-forensics")
		// One prune covering every exit path: a stall can add a console file,
		// a procstate file, or both, and the paths that produce no console
		// (unit supervision, a console already gone) must not grow the
		// quarantine without bound.
		if m.forensicsOK {
			defer pruneOldest(dir, stallForensicsKeep)
		}
		if proc != nil {
			m.logStallProcState(vmID, waited, proc, dir, failedAt)
		}
		if renamed {
			_ = os.Chmod(dst, 0o600)
			tail, size, err := tailFile(dst, 4096)
			if err != nil {
				m.log.Warn().Str("vm_id", vmID).Err(err).
					Msg("guest not ready — quarantined console unreadable")
			} else {
				m.logStallSummary(vmID, waited, tail, size, dst)
			}
			return
		}
		select {
		case stallJournalSem <- struct{}{}:
			defer func() { <-stallJournalSem }()
		default:
			m.log.Warn().Str("vm_id", vmID).
				Msg("guest not ready — journal forensics skipped (concurrent captures saturated)")
			return
		}
		jctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// --since/--until bound the sample to THIS launch: -u alone would
		// mix in a prior invocation of the same unit name, and this
		// detached read can also outlive the teardown into a same-ID
		// retry whose newer lines -n would otherwise select. Microsecond
		// stamps, since whole-second flooring could drop the failure
		// second's own tail.
		unit := systemdUnitName(vmID)
		args := []string{"-u", unit,
			"--since", journalStamp(launchedAt),
			"--until", journalStamp(failedAt),
			"-n", "60", "--no-pager", "-o", "cat"}
		// Best-effort invocation pinning on top of the time bounds: the
		// window can straddle a unit REPLACEMENT (a lingering same-ID unit
		// restarted into this launch), whose tail time alone would admit.
		// The lookup races both the teardown (unit unloaded → empty id)
		// and a same-ID retry (id belongs to the NEW launch, whose entries
		// the --until bound excludes → empty result). Both races degrade
		// to the time-bounded query below instead of losing the summary.
		pinned := false
		if idOut, idErr := exec.CommandContext(jctx, "systemctl", "show", "-p", "InvocationID", "--value", unit).Output(); idErr == nil {
			if id := strings.TrimSpace(string(idOut)); id != "" {
				args = append(args, "_SYSTEMD_INVOCATION_ID="+id)
				pinned = true
			}
		}
		out, jErr := exec.CommandContext(jctx, "journalctl", args...).Output()
		if pinned && jErr == nil && len(out) == 0 {
			out, jErr = exec.CommandContext(jctx, "journalctl", args[:len(args)-1]...).Output()
		}
		if jErr != nil || len(out) == 0 {
			m.log.Warn().Str("vm_id", vmID).AnErr("journal_err", jErr).
				Msg("guest not ready — console unavailable for forensics")
			return
		}
		m.logStallSummary(vmID, waited, string(out), int64(len(out)), "journald")
	}()
}

func (m *Manager) logStallSummary(vmID string, waited time.Duration, tail string, size int64, preserved string) {
	fcLines, boxdLines, guestLines, panicked := summarizeConsoleTail(tail)
	m.log.Warn().Str("vm_id", vmID).
		Int64("wait_boxd_ms", waited.Milliseconds()).
		Int64("console_bytes", size).
		Int("console_fc_lines", fcLines).
		Int("console_boxd_lines", boxdLines).
		Int("console_guest_lines", guestLines).
		Bool("console_panic", panicked).
		Str("console_preserved", preserved).
		Msg("guest not ready within the readiness window — tearing down")
}

// journalStamp renders a journalctl @-timestamp with microsecond precision.
func journalStamp(t time.Time) string {
	return fmt.Sprintf("@%d.%06d", t.Unix(), t.Nanosecond()/1000)
}

// pruneOldest keeps at most keep entries in dir, dropping the oldest by
// name (names begin with the capture unix time).
func pruneOldest(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) <= keep {
		return
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-keep] {
		_ = os.Remove(filepath.Join(dir, n))
	}
}

// boxdHealthProbe is the /health poll behind waitForBoxd; a var so tests can
// drive the readiness gate without a live guest.
var boxdHealthProbe = waitForHTTPHealth

func (m *Manager) waitForBoxd(ctx context.Context, vmIP string, timeout time.Duration) error {
	return boxdHealthProbe(ctx, vmIP, timeout)
}

// boxdResumeReadyBudget bounds the post-resume readiness gate. Sized well
// above the multi-second cold-memory stall tail (serving even /health can
// block on lazily-faulted pages after a UFFD resume), with margin because
// that stall's root cause is still open and can worsen under host disk
// pressure. Spent in full only when boxd is genuinely unreachable — a wedged
// guest — so the generous bound costs nothing on the happy path but keeps a
// slow-but-healthy resume from being torn down.
const boxdResumeReadyBudget = 30 * time.Second

// resumeReadyOrAbort confirms boxd answered after a resume, else tears the
// resume down. The probe runs on a budget DETACHED from the caller's ctx: a
// client disconnect or a spent deadline must never read as a dead guest, or
// the abort would stop a healthy VM the control plane's retry would have
// adopted (the self-heal path). Only a genuinely unreachable agent — silent
// for the whole budget — trips the abort, which reverts to the original pause
// snapshot so the retry does a clean fresh restore. Caller holds the VM's
// lifecycle lock (abort mutates the record).
func (m *Manager) resumeReadyOrAbort(callerCtx context.Context, vmID, ip string) error {
	// Detached from caller CANCELLATION on purpose (a disconnect must not
	// abort a healthy resume mid-probe) — but clamped to the caller's
	// DEADLINE like the restore gate: the abort below is bounded teardown
	// plus persistence, and the definitive verdict must return in-band
	// rather than losing the race to the client deadline and triggering a
	// transient retry against the still-held lifecycle lock.
	budget := boxdResumeReadyBudget
	if dl, ok := callerCtx.Deadline(); ok {
		if remaining := time.Until(dl) - bootVerdictReserve; remaining < budget {
			budget = remaining
		}
	}
	if err := m.waitForBoxd(context.WithoutCancel(callerCtx), ip, budget); err != nil {
		m.abortResumeLocked(vmID)
		return err
	}
	// /health answered — but on an IP, not a VM identity, and a recycle can
	// hand ip to a stranger mid-probe (see vmOwnsIP; likeliest while a
	// cold-fault resume is slow to answer). Re-check ownership before
	// reporting ready. Ownership loss means destroyed, so abort no-ops.
	if !m.vmOwnsIP(vmID, ip) {
		m.abortResumeLocked(vmID)
		return fmt.Errorf("vm %s no longer owns %s after readiness (destroyed mid-resume?)", vmID, ip)
	}
	return nil
}

// retriedLaunchTarget returns the tracked instance for vmID when a resume or
// restore request is a retry of one that already completed: Running with the
// SAME artifacts (a different snapshot must replace the VM as before). The
// second result is true when the record is unverified (see VMRecord).
//
// Called while holding vmID's lifecycle lock, so Status is trustworthy: no
// concurrent op is mid-flight, and a Running instance is a finished prior
// attempt. Hence no boxd probe — it couldn't tell a slow-booting boxd (30s
// warmup) from a dead one, and a false negative relaunches over the live
// VM, rolling the guest back. DestroyVM bypasses the lock, so the recheck
// drops an instance a concurrent destroy removed.
//
// A reset-to-snapshot flow (none today) must not reuse these RPCs as-is.
// vmDeadForRetry reports a VM as definitively not running, dispatching on
// supervision mode; swappable in tests. Inconclusive answers read as alive
// (never relaunch on doubt). The Manager receiver is captured so the cgroup
// oracle can reach the delegated subtree.
var vmDeadForRetry = func(m *Manager, vmID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return m.vmDefinitelyDead(ctx, vmID, m.supervisionForVM(vmID))
}

// vmUnitFullyDown reports a VM's unit in a TERMINAL state (unitFullyDown);
// swappable in tests. Sites that release a record and its namespace need
// this claim, not vmDeadForRetry — deactivating reads dead there while the
// process may still be exiting.
var vmUnitFullyDown = func(vmID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return unitFullyDown(ctx, systemdUnitName(vmID))
}

// adoptionBoxdReady is the boxd readiness gate for restore adoption and the
// unverified relaunch (via verifyBoxdReady); a var for the same test seam
// vmDeadForRetry uses.
var adoptionBoxdReady = func(ctx context.Context, m *Manager, ip string) error {
	return m.waitForBoxd(ctx, ip, 30*time.Second)
}

// verifyBoxdReady runs the crash-window readiness gate on a budget DETACHED
// from the caller's ctx. Every gate outcome is destructive or durable — tear
// the VM down, flip it out of Running, clear the marker — so a caller
// disconnect or spent deadline must never masquerade as a dead guest.
//
// Detaching is also what makes a verdict reachable at all: callers arrive with
// a deadline no larger than this gate's own budget and have already spent part
// of it, so an inherited ctx always expires first and every attempt would end
// "no verdict", leaving the record unchanged for the next attempt to repeat.
// The wall-clock bound inside waitForBoxd still caps the wait.
func (m *Manager) verifyBoxdReady(callerCtx context.Context, ip string) error {
	return adoptionBoxdReady(context.WithoutCancel(callerCtx), m, ip)
}

// commitResumeState persists a resumed instance and verifies the VM was not
// destroyed mid-flight. Persist-then-verify, as the restore path does:
// DestroyVM bypasses the lifecycle lock, so it can land while a resume runs —
// most likely during the unverified readiness wait, which spends a full budget
// detached from the caller. Checking AFTER the write leaves no window: the
// destroy either erased the record itself or is caught here, and we erase our
// own resurrecting write rather than hand back a destroyed VM.
func (m *Manager) commitResumeState(inst *VMInstance) error {
	// A successful relaunch retires any parked-teardown marker: the process
	// below this record is now the live one it manages.
	inst.mu.Lock()
	inst.TeardownPending = ""
	inst.mu.Unlock()
	wrote := m.persistState(inst)
	m.mu.RLock()
	_, stillTracked := m.vms[inst.ID]
	m.mu.RUnlock()
	// The map entry outlives most of DestroyVM — it stops the unit and frees
	// the slot first — so tracked-ness alone would report success for a VM
	// already being torn down. The tombstone covers the whole teardown.
	_, destroying := m.destroying.Load(inst.ID)
	if stillTracked && !destroying {
		if !wrote {
			// Undurable Running must fail the resume (restore's discipline):
			// the durable record still reads its pre-resume state, and after
			// a vmd restart the error rules would trust it and stop this
			// healthy unit. The guest resumed moments ago, so the teardown
			// discards nothing; the retry relaunches with a fresh persist.
			// In-memory Error keeps a same-artifact retry from adopting the
			// unit this teardown is stopping.
			m.stopUnitDuringRestoreError(inst.ID)
			inst.mu.Lock()
			inst.Status = StatusError
			inst.DirtyTracked = false // unit stopped; a relaunch re-arms tracking
			inst.mu.Unlock()
			return fmt.Errorf("vm %s resumed but its state could not be persisted", inst.ID)
		}
		return nil
	}
	m.deleteState(inst.ID)
	// The relaunch may have started a Firecracker after the destroy's
	// teardown ran; stop it or it outlives the sandbox.
	m.stopUnitDuringRestoreError(inst.ID)
	return status.Errorf(codes.NotFound, "vm %s was destroyed during resume", inst.ID)
}

// commitVerifiedAdoption makes a just-verified crash-window adoption durable:
// re-check identity after the wait stretched the window, clear the marker,
// and persist — treating BOTH destroy signals (instance swapped out, store
// refusing the write) as NotFound, so a destroy racing the verification can
// never be reported as a successful adoption. Shared by restore and resume
// adoption so the two paths cannot drift.
func (m *Manager) commitVerifiedAdoption(existing *VMInstance) error {
	m.mu.RLock()
	still := m.vms[existing.ID] == existing
	m.mu.RUnlock()
	if !still {
		return status.Errorf(codes.NotFound, "vm %s was destroyed during restore", existing.ID)
	}
	existing.mu.Lock()
	existing.Unverified = false
	existing.mu.Unlock()
	// Only a deletion aborts the adoption; an undurable clear is healed by
	// the next adoption's re-verify.
	if wrote, perr := m.persistStateIfPresent(existing); perr == nil && !wrote {
		return status.Errorf(codes.NotFound, "vm %s was destroyed during restore", existing.ID)
	}
	return nil
}

func (m *Manager) retriedLaunchTarget(vmID, snapshotPath, memPath string) (*VMInstance, bool) {
	m.mu.RLock()
	existing := m.vms[vmID]
	m.mu.RUnlock()
	if existing == nil {
		return nil, false
	}
	existing.mu.RLock()
	running := existing.Status == StatusRunning
	unverified := existing.Unverified
	sameArtifacts := existing.SnapshotPath == snapshotPath && existing.MemFilePath == memPath
	existing.mu.RUnlock()
	if !running || !sameArtifacts {
		return nil, false
	}
	// Process-level liveness, not boxd readiness: a record can read Running
	// while the firecracker died (crash while vmd was down, then a
	// cleanupStale=false reattach loads it). A slow-booting VM's unit is
	// still active, so this catches a corpse without false-negativing a
	// warming one — the trap the removed boxd probe fell into. Inconclusive
	// (systemctl slow) reads as alive: never relaunch on doubt.
	if vmDeadForRetry(m, vmID) {
		return nil, false
	}
	m.mu.RLock()
	still := m.vms[vmID] == existing
	m.mu.RUnlock()
	if !still {
		return nil, false
	}
	// needsVerify: a reattached crash-window record never proved boxd
	// readiness. Both adoptions verify such a target with the bounded gate
	// before adopting; only verified targets adopt blind.
	return existing, unverified
}
