package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	fcclient "github.com/superserve-ai/sandbox/internal/vm/fc/client"
	"github.com/superserve-ai/sandbox/internal/vm/fc/client/operations"
	"github.com/superserve-ai/sandbox/internal/vm/fc/models"
)

// ErrTornSnapshot is the firecracker fork's 0-byte side-car sentinel —
// retry won't help, the snapshot must be retaken from a healthy source.
var ErrTornSnapshot = errors.New("torn snapshot (overlay side-car empty)")

// tornSnapshotMarker is the exact substring the forked Firecracker embeds in
// its error when it detects a 0-byte side-car on snapshot load. Kept as a
// named constant so a fork message change breaks the build here, not silently
// at runtime.
const tornSnapshotMarker = "(torn snapshot save)"

func isTornSnapshotErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), tornSnapshotMarker)
}

// ---------------------------------------------------------------------------
// Firecracker config (our internal type, not a Firecracker API type)
// ---------------------------------------------------------------------------

// FirecrackerConfig holds the inputs needed to configure a Firecracker VM.
type FirecrackerConfig struct {
	SocketPath string
	KernelPath string
	KernelArgs string
	RootfsPath string
	// Non-empty BasePath triggers overlay mode: RootfsPath becomes a
	// sparse per-VM overlay backed by this shared read-only base.
	BasePath   string
	VCPUCount  int
	MemSizeMiB int
	TAPDevice  string
	MACAddress string
	VMID       string
	VsockPath  string
	VMIP       string
	GatewayIP  string
	// StateDiskPath, when non-empty, is the host path to the Actor's durable
	// /state block device (a pre-formatted ext4 image). It is attached as the
	// VM's second drive (vdb); boxd mounts it at /state on boot. Empty for
	// ephemeral sandboxes with no durable state.
	StateDiskPath string
}

// ---------------------------------------------------------------------------
// SDK client helper
// ---------------------------------------------------------------------------

// newFCClient creates a Firecracker API client that talks over the given Unix socket.
func newFCClient(socketPath string) *fcclient.Firecracker {
	transport := httptransport.New(fcclient.DefaultHost, fcclient.DefaultBasePath, fcclient.DefaultSchemes)
	transport.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			addr, err := net.ResolveUnixAddr("unix", socketPath)
			if err != nil {
				return nil, err
			}
			return net.DialUnix("unix", nil, addr)
		},
	}
	c := fcclient.NewHTTPClient(strfmt.NewFormats())
	c.SetTransport(transport)
	return c
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

// vmHostname returns a short hostname for a VM.
func vmHostname(vmID string) string {
	if rest, ok := strings.CutPrefix(vmID, "build-"); ok {
		return "build-" + shortID(rest)
	}
	return "sandbox-" + shortID(vmID)
}

func shortID(s string) string {
	if len(s) >= 8 {
		return s[:8]
	}
	return s
}

// ---------------------------------------------------------------------------
// configureMachine configures the Firecracker instance via its HTTP API.
// ---------------------------------------------------------------------------

func ConfigureMachine(socketPath string, cfg FirecrackerConfig) error {
	fc := newFCClient(socketPath)
	ctx := context.Background()

	bootArgs := cfg.KernelArgs
	if bootArgs == "" {
		bootArgs = "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0 random.trust_cpu=on"
	}
	if cfg.VMIP != "" && cfg.GatewayIP != "" {
		bootArgs += fmt.Sprintf(" ip=%s::%s:255.255.255.0::eth0:off", cfg.VMIP, cfg.GatewayIP)
	}

	// 1. Set boot source.
	if _, err := fc.Operations.PutGuestBootSource(&operations.PutGuestBootSourceParams{
		Context: ctx,
		Body: &models.BootSource{
			KernelImagePath: &cfg.KernelPath,
			BootArgs:        bootArgs,
		},
	}); err != nil {
		return fmt.Errorf("set boot source: %w", err)
	}

	// 2. Set machine configuration.
	if _, err := fc.Operations.PutMachineConfiguration(&operations.PutMachineConfigurationParams{
		Context: ctx,
		Body: &models.MachineConfiguration{
			VcpuCount:  int64Ptr(int64(cfg.VCPUCount)),
			MemSizeMib: int64Ptr(int64(cfg.MemSizeMiB)),
			Smt:        boolPtr(false),
		},
	}); err != nil {
		return fmt.Errorf("set machine config: %w", err)
	}

	// 3. Attach rootfs drive.
	driveID := "rootfs"
	drive := &models.Drive{
		DriveID:      &driveID,
		PathOnHost:   cfg.RootfsPath,
		IsRootDevice: boolPtr(true),
		IsReadOnly:   false,
	}
	if cfg.BasePath != "" {
		drive.IoEngine = strPtr("Overlay")
		drive.BasePath = cfg.BasePath
	}
	if _, err := fc.Operations.PutGuestDriveByID(&operations.PutGuestDriveByIDParams{
		Context: ctx,
		DriveID: driveID,
		Body:    drive,
	}); err != nil {
		// Name the missing fork instead of leaking firecracker's opaque io_engine error.
		if cfg.BasePath != "" && strings.Contains(err.Error(), "io_engine") {
			return fmt.Errorf("attach drive rootfs: overlay-mode requires the firecracker fork (feat/block-overlay-cow-v1.15) on this host: %w", err)
		}
		return fmt.Errorf("attach drive rootfs: %w", err)
	}

	// 3b. Attach the durable /state disk as the second drive (vdb), if this VM
	// has durable state. boxd mounts it at /state on boot. Non-root, read-write.
	if cfg.StateDiskPath != "" {
		stateID := "state"
		if _, err := fc.Operations.PutGuestDriveByID(&operations.PutGuestDriveByIDParams{
			Context: ctx,
			DriveID: stateID,
			Body: &models.Drive{
				DriveID:      &stateID,
				PathOnHost:   cfg.StateDiskPath,
				IsRootDevice: boolPtr(false),
				IsReadOnly:   false,
			},
		}); err != nil {
			return fmt.Errorf("attach drive state: %w", err)
		}
	}

	// 4. Attach network interface.
	if cfg.TAPDevice != "" {
		ifaceID := "eth0"
		if _, err := fc.Operations.PutGuestNetworkInterfaceByID(&operations.PutGuestNetworkInterfaceByIDParams{
			Context: ctx,
			IfaceID: ifaceID,
			Body: &models.NetworkInterface{
				IfaceID:     &ifaceID,
				GuestMac:    cfg.MACAddress,
				HostDevName: &cfg.TAPDevice,
			},
		}); err != nil {
			return fmt.Errorf("attach network interface eth0: %w", err)
		}
	}

	// 5. Enable entropy device with rate limiter — Firecracker VMs have
	// near-zero entropy after snapshot restore which breaks TLS handshakes.
	// The entropy device provides virtio-rng backed by the host's /dev/urandom.
	// Rate limiter: 1KB every 100ms = continuous entropy feed.
	// See: https://github.com/firecracker-microvm/firecracker/blob/main/docs/entropy.md
	if _, err := fc.Operations.PutEntropyDevice(&operations.PutEntropyDeviceParams{
		Context: ctx,
		Body: &models.EntropyDevice{
			RateLimiter: &models.RateLimiter{
				Bandwidth: &models.TokenBucket{
					OneTimeBurst: int64Ptr(0),
					Size:         int64Ptr(1024),
					RefillTime:   int64Ptr(100),
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("configure entropy device: %w", err)
	}

	// 6. Configure vsock device.
	if cfg.VsockPath != "" {
		if _, err := fc.Operations.PutGuestVsock(&operations.PutGuestVsockParams{
			Context: ctx,
			Body: &models.Vsock{
				GuestCid: int64Ptr(3),
				UdsPath:  &cfg.VsockPath,
			},
		}); err != nil {
			return fmt.Errorf("configure vsock: %w", err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// startInstance tells Firecracker to boot the VM.
// ---------------------------------------------------------------------------

func StartInstance(socketPath string) error {
	fc := newFCClient(socketPath)
	actionType := models.InstanceActionInfoActionTypeInstanceStart
	if _, err := fc.Operations.CreateSyncAction(&operations.CreateSyncActionParams{
		Context: context.Background(),
		Info: &models.InstanceActionInfo{
			ActionType: &actionType,
		},
	}); err != nil {
		return fmt.Errorf("start instance: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Snapshot operations
// ---------------------------------------------------------------------------

// SnapshotMode controls per-disk flatten behavior at snapshot creation.
type SnapshotMode int

const (
	// SnapshotNormal: leave overlay deltas as-is. Sandboxes restored from
	// this snapshot replay the delta into a per-VM overlay on create.
	SnapshotNormal SnapshotMode = iota
	// SnapshotFlatten: bake each overlay's dirty blocks into base.ext4 and
	// zero the side-car bitmap. Sandboxes restored from this snapshot skip
	// apply_delta. Only safe when the base isn't shared with other live VMs.
	SnapshotFlatten
)

// CreateSnapshot pauses the VM and creates a full snapshot. Non-empty
// blockDeltaDir tells the forked engine to also emit <drive_id>.delta files
// containing dirty blocks — required to create sandboxes from this template.
// mode=SnapshotFlatten bakes those deltas into base.ext4 (see SnapshotMode).
func CreateSnapshot(socketPath, snapshotPath, memPath, blockDeltaDir string, mode SnapshotMode) error {
	if mode == SnapshotFlatten && blockDeltaDir == "" {
		return fmt.Errorf("SnapshotFlatten requires non-empty blockDeltaDir")
	}
	fc := newFCClient(socketPath)
	ctx := context.Background()

	// Pause the VM.
	if _, err := fc.Operations.PatchVM(&operations.PatchVMParams{
		Context: ctx,
		Body:    &models.VM{State: strPtr(models.VMStatePaused)},
	}); err != nil {
		return fmt.Errorf("pause VM: %w", err)
	}

	// Create the snapshot.
	if _, err := fc.Operations.CreateSnapshot(&operations.CreateSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotCreateParams{
			SnapshotPath:  &snapshotPath,
			MemFilePath:   &memPath,
			SnapshotType:  models.SnapshotCreateParamsSnapshotTypeFull,
			BlockDeltaDir: blockDeltaDir,
			Flatten:       mode == SnapshotFlatten,
		},
	}); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	return nil
}

// PauseVM freezes a running VM's vCPUs (PATCH /vm Paused) without taking a
// snapshot or stopping the process. This is the bare Tier-1 pause: memory stays
// resident, so a later UnpauseVM resume faults in zero pages (sub-ms wake,
// latency-validated). Contrast CreateSnapshot, which pauses *and* writes a Full
// snapshot for Tier-2.
func PauseVM(socketPath string) error {
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.PatchVM(&operations.PatchVMParams{
		Context: context.Background(),
		Body:    &models.VM{State: strPtr(models.VMStatePaused)},
	}); err != nil {
		return fmt.Errorf("pause VM: %w", err)
	}
	return nil
}

// UnpauseVM resumes a paused VM's vCPUs. Used after CreateSnapshot to make
// snapshot creation non-destructive, and as the Tier-1 wake for a bare-paused VM.
func UnpauseVM(socketPath string) error {
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.PatchVM(&operations.PatchVMParams{
		Context: context.Background(),
		Body:    &models.VM{State: strPtr(models.VMStateResumed)},
	}); err != nil {
		return fmt.Errorf("unpause VM: %w", err)
	}
	return nil
}

// RestoreSnapshot loads a snapshot and resumes the VM. Non-empty blockDeltaDir
// hydrates a fresh per-VM overlay from <dir>/<drive_id>.delta — pass empty
// for in-place resume (existing overlay already carries state).
func RestoreSnapshot(socketPath, snapshotPath, memPath, blockDeltaDir string) error {
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: context.Background(),
		Body: &models.SnapshotLoadParams{
			SnapshotPath: &snapshotPath,
			MemBackend: &models.MemoryBackend{
				BackendType: strPtr(models.MemoryBackendBackendTypeFile),
				BackendPath: &memPath,
			},
			ResumeVM:         true,
			NetworkOverrides: []*models.NetworkOverride{}, // Empty, not nil — Firecracker rejects null.
			BlockDeltaDir:    blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot: %w: %v", ErrTornSnapshot, err)
		}
		return fmt.Errorf("load snapshot: %w", err)
	}
	return nil
}

// RestoreSnapshotWithOverrides loads a snapshot, overrides the network TAP
// device, and resumes the VM. See RestoreSnapshot for blockDeltaDir semantics.
func RestoreSnapshotWithOverrides(socketPath, snapshotPath, memPath, ifaceID, tapDevice, blockDeltaDir string) error {
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: context.Background(),
		Body: &models.SnapshotLoadParams{
			SnapshotPath: &snapshotPath,
			MemBackend: &models.MemoryBackend{
				BackendType: strPtr(models.MemoryBackendBackendTypeFile),
				BackendPath: &memPath,
			},
			ResumeVM: true,
			NetworkOverrides: []*models.NetworkOverride{
				{IfaceID: &ifaceID, HostDevName: &tapDevice},
			},
			BlockDeltaDir: blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot: %w: %v", ErrTornSnapshot, err)
		}
		return fmt.Errorf("load snapshot: %w", err)
	}
	return nil
}

// RestoreSnapshotWithStateRepoint restores a snapshot that carries a /state
// PLACEHOLDER drive and re-points that drive to this Actor's per-identity /state
// image before the guest runs — the production durable-/state-on-restore path.
//
// The sequence is hardware-validated (see internal/state/STATE-MOUNT-FINDINGS.md):
// load the snapshot PAUSED (resume_vm=false), PatchGuestDriveByID swaps the
// /state drive's backing file, then resume. The template snapshot must capture
// /state UNMOUNTED (boxd defers the mount to post-restore) so the swap is safe.
// stateDriveID is the drive id the template baked (e.g. "state"); ifaceID/
// tapDevice override the network like RestoreSnapshotWithOverrides.
func RestoreSnapshotWithStateRepoint(socketPath, snapshotPath, memPath, ifaceID, tapDevice, blockDeltaDir, stateDriveID, stateDiskPath string) error {
	if stateDriveID == "" || stateDiskPath == "" {
		return fmt.Errorf("repoint restore requires stateDriveID and stateDiskPath")
	}
	fc := newFCClient(socketPath)
	ctx := context.Background()

	var netOverrides []*models.NetworkOverride
	if ifaceID != "" {
		netOverrides = []*models.NetworkOverride{{IfaceID: &ifaceID, HostDevName: &tapDevice}}
	} else {
		netOverrides = []*models.NetworkOverride{} // FC rejects null
	}

	// 1. Load PAUSED so drives can be re-pointed before the guest resumes.
	if _, err := fc.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotLoadParams{
			SnapshotPath:     &snapshotPath,
			MemBackend:       &models.MemoryBackend{BackendType: strPtr(models.MemoryBackendBackendTypeFile), BackendPath: &memPath},
			ResumeVM:         false,
			NetworkOverrides: netOverrides,
			BlockDeltaDir:    blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot: %w: %v", ErrTornSnapshot, err)
		}
		return fmt.Errorf("load snapshot: %w", err)
	}

	// 2. Re-point the /state drive to this Actor's per-identity image.
	if _, err := fc.Operations.PatchGuestDriveByID(&operations.PatchGuestDriveByIDParams{
		Context: ctx,
		DriveID: stateDriveID,
		Body:    &models.PartialDrive{DriveID: &stateDriveID, PathOnHost: stateDiskPath},
	}); err != nil {
		return fmt.Errorf("repoint /state drive %q to %q: %w", stateDriveID, stateDiskPath, err)
	}

	// 3. Resume.
	if _, err := fc.Operations.PatchVM(&operations.PatchVMParams{
		Context: ctx,
		Body:    &models.VM{State: strPtr(models.VMStateResumed)},
	}); err != nil {
		return fmt.Errorf("resume after /state repoint: %w", err)
	}
	return nil
}

// RestoreSnapshotUffdInternalWithOverrides loads a snapshot using Firecracker's
// in-process UFFD handler. Pages are demand-loaded from `memPath` by a handler
// thread inside the Firecracker process whose lifetime equals the VM's, so vmd
// restarts cannot leave the kernel waiting on a dead handler.
//
// `accessLogPath` (optional) is a recorded page-access trace replayed as
// prefetch; `recordToPath` (optional) is where the handler writes each served
// page offset (template-build mode). When recordToPath is set, prefetch is
// suppressed on the Firecracker side regardless of accessLogPath.
func RestoreSnapshotUffdInternalWithOverrides(
	socketPath, snapshotPath, memPath, accessLogPath, recordToPath, ifaceID, tapDevice, blockDeltaDir string,
) error {
	// Bound LoadSnapshot so a hung Firecracker doesn't wedge vmd.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotLoadParams{
			SnapshotPath: &snapshotPath,
			MemBackend: &models.MemoryBackend{
				BackendType:   strPtr(models.MemoryBackendBackendTypeUffdInternal),
				BackendPath:   &memPath,
				AccessLogPath: accessLogPath,
				RecordTo:      recordToPath,
			},
			ResumeVM: true,
			NetworkOverrides: []*models.NetworkOverride{
				{IfaceID: &ifaceID, HostDevName: &tapDevice},
			},
			BlockDeltaDir: blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot (uffd-internal): %w: %v", ErrTornSnapshot, err)
		}
		return fmt.Errorf("load snapshot (uffd-internal): %w", err)
	}
	return nil
}
