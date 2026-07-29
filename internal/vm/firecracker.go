package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// ErrLayeredInvalidSnapshot is the firecracker fork's sentinel for a structurally
// invalid layered restore (overlay/base size mismatch, huge-page overlay, block
// size > page size, missing base). It is permanent — retrying or falling back to a
// standalone load of the overlay won't help (the latter would read base pages as
// zero holes), so the caller must use a Full/previous snapshot instead.
var ErrLayeredInvalidSnapshot = errors.New("layered restore overlay/base pairing is invalid")

// layeredInvalidMarker is the exact substring the forked Firecracker embeds in its
// error for an invalid layered restore (the GuestMemoryFromUffdError::LayeredInvalid
// display text). Named so a fork message change is updated here, not missed at runtime.
const layeredInvalidMarker = "overlay/base pairing is invalid"

func isLayeredInvalidErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), layeredInvalidMarker)
}

// Firecracker's tap-attach failure when a previous owner still holds the
// device (TUNSETIFF EBUSY). Both substrings must match: the tap-open prefix
// alone wraps every tap errno (EPERM, ENODEV, ...), which retrying on a
// different slot can't fix. Lower-case; matching is case-insensitive so a
// casing drift in the message can't silently disable the retry. Named so a
// fork message change is updated here, not missed at runtime.
const (
	tapOpenMarker = "open tap device failed"
	tapBusyMarker = "resource busy"
)

// isTapDeviceBusyErr reports whether err is the still-held-tap attach failure —
// the one restore error worth retrying on a different network slot.
func isTapDeviceBusyErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, tapOpenMarker) && strings.Contains(s, tapBusyMarker)
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

// CreateDiffSnapshot pauses the VM and writes a Diff snapshot: only the pages
// dirtied since load, written at their offsets into memPath. Requires the VM to
// have been loaded with dirty tracking on. Whether memPath ends up a complete
// image or a sparse overlay is the caller's choice, set by what memPath holds
// going in:
//   - in-place merge: memPath already holds the base image (same size), so the
//     dirty pages overwrite it and it stays a complete, standalone image.
//   - layered overlay: memPath is fresh/sparse, so it ends up holding only the
//     changed pages — restored over a separate base, never loaded standalone.
//
// VMState reports which state the Firecracker process on socketPath holds
// its microVM in ("Not started", "Running", "Paused"). A healthy API
// answering "Not started" is the signature of an empty shell — a live
// process with no microVM inside — which unit-level liveness cannot
// distinguish from a running VM.
//
// Deliberately a bare HTTP GET rather than the generated client: probes run
// per-VM on every reconciler pass, so the dial must honor ctx (a socket
// with a saturated accept queue would otherwise hang the pass forever) and
// the connection must not linger (a kept-alive FD per probed VM per pass
// would exhaust descriptors on a large fleet).
func VMState(ctx context.Context, socketPath string) (string, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("describe instance: status %d", resp.StatusCode)
	}
	var info struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&info); err != nil {
		return "", fmt.Errorf("describe instance: %w", err)
	}
	if info.State == "" {
		return "", fmt.Errorf("describe instance: empty state")
	}
	return info.State, nil
}

func CreateDiffSnapshot(socketPath, snapshotPath, memPath string) error {
	fc := newFCClient(socketPath)
	ctx := context.Background()

	if _, err := fc.Operations.PatchVM(&operations.PatchVMParams{
		Context: ctx,
		Body:    &models.VM{State: strPtr(models.VMStatePaused)},
	}); err != nil {
		return fmt.Errorf("pause VM: %w", err)
	}

	if _, err := fc.Operations.CreateSnapshot(&operations.CreateSnapshotParams{
		Context: ctx,
		Body: &models.SnapshotCreateParams{
			SnapshotPath: &snapshotPath,
			MemFilePath:  &memPath,
			SnapshotType: models.SnapshotCreateParamsSnapshotTypeDiff,
		},
	}); err != nil {
		return fmt.Errorf("create diff snapshot: %w", err)
	}
	return nil
}

// UnpauseVM resumes a paused VM's vCPUs. Used after CreateSnapshot to make
// snapshot creation non-destructive.
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

// LoadSnapshotNoResume loads a snapshot but leaves the vCPUs paused — used to
// re-snapshot it (SnapshotPausedVM) and verify the memory round-trips. The TAP
// override mirrors RestoreSnapshot* so device restore succeeds.
func LoadSnapshotNoResume(socketPath, snapshotPath, memPath, ifaceID, tapDevice, blockDeltaDir string) error {
	// Empty, not nil — Firecracker rejects null. Only override the TAP when one
	// is actually provided; a blank HostDevName is invalid.
	overrides := []*models.NetworkOverride{}
	if tapDevice != "" {
		overrides = []*models.NetworkOverride{{IfaceID: &ifaceID, HostDevName: &tapDevice}}
	}
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.LoadSnapshot(&operations.LoadSnapshotParams{
		Context: context.Background(),
		Body: &models.SnapshotLoadParams{
			SnapshotPath: &snapshotPath,
			MemBackend: &models.MemoryBackend{
				BackendType: strPtr(models.MemoryBackendBackendTypeFile),
				BackendPath: &memPath,
			},
			ResumeVM:         false,
			NetworkOverrides: overrides,
			BlockDeltaDir:    blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot (no-resume): %w: %v", ErrTornSnapshot, err)
		}
		return fmt.Errorf("load snapshot (no-resume): %w", err)
	}
	return nil
}

// SnapshotPausedVM creates a Full snapshot of an already-paused VM (e.g. one
// loaded via LoadSnapshotNoResume), issuing no pause first as CreateSnapshot does.
func SnapshotPausedVM(socketPath, snapshotPath, memPath string) error {
	fc := newFCClient(socketPath)
	if _, err := fc.Operations.CreateSnapshot(&operations.CreateSnapshotParams{
		Context: context.Background(),
		Body: &models.SnapshotCreateParams{
			SnapshotPath: &snapshotPath,
			MemFilePath:  &memPath,
			SnapshotType: models.SnapshotCreateParamsSnapshotTypeFull,
		},
	}); err != nil {
		return fmt.Errorf("create snapshot (paused): %w", err)
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
	socketPath, snapshotPath, memPath, basePath, accessLogPath, recordToPath, ifaceID, tapDevice, blockDeltaDir string,
	trackDirty, abortOnHandlerDeath bool,
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
				BackendType: strPtr(models.MemoryBackendBackendTypeUffdInternal),
				BackendPath: &memPath,
				// Layered restore: pages absent from memPath (the overlay/diff) are
				// served from this base (template). Empty ⇒ single-file restore.
				BasePath:            basePath,
				AccessLogPath:       accessLogPath,
				RecordTo:            recordToPath,
				AbortOnHandlerDeath: abortOnHandlerDeath,
			},
			// Arms dirty-page tracking so the next pause can write an incremental
			// (Diff) snapshot instead of a Full one.
			TrackDirtyPages: trackDirty,
			ResumeVM:        true,
			NetworkOverrides: []*models.NetworkOverride{
				{IfaceID: &ifaceID, HostDevName: &tapDevice},
			},
			BlockDeltaDir: blockDeltaDir,
		},
	}); err != nil {
		if isTornSnapshotErr(err) {
			return fmt.Errorf("load snapshot (uffd-internal): %w: %v", ErrTornSnapshot, err)
		}
		if isLayeredInvalidErr(err) {
			return fmt.Errorf("load snapshot (uffd-internal): %w: %v", ErrLayeredInvalidSnapshot, err)
		}
		return fmt.Errorf("load snapshot (uffd-internal): %w", err)
	}
	return nil
}
