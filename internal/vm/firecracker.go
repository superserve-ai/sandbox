package vm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	fcclient "github.com/superserve-ai/sandbox/internal/vm/fc/client"
	"github.com/superserve-ai/sandbox/internal/vm/fc/client/operations"
	"github.com/superserve-ai/sandbox/internal/vm/fc/models"
)

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

// CreateSnapshot pauses the VM and creates a full snapshot. Non-empty
// blockDeltaDir tells the forked engine to also emit <drive_id>.delta files
// containing dirty blocks — required to create sandboxes from this template.
func CreateSnapshot(socketPath, snapshotPath, memPath, blockDeltaDir string) error {
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
		},
	}); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
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
		return fmt.Errorf("load snapshot: %w", err)
	}
	return nil
}
