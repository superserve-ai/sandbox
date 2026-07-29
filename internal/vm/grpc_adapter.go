package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// GRPCAdapter wraps a Manager to implement vmdpb.VMDaemonServer.
type GRPCAdapter struct {
	vmdpb.UnimplementedVMDaemonServer
	mgr             *Manager
	secrets         *SecretsBrokerClient
	sandboxProxyURL string // SECRETSPROXY_SANDBOX_ADDR — empty disables HTTPS_PROXY injection
}

// NewGRPCAdapter creates a new adapter that bridges the proto interface to the Manager.
func NewGRPCAdapter(mgr *Manager) *GRPCAdapter {
	return &GRPCAdapter{mgr: mgr, secrets: NewSecretsBrokerClient("")}
}

// WithSecretsBroker enables the secretsproxy integration; empty socketPath disables it.
// sandboxProxyURL is the host:port the sandbox writes into HTTPS_PROXY.
func (a *GRPCAdapter) WithSecretsBroker(socketPath, sandboxProxyURL string) *GRPCAdapter {
	a.secrets = NewSecretsBrokerClient(socketPath)
	a.sandboxProxyURL = sandboxProxyURL
	return a
}

func (a *GRPCAdapter) GetCapabilities(context.Context, *vmdpb.GetCapabilitiesRequest) (*vmdpb.GetCapabilitiesResponse, error) {
	enabled := a != nil && a.mgr != nil && a.mgr.savedSnapshotsSupported()
	return &vmdpb.GetCapabilitiesResponse{SavedSnapshotsV1: enabled}, nil
}

func (a *GRPCAdapter) DestroyVM(ctx context.Context, req *vmdpb.DestroyVMRequest) (*vmdpb.DestroyVMResponse, error) {
	err := a.mgr.DestroyVM(ctx, req.GetVmId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &vmdpb.DestroyVMResponse{
		VmId:      req.GetVmId(),
		CleanedUp: true,
	}, nil
}

func (a *GRPCAdapter) PauseVM(ctx context.Context, req *vmdpb.PauseVMRequest) (*vmdpb.PauseVMResponse, error) {
	snapshotPath, memPath, err := a.mgr.PauseVM(ctx, req.GetVmId(), req.GetSnapshotDir())
	if err != nil {
		return nil, err
	}
	return &vmdpb.PauseVMResponse{
		VmId:         req.GetVmId(),
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	}, nil
}

func (a *GRPCAdapter) ResumeVM(ctx context.Context, req *vmdpb.ResumeVMRequest) (*vmdpb.ResumeVMResponse, error) {
	inst, err := a.mgr.ResumeVM(ctx, req.GetVmId(), req.GetSnapshotPath(), req.GetMemFilePath())
	if err != nil {
		return nil, err
	}

	// Resume is a no-op for secrets: the agent's HTTPS_PROXY (with its JWT) and
	// per-binding proxy tokens are in the snapshot and don't need re-injection.
	if err := postBoxdInit(ctx, inst.IP, req.GetEnvVars(), vmHostname(inst.ID)); err != nil {
		return nil, status.Errorf(codes.Internal, "env vars injection failed: %v", err)
	}

	return &vmdpb.ResumeVMResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount: inst.Config.VCPU,
			MemoryMib: inst.Config.MemoryMiB,
		},
	}, nil
}

func (a *GRPCAdapter) CreateSnapshot(ctx context.Context, req *vmdpb.CreateSnapshotRequest) (*vmdpb.CreateSnapshotResponse, error) {
	if req.GetSnapshotId() != "" {
		saved, err := a.mgr.CreateSavedSnapshot(ctx, req.GetVmId(), req.GetSnapshotId())
		if err != nil {
			if errors.Is(err, ErrSavedSnapshotSourceResume) {
				st := status.New(codes.Internal, "saved snapshot source failed to resume after capture")
				withDetails, detailErr := st.WithDetails(&errdetails.ErrorInfo{
					Reason: vmdclient.SavedSnapshotSourceResumeFailureReason,
					Domain: "vmd.superserve.ai",
				})
				if detailErr == nil {
					return nil, withDetails.Err()
				}
				return nil, st.Err()
			}
			if errors.Is(err, context.Canceled) {
				return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)
			}
			if status.Code(err) == codes.Unknown {
				err = status.Error(codes.Unavailable, "saved snapshot host capture failed")
			}
			return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationCapture, err)
		}
		return &vmdpb.CreateSnapshotResponse{
			VmId:          req.GetVmId(),
			SnapshotId:    saved.SnapshotID,
			SnapshotPath:  saved.Artifacts.SnapshotPath,
			MemFilePath:   saved.Artifacts.MemFilePath,
			CreatedAtUnix: saved.CreatedAt.Unix(),
			Artifacts: &vmdpb.SavedSnapshotArtifacts{
				SchemaVersion:   saved.SchemaVersion,
				ManifestPath:    saved.Artifacts.ManifestPath,
				SnapshotPath:    saved.Artifacts.SnapshotPath,
				MemFilePath:     saved.Artifacts.MemFilePath,
				MemoryBasePath:  saved.Artifacts.MemoryBasePath,
				DiskBasePath:    saved.Artifacts.DiskBasePath,
				DiskDeltaPath:   saved.Artifacts.DiskDeltaPath,
				DiskOverlayPath: saved.Artifacts.DiskOverlayPath,
				DiskFullPath:    saved.Artifacts.DiskFullPath,
				ManifestDigest:  saved.ManifestDigest,
			},
			ResourceLimits: &vmdpb.ResourceLimits{
				VcpuCount:   saved.Resources.VCPU,
				MemoryMib:   saved.Resources.MemoryMiB,
				DiskSizeMib: saved.Resources.DiskSizeMiB,
			},
			LogicalSizeBytes:         saved.LogicalSizeBytes,
			ExclusiveSizeBytes:       saved.ExclusiveSizeBytes,
			SourceLogicalSizeBytes:   saved.SourceLogicalSizeBytes,
			SourceExclusiveSizeBytes: saved.SourceExclusiveSizeBytes,
			SourceState:              saved.SourceState,
		}, nil
	}
	snapshotPath, memPath, err := a.mgr.CreateVMSnapshot(ctx, req.GetVmId(), req.GetSnapshotDir())
	if err != nil {
		return nil, err
	}
	return &vmdpb.CreateSnapshotResponse{
		VmId:          req.GetVmId(),
		SnapshotPath:  snapshotPath,
		MemFilePath:   memPath,
		CreatedAtUnix: time.Now().Unix(),
	}, nil
}

func (a *GRPCAdapter) RestoreSavedSnapshot(ctx context.Context, req *vmdpb.RestoreSavedSnapshotRequest) (*vmdpb.RestoreSavedSnapshotResponse, error) {
	if len(req.GetExpectedManifestDigest()) != sha256.Size*2 {
		return nil, status.Error(codes.InvalidArgument, "expected_manifest_digest must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(req.GetExpectedManifestDigest()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "expected_manifest_digest must be a SHA-256 hex digest")
	}
	clear := make(map[string]string, len(req.GetClearEnvKeys()))
	for _, key := range req.GetClearEnvKeys() {
		if key == "" {
			return nil, status.Error(codes.InvalidArgument, "clear_env_keys cannot contain an empty key")
		}
		clear[key] = ""
	}
	var netCfg *network.Config
	if nc := req.GetNetworkConfig(); nc != nil {
		netCfg = &network.Config{
			HostInterface: nc.GetHostInterface(),
			SubnetCIDR:    nc.GetSubnetCidr(),
			GatewayIP:     nc.GetGatewayIp(),
			EnableNAT:     nc.GetEnableNat(),
		}
	}
	var egress *network.EgressRules
	if sandboxNetwork := req.GetSandboxNetwork(); sandboxNetwork != nil && sandboxNetwork.GetEgress() != nil {
		rules := sandboxNetwork.GetEgress()
		egress = &network.EgressRules{
			AllowedCIDRs:   rules.GetAllowedCidrs(),
			DeniedCIDRs:    rules.GetDeniedCidrs(),
			AllowedDomains: rules.GetAllowedDomains(),
			SandboxID:      req.GetVmId(),
		}
	}
	if access := req.GetPreviewAccess(); access != "" && access != preview.AccessLegacyPublic && access != preview.AccessPublic && access != preview.AccessPrivate {
		return nil, status.Errorf(codes.InvalidArgument, "preview_access must be empty, %q, %q or %q, got %q", preview.AccessLegacyPublic, preview.AccessPublic, preview.AccessPrivate, access)
	}
	previewPorts, err := previewPortsFromProto(req.GetPreviewPorts())
	if err != nil {
		return nil, err
	}
	if previewPortsContainTokenizedAccess(previewPorts) && req.GetPreviewPolicyRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "tokenized preview policy requires a positive preview_policy_revision")
	}
	inst, saved, err := a.mgr.RestoreSavedSnapshot(
		ctx,
		req.GetVmId(),
		req.GetManifestPath(),
		req.GetExpectedManifestDigest(),
		netCfg,
		egress,
		req.GetTeamId(),
		req.GetOwnerId(),
		req.GetPreviewAccess(),
		previewPorts,
		req.GetPreviewPolicyRevision(),
	)
	if err != nil {
		return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationRestore, err)
	}

	// boxd /init is additive, so overwrite captured source-specific secret
	// token defaults with empty values before exposing the child. Fresh child
	// values and HTTPS_PROXY are injected afterward through InjectSandboxEnv.
	if len(clear) > 0 {
		if err := postBoxdInit(ctx, inst.IP, clear, vmHostname(inst.ID)); err != nil {
			// Do not leave a reachable child with captured boxd defaults after
			// the security scrub failed. Control-plane cleanup remains idempotent.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = a.mgr.DestroyVM(cleanupCtx, inst.ID, true)
			cancel()
			return nil, vmdclient.SanitizeSavedSnapshotError(
				vmdclient.SavedSnapshotOperationRestore,
				status.Errorf(codes.Internal, "clear captured env defaults: %v", err),
			)
		}
	}

	return &vmdpb.RestoreSavedSnapshotResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount:   saved.Resources.VCPU,
			MemoryMib:   saved.Resources.MemoryMiB,
			DiskSizeMib: saved.Resources.DiskSizeMiB,
		},
	}, nil
}

func (a *GRPCAdapter) DeleteSavedSnapshot(ctx context.Context, req *vmdpb.DeleteSavedSnapshotRequest) (*vmdpb.DeleteSavedSnapshotResponse, error) {
	if err := a.mgr.DeleteSavedSnapshot(ctx, req.GetSourceVmId(), req.GetSnapshotId()); err != nil {
		return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationDelete, err)
	}
	return &vmdpb.DeleteSavedSnapshotResponse{Deleted: true}, nil
}

func (a *GRPCAdapter) GetWritableLayerUsage(_ context.Context, req *vmdpb.GetWritableLayerUsageRequest) (*vmdpb.GetWritableLayerUsageResponse, error) {
	logical, exclusive, err := a.mgr.SandboxWritableLayerUsage(req.GetVmId())
	if err != nil {
		return nil, vmdclient.SanitizeSavedSnapshotError(vmdclient.SavedSnapshotOperationWritableLayerMeasurement, err)
	}
	return &vmdpb.GetWritableLayerUsageResponse{
		LogicalSizeBytes:   logical,
		ExclusiveSizeBytes: exclusive,
	}, nil
}

func (a *GRPCAdapter) RestoreSnapshot(ctx context.Context, req *vmdpb.RestoreSnapshotRequest) (*vmdpb.RestoreSnapshotResponse, error) {
	var vmCfg VMConfig
	if rl := req.GetResourceLimits(); rl != nil {
		vmCfg = VMConfig{
			VCPU:        rl.GetVcpuCount(),
			MemoryMiB:   rl.GetMemoryMib(),
			DiskSizeMiB: rl.GetDiskSizeMib(),
		}
	}
	vmCfg.BasePath = req.GetBasePath()
	vmCfg.DeltaDir = req.GetDeltaDir()

	var netCfg *network.Config
	if nc := req.GetNetworkConfig(); nc != nil {
		netCfg = &network.Config{
			HostInterface: nc.GetHostInterface(),
			SubnetCIDR:    nc.GetSubnetCidr(),
			GatewayIP:     nc.GetGatewayIp(),
			EnableNAT:     nc.GetEnableNat(),
		}
	}

	if access := req.GetPreviewAccess(); access != "" && access != preview.AccessLegacyPublic && access != preview.AccessPublic && access != preview.AccessPrivate {
		return nil, status.Errorf(codes.InvalidArgument, "preview_access must be empty, %q, %q or %q, got %q", preview.AccessLegacyPublic, preview.AccessPublic, preview.AccessPrivate, access)
	}
	previewPorts, err := previewPortsFromProto(req.GetPreviewPorts())
	if err != nil {
		return nil, err
	}
	if previewPortsContainTokenizedAccess(previewPorts) && req.GetPreviewPolicyRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "tokenized preview policy requires a positive preview_policy_revision")
	}

	inst, err := a.mgr.RestoreVMSnapshot(ctx, req.GetVmId(), req.GetSnapshotPath(), req.GetMemFilePath(), vmCfg, netCfg, req.GetTeamId(), req.GetOwnerId(), req.GetPreviewAccess(), previewPorts, req.GetPreviewPolicyRevision())
	if err != nil {
		return nil, err
	}

	// Env vars are pushed in a separate InjectSandboxEnv call so the control
	// plane can mint a JWT against the now-known source IP before injection.
	return &vmdpb.RestoreSnapshotResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount: inst.Config.VCPU,
			MemoryMib: inst.Config.MemoryMiB,
		},
	}, nil
}

// InjectSandboxEnv pushes env vars and the sandbox's hostname into the running
// boxd. When secrets_jwt is non-empty vmd builds the HTTPS_PROXY URL from its
// configured daemon address and adds it to env_vars before sending.
func (a *GRPCAdapter) InjectSandboxEnv(ctx context.Context, req *vmdpb.InjectSandboxEnvRequest) (*vmdpb.InjectSandboxEnvResponse, error) {
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id is required")
	}
	inst, err := a.mgr.GetVMInfo(ctx, vmID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "vm %s: %v", vmID, err)
	}
	envVars := req.GetEnvVars()
	jwt := req.GetSecretsJwt()
	if err := RequireProxyForJWT(jwt, a.sandboxProxyURL); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	if jwt != "" {
		envVars = InjectHTTPSProxyEnvWithJWT(envVars, a.sandboxProxyURL, jwt)
	}
	if err := postBoxdInit(ctx, inst.IP, envVars, vmHostname(vmID)); err != nil {
		return nil, status.Errorf(codes.Internal, "post-init failed: %v", err)
	}
	return &vmdpb.InjectSandboxEnvResponse{VmId: vmID}, nil
}

// DeleteSnapshot unlinks the vmstate + memory files for a previous snapshot.
// Idempotent; paths are scoped to <SnapshotDir>/<vm_id>/ at the Manager layer,
// so a call cannot unlink files belonging to a different sandbox.
func (a *GRPCAdapter) DeleteSnapshot(ctx context.Context, req *vmdpb.DeleteSnapshotRequest) (*vmdpb.DeleteSnapshotResponse, error) {
	vmID := req.GetVmId()
	snapshotPath := req.GetSnapshotPath()
	memPath := req.GetMemFilePath()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be set")
	}
	if snapshotPath == "" && memPath == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot_path and/or mem_file_path must be set")
	}
	if err := a.mgr.DeleteSnapshotFiles(vmID, snapshotPath, memPath); err != nil {
		return nil, err
	}
	return &vmdpb.DeleteSnapshotResponse{Deleted: true}, nil
}

// DeleteSandboxSnapshots removes a sandbox's entire snapshot directory.
// Idempotent; scoped to <SnapshotDir>/<vm_id>/ at the Manager layer.
func (a *GRPCAdapter) DeleteSandboxSnapshots(ctx context.Context, req *vmdpb.DeleteSandboxSnapshotsRequest) (*vmdpb.DeleteSandboxSnapshotsResponse, error) {
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be set")
	}
	if err := a.mgr.DeleteSandboxSnapshots(vmID); err != nil {
		return nil, err
	}
	return &vmdpb.DeleteSandboxSnapshotsResponse{Deleted: true}, nil
}

// DeleteTemplateArtifacts removes a template's snapshot dir + rootfs dir.
// Idempotent.
func (a *GRPCAdapter) DeleteTemplateArtifacts(ctx context.Context, req *vmdpb.DeleteTemplateArtifactsRequest) (*vmdpb.DeleteTemplateArtifactsResponse, error) {
	tplID := req.GetTemplateId()
	if tplID == "" {
		return nil, status.Error(codes.InvalidArgument, "template_id must be set")
	}
	if err := a.mgr.DeleteTemplateArtifacts(tplID); err != nil {
		return nil, err
	}
	return &vmdpb.DeleteTemplateArtifactsResponse{Deleted: true}, nil
}

// ListBuildArtifacts returns every per-build dir on the host's snapshot
// storage. The controlplane reconciler uses this to find orphans.
func (a *GRPCAdapter) ListBuildArtifacts(ctx context.Context, req *vmdpb.ListBuildArtifactsRequest) (*vmdpb.ListBuildArtifactsResponse, error) {
	entries, err := a.mgr.ListBuildArtifacts()
	if err != nil {
		return nil, err
	}
	resp := &vmdpb.ListBuildArtifactsResponse{Entries: make([]*vmdpb.BuildArtifactEntry, 0, len(entries))}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &vmdpb.BuildArtifactEntry{
			TemplateId: e.TemplateID,
			BuildId:    e.BuildID,
			MtimeUnix:  e.MTime.Unix(),
		})
	}
	return resp, nil
}

// ListDir lists a directory inside a running VM via boxd's
// FilesystemService.ListDir (see Manager.ListDir).
func (a *GRPCAdapter) ListDir(ctx context.Context, req *vmdpb.ListDirRequest) (*vmdpb.ListDirResponse, error) {
	entries, err := a.mgr.ListDir(ctx, req.GetVmId(), req.GetPath())
	if err != nil {
		return nil, err
	}
	resp := &vmdpb.ListDirResponse{Entries: make([]*vmdpb.ListDirEntry, 0, len(entries))}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &vmdpb.ListDirEntry{
			Name:         e.Name,
			IsDir:        e.IsDir,
			Size:         e.Size,
			ModifiedUnix: e.ModifiedUnix,
		})
	}
	return resp, nil
}

// DeleteBuildArtifacts removes a single build's subdir under a template.
func (a *GRPCAdapter) DeleteBuildArtifacts(ctx context.Context, req *vmdpb.DeleteBuildArtifactsRequest) (*vmdpb.DeleteBuildArtifactsResponse, error) {
	tplID := req.GetTemplateId()
	buildID := req.GetBuildId()
	if tplID == "" || buildID == "" {
		return nil, status.Error(codes.InvalidArgument, "template_id and build_id must be set")
	}
	if err := a.mgr.DeleteBuildArtifacts(tplID, buildID); err != nil {
		return nil, err
	}
	return &vmdpb.DeleteBuildArtifactsResponse{Deleted: true}, nil
}

func (a *GRPCAdapter) GetVMInfo(ctx context.Context, req *vmdpb.GetVMInfoRequest) (*vmdpb.GetVMInfoResponse, error) {
	inst, err := a.mgr.GetVMInfo(ctx, req.GetVmId())
	if err != nil {
		return nil, err
	}

	return &vmdpb.GetVMInfoResponse{
		VmId:       inst.ID,
		Status:     vmStatusToProto(inst.Status),
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount:   inst.Config.VCPU,
			MemoryMib:   inst.Config.MemoryMiB,
			DiskSizeMib: inst.Config.DiskSizeMiB,
		},
		Metadata:      inst.Metadata,
		CreatedAtUnix: inst.CreatedAt.Unix(),
		UptimeSeconds: int64(time.Since(inst.CreatedAt).Seconds()),
	}, nil
}

func (a *GRPCAdapter) SetupNetwork(ctx context.Context, req *vmdpb.SetupNetworkRequest) (*vmdpb.SetupNetworkResponse, error) {
	nc := req.GetNetworkConfig()
	if nc == nil {
		return nil, status.Error(codes.InvalidArgument, "network_config is required")
	}

	netCfg := &network.Config{
		HostInterface: nc.GetHostInterface(),
		SubnetCIDR:    nc.GetSubnetCidr(),
		GatewayIP:     nc.GetGatewayIp(),
		EnableNAT:     nc.GetEnableNat(),
	}

	info, err := a.mgr.netMgr.SetupVM(ctx, req.GetVmId(), netCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "setup network: %v", err)
	}

	return &vmdpb.SetupNetworkResponse{
		VmId:       req.GetVmId(),
		TapDevice:  info.TAPDevice,
		VmIp:       info.VMIP,
		GatewayIp:  info.GatewayIP,
		MacAddress: info.MACAddress,
	}, nil
}

func (a *GRPCAdapter) UpdateSandboxNetwork(ctx context.Context, req *vmdpb.UpdateSandboxNetworkRequest) (*vmdpb.UpdateSandboxNetworkResponse, error) {
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id is required")
	}

	egress := req.GetEgress()
	if egress == nil {
		return nil, status.Error(codes.InvalidArgument, "egress config is required")
	}

	// This RPC reads netMgr state directly (below), which the background startup
	// reattach may not have restored yet. Resolve the VM through getInstance first
	// so it's reattached on demand (or NotFound if it's genuinely gone).
	inst, err := a.mgr.getInstance(vmID)
	if err != nil {
		return nil, err
	}
	rules := &network.EgressRules{
		AllowedCIDRs:   append([]string(nil), egress.GetAllowedCidrs()...),
		DeniedCIDRs:    append([]string(nil), egress.GetDeniedCidrs()...),
		AllowedDomains: append([]string(nil), egress.GetAllowedDomains()...),
		SandboxID:      vmID,
	}

	// Update nftables rules (non-TCP traffic).
	if err := a.mgr.netMgr.UpdateFirewallRules(vmID, egress.GetAllowedCidrs(), egress.GetDeniedCidrs()); err != nil {
		return nil, status.Errorf(codes.Internal, "update firewall rules: %v", err)
	}

	// Update egress proxy rules (TCP traffic — domain + CIDR filtering).
	if a.mgr.egressProxy != nil {
		netInfo := a.mgr.netMgr.GetVMNetInfo(vmID)
		if netInfo != nil {
			a.mgr.egressProxy.SetRules(netInfo.HostIP, rules)
		}
	}

	inst.mu.Lock()
	inst.Config.EgressPolicy = rules
	inst.mu.Unlock()
	a.mgr.persistState(inst)

	return &vmdpb.UpdateSandboxNetworkResponse{VmId: vmID}, nil
}

func (a *GRPCAdapter) UpdateSandboxPreviewPolicy(_ context.Context, req *vmdpb.UpdateSandboxPreviewPolicyRequest) (*vmdpb.UpdateSandboxPreviewPolicyResponse, error) {
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id is required")
	}
	access := req.GetPreviewAccess()
	if access != preview.AccessLegacyPublic && access != preview.AccessPublic && access != preview.AccessPrivate {
		return nil, status.Errorf(codes.InvalidArgument, "preview_access must be %q, %q or %q, got %q", preview.AccessLegacyPublic, preview.AccessPublic, preview.AccessPrivate, access)
	}
	ports, err := previewPortsFromProto(req.GetPreviewPorts())
	if err != nil {
		return nil, err
	}
	if previewPortsContainTokenizedAccess(ports) && req.GetPolicyRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "tokenized preview policy requires a positive policy_revision")
	}
	if err := a.mgr.UpdateSandboxPreviewPolicy(vmID, access, ports, req.GetPolicyRevision()); err != nil {
		return nil, err
	}
	return &vmdpb.UpdateSandboxPreviewPolicyResponse{VmId: vmID}, nil
}

func previewPortsFromProto(in []*vmdpb.PreviewPort) (map[int32]PreviewPortPolicy, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[int32]PreviewPortPolicy, len(in))
	for _, item := range in {
		port := item.GetPort()
		if err := preview.ValidatePublishedPort(port); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid preview port %d: %v", port, err)
		}
		if _, duplicate := out[port]; duplicate {
			return nil, status.Errorf(codes.InvalidArgument, "duplicate preview port: %d", port)
		}
		access := item.GetAccess()
		tokenVersion := item.GetTokenVersion()
		if preview.IsTokenizedAccess(access) {
			if tokenVersion <= 0 {
				return nil, status.Errorf(codes.InvalidArgument, "tokenized preview port %d requires a positive token_version", port)
			}
		} else {
			// Phase 1/2 and future non-token modes do not activate credentials,
			// even if a newer or malformed sender populated the additive field.
			tokenVersion = 0
		}
		out[port] = PreviewPortPolicy{Access: access, TokenVersion: tokenVersion}
	}
	return out, nil
}

func previewPortsContainTokenizedAccess(ports map[int32]PreviewPortPolicy) bool {
	for _, policy := range ports {
		if preview.IsTokenizedAccess(policy.Access) {
			return true
		}
	}
	return false
}

// InvalidateSecret forwards the invalidate call to the local secretsproxy daemon.
// Returns OK when the daemon is disabled on this host.
func (a *GRPCAdapter) InvalidateSecret(ctx context.Context, req *vmdpb.InvalidateSecretRequest) (*vmdpb.InvalidateSecretResponse, error) {
	if req.GetSecretId() == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if err := a.secrets.InvalidateSecret(ctx, req.GetSecretId()); err != nil {
		return nil, status.Errorf(codes.Internal, "secretsproxy invalidate: %v", err)
	}
	return &vmdpb.InvalidateSecretResponse{}, nil
}

// RevokeSandbox forwards the revoke to the local secretsproxy daemon.
func (a *GRPCAdapter) RevokeSandbox(ctx context.Context, req *vmdpb.RevokeSandboxRequest) (*vmdpb.RevokeSandboxResponse, error) {
	if req.GetSandboxId() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if err := a.secrets.RevokeSandbox(ctx, req.GetSandboxId()); err != nil {
		return nil, status.Errorf(codes.Internal, "secretsproxy revoke: %v", err)
	}
	return &vmdpb.RevokeSandboxResponse{}, nil
}

// InvalidateSandboxRules forwards the egress-rules invalidation to the local
// secretsproxy daemon. Returns OK when the daemon is disabled on this host.
func (a *GRPCAdapter) InvalidateSandboxRules(ctx context.Context, req *vmdpb.InvalidateSandboxRulesRequest) (*vmdpb.InvalidateSandboxRulesResponse, error) {
	if req.GetSandboxId() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if err := a.secrets.InvalidateSandboxRules(ctx, req.GetSandboxId()); err != nil {
		return nil, status.Errorf(codes.Internal, "secretsproxy invalidate rules: %v", err)
	}
	return &vmdpb.InvalidateSandboxRulesResponse{}, nil
}

func (a *GRPCAdapter) BuildTemplate(ctx context.Context, req *vmdpb.BuildTemplateRequest) (*vmdpb.BuildTemplateResponse, error) {
	if req.GetTemplateId() == "" {
		return nil, status.Error(codes.InvalidArgument, "template_id is required")
	}
	if req.GetFrom() == "" {
		return nil, status.Error(codes.InvalidArgument, "from is required")
	}

	spec := builder.BuildSpec{
		From:     req.GetFrom(),
		StartCmd: req.GetStartCmd(),
		ReadyCmd: req.GetReadyCmd(),
	}
	for i, pstep := range req.GetSteps() {
		step, err := buildStepFromProto(pstep)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "steps[%d]: %v", i, err)
		}
		spec.Steps = append(spec.Steps, step)
	}

	buildVMID, err := a.mgr.BuildTemplate(ctx, BuildTemplateRequest{
		TemplateID: req.GetTemplateId(),
		Spec:       spec,
		VCPU:       req.GetVcpu(),
		MemoryMiB:  req.GetMemoryMib(),
		DiskMiB:    req.GetDiskMib(),
		BuildVMID:  req.GetBuildVmId(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build template: %v", err)
	}

	return &vmdpb.BuildTemplateResponse{BuildVmId: buildVMID}, nil
}

func (a *GRPCAdapter) GetBuildStatus(ctx context.Context, req *vmdpb.GetBuildStatusRequest) (*vmdpb.GetBuildStatusResponse, error) {
	if req.GetBuildVmId() == "" {
		return nil, status.Error(codes.InvalidArgument, "build_vm_id is required")
	}
	snap, ok := a.mgr.GetBuildStatus(req.GetBuildVmId())
	if !ok {
		return &vmdpb.GetBuildStatusResponse{NotFound: true}, nil
	}
	resp := &vmdpb.GetBuildStatusResponse{
		Status:        string(snap.Status),
		ErrorMessage:  snap.Error,
		StartedAtUnix: snap.StartedAt.Unix(),
	}
	if !snap.EndedAt.IsZero() {
		resp.EndedAtUnix = snap.EndedAt.Unix()
	}
	if snap.Result != nil {
		resp.SnapshotPath = snap.Result.SnapshotPath
		resp.MemFilePath = snap.Result.MemFilePath
		resp.RootfsPath = snap.Result.RootfsPath
		resp.BasePath = snap.Result.BasePath
		resp.DeltaPath = snap.Result.DeltaPath
		resp.ResolvedDigest = snap.Result.ResolvedDigest
		resp.SizeBytes = snap.Result.SizeBytes
	}
	return resp, nil
}

func (a *GRPCAdapter) CancelBuild(ctx context.Context, req *vmdpb.CancelBuildRequest) (*vmdpb.CancelBuildResponse, error) {
	if req.GetBuildVmId() == "" {
		return nil, status.Error(codes.InvalidArgument, "build_vm_id is required")
	}
	if err := a.mgr.CancelBuild(ctx, req.GetBuildVmId()); err != nil {
		return nil, status.Errorf(codes.Internal, "cancel build: %v", err)
	}
	return &vmdpb.CancelBuildResponse{}, nil
}

// StreamBuildLogs bridges the manager's in-memory pub-sub into a gRPC
// server stream. Subscribing replays buffered history first, then streams
// new events until the build reaches a terminal status (log buffer closes).
// Returns NotFound when the build is unknown — the client maps that to a
// 404 on its SSE endpoint.
func (a *GRPCAdapter) StreamBuildLogs(req *vmdpb.StreamBuildLogsRequest, stream vmdpb.VMDaemon_StreamBuildLogsServer) error {
	if req.GetBuildVmId() == "" {
		return status.Error(codes.InvalidArgument, "build_vm_id is required")
	}
	sub, unsubscribe, ok := a.mgr.subscribeBuildLogs(req.GetBuildVmId())
	if !ok {
		return status.Errorf(codes.NotFound, "build %s not found", req.GetBuildVmId())
	}
	defer unsubscribe()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, open := <-sub:
			if !open {
				// Buffer closed → build terminal, stream already emitted
				// the Finished event. Clean return closes the RPC.
				return nil
			}
			pbEv := &vmdpb.BuildLogEvent{
				TimestampUnix:      ev.Timestamp.Unix(),
				TimestampUnixNanos: ev.Timestamp.UnixNano(),
				Stream:             string(ev.Stream),
				Text:               ev.Text,
				Finished:           ev.Finished,
				Status:             string(ev.Status),
			}
			if err := stream.Send(pbEv); err != nil {
				return err
			}
			if ev.Finished {
				return nil
			}
		}
	}
}

// buildStepFromProto converts a proto BuildStep to the internal/builder
// type. Enforces the "exactly one op" invariant at the gRPC boundary so
// BuildTemplate never has to worry about it.
func buildStepFromProto(p *vmdpb.BuildStep) (builder.BuildStep, error) {
	if p == nil {
		return builder.BuildStep{}, nil
	}
	switch op := p.GetOp().(type) {
	case *vmdpb.BuildStep_Run:
		run := op.Run
		return builder.BuildStep{Run: &run}, nil
	case *vmdpb.BuildStep_Env:
		return builder.BuildStep{Env: &builder.EnvOp{Key: op.Env.GetKey(), Value: op.Env.GetValue()}}, nil
	case *vmdpb.BuildStep_Workdir:
		wd := op.Workdir
		return builder.BuildStep{Workdir: &wd}, nil
	case *vmdpb.BuildStep_User:
		return builder.BuildStep{User: &builder.UserOp{
			Name: op.User.GetName(),
			Sudo: op.User.GetSudo(),
		}}, nil
	default:
		return builder.BuildStep{}, &fieldError{"op must be one of run/copy/env/workdir/user"}
	}
}

type fieldError struct{ msg string }

func (e *fieldError) Error() string { return e.msg }

func vmStatusToProto(s VMStatus) vmdpb.VMStatus {
	switch s {
	case StatusCreating:
		return vmdpb.VMStatus_VM_STATUS_CREATING
	case StatusRunning:
		return vmdpb.VMStatus_VM_STATUS_RUNNING
	case StatusPaused:
		return vmdpb.VMStatus_VM_STATUS_PAUSED
	case StatusStopped:
		return vmdpb.VMStatus_VM_STATUS_STOPPED
	case StatusError:
		return vmdpb.VMStatus_VM_STATUS_ERROR
	default:
		return vmdpb.VMStatus_VM_STATUS_UNSPECIFIED
	}
}
