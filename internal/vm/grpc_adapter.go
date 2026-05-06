package vm

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// GRPCAdapter wraps a Manager to implement vmdpb.VMDaemonServer.
type GRPCAdapter struct {
	vmdpb.UnimplementedVMDaemonServer
	mgr *Manager
}

// NewGRPCAdapter creates a new adapter that bridges the proto interface to the Manager.
func NewGRPCAdapter(mgr *Manager) *GRPCAdapter {
	return &GRPCAdapter{mgr: mgr}
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
		VmId:        req.GetVmId(),
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	}, nil
}

func (a *GRPCAdapter) ResumeVM(ctx context.Context, req *vmdpb.ResumeVMRequest) (*vmdpb.ResumeVMResponse, error) {
	inst, err := a.mgr.ResumeVM(ctx, req.GetVmId(), req.GetSnapshotPath(), req.GetMemFilePath())
	if err != nil {
		return nil, err
	}

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

	inst, err := a.mgr.RestoreVMSnapshot(ctx, req.GetVmId(), req.GetSnapshotPath(), req.GetMemFilePath(), req.GetOverlayPath(), vmCfg, netCfg)
	if err != nil {
		return nil, err
	}

	// Apply caller env vars and the per-sandbox hostname.
	if initErr := postBoxdInit(ctx, inst.IP, req.GetEnvVars(), vmHostname(inst.ID)); initErr != nil {
		// Tear the VM down — a sandbox whose env vars weren't applied
		// would silently serve stale/missing secrets to the user.
		_ = a.mgr.DestroyVM(ctx, inst.ID, true)
		return nil, status.Errorf(codes.Internal, "post-restore init failed: %v", initErr)
	}

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

func (a *GRPCAdapter) ExecCommand(req *vmdpb.ExecCommandRequest, stream grpc.ServerStreamingServer[vmdpb.ExecCommandResponse]) error {
	if req.GetCommand() == "" {
		return status.Error(codes.InvalidArgument, "command is required")
	}

	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var opts *ExecOptions
	if len(req.GetArgs()) > 0 || len(req.GetEnv()) > 0 || req.GetWorkingDir() != "" {
		opts = &ExecOptions{
			Args:       req.GetArgs(),
			Env:        req.GetEnv(),
			WorkingDir: req.GetWorkingDir(),
		}
	}

	return a.mgr.ExecCommandStream(stream.Context(), req.GetVmId(), req.GetCommand(), timeout, opts,
		func(stdout, stderr []byte, exitCode int32, finished bool) {
			_ = stream.Send(&vmdpb.ExecCommandResponse{
				Stdout:   stdout,
				Stderr:   stderr,
				ExitCode: exitCode,
				Finished: finished,
			})
		},
	)
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

	// Update nftables rules (non-TCP traffic).
	if err := a.mgr.netMgr.UpdateFirewallRules(vmID, egress.GetAllowedCidrs(), egress.GetDeniedCidrs()); err != nil {
		return nil, status.Errorf(codes.Internal, "update firewall rules: %v", err)
	}

	// Update egress proxy rules (TCP traffic — domain + CIDR filtering).
	if a.mgr.egressProxy != nil {
		netInfo := a.mgr.netMgr.GetVMNetInfo(vmID)
		if netInfo != nil {
			a.mgr.egressProxy.SetRules(netInfo.HostIP, &network.EgressRules{
				AllowedCIDRs:   egress.GetAllowedCidrs(),
				DeniedCIDRs:    egress.GetDeniedCidrs(),
				AllowedDomains: egress.GetAllowedDomains(),
			})
		}
	}

	return &vmdpb.UpdateSandboxNetworkResponse{VmId: vmID}, nil
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
