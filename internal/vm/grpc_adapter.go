package vm

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

func (a *GRPCAdapter) CreateVM(ctx context.Context, req *vmdpb.CreateVMRequest) (*vmdpb.CreateVMResponse, error) {
	var vcpu, memMiB, diskMiB uint32
	if rl := req.GetResourceLimits(); rl != nil {
		vcpu = rl.GetVcpuCount()
		memMiB = rl.GetMemoryMib()
		diskMiB = rl.GetDiskSizeMib()
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

	inst, err := a.mgr.CreateVM(ctx, req.GetVmId(), vcpu, memMiB, diskMiB,
		req.GetKernelPath(), req.GetKernelArgs(), req.GetBaseRootfsPath(),
		netCfg, req.GetMetadata())
	if err != nil {
		return nil, err
	}

	return &vmdpb.CreateVMResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		TapDevice:  inst.TAPDevice,
		Pid:        uint32(inst.PID),
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount: inst.Config.VCPU,
			MemoryMib: inst.Config.MemoryMiB,
		},
	}, nil
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
	return &vmdpb.ResumeVMResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
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
	return &vmdpb.RestoreSnapshotResponse{
		VmId:       inst.ID,
		SocketPath: inst.SocketPath,
		IpAddress:  inst.IP,
		Pid:        uint32(inst.PID),
	}, nil
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
