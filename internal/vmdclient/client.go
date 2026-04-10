// Package vmdclient defines the interface for talking to a VM daemon.
// It lives in its own leaf package so both internal/api and
// internal/hostreg can reference it without circular imports.
package vmdclient

import "context"

// Client defines the subset of the VM daemon gRPC interface used by the
// control plane. Implementations: grpcVMDClient in cmd/controlplane,
// stubVMD in tests.
type Client interface {
	CreateInstance(ctx context.Context, instanceID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	DestroyInstance(ctx context.Context, instanceID string, force bool) error
	PauseInstance(ctx context.Context, instanceID, snapshotDir string) (snapshotPath, memPath string, err error)
	ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	ExecCommand(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (stdout, stderr string, exitCode int32, err error)
	ExecCommandStream(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func(stdout, stderr []byte, exitCode int32, finished bool)) error
	UpdateSandboxNetwork(ctx context.Context, instanceID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error
}
