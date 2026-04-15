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
	// RestoreSnapshot is the stateless restore path used as a fallback when
	// ResumeInstance fails with NotFound (e.g. after a VMD crash lost the
	// in-memory map but the snapshot files are still on disk).
	RestoreSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	// DeleteSnapshot removes the on-disk vmstate + memory files for a
	// previous snapshot. Idempotent: missing files return nil. Used by the
	// control plane to garbage-collect the previous snapshot after a new
	// pause writes a fresh one.
	DeleteSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string) error
	ExecCommand(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (stdout, stderr string, exitCode int32, err error)
	ExecCommandStream(ctx context.Context, instanceID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func(stdout, stderr []byte, exitCode int32, finished bool)) error
	UpdateSandboxNetwork(ctx context.Context, instanceID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error

	// BuildTemplate kicks off an async template build on this vmd host.
	// Returns the opaque build VM id; poll GetBuildStatus with it until a
	// terminal status is reached. vmd runs the build well past this RPC's
	// lifetime; the call returns as soon as the build is enqueued.
	BuildTemplate(ctx context.Context, req BuildTemplateInput) (buildVMID string, err error)

	// GetBuildStatus polls the current state of a build dispatched via
	// BuildTemplate. NotFound=true signals vmd has no record of this build
	// (typically after a vmd restart lost the in-memory registry).
	GetBuildStatus(ctx context.Context, buildVMID string) (BuildStatusResult, error)

	// CancelBuild tells vmd to abort an in-flight build. Idempotent — safe
	// to call on unknown or already-terminal builds.
	CancelBuild(ctx context.Context, buildVMID string) error
}

// BuildTemplateInput mirrors vmdpb.BuildTemplateRequest at the client layer
// so callers don't have to import the proto package directly.
type BuildTemplateInput struct {
	TemplateID string
	From       string
	Steps      []BuildStep
	StartCmd   string
	ReadyCmd   string
	VCPU       uint32
	MemoryMiB  uint32
	DiskMiB    uint32
}

// BuildStep mirrors vmdpb.BuildStep — exactly one of Run/Copy/Env/Workdir.
type BuildStep struct {
	Run     *string
	Copy    *BuildCopyOp
	Env     *BuildEnvOp
	Workdir *string
}

type BuildCopyOp struct {
	Src string // base64-encoded tar
	Dst string
}

type BuildEnvOp struct {
	Key   string
	Value string
}

// BuildStatusResult is the decoded form of vmdpb.GetBuildStatusResponse.
// Status values: "running", "snapshotting", "ready", "failed", "cancelled".
type BuildStatusResult struct {
	NotFound       bool
	Status         string
	SnapshotPath   string // populated on ready
	MemFilePath    string // populated on ready
	RootfsPath     string // populated on ready
	ResolvedDigest string // populated on ready
	SizeBytes      int64  // populated on ready
	ErrorMessage   string // populated on failed/cancelled
	StartedAtUnix  int64
	EndedAtUnix    int64
}
