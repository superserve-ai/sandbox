// Package vmdclient defines the interface for talking to a VM daemon.
// It lives in its own leaf package so both internal/api and
// internal/hostreg can reference it without circular imports.
package vmdclient

import "context"

// Client defines the subset of the VM daemon gRPC interface used by the
// control plane. Implementations: grpcVMDClient in cmd/controlplane,
// stubVMD in tests.
type Client interface {
	DestroyInstance(ctx context.Context, instanceID string, force bool) error
	PauseInstance(ctx context.Context, instanceID, snapshotDir string) (snapshotPath, memPath string, err error)
	ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	// RestoreSnapshot is the stateless restore path used as a fallback when
	// ResumeInstance fails with NotFound (e.g. after a VMD crash lost the
	// in-memory map but the snapshot files are still on disk).
	RestoreSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	// DeleteSnapshot removes the on-disk vmstate + memory files for a
	// previous snapshot. Idempotent: missing files return nil. Used by the
	// control plane to garbage-collect the previous snapshot after a new
	// pause writes a fresh one.
	DeleteSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string) error
	// DeleteTemplateArtifacts removes a template's snapshot dir + rootfs
	// dir on the host. Idempotent.
	DeleteTemplateArtifacts(ctx context.Context, templateID string) error
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

	// StreamBuildLogs opens a server-streaming RPC and delivers each event
	// to onEvent. Replays buffered history first, then streams live events
	// until the build reaches a terminal status (stream closes cleanly) or
	// ctx is cancelled. Returns nil on clean close, an error on transport
	// failure or gRPC NotFound (which callers surface as SSE 404).
	StreamBuildLogs(ctx context.Context, buildVMID string, onEvent func(BuildLogEvent) error) error
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
	// BuildVMID overrides vmd's default id generation.
	BuildVMID string
}

// BuildStep mirrors vmdpb.BuildStep — exactly one of Run/Env/Workdir/User.
type BuildStep struct {
	Run     *string
	Env     *BuildEnvOp
	Workdir *string
	User    *BuildUserOp
}

type BuildEnvOp struct {
	Key   string
	Value string
}

type BuildUserOp struct {
	Name string
	Sudo bool
}

// BuildLogEvent is one decoded event from StreamBuildLogs. Finished=true
// signals the build reached a terminal status and the stream has closed.
type BuildLogEvent struct {
	TimestampUnixNanos int64
	Stream             string // "stdout" | "stderr" | "system"
	Text               string
	Finished           bool
	Status             string // "ready" | "failed" | "cancelled" when Finished
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
