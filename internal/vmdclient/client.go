// Package vmdclient defines the interface for talking to a VM daemon.
// It lives in its own leaf package so both internal/api and
// internal/hostreg can reference it without circular imports.
package vmdclient

import (
	"context"
)

// PortPolicy is the control-plane representation of one published preview
// port. Phase 2 carries only its independent access mode; later phases may add
// credential state without changing the surrounding map shape.
type PortPolicy struct {
	Access string
}

// Client defines the subset of the VM daemon gRPC interface used by the
// control plane. Implementations: grpcVMDClient in cmd/controlplane,
// stubVMD in tests.
type Client interface {
	DestroyInstance(ctx context.Context, instanceID string, force bool) error
	PauseInstance(ctx context.Context, instanceID, snapshotDir string) (snapshotPath, memPath string, err error)
	// ResumeInstance restores a paused VM.
	ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	// RestoreSnapshot is the stateless restore path used as a fallback when
	// ResumeInstance fails with NotFound (e.g. after a VMD crash lost the
	// in-memory map but the snapshot files are still on disk). basePath +
	// deltaDir are populated for overlay-mode templates, empty for legacy.
	// For sandboxes with secrets the caller passes envVars=nil here and uses
	// InjectSandboxEnv below once the source IP is known and a JWT is minted.
	RestoreSnapshot(ctx context.Context, instanceID, snapshotPath, memPath, basePath, deltaDir, teamID, ownerID string, previewAccess string, previewPorts map[int32]PortPolicy, previewPolicyRevision int64, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error)
	// InjectSandboxEnv pushes env vars and the optional secrets JWT into a
	// running sandbox's boxd. Idempotent.
	InjectSandboxEnv(ctx context.Context, instanceID string, envVars map[string]string, secretsJWT string) error
	// DeleteSnapshot removes the on-disk vmstate + memory files for a
	// previous snapshot. Idempotent: missing files return nil. Used by the
	// control plane to garbage-collect the previous snapshot after a new
	// pause writes a fresh one.
	DeleteSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string) error
	// DeleteSandboxSnapshots removes a sandbox's entire on-disk snapshot
	// directory. Path-based and idempotent — reclaims pause artifacts even
	// when no snapshot row exists. Only for a sandbox being deleted.
	DeleteSandboxSnapshots(ctx context.Context, instanceID string) error
	// DeleteTemplateArtifacts removes a template's snapshot dir + rootfs
	// dir on the host. Idempotent.
	DeleteTemplateArtifacts(ctx context.Context, templateID string) error
	// DeleteBuildArtifacts removes a single build's subdir. Idempotent.
	DeleteBuildArtifacts(ctx context.Context, templateID, buildID string) error
	// ListBuildArtifacts returns all per-build dirs on this host's snapshot
	// storage. Used by the controlplane reconciler.
	ListBuildArtifacts(ctx context.Context) ([]BuildArtifactEntry, error)
	// ListDir returns a one-level listing of a directory inside a running VM
	// via boxd's FilesystemService.ListDir. Works on every sandbox regardless
	// of boxd version.
	ListDir(ctx context.Context, instanceID, path string) ([]DirEntry, error)
	UpdateSandboxNetwork(ctx context.Context, instanceID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error
	// UpdateSandboxPreviewPolicy atomically replaces the per-port preview policy
	// on the host record. A NotFound record is seeded on next restore.
	UpdateSandboxPreviewPolicy(ctx context.Context, instanceID, previewAccess string, previewPorts map[int32]PortPolicy, policyRevision int64) error

	// InvalidateSecret asks vmd's local secretsproxy daemon to drop the
	// cached cleartext for secretID. Used by the control plane to push
	// a rotation or revocation faster than the daemon's vault-cache TTL.
	// Idempotent on the daemon side.
	InvalidateSecret(ctx context.Context, secretID string) error

	// RevokeSandbox tells the local secretsproxy daemon that sandboxID's
	// JWT must no longer authorize requests. Idempotent.
	RevokeSandbox(ctx context.Context, sandboxID string) error

	// InvalidateSandboxRules asks the local secretsproxy daemon to drop its
	// cached egress rules for sandboxID, so the next request re-fetches them.
	// Used by the control plane after a network PATCH. Idempotent.
	InvalidateSandboxRules(ctx context.Context, sandboxID string) error

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

// BuildArtifactEntry mirrors vmdpb.BuildArtifactEntry — one per-build dir
// on a host's snapshot storage.
type BuildArtifactEntry struct {
	TemplateID string
	BuildID    string
	MTimeUnix  int64
}

// DirEntry mirrors vmdpb.ListDirEntry — one entry returned by ListDir.
// ModifiedUnix is 0 when the sandbox's boxd predates that field.
type DirEntry struct {
	Name         string
	IsDir        bool
	Size         int64
	ModifiedUnix int64
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
	BasePath       string // populated on ready, overlay-mode templates only
	DeltaPath      string // populated on ready, overlay-mode templates only
	ResolvedDigest string // populated on ready
	SizeBytes      int64  // populated on ready
	ErrorMessage   string // populated on failed/cancelled
	StartedAtUnix  int64
	EndedAtUnix    int64
}
