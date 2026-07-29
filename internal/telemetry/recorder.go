package telemetry

import (
	"context"
	"time"
)

const (
	ResultSuccess  = "success"
	ResultError    = "error"
	ResultConflict = "conflict"
	ResultTimeout  = "timeout"

	SavedSnapshotOperationCapture = "capture"
	SavedSnapshotOperationRestore = "restore"
	SavedSnapshotOperationDelete  = "delete"
	SavedSnapshotOperationCleanup = "cleanup"

	SavedSnapshotOutcomeSuccess           = ResultSuccess
	SavedSnapshotOutcomeError             = ResultError
	SavedSnapshotOutcomeRetry             = "retry"
	SavedSnapshotOutcomeQueued            = "queued"
	SavedSnapshotOutcomeDependencyBlocked = "dependency_blocked"
	SavedSnapshotOutcomeArtifactCorrupt   = "artifact_corrupt"
	SavedSnapshotOutcomeUnavailable       = "artifact_unavailable"
)

// SandboxTransition records low-cardinality operational lifecycle metrics.
// Keep tenant, user, API key, and sandbox identifiers out of metric labels;
// use logs or traces for per-sandbox investigation.
type SandboxTransition struct {
	Operation string
	Result    string
	Region    string
	HostID    string
	Duration  time.Duration
}

// VMDCall records operational health for calls to VM daemons. Method and
// result should be bounded enums, not raw error messages.
type VMDCall struct {
	Method   string
	Result   string
	Region   string
	HostID   string
	Duration time.Duration
}

// SavedSnapshotOutcome records snapshot-specific state and reconciliation
// outcomes that a generic RPC result cannot describe. Operation and Outcome
// are closed enums; identifiers, paths, failure reasons, and raw errors must
// remain in logs or audit events rather than metric labels.
type SavedSnapshotOutcome struct {
	Operation string
	Outcome   string
	Region    string
	HostID    string
}

// HostCapacity records aggregate host capacity. This is intentionally
// host-scoped, not sandbox-scoped, so millions of sandboxes do not create
// millions of time series.
type HostCapacity struct {
	Region        string
	HostID        string
	UsedVCPU      int64
	UsedMemoryMiB int64
	Sandboxes     int64
}

// DBPoolStats records pgxpool pressure and acquisition health. The *Delta
// fields are per-sample deltas from pgxpool.Stat() cumulative counters.
type DBPoolStats struct {
	AcquiredConns               int64
	IdleConns                   int64
	TotalConns                  int64
	AcquireDelta                int64
	EmptyAcquireDelta           int64
	CanceledAcquireDelta        int64
	AcquireDurationSecondsDelta float64
}

// Recorder is the operational metrics boundary. Implementations should emit
// OpenTelemetry metrics through a collector; callers should not write ad hoc
// operational metrics into Postgres.
type Recorder interface {
	RecordSandboxTransition(context.Context, SandboxTransition)
	RecordVMDCall(context.Context, VMDCall)
	RecordSavedSnapshotOutcome(context.Context, SavedSnapshotOutcome)
	RecordHostCapacity(context.Context, HostCapacity)
	RecordDBPoolStats(context.Context, DBPoolStats)
}

type noopRecorder struct{}

func NewNoopRecorder() Recorder                                                 { return noopRecorder{} }
func (noopRecorder) RecordSandboxTransition(context.Context, SandboxTransition) {}
func (noopRecorder) RecordVMDCall(context.Context, VMDCall)                     {}
func (noopRecorder) RecordSavedSnapshotOutcome(context.Context, SavedSnapshotOutcome) {
}
func (noopRecorder) RecordHostCapacity(context.Context, HostCapacity) {}
func (noopRecorder) RecordDBPoolStats(context.Context, DBPoolStats)   {}
