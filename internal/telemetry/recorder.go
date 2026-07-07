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
	RecordHostCapacity(context.Context, HostCapacity)
	RecordDBPoolStats(context.Context, DBPoolStats)
}

type noopRecorder struct{}

func NewNoopRecorder() Recorder                                                 { return noopRecorder{} }
func (noopRecorder) RecordSandboxTransition(context.Context, SandboxTransition) {}
func (noopRecorder) RecordVMDCall(context.Context, VMDCall)                     {}
func (noopRecorder) RecordHostCapacity(context.Context, HostCapacity)           {}
func (noopRecorder) RecordDBPoolStats(context.Context, DBPoolStats)             {}
