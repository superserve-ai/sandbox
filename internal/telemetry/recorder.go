package telemetry

import (
	"context"
	"time"
)

const (
	ResultSuccess     = "success"
	ResultError       = "error"
	ResultConflict    = "conflict"
	ResultTimeout     = "timeout"
	ResultClientError = "client_error"
)

// Result values for SandboxResumeSettleWait. Distinct from the ResultX enum
// above: none of these outcomes map onto success/error/conflict.
// "Settled" means specifically pausing→paused — the outcome the wait exists
// for. A row that left 'pausing' for any other state (a failed pause
// reverting to active, a delete claiming the row) diverged: the resume still
// 409s, and counting it as settled would contaminate the settle metric with
// pause failures.
const (
	SettleResultSettled  = "settled"  // pausing → paused; the resume proceeds
	SettleResultDiverged = "diverged" // pausing → any non-paused state; the resume 409s
	SettleResultTimeout  = "timeout"  // still 'pausing' when the window expired
	SettleResultCanceled = "canceled" // caller disconnected or timed out mid-wait
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

// SandboxResumeSettleWait records ResumeSandbox waiting through a racing
// finalize-pause write (pausing -> paused) before it could proceed or gave
// up. Emitted once per resume that had to wait past the first read — never
// per poll — so its volume tracks resume request rate, not poll count. This
// is what lets "resume settled through a race" be told apart from "resume
// was just slow" in dashboards, since both would otherwise fold into the
// same overall resume duration histogram.
type SandboxResumeSettleWait struct {
	Result   string // one of the SettleResult* constants
	Region   string
	HostID   string
	Duration time.Duration
	Reads    int64
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

// BackupCoverage records, per host, how many paused, non-destroyed
// sandboxes have no verified backup generation, and the age of the
// oldest such pause. Host-scoped like HostCapacity so cardinality stays
// bounded by the fleet, not the sandbox population. An explicit zero is
// meaningful: it is what lets the coverage alert clear deterministically
// once a host's backlog converges.
//
// Unlike the other gauge families, coverage is recorded as a full
// snapshot (a slice of these) that REPLACES the previous one, because
// exactly one lease-elected replica per cell may publish it: snapshot
// semantics let a replica that lost the lease publish an empty snapshot
// and stop exporting entirely, where per-point recording would leave
// its last values exporting forever.
type BackupCoverage struct {
	Region                    string
	HostID                    string
	UncoveredPaused           int64
	OldestUncoveredAgeSeconds float64
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

// PausedNetworkPressure records a pressure-controller snapshot and any reclaim
// activity performed during that pass.
type PausedNetworkPressure struct {
	TotalSlots     int64
	UsedSlots      int64
	AvailableSlots int64
	FreshPool      int64
	RecycledPool   int64
	NetnsTotal     int64
	MountTotal     int64
	PressureState  string

	ReclaimedRecycle  int64
	ReclaimedTeardown int64
	ReclaimedPaused   int64
}

// LauncherState is a per-host sample of the launch path: whether Firecracker is
// starting inside the pruned launcher mount namespace, or has fallen back to the
// legacy path and pays the full host mount table on every start.
//
// Emitted on its own cadence rather than riding the paused-network snapshot,
// because a host on the legacy path is a latency incident whether or not the
// reclaim controller is enabled.
type LauncherState struct {
	Ready bool
}

// LatencyPhase records one timed phase of a sandbox operation, the unit the
// latency dashboards aggregate (p50/p90/p99 via histogram_quantile). Every
// label is a bounded enum owned by the emitting call site — never tenant,
// sandbox, or error text.
type LatencyPhase struct {
	Plane    string // controlplane | vmd | dataplane
	Op       string // create | resume | launch | restore | exec
	Phase    string // e.g. sched, vmd, cgroup, wait_socket, wait_boxd, run
	Mode     string // direct | unit | "" where supervision doesn't apply
	Region   string
	HostID   string
	Duration time.Duration
}

// CapacityShadow is one shadow ranking evaluation: what capacity-based
// placement WOULD have chosen, measured against what the live scheduler
// actually did, plus how much of the fleet is describable at all.
// Emitted from a background worker, never from a request. Every label is
// a bounded enum owned by the scheduler.
type CapacityShadow struct {
	Result    string // ranked | no_candidates | error
	Agreement string // same | different | unknown
	// Fleet composition as the ranker saw it, for readiness tracking.
	Described      int
	UnderDescribed int
	Legacy         int
	Stale          int
	Duration       time.Duration
}

// Recorder is the operational metrics boundary. Implementations should emit
// OpenTelemetry metrics through a collector; callers should not write ad hoc
// operational metrics into Postgres.
type Recorder interface {
	RecordSandboxTransition(context.Context, SandboxTransition)
	RecordSandboxResumeSettleWait(context.Context, SandboxResumeSettleWait)
	RecordVMDCall(context.Context, VMDCall)
	RecordHostResolution(context.Context, HostResolution)
	RecordCapacityShadow(context.Context, CapacityShadow)
	RecordHostCapacity(context.Context, HostCapacity)
	RecordBackupCoverage(context.Context, []BackupCoverage)
	RecordDBPoolStats(context.Context, DBPoolStats)
	RecordPausedNetworkPressure(context.Context, PausedNetworkPressure)
	RecordLauncherState(context.Context, LauncherState)
	RecordLatencyPhase(context.Context, LatencyPhase)
}

type noopRecorder struct{}

func NewNoopRecorder() Recorder { return noopRecorder{} }

// isNoopRecorder reports whether r is the do-nothing recorder main
// falls back to when OTel init fails. Components that hold exclusive
// resources in exchange for exporting metrics (the coverage sampler's
// lease) check this so a replica that cannot export never takes the
// resource from one that can. Recorders that merely embed the noop
// (test fakes) are not the noop.
func isNoopRecorder(r Recorder) bool {
	_, ok := r.(noopRecorder)
	return ok
}
func (noopRecorder) RecordSandboxTransition(context.Context, SandboxTransition)             {}
func (noopRecorder) RecordSandboxResumeSettleWait(context.Context, SandboxResumeSettleWait) {}
func (noopRecorder) RecordVMDCall(context.Context, VMDCall)                                 {}
func (noopRecorder) RecordHostResolution(context.Context, HostResolution)                   {}
func (noopRecorder) RecordCapacityShadow(context.Context, CapacityShadow)                   {}
func (noopRecorder) RecordHostCapacity(context.Context, HostCapacity)                       {}
func (noopRecorder) RecordBackupCoverage(context.Context, []BackupCoverage)                 {}
func (noopRecorder) RecordDBPoolStats(context.Context, DBPoolStats)                         {}
func (noopRecorder) RecordPausedNetworkPressure(context.Context, PausedNetworkPressure)     {}
func (noopRecorder) RecordLauncherState(context.Context, LauncherState)                     {}
func (noopRecorder) RecordLatencyPhase(context.Context, LatencyPhase)                       {}
