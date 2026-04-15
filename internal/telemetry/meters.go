package telemetry

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Cardinality discipline — read this before adding a metric.
//
// FORBIDDEN labels on counters and histograms:
//   - sandbox_id
//   - team_id / user_id
//   - api_key_id
//   - request_id / trace_id
//   - any other unbounded identifier
//
// These belong on traces and logs, not metrics. One rogue label explodes
// backend storage cost and makes dashboards unusable. Per-sandbox dimensions
// are handled via delta-temporality observable gauges (Phase 2 sandbox
// observer) where the series dies when the sandbox dies.
//
// ALLOWED label dimensions (small bounded enums):
//   - service, host_id, environment
//   - state, outcome (ok|error|timeout)
//   - kind, op, method, code
//   - status_class (2xx|4xx|5xx) — never raw HTTP status codes as labels
//
// Code sites import this package and call e.g.
// telemetry.SandboxLifecycleDuration().Record(ctx, secs, ...attrs).

const meterName = "github.com/superserve-ai/sandbox"

var (
	initOnce sync.Once

	sandboxLifecycleDuration metric.Float64Histogram
	snapshotOpDuration       metric.Float64Histogram
	snapshotOrphanGCTotal    metric.Int64Counter
	reconcilerRunDuration    metric.Float64Histogram
	reconcilerDriftTotal     metric.Int64Counter
	reaperReapedTotal        metric.Int64Counter
	proxyHMACFailuresTotal   metric.Int64Counter
	dataplaneAuthFailures    metric.Int64Counter
)

// initMeters lazily builds the metric handles against the global meter
// provider. Safe to call repeatedly; runs once.
func initMeters() {
	initOnce.Do(func() {
		m := otel.Meter(meterName)

		sandboxLifecycleDuration, _ = m.Float64Histogram(
			"sandbox.lifecycle.duration",
			metric.WithUnit("s"),
			metric.WithDescription("End-to-end duration of a sandbox lifecycle operation."),
		)
		snapshotOpDuration, _ = m.Float64Histogram(
			"sandbox.snapshot.duration",
			metric.WithUnit("s"),
			metric.WithDescription("Duration of a snapshot operation (create, restore, delete, gc)."),
		)
		snapshotOrphanGCTotal, _ = m.Int64Counter(
			"sandbox.snapshot.orphan_gc.total",
			metric.WithDescription("Snapshots reclaimed by the orphan GC."),
		)
		reconcilerRunDuration, _ = m.Float64Histogram(
			"vmd.reconciler.run.duration",
			metric.WithUnit("s"),
			metric.WithDescription("Duration of a reconciler tick."),
		)
		reconcilerDriftTotal, _ = m.Int64Counter(
			"vmd.reconciler.drift.total",
			metric.WithDescription("Drift events detected by the reconciler, by kind."),
		)
		reaperReapedTotal, _ = m.Int64Counter(
			"controlplane.reaper.reaped.total",
			metric.WithDescription("Sandboxes destroyed by the timeout reaper, by reason."),
		)
		proxyHMACFailuresTotal, _ = m.Int64Counter(
			"proxy.hmac.failures.total",
			metric.WithDescription("Edge-proxy data-plane requests rejected for invalid HMAC."),
		)
		dataplaneAuthFailures, _ = m.Int64Counter(
			"controlplane.auth.failures.total",
			metric.WithDescription("API key validation failures, by outcome."),
		)
	})
}

// SandboxLifecycleOp identifies the operation labelled on lifecycle metrics.
type SandboxLifecycleOp string

const (
	OpCreate  SandboxLifecycleOp = "create"
	OpPause   SandboxLifecycleOp = "pause"
	OpResume  SandboxLifecycleOp = "resume"
	OpDestroy SandboxLifecycleOp = "destroy"
)

// Outcome is the small bounded enum used on counters/histograms that need
// to distinguish success from failure. Never use raw error strings here.
type Outcome string

const (
	OutcomeOK      Outcome = "ok"
	OutcomeError   Outcome = "error"
	OutcomeTimeout Outcome = "timeout"
)

// RecordSandboxLifecycle records the duration of a sandbox lifecycle op.
// `from` is "cold" | "warm_pool" | "snapshot" for create; empty otherwise.
func RecordSandboxLifecycle(ctx context.Context, op SandboxLifecycleOp, outcome Outcome, from string, seconds float64) {
	initMeters()
	if sandboxLifecycleDuration == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("op", string(op)),
		attribute.String("outcome", string(outcome)),
	}
	if from != "" {
		attrs = append(attrs, attribute.String("from", from))
	}
	sandboxLifecycleDuration.Record(ctx, seconds, metric.WithAttributes(attrs...))
}

// RecordSnapshotOp records the duration of a snapshot operation.
// op ∈ {"create", "restore", "delete", "gc"}.
func RecordSnapshotOp(ctx context.Context, op string, outcome Outcome, seconds float64) {
	initMeters()
	if snapshotOpDuration == nil {
		return
	}
	snapshotOpDuration.Record(ctx, seconds, metric.WithAttributes(
		attribute.String("op", op),
		attribute.String("outcome", string(outcome)),
	))
}

// IncSnapshotOrphanGC increments the orphan-snapshot GC counter.
func IncSnapshotOrphanGC(ctx context.Context, n int64) {
	initMeters()
	if snapshotOrphanGCTotal == nil || n == 0 {
		return
	}
	snapshotOrphanGCTotal.Add(ctx, n)
}

// RecordReconcilerRun records one reconciler tick duration.
func RecordReconcilerRun(ctx context.Context, seconds float64) {
	initMeters()
	if reconcilerRunDuration == nil {
		return
	}
	reconcilerRunDuration.Record(ctx, seconds)
}

// IncReconcilerDrift increments the drift counter for `kind`. Bounded enum.
func IncReconcilerDrift(ctx context.Context, kind string) {
	initMeters()
	if reconcilerDriftTotal == nil {
		return
	}
	reconcilerDriftTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", kind)))
}

// IncReaperReaped increments the reaper counter labelled by reason.
// reason ∈ {"timeout", "paused_max_age", "destroyed"}.
func IncReaperReaped(ctx context.Context, reason string, n int64) {
	initMeters()
	if reaperReapedTotal == nil || n == 0 {
		return
	}
	reaperReapedTotal.Add(ctx, n, metric.WithAttributes(attribute.String("reason", reason)))
}

// IncProxyHMACFailure records a rejected data-plane request.
func IncProxyHMACFailure(ctx context.Context) {
	initMeters()
	if proxyHMACFailuresTotal == nil {
		return
	}
	proxyHMACFailuresTotal.Add(ctx, 1)
}

// IncAuthFailure records a control-plane API key auth failure.
// outcome ∈ {"expired", "invalid", "revoked"}.
func IncAuthFailure(ctx context.Context, outcome string) {
	initMeters()
	if dataplaneAuthFailures == nil {
		return
	}
	dataplaneAuthFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RegisterPoolGauge registers an observable up-down counter that publishes
// the current available count of `kind`. The callback is invoked on each
// metric export tick (15s). kind ∈ {"tap", "netns", "ip", "snapshot_overlay"}.
func RegisterPoolGauge(kind string, getter func() int64) error {
	initMeters()
	m := otel.Meter(meterName)
	_, err := m.Int64ObservableUpDownCounter(
		"vmd.pool.available",
		metric.WithDescription("Available slots in a pre-allocated pool."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(getter(), metric.WithAttributes(attribute.String("kind", kind)))
			return nil
		}),
	)
	return err
}

// RegisterActiveSandboxesGauge registers an observable up-down counter that
// publishes the count of sandboxes currently in `state`. Use a single
// callback that emits one observation per state to keep cardinality bounded.
func RegisterActiveSandboxesGauge(getter func() map[string]int64) error {
	initMeters()
	m := otel.Meter(meterName)
	_, err := m.Int64ObservableUpDownCounter(
		"sandbox.active",
		metric.WithDescription("Sandboxes currently in each lifecycle state."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for state, n := range getter() {
				o.Observe(n, metric.WithAttributes(attribute.String("state", state)))
			}
			return nil
		}),
	)
	return err
}
