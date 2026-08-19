package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Backup upload results. Bounded by safeUploadResult; anything outside the
// vocabulary is recorded as failed rather than minting a new label value.
const (
	BackupUploadVerified  = "verified"  // generation streamed and digest-verified in the bucket
	BackupUploadDeduped   = "deduped"   // generation completed without streaming new bytes
	BackupUploadAbandoned = "abandoned" // sources gone or mutated; nothing made durable
	BackupUploadFailed    = "failed"    // attempt errored; task nacked for retry
)

// Journal priorities as metric label values. Bounded by construction: the
// recorder only ever emits these three.
const (
	BackupPriorityPause      = "pause"
	BackupPriorityCheckpoint = "checkpoint"
	BackupPriorityBestEffort = "best_effort"
)

// BackupOTelConfig configures the vmd-side backup recorder. HostID is
// static per process (one vmd per host), unlike the control plane's
// per-call host label.
type BackupOTelConfig struct {
	OTelConfig
	HostID string
}

// BackupSample is one periodic gauge snapshot of the backup pipeline.
// Enabled is emitted even when the pipeline is off: a production host
// running with backup silently disabled must be visible as
// backup_enabled=0, not as an absence of data.
// Each read that backs a gauge below carries its own OK flag: a failed
// BoltDB/state-store read must drop that gauge from the sample rather than
// publish a zero, which would read as an empty queue and could reset the
// backlog-age alert or suppress the stalled-outbox alert.
type BackupSample struct {
	Enabled bool

	PendingPause, PendingCheckpoint, PendingBestEffort int
	PendingOK                                          bool

	// Oldest*Age is the age of each tier's oldest queued task by enqueue
	// time; zero when that tier is empty. Per tier because the tiers
	// have opposite service expectations: pause freshness is the alerted
	// signal, while a best-effort backfill backlog is deliberately
	// patient.
	OldestPauseAge, OldestCheckpointAge, OldestBestEffortAge time.Duration
	OldestPendingAgeOK                                       bool

	PendingMarkers   int
	PendingMarkersOK bool

	OutboxPending   int
	OutboxPendingOK bool
}

// BackupRecorder emits the backup pipeline's bounded operational metrics
// through OTLP. All methods are nil-safe: a nil recorder (metrics
// disabled) makes every call a no-op, so instrumented code paths never
// branch on whether metrics are configured, and recording can never
// affect backup behavior.
type BackupRecorder struct {
	provider *sdkmetric.MeterProvider

	serviceName string
	environment string
	hostID      string
	instanceID  string

	enabled           metric.Int64Gauge
	journalPending    metric.Int64Gauge
	oldestPendingAge  metric.Float64Gauge
	pendingMarkers    metric.Int64Gauge
	outboxPending     metric.Int64Gauge
	uploads           metric.Int64Counter
	uploadBytes       metric.Int64Counter
	notifyFailures    metric.Int64Counter
	hashDuration      metric.Float64Histogram
	stageDuration     metric.Float64Histogram
	uploadDuration    metric.Float64Histogram
	pauseHookDuration metric.Float64Histogram
}

// Explicit histogram boundaries: the SDK defaults top out at 10 and were
// chosen for milliseconds, which would collapse every second-scale
// observation into one bucket and make the p99 alerts meaningless.
var (
	// Hook and staging work is O(dirtied bytes): normally tens of ms; a
	// disk-size-scaled synchronous regression lands in whole seconds.
	backupFastBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	// Hashing and uploads scale with artifact size under the bandwidth
	// cap: seconds for typical overlays, minutes for multi-GB bases.
	backupSlowBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}
)

// NewBackupRecorder constructs an OTLP/HTTP backup metrics recorder, the
// same env-driven construction as NewOTelRecorder but under the vmd
// service name. Call Shutdown on process exit to flush briefly.
func NewBackupRecorder(ctx context.Context, cfg BackupOTelConfig) (*BackupRecorder, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sandbox-vmd"
	}
	if cfg.Environment == "" {
		cfg.Environment = "dev"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "http://localhost:4318"
	}
	if cfg.ExportInterval <= 0 {
		cfg.ExportInterval = 15 * time.Second
	}
	// Every meter-provider constructor in this package must resolve its own
	// InstanceID — see resolveInstanceID for why this can't live in a
	// shared helper further down the call chain.
	cfg.InstanceID = resolveInstanceID(cfg.InstanceID)
	provider, err := newOTLPMeterProvider(ctx, cfg.OTelConfig)
	if err != nil {
		return nil, err
	}
	return NewBackupRecorderWithProvider(provider, cfg)
}

// NewBackupRecorderWithProvider builds the recorder's instruments on an
// existing meter provider. Tests pass one backed by a manual reader.
func NewBackupRecorderWithProvider(provider *sdkmetric.MeterProvider, cfg BackupOTelConfig) (*BackupRecorder, error) {
	meter := provider.Meter(instrumentationName)
	r := &BackupRecorder{
		provider:    provider,
		serviceName: cfg.ServiceName,
		environment: cfg.Environment,
		hostID:      safeHostID(cfg.HostID),
		instanceID:  cfg.InstanceID,
	}
	var err error
	if r.enabled, err = meter.Int64Gauge("backup_enabled"); err != nil {
		return nil, err
	}
	if r.journalPending, err = meter.Int64Gauge("backup_journal_pending"); err != nil {
		return nil, err
	}
	if r.oldestPendingAge, err = meter.Float64Gauge("backup_oldest_pending_age_seconds"); err != nil {
		return nil, err
	}
	if r.pendingMarkers, err = meter.Int64Gauge("backup_pending_markers"); err != nil {
		return nil, err
	}
	if r.outboxPending, err = meter.Int64Gauge("backup_outbox_pending"); err != nil {
		return nil, err
	}
	if r.uploads, err = meter.Int64Counter("backup_upload_total"); err != nil {
		return nil, err
	}
	if r.uploadBytes, err = meter.Int64Counter("backup_upload_bytes_total"); err != nil {
		return nil, err
	}
	if r.notifyFailures, err = meter.Int64Counter("backup_notify_failures_total"); err != nil {
		return nil, err
	}
	if r.hashDuration, err = meter.Float64Histogram("backup_hash_duration_seconds",
		metric.WithExplicitBucketBoundaries(backupSlowBuckets...)); err != nil {
		return nil, err
	}
	if r.stageDuration, err = meter.Float64Histogram("backup_stage_duration_seconds",
		metric.WithExplicitBucketBoundaries(backupFastBuckets...)); err != nil {
		return nil, err
	}
	if r.uploadDuration, err = meter.Float64Histogram("backup_upload_duration_seconds",
		metric.WithExplicitBucketBoundaries(backupSlowBuckets...)); err != nil {
		return nil, err
	}
	if r.pauseHookDuration, err = meter.Float64Histogram("backup_pause_hook_duration_seconds",
		metric.WithExplicitBucketBoundaries(backupFastBuckets...)); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *BackupRecorder) Shutdown(ctx context.Context) error {
	if r == nil || r.provider == nil {
		return nil
	}
	return r.provider.Shutdown(ctx)
}

// RecordUpload counts one task attempt's outcome and its wall time.
func (r *BackupRecorder) RecordUpload(ctx context.Context, result string, d time.Duration) {
	if r == nil {
		return
	}
	opt := metric.WithAttributes(r.attrs(attribute.String("result", safeUploadResult(result)))...)
	r.uploads.Add(ctx, 1, opt)
	if d >= 0 {
		r.uploadDuration.Record(ctx, d.Seconds(), opt)
	}
}

// AddUploadBytes counts bytes streamed into newly created bucket objects
// (dedupes ship nothing new and count zero).
func (r *BackupRecorder) AddUploadBytes(ctx context.Context, n int64) {
	if r == nil || n <= 0 {
		return
	}
	r.uploadBytes.Add(ctx, n, metric.WithAttributes(r.attrs()...))
}

// RecordHashDuration observes one artifact-manifest hashing pass.
func (r *BackupRecorder) RecordHashDuration(ctx context.Context, d time.Duration) {
	if r == nil {
		return
	}
	r.hashDuration.Record(ctx, d.Seconds(), metric.WithAttributes(r.attrs()...))
}

// RecordStageDuration observes one staging copy (pause artifacts or an
// enqueue-path snapshot).
func (r *BackupRecorder) RecordStageDuration(ctx context.Context, d time.Duration) {
	if r == nil {
		return
	}
	r.stageDuration.Record(ctx, d.Seconds(), metric.WithAttributes(r.attrs()...))
}

// RecordPauseHookDuration observes the synchronous time the pause RPC
// path spends in the backup hook. It exists so any synchronous term
// added to this path alerts instead of surfacing only in logs.
func (r *BackupRecorder) RecordPauseHookDuration(ctx context.Context, d time.Duration) {
	if r == nil {
		return
	}
	r.pauseHookDuration.Record(ctx, d.Seconds(), metric.WithAttributes(r.attrs()...))
}

// AddNotifyFailure counts one failed completion-notification delivery
// step (outbox read or clear); the outbox retries, so a sustained rate
// means write-back is stalled.
func (r *BackupRecorder) AddNotifyFailure(ctx context.Context) {
	if r == nil {
		return
	}
	r.notifyFailures.Add(ctx, 1, metric.WithAttributes(r.attrs()...))
}

// RecordSample emits the periodic gauge snapshot.
func (r *BackupRecorder) RecordSample(ctx context.Context, s BackupSample) {
	if r == nil {
		return
	}
	opt := metric.WithAttributes(r.attrs()...)
	enabled := int64(0)
	if s.Enabled {
		enabled = 1
	}
	r.enabled.Record(ctx, enabled, opt)
	if s.PendingOK {
		r.journalPending.Record(ctx, int64(s.PendingPause),
			metric.WithAttributes(r.attrs(attribute.String("priority", BackupPriorityPause))...))
		r.journalPending.Record(ctx, int64(s.PendingCheckpoint),
			metric.WithAttributes(r.attrs(attribute.String("priority", BackupPriorityCheckpoint))...))
		r.journalPending.Record(ctx, int64(s.PendingBestEffort),
			metric.WithAttributes(r.attrs(attribute.String("priority", BackupPriorityBestEffort))...))
	}
	if s.OldestPendingAgeOK {
		for _, tier := range []struct {
			age      time.Duration
			priority string
		}{
			{s.OldestPauseAge, BackupPriorityPause},
			{s.OldestCheckpointAge, BackupPriorityCheckpoint},
			{s.OldestBestEffortAge, BackupPriorityBestEffort},
		} {
			age := tier.age.Seconds()
			if age < 0 { // clock skew must not report a negative backlog
				age = 0
			}
			r.oldestPendingAge.Record(ctx, age,
				metric.WithAttributes(r.attrs(attribute.String("priority", tier.priority))...))
		}
	}
	if s.PendingMarkersOK {
		r.pendingMarkers.Record(ctx, int64(s.PendingMarkers), opt)
	}
	if s.OutboxPendingOK {
		r.outboxPending.Record(ctx, int64(s.OutboxPending), opt)
	}
}

func (r *BackupRecorder) attrs(extra ...attribute.KeyValue) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", r.serviceName),
		attribute.String("environment", r.environment),
		attribute.String("host_id", r.hostID),
	}
	return append(attrs, extra...)
}

func safeUploadResult(v string) string {
	switch v {
	case BackupUploadVerified, BackupUploadDeduped, BackupUploadAbandoned, BackupUploadFailed:
		return v
	default:
		return BackupUploadFailed
	}
}
