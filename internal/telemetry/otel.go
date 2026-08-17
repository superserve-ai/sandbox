package telemetry

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const instrumentationName = "github.com/superserve-ai/sandbox/internal/telemetry"

// OTelConfig contains the app-level metrics settings needed by the recorder.
type OTelConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	Endpoint       string
	Insecure       bool
	ExportInterval time.Duration
	// HostID scopes per-host series to the host that produced them. The
	// collector stamps host_id only onto its own hostmetrics pipeline,
	// assuming OTLP senders label their own series — so without this, a
	// per-host gauge is indistinguishable between cells and cannot be
	// alerted on per host. Empty (the control plane, which is not per-host)
	// records as "unknown".
	HostID string
}

// OTelRecorder emits the sandbox control plane's bounded operational metrics
// through OTLP. It intentionally exposes only a small label vocabulary.
type OTelRecorder struct {
	provider *sdkmetric.MeterProvider

	serviceName string
	environment string
	hostID      string

	sandboxTransitions       metric.Int64Counter
	sandboxDuration          metric.Float64Histogram
	resumeSettleWaits        metric.Int64Counter
	resumeSettleWaitDuration metric.Float64Histogram
	resumeSettleWaitReads    metric.Int64Histogram
	vmdCalls                 metric.Int64Counter
	vmdDuration              metric.Float64Histogram
	hostVCPU                 metric.Int64Gauge
	hostMemoryMiB            metric.Int64Gauge
	hostSandboxes            metric.Int64Gauge
	// Observable, uniquely in this file: coverage is published by one
	// lease-elected replica per cell, and a synchronous gauge retains
	// its last value per process, so a replica that lost leadership
	// would keep exporting stale competing series for its lifetime.
	// The callback exports only the current snapshot, so a non-leader
	// (holding an empty snapshot) exports nothing at all.
	backupUncoveredPaused    metric.Int64ObservableGauge
	backupUncoveredOldestAge metric.Float64ObservableGauge
	backupCoverageMu         sync.Mutex
	backupCoverage           []BackupCoverage
	dbAcquiredConns          metric.Int64Gauge
	dbIdleConns              metric.Int64Gauge
	dbTotalConns             metric.Int64Gauge
	dbAcquire                metric.Int64Counter
	dbEmptyAcquire           metric.Int64Counter
	dbCanceledAcquire        metric.Int64Counter
	dbAcquireDurationSeconds metric.Float64Counter
	pausedNetworkSlotsTotal  metric.Int64Gauge
	pausedNetworkSlotsUsed   metric.Int64Gauge
	pausedNetworkSlotsAvail  metric.Int64Gauge
	pausedNetworkPoolSlots   metric.Int64Gauge
	pausedNetworkNetnsTotal  metric.Int64Gauge
	pausedNetworkMountTotal  metric.Int64Gauge
	pausedNetworkPressure    metric.Int64Gauge
	pausedNetworkReclaimed   metric.Int64Counter
	pausedNetworkPaused      metric.Int64Counter
	launcherReady            metric.Int64Gauge
}

// NewOTelRecorder constructs an OTLP/HTTP metrics recorder. Call Shutdown on
// process exit to flush briefly without blocking shutdown indefinitely.
func NewOTelRecorder(ctx context.Context, cfg OTelConfig) (*OTelRecorder, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sandbox-controlplane"
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

	provider, err := newOTLPMeterProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	meter := provider.Meter(instrumentationName)

	r := &OTelRecorder{
		provider:    provider,
		serviceName: cfg.ServiceName,
		environment: cfg.Environment,
		hostID:      safeHostID(cfg.HostID),
	}
	if r.sandboxTransitions, err = meter.Int64Counter("sandbox_transition_total"); err != nil {
		return nil, err
	}
	if r.sandboxDuration, err = meter.Float64Histogram("sandbox_transition_duration_seconds"); err != nil {
		return nil, err
	}
	if r.resumeSettleWaits, err = meter.Int64Counter("sandbox_resume_settle_wait_total"); err != nil {
		return nil, err
	}
	if r.resumeSettleWaitDuration, err = meter.Float64Histogram("sandbox_resume_settle_wait_duration_seconds"); err != nil {
		return nil, err
	}
	if r.resumeSettleWaitReads, err = meter.Int64Histogram("sandbox_resume_settle_wait_reads"); err != nil {
		return nil, err
	}
	if r.vmdCalls, err = meter.Int64Counter("vmd_call_total"); err != nil {
		return nil, err
	}
	if r.vmdDuration, err = meter.Float64Histogram("vmd_call_duration_seconds"); err != nil {
		return nil, err
	}
	if r.hostVCPU, err = meter.Int64Gauge("host_capacity_used_vcpu"); err != nil {
		return nil, err
	}
	if r.hostMemoryMiB, err = meter.Int64Gauge("host_capacity_used_memory_mib"); err != nil {
		return nil, err
	}
	if r.hostSandboxes, err = meter.Int64Gauge("host_capacity_running_sandboxes"); err != nil {
		return nil, err
	}
	if r.backupUncoveredPaused, err = meter.Int64ObservableGauge("backup_uncovered_paused_sandboxes"); err != nil {
		return nil, err
	}
	if r.backupUncoveredOldestAge, err = meter.Float64ObservableGauge("backup_uncovered_oldest_age_seconds"); err != nil {
		return nil, err
	}
	if _, err = meter.RegisterCallback(r.observeBackupCoverage, r.backupUncoveredPaused, r.backupUncoveredOldestAge); err != nil {
		return nil, err
	}
	if r.dbAcquiredConns, err = meter.Int64Gauge("db_pool_acquired_conns"); err != nil {
		return nil, err
	}
	if r.dbIdleConns, err = meter.Int64Gauge("db_pool_idle_conns"); err != nil {
		return nil, err
	}
	if r.dbTotalConns, err = meter.Int64Gauge("db_pool_total_conns"); err != nil {
		return nil, err
	}
	if r.dbAcquire, err = meter.Int64Counter("db_pool_acquire_total"); err != nil {
		return nil, err
	}
	if r.dbEmptyAcquire, err = meter.Int64Counter("db_pool_empty_acquire_total"); err != nil {
		return nil, err
	}
	if r.dbCanceledAcquire, err = meter.Int64Counter("db_pool_canceled_acquire_total"); err != nil {
		return nil, err
	}
	if r.dbAcquireDurationSeconds, err = meter.Float64Counter("db_pool_acquire_duration_seconds_total"); err != nil {
		return nil, err
	}
	if r.pausedNetworkSlotsTotal, err = meter.Int64Gauge("vmd_network_slots_total"); err != nil {
		return nil, err
	}
	if r.pausedNetworkSlotsUsed, err = meter.Int64Gauge("vmd_network_slots_used"); err != nil {
		return nil, err
	}
	if r.pausedNetworkSlotsAvail, err = meter.Int64Gauge("vmd_network_slots_available"); err != nil {
		return nil, err
	}
	if r.pausedNetworkPoolSlots, err = meter.Int64Gauge("vmd_network_pool_slots"); err != nil {
		return nil, err
	}
	if r.pausedNetworkNetnsTotal, err = meter.Int64Gauge("vmd_network_netns_total"); err != nil {
		return nil, err
	}
	if r.pausedNetworkMountTotal, err = meter.Int64Gauge("vmd_network_mounts_total"); err != nil {
		return nil, err
	}
	if r.pausedNetworkPressure, err = meter.Int64Gauge("vmd_network_controller_pressure_state"); err != nil {
		return nil, err
	}
	if r.pausedNetworkReclaimed, err = meter.Int64Counter("vmd_network_slots_reclaimed_total"); err != nil {
		return nil, err
	}
	if r.pausedNetworkPaused, err = meter.Int64Counter("vmd_network_slots_reclaimed_paused_total"); err != nil {
		return nil, err
	}
	if r.launcherReady, err = meter.Int64Gauge("vmd_launcher_ready"); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *OTelRecorder) Shutdown(ctx context.Context) error {
	if r == nil || r.provider == nil {
		return nil
	}
	return r.provider.Shutdown(ctx)
}

func (r *OTelRecorder) RecordSandboxTransition(ctx context.Context, t SandboxTransition) {
	if r == nil {
		return
	}
	attrs := r.attrs(
		attribute.String("operation", safeOperation(t.Operation)),
		attribute.String("result", safeResult(t.Result)),
		attribute.String("region", safeRegion(t.Region)),
		attribute.String("host_id", safeHostID(t.HostID)),
	)
	opt := metric.WithAttributes(attrs...)
	r.sandboxTransitions.Add(ctx, 1, opt)
	if t.Duration > 0 {
		r.sandboxDuration.Record(ctx, t.Duration.Seconds(), opt)
	}
}

// RecordSandboxResumeSettleWait is called at most once per resume request —
// only when ResumeSandbox actually had to wait out a racing finalize-pause —
// so its cost does not scale with poll count.
func (r *OTelRecorder) RecordSandboxResumeSettleWait(ctx context.Context, w SandboxResumeSettleWait) {
	if r == nil {
		return
	}
	attrs := r.attrs(
		attribute.String("result", safeSettleResult(w.Result)),
		attribute.String("region", safeRegion(w.Region)),
		attribute.String("host_id", safeHostID(w.HostID)),
	)
	opt := metric.WithAttributes(attrs...)
	r.resumeSettleWaits.Add(ctx, 1, opt)
	if w.Duration > 0 {
		r.resumeSettleWaitDuration.Record(ctx, w.Duration.Seconds(), opt)
	}
	if w.Reads > 0 {
		r.resumeSettleWaitReads.Record(ctx, w.Reads, opt)
	}
}

func (r *OTelRecorder) RecordVMDCall(ctx context.Context, c VMDCall) {
	if r == nil {
		return
	}
	attrs := r.attrs(
		attribute.String("method", safeMethod(c.Method)),
		attribute.String("result", safeResult(c.Result)),
		attribute.String("region", safeRegion(c.Region)),
		attribute.String("host_id", safeHostID(c.HostID)),
	)
	opt := metric.WithAttributes(attrs...)
	r.vmdCalls.Add(ctx, 1, opt)
	if c.Duration > 0 {
		r.vmdDuration.Record(ctx, c.Duration.Seconds(), opt)
	}
}

func (r *OTelRecorder) RecordHostCapacity(ctx context.Context, c HostCapacity) {
	if r == nil {
		return
	}
	attrs := r.attrs(attribute.String("region", safeRegion(c.Region)), attribute.String("host_id", safeHostID(c.HostID)))
	opt := metric.WithAttributes(attrs...)
	r.hostVCPU.Record(ctx, c.UsedVCPU, opt)
	r.hostMemoryMiB.Record(ctx, c.UsedMemoryMiB, opt)
	r.hostSandboxes.Record(ctx, c.Sandboxes, opt)
}

// RecordBackupCoverage replaces the published durability-coverage
// snapshot. Zero-valued entries are kept (an explicit zero is what lets
// the coverage alert clear deterministically), a negative age from
// clock skew between the database and the sampler clamps to zero, and
// a nil snapshot means this replica is not the elected sampler and must
// export nothing.
func (r *OTelRecorder) RecordBackupCoverage(_ context.Context, snapshot []BackupCoverage) {
	if r == nil {
		return
	}
	cleaned := make([]BackupCoverage, 0, len(snapshot))
	for _, c := range snapshot {
		if c.OldestUncoveredAgeSeconds < 0 {
			c.OldestUncoveredAgeSeconds = 0
		}
		cleaned = append(cleaned, c)
	}
	r.backupCoverageMu.Lock()
	r.backupCoverage = cleaned
	r.backupCoverageMu.Unlock()
}

// observeBackupCoverage exports the current coverage snapshot. Series
// absent from the snapshot are simply not observed, which is how a
// group that lost its last paused sandbox (or a replica that lost the
// sampler lease) retires its series instead of freezing them.
func (r *OTelRecorder) observeBackupCoverage(_ context.Context, o metric.Observer) error {
	r.backupCoverageMu.Lock()
	snapshot := r.backupCoverage
	r.backupCoverageMu.Unlock()
	for _, c := range snapshot {
		attrs := r.attrs(attribute.String("region", safeRegion(c.Region)), attribute.String("host_id", safeHostID(c.HostID)))
		opt := metric.WithAttributes(attrs...)
		o.ObserveInt64(r.backupUncoveredPaused, c.UncoveredPaused, opt)
		o.ObserveFloat64(r.backupUncoveredOldestAge, c.OldestUncoveredAgeSeconds, opt)
	}
	return nil
}

func (r *OTelRecorder) RecordDBPoolStats(ctx context.Context, s DBPoolStats) {
	if r == nil {
		return
	}
	attrs := r.attrs()
	opt := metric.WithAttributes(attrs...)
	r.dbAcquiredConns.Record(ctx, s.AcquiredConns, opt)
	r.dbIdleConns.Record(ctx, s.IdleConns, opt)
	r.dbTotalConns.Record(ctx, s.TotalConns, opt)
	if s.AcquireDelta > 0 {
		r.dbAcquire.Add(ctx, s.AcquireDelta, opt)
	}
	if s.EmptyAcquireDelta > 0 {
		r.dbEmptyAcquire.Add(ctx, s.EmptyAcquireDelta, opt)
	}
	if s.CanceledAcquireDelta > 0 {
		r.dbCanceledAcquire.Add(ctx, s.CanceledAcquireDelta, opt)
	}
	if s.AcquireDurationSecondsDelta > 0 {
		r.dbAcquireDurationSeconds.Add(ctx, s.AcquireDurationSecondsDelta, opt)
	}
}

// RecordLauncherState emits vmd_launcher_ready as 1/0. Alert on it: a sustained
// 0 means every Firecracker start on that host is walking the full mount table,
// which is customer-visible latency long before anything errors.
func (r *OTelRecorder) RecordLauncherState(ctx context.Context, s LauncherState) {
	if r == nil {
		return
	}
	ready := int64(0)
	if s.Ready {
		ready = 1
	}
	r.launcherReady.Record(ctx, ready, metric.WithAttributes(r.selfAttrs()...))
}

func (r *OTelRecorder) RecordPausedNetworkPressure(ctx context.Context, p PausedNetworkPressure) {
	if r == nil {
		return
	}
	// These describe the emitting host's own network state, so they carry
	// host_id — without it every cell's series collapse into one and cannot be
	// alerted on or attributed per host.
	attrs := r.selfAttrs()
	opt := metric.WithAttributes(attrs...)
	r.pausedNetworkSlotsTotal.Record(ctx, p.TotalSlots, opt)
	r.pausedNetworkSlotsUsed.Record(ctx, p.UsedSlots, opt)
	r.pausedNetworkSlotsAvail.Record(ctx, p.AvailableSlots, opt)
	r.pausedNetworkPoolSlots.Record(ctx, p.FreshPool, metric.WithAttributes(append(attrs, attribute.String("type", "fresh"))...))
	r.pausedNetworkPoolSlots.Record(ctx, p.RecycledPool, metric.WithAttributes(append(attrs, attribute.String("type", "recycled"))...))
	r.pausedNetworkNetnsTotal.Record(ctx, p.NetnsTotal, opt)
	r.pausedNetworkMountTotal.Record(ctx, p.MountTotal, opt)
	currentReason := safePressureReason(p.PressureState)
	for _, reason := range []string{"idle", "slot", "kernel", "both"} {
		value := int64(0)
		if reason == currentReason {
			value = 1
		}
		r.pausedNetworkPressure.Record(ctx, value, metric.WithAttributes(append(attrs, attribute.String("reason", reason))...))
	}
	if p.ReclaimedRecycle > 0 {
		r.pausedNetworkReclaimed.Add(ctx, p.ReclaimedRecycle, metric.WithAttributes(append(attrs, attribute.String("mode", "recycle"))...))
	}
	if p.ReclaimedTeardown > 0 {
		r.pausedNetworkReclaimed.Add(ctx, p.ReclaimedTeardown, metric.WithAttributes(append(attrs, attribute.String("mode", "teardown"))...))
	}
	if p.ReclaimedPaused > 0 {
		r.pausedNetworkPaused.Add(ctx, p.ReclaimedPaused, opt)
	}
}

// selfAttrs labels a series with the host that EMITTED it, for gauges that
// describe this process's own host rather than a call's target. Kept separate
// from attrs: the call-flavoured recorders already carry a host_id meaning
// "the host this operation addressed", and a second key would collide.
func (r *OTelRecorder) selfAttrs(extra ...attribute.KeyValue) []attribute.KeyValue {
	return append([]attribute.KeyValue{
		attribute.String("service.name", r.serviceName),
		attribute.String("environment", r.environment),
		attribute.String("host_id", r.hostID),
	}, extra...)
}

func (r *OTelRecorder) attrs(extra ...attribute.KeyValue) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", r.serviceName),
		attribute.String("environment", r.environment),
	}
	return append(attrs, extra...)
}

func safeResult(v string) string {
	switch v {
	case ResultSuccess, ResultError, ResultConflict, ResultTimeout:
		return v
	default:
		return ResultError
	}
}

func safeSettleResult(v string) string {
	switch v {
	case SettleResultSettled, SettleResultTimeout:
		return v
	default:
		return SettleResultTimeout
	}
}

func safeOperation(v string) string {
	switch v {
	case "create", "pause", "resume", "delete", "fail", "timeout_pause":
		return v
	default:
		return "unknown"
	}
}

func safeMethod(v string) string {
	switch v {
	case "CreateVM", "PauseVM", "ResumeVM", "DeleteVM", "BuildTemplate", "GetBuildStatus", "CancelBuild":
		return v
	case "RestoreSnapshot":
		return "CreateVM"
	default:
		return "unknown"
	}
}

func safePressureReason(v string) string {
	switch v {
	case "idle", "slot", "kernel", "both":
		return v
	default:
		return "idle"
	}
}

func safeRegion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func safeHostID(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// newOTLPMeterProvider builds the OTLP/HTTP exporter, resource, and
// periodic-reader meter provider shared by every recorder in this
// package. cfg must already have its defaults applied.
func newOTLPMeterProvider(ctx context.Context, cfg OTelConfig) (*sdkmetric.MeterProvider, error) {
	exporterOpts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(cfg.Endpoint)}
	if cfg.Insecure || strings.HasPrefix(cfg.Endpoint, "http://") {
		exporterOpts = append(exporterOpts, otlpmetrichttp.WithInsecure())
	}
	exporter, err := otlpmetrichttp.New(ctx, exporterOpts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp metric exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("",
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", cfg.ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.ExportInterval))),
	), nil
}
