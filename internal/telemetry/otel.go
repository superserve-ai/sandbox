package telemetry

import (
	"context"
	"fmt"
	"strings"
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
}

// OTelRecorder emits the sandbox control plane's bounded operational metrics
// through OTLP. It intentionally exposes only a small label vocabulary.
type OTelRecorder struct {
	provider *sdkmetric.MeterProvider

	serviceName string
	environment string

	sandboxTransitions       metric.Int64Counter
	sandboxDuration          metric.Float64Histogram
	vmdCalls                 metric.Int64Counter
	vmdDuration              metric.Float64Histogram
	hostVCPU                 metric.Int64Gauge
	hostMemoryMiB            metric.Int64Gauge
	hostSandboxes            metric.Int64Gauge
	dbAcquiredConns          metric.Int64Gauge
	dbIdleConns              metric.Int64Gauge
	dbTotalConns             metric.Int64Gauge
	dbAcquire                metric.Int64Counter
	dbEmptyAcquire           metric.Int64Counter
	dbCanceledAcquire        metric.Int64Counter
	dbAcquireDurationSeconds metric.Float64Counter
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

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.ExportInterval))),
	)
	meter := provider.Meter(instrumentationName)

	r := &OTelRecorder{
		provider:    provider,
		serviceName: cfg.ServiceName,
		environment: cfg.Environment,
	}
	if r.sandboxTransitions, err = meter.Int64Counter("sandbox_transition_total"); err != nil {
		return nil, err
	}
	if r.sandboxDuration, err = meter.Float64Histogram("sandbox_transition_duration_seconds"); err != nil {
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
