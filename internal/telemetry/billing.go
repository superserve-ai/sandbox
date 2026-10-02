package telemetry

import (
	"context"
	"math"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// BillingRecorder is optional so existing lifecycle recorders need no billing hooks.
type BillingRecorder interface {
	RecordBillingWork(context.Context, string, bool, time.Duration, int64)
	RecordBillingLag(context.Context, float64)
	RecordBillingBacklog(context.Context, string, int64, float64)
	RecordBillingReconciliation(context.Context, string, float64, *float64, *float64)
}

type NoopBillingRecorder struct{}

func (NoopBillingRecorder) RecordBillingWork(context.Context, string, bool, time.Duration, int64) {}
func (NoopBillingRecorder) RecordBillingLag(context.Context, float64)                             {}
func (NoopBillingRecorder) RecordBillingBacklog(context.Context, string, int64, float64)          {}
func (NoopBillingRecorder) RecordBillingReconciliation(context.Context, string, float64, *float64, *float64) {
}

type billingMetrics struct {
	operations     metric.Int64Counter
	duration       metric.Float64Histogram
	volume         metric.Int64Counter
	lag            metric.Float64Histogram
	backlog        metric.Int64Gauge
	oldest         metric.Float64Gauge
	reconciliation metric.Int64Counter
	quantity       metric.Float64Histogram
	discrepancy    metric.Float64Histogram
	freshness      metric.Float64Histogram
}

func (r *OTelRecorder) initBilling(m metric.Meter) error {
	var err error
	b := &billingMetrics{}
	if b.operations, err = m.Int64Counter("billing_operations_total"); err != nil {
		return err
	}
	if b.duration, err = m.Float64Histogram("billing_operation_duration_seconds", metric.WithExplicitBucketBoundaries(latencyBuckets...)); err != nil {
		return err
	}
	if b.volume, err = m.Int64Counter("billing_work_items_total"); err != nil {
		return err
	}
	if b.lag, err = m.Float64Histogram("billing_work_due_lag_seconds", metric.WithExplicitBucketBoundaries(60, 300, 1800, 3600, 21600, 86400)); err != nil {
		return err
	}
	if b.backlog, err = m.Int64Gauge("billing_event_backlog_capped"); err != nil {
		return err
	}
	if b.oldest, err = m.Float64Gauge("billing_event_oldest_age_seconds"); err != nil {
		return err
	}
	if b.reconciliation, err = m.Int64Counter("billing_reconciliation_total"); err != nil {
		return err
	}
	if b.quantity, err = m.Float64Histogram("billing_observed_quantity", metric.WithExplicitBucketBoundaries(0, 1, 10, 100, 1000, 10000, 100000, 1000000)); err != nil {
		return err
	}
	if b.discrepancy, err = m.Float64Histogram("billing_discrepancy_quantity", metric.WithExplicitBucketBoundaries(0, 1, 10, 100, 1000, 10000, 100000)); err != nil {
		return err
	}
	if b.freshness, err = m.Float64Histogram("billing_previous_observation_age_seconds", metric.WithExplicitBucketBoundaries(60, 3600, 7200, 21600, 86400)); err != nil {
		return err
	}
	r.billing = b
	return nil
}

func (r *OTelRecorder) RecordBillingWork(ctx context.Context, operation string, failed bool, duration time.Duration, items int64) {
	if r == nil || r.billing == nil {
		return
	}
	switch operation {
	case "tick", "measurement", "submission", "reconciliation", "backlog_sample":
	default:
		operation = "unknown"
	}
	result := "success"
	if failed {
		result = "error"
	}
	opt := metric.WithAttributes(attribute.String("operation", operation), attribute.String("result", result))
	r.billing.operations.Add(ctx, 1, opt)
	r.billing.duration.Record(ctx, math.Max(0, duration.Seconds()), opt)
	if items > 0 {
		r.billing.volume.Add(ctx, items, opt)
	}
}
func (r *OTelRecorder) RecordBillingLag(ctx context.Context, seconds float64) {
	if r == nil || r.billing == nil {
		return
	}
	r.billing.lag.Record(ctx, math.Max(0, seconds))
}
func (r *OTelRecorder) RecordBillingBacklog(ctx context.Context, state string, count int64, age float64) {
	if r == nil || r.billing == nil {
		return
	}
	switch state {
	case "pending", "uncertain", "recovery_required", "rejected", "submitted", "adopted":
	default:
		state = "unknown"
	}
	opt := metric.WithAttributes(attribute.String("state", state))
	r.billing.backlog.Record(ctx, count, opt)
	r.billing.oldest.Record(ctx, math.Max(0, age), opt)
}

// Quantities are samples of individual resource reconciliations, never fleet
// totals. A missing provider value must not become a zero or a match.
func (r *OTelRecorder) RecordBillingReconciliation(ctx context.Context, resource string, local float64, counted, previousAge *float64) {
	if r == nil || r.billing == nil {
		return
	}
	switch resource {
	case "cpu", "memory", "storage":
	default:
		resource = "unknown"
	}
	result := "unavailable"
	if counted != nil {
		result = "matched"
		if *counted < local {
			result = "missing"
		} else if *counted > local {
			result = "excess"
		}
	}
	freshness := "unknown"
	if previousAge != nil {
		freshness = "fresh"
		if *previousAge > 21600 {
			freshness = "stale"
		}
	}
	opt := metric.WithAttributes(attribute.String("resource", resource), attribute.String("result", result), attribute.String("freshness", freshness))
	r.billing.reconciliation.Add(ctx, 1, opt)
	r.billing.quantity.Record(ctx, local, metric.WithAttributes(attribute.String("resource", resource), attribute.String("source", "local")))
	if counted != nil {
		r.billing.quantity.Record(ctx, *counted, metric.WithAttributes(attribute.String("resource", resource), attribute.String("source", "provider")))
		r.billing.discrepancy.Record(ctx, math.Abs(local-*counted), opt)
	}
	if previousAge != nil {
		r.billing.freshness.Record(ctx, math.Max(0, *previousAge), opt)
	}
}
