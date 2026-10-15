package telemetry

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestBillingMetricsBoundLabelsAndKeepUnknownProviderDistinct(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(ctx)
	r := &OTelRecorder{}
	if err := r.initBilling(provider.Meter("test")); err != nil {
		t.Fatal(err)
	}
	r.RecordBillingWork(ctx, "raw-secret", true, time.Second, 2)
	r.RecordBillingLag(ctx, 3600)
	for _, state := range []string{"pending", "uncertain", "recovery_required", "rejected", "submitted", "adopted"} {
		r.RecordBillingBacklog(ctx, state, 3, 90)
	}
	r.RecordBillingReconciliation(ctx, "raw-secret", 10, nil, nil)
	counted, age := 8.0, 86400.0
	r.RecordBillingReconciliation(ctx, "cpu", 10, &counted, &age)
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			seen[m.Name] = true
			switch m.Name {
			case "billing_operations_total":
				points := m.Data.(metricdata.Sum[int64]).DataPoints
				if len(points) != 1 || points[0].Value != 1 {
					t.Fatalf("operations: %+v", points)
				}
				for _, a := range points[0].Attributes.ToSlice() {
					if a.Key == "operation" && a.Value.AsString() != "unknown" {
						t.Fatal(a)
					}
				}
			case "billing_event_backlog_capped":
				if points := m.Data.(metricdata.Gauge[int64]).DataPoints; len(points) != 6 {
					t.Fatalf("collapsed event states: %+v", points)
				}
			case "billing_reconciliation_total":
				results := map[string]bool{}
				for _, point := range m.Data.(metricdata.Sum[int64]).DataPoints {
					for _, a := range point.Attributes.ToSlice() {
						if a.Value.AsString() == "raw-secret" {
							t.Fatal("unbounded label")
						}
						if a.Key == "result" || a.Key == "freshness" {
							results[a.Value.AsString()] = true
						}
					}
				}
				for _, label := range []string{"unavailable", "missing", "unknown", "stale"} {
					if !results[label] {
						t.Fatalf("missing %s: %v", label, results)
					}
				}
			case "billing_discrepancy_quantity":
				points := m.Data.(metricdata.Histogram[float64]).DataPoints
				if len(points) != 1 || points[0].Count != 1 || points[0].Sum != 2 {
					t.Fatalf("unknown provider produced discrepancy: %+v", points)
				}
			}
		}
	}
	for _, name := range []string{"billing_operations_total", "billing_work_items_total", "billing_operation_duration_seconds", "billing_event_backlog_capped", "billing_event_oldest_age_seconds", "billing_work_due_lag_seconds", "billing_reconciliation_total", "billing_observed_quantity", "billing_discrepancy_quantity", "billing_previous_observation_age_seconds"} {
		if !seen[name] {
			t.Errorf("missing instrument %s", name)
		}
	}
}

func TestProBillingBacklogClearsAndBoundsLabels(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(ctx)
	r := &OTelRecorder{}
	if err := r.initBilling(provider.Meter("test")); err != nil {
		t.Fatal(err)
	}
	r.RecordProBillingBacklog(ctx, "pro_monthly", 3, 700, 4, 1000)
	r.RecordProBillingBacklog(ctx, "pro_monthly", 0, 0, 0, 0)
	r.RecordProBillingBacklog(ctx, "unbounded-customer", 2000, 900, 2000, 1800)
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "billing_pro_paid_activation_pending" && m.Name != "billing_pro_recovery_overdue" {
				continue
			}
			seen++
			for _, point := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				v, _ := point.Attributes.Value("offer")
				switch v.AsString() {
				case "pro_monthly":
					if point.Value != 0 {
						t.Fatal("recovered backlog did not clear")
					}
				case "unknown":
					if point.Value != 1000 {
						t.Fatal("backlog is unbounded")
					}
				default:
					t.Fatal("unbounded offer label")
				}
			}
		}
	}
	if seen != 2 {
		t.Fatal("missing Pro backlog instruments")
	}
}
