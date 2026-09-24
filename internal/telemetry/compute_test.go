package telemetry

import (
	"context"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"testing"
)

func TestComputeDecisionAndRefreshMetrics(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(ctx) })
	meter := provider.Meter(instrumentationName)
	decisions, err := meter.Int64Counter("compute_restriction_decision_total")
	if err != nil {
		t.Fatal(err)
	}
	refreshes, err := meter.Int64Counter("compute_restriction_refresh_total")
	if err != nil {
		t.Fatal(err)
	}
	signup, err := meter.Int64Counter("signup_restriction_decision_total")
	if err != nil {
		t.Fatal(err)
	}
	r := &OTelRecorder{computeDecisions: decisions, computeRefreshes: refreshes, signupDecisions: signup}
	r.RecordComputeDecision(ctx, "create", "observe", "would_deny", "user")
	r.RecordComputeDecision(ctx, "resume", "enforce", "blocked", "team")
	r.RecordComputeDecision(ctx, "create", "off", "allowed", "none")
	r.RecordComputeDecision(ctx, "private-value", "private-value", "private-value", "private-value")
	r.RecordComputeRefresh(ctx, "success")
	r.RecordComputeRefresh(ctx, "read_error")
	r.RecordSignupDecision(ctx, "enforce", "blocked", "fingerprint")
	r.RecordSignupDecision(ctx, "private-value", "private-value", "private-value")
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]int64{}
	results := map[string]int64{}
	signupOutcomes := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			for _, p := range m.Data.(metricdata.Sum[int64]).DataPoints {
				source, _ := p.Attributes.Value("source")
				if source.AsString() != "config" {
					t.Fatal("missing backend")
				}
				for _, attr := range p.Attributes.ToSlice() {
					if attr.Value.AsString() == "private-value" {
						t.Fatal("unbounded label")
					}
				}
				if m.Name == "compute_restriction_decision_total" {
					v, _ := p.Attributes.Value("outcome")
					outcomes[v.AsString()] += p.Value
				} else if m.Name == "signup_restriction_decision_total" {
					v, _ := p.Attributes.Value("decision")
					signupOutcomes[v.AsString()] += p.Value
				} else {
					v, _ := p.Attributes.Value("result")
					results[v.AsString()] += p.Value
				}
			}
		}
	}
	for _, outcome := range []string{"allowed", "would_deny", "blocked", "unknown"} {
		if outcomes[outcome] != 1 {
			t.Fatalf("outcomes=%v", outcomes)
		}
	}
	if results["success"] != 1 || results["read_error"] != 1 {
		t.Fatalf("results=%v", results)
	}
	if signupOutcomes["blocked"] != 1 || signupOutcomes["unknown"] != 1 {
		t.Fatalf("signup outcomes=%v", signupOutcomes)
	}
}
