package telemetry

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestSafeResultBoundsValues(t *testing.T) {
	for _, result := range []string{ResultSuccess, ResultError, ResultConflict, ResultTimeout} {
		if got := safeResult(result); got != result {
			t.Fatalf("safeResult(%q) = %q", result, got)
		}
	}
	if got := safeResult("raw error: secret token leaked"); got != ResultError {
		t.Fatalf("unexpected fallback result: %q", got)
	}
}

func TestSafeOperationBoundsValues(t *testing.T) {
	for _, op := range []string{"create", "pause", "resume", "delete", "fail", "timeout_pause"} {
		if got := safeOperation(op); got != op {
			t.Fatalf("safeOperation(%q) = %q", op, got)
		}
	}
	if got := safeOperation("sandbox_id=abc"); got != "unknown" {
		t.Fatalf("unexpected fallback operation: %q", got)
	}
}

func TestSafeMethodBoundsValues(t *testing.T) {
	for _, method := range []string{"CreateVM", "PauseVM", "ResumeVM", "DeleteVM", "BuildTemplate", "GetBuildStatus", "CancelBuild"} {
		if got := safeMethod(method); got != method {
			t.Fatalf("safeMethod(%q) = %q", method, got)
		}
	}
	if got := safeMethod("https://raw-url.example/vm/123"); got != "unknown" {
		t.Fatalf("unexpected fallback method: %q", got)
	}
	if got := safeMethod("RestoreSnapshot"); got != "CreateVM" {
		t.Fatalf("safeMethod(%q) = %q", "RestoreSnapshot", got)
	}
}

func TestDeltasNeverNegative(t *testing.T) {
	if got := nonNegativeDelta(10, 7); got != 3 {
		t.Fatalf("delta = %d", got)
	}
	if got := nonNegativeDelta(1, 7); got != 0 {
		t.Fatalf("reset delta = %d", got)
	}
	if got := nonNegativeDurationDelta(10*time.Second, 7*time.Second); got != 3*time.Second {
		t.Fatalf("duration delta = %s", got)
	}
	if got := nonNegativeDurationDelta(time.Second, 7*time.Second); got != 0 {
		t.Fatalf("reset duration delta = %s", got)
	}
}

func TestDBPoolDeltasSeedFromFirstSample(t *testing.T) {
	acquire, emptyAcquire, canceledAcquire, acquireDuration := dbPoolDeltas(
		false,
		10, 0,
		4, 0,
		2, 0,
		15*time.Second, 0,
	)
	if acquire != 0 || emptyAcquire != 0 || canceledAcquire != 0 || acquireDuration != 0 {
		t.Fatalf("first sample deltas = (%d, %d, %d, %s), want all zero", acquire, emptyAcquire, canceledAcquire, acquireDuration)
	}

	acquire, emptyAcquire, canceledAcquire, acquireDuration = dbPoolDeltas(
		true,
		15, 10,
		6, 4,
		3, 2,
		21*time.Second, 15*time.Second,
	)
	if acquire != 5 || emptyAcquire != 2 || canceledAcquire != 1 || acquireDuration != 6*time.Second {
		t.Fatalf("seeded sample deltas = (%d, %d, %d, %s)", acquire, emptyAcquire, canceledAcquire, acquireDuration)
	}
}

func TestHostCapacityQueryTimeoutIndependentOfInterval(t *testing.T) {
	for _, interval := range []time.Duration{500 * time.Millisecond, 2 * time.Second, 15 * time.Second} {
		if got := hostCapacityQueryTimeoutForInterval(interval); got != hostCapacityQueryTimeout {
			t.Fatalf("timeout(%s) = %s, want %s", interval, got, hostCapacityQueryTimeout)
		}
	}
}
func TestRecordVMDCallEmitsHostIDAndMethodAttributes(t *testing.T) {
	ctx := context.Background()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
	)
	t.Cleanup(func() {
		if err := provider.Shutdown(ctx); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})

	meter := provider.Meter(instrumentationName)

	vmdCalls, err := meter.Int64Counter("vmd_call_total")
	if err != nil {
		t.Fatalf("create VMD call counter: %v", err)
	}

	vmdDuration, err := meter.Float64Histogram(
		"vmd_call_duration_seconds",
	)
	if err != nil {
		t.Fatalf("create VMD duration histogram: %v", err)
	}

	recorder := &OTelRecorder{
		provider:    provider,
		serviceName: "sandbox-controlplane",
		environment: "staging",
		vmdCalls:    vmdCalls,
		vmdDuration: vmdDuration,
	}

	recorder.RecordVMDCall(ctx, VMDCall{
		Method:   "BuildTemplate",
		Result:   ResultSuccess,
		Region:   "us-central1",
		HostID:   "host-123",
		Duration: 250 * time.Millisecond,
	})

	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &resourceMetrics); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	var datapoint *metricdata.HistogramDataPoint[float64]

	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, metric := range scopeMetrics.Metrics {
			if metric.Name != "vmd_call_duration_seconds" {
				continue
			}

			histogram, ok := metric.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf(
					"metric data type = %T, want metricdata.Histogram[float64]",
					metric.Data,
				)
			}

			if len(histogram.DataPoints) != 1 {
				t.Fatalf(
					"histogram datapoints = %d, want 1",
					len(histogram.DataPoints),
				)
			}

			datapoint = &histogram.DataPoints[0]
		}
	}

	if datapoint == nil {
		t.Fatal("vmd_call_duration_seconds metric not found")
	}

	attributes := make(map[string]string)
	for _, attr := range datapoint.Attributes.ToSlice() {
		attributes[string(attr.Key)] = attr.Value.AsString()
	}

	want := map[string]string{
		"service.name": "sandbox-controlplane",
		"environment":  "staging",
		"method":       "BuildTemplate",
		"result":       ResultSuccess,
		"region":       "us-central1",
		"host_id":      "host-123",
	}

	for key, wantValue := range want {
		if got := attributes[key]; got != wantValue {
			t.Errorf(
				"attribute %q = %q, want %q; all attributes: %#v",
				key,
				got,
				wantValue,
				attributes,
			)
		}
	}
}
