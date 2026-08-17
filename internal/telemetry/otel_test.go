package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

func TestRecordPausedNetworkPressureEmitsControllerMetrics(t *testing.T) {
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

	mustGauge := func(name string) metric.Int64Gauge {
		instrument, err := meter.Int64Gauge(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return instrument
	}
	mustCounter := func(name string) metric.Int64Counter {
		instrument, err := meter.Int64Counter(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return instrument
	}

	recorder := &OTelRecorder{
		provider:                provider,
		serviceName:             "sandbox-vmd",
		environment:             "staging",
		pausedNetworkSlotsTotal: mustGauge("vmd_network_slots_total"),
		pausedNetworkSlotsUsed:  mustGauge("vmd_network_slots_used"),
		pausedNetworkSlotsAvail: mustGauge("vmd_network_slots_available"),
		pausedNetworkPoolSlots:  mustGauge("vmd_network_pool_slots"),
		pausedNetworkNetnsTotal: mustGauge("vmd_network_netns_total"),
		pausedNetworkMountTotal: mustGauge("vmd_network_mounts_total"),
		pausedNetworkPressure:   mustGauge("vmd_network_controller_pressure_state"),
		pausedNetworkReclaimed:  mustCounter("vmd_network_slots_reclaimed_total"),
		pausedNetworkPaused:     mustCounter("vmd_network_slots_reclaimed_paused_total"),
	}

	recorder.RecordPausedNetworkPressure(ctx, PausedNetworkPressure{
		TotalSlots:        65000,
		UsedSlots:         64950,
		AvailableSlots:    50,
		FreshPool:         12,
		RecycledPool:      8,
		NetnsTotal:        51,
		MountTotal:        102,
		PressureState:     "kernel",
		ReclaimedRecycle:  2,
		ReclaimedTeardown: 3,
		ReclaimedPaused:   5,
	})

	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &resourceMetrics); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	seen := map[string]bool{}
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, metric := range scopeMetrics.Metrics {
			switch metric.Name {
			case "vmd_network_slots_total":
				gauge, ok := metric.Data.(metricdata.Gauge[int64])
				if !ok {
					t.Fatalf("slots total data type = %T, want metricdata.Gauge[int64]", metric.Data)
				}
				if len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Value != 65000 {
					t.Fatalf("slots total datapoints = %+v, want one value 65000", gauge.DataPoints)
				}
				seen[metric.Name] = true
			case "vmd_network_pool_slots":
				gauge, ok := metric.Data.(metricdata.Gauge[int64])
				if !ok {
					t.Fatalf("pool slots data type = %T, want metricdata.Gauge[int64]", metric.Data)
				}
				if len(gauge.DataPoints) != 2 {
					t.Fatalf("pool slot datapoints = %d, want 2", len(gauge.DataPoints))
				}
				byType := map[string]int64{}
				for _, dp := range gauge.DataPoints {
					attrs := map[string]string{}
					for _, attr := range dp.Attributes.ToSlice() {
						attrs[string(attr.Key)] = attr.Value.AsString()
					}
					byType[attrs["type"]] = dp.Value
				}
				if byType["fresh"] != 12 || byType["recycled"] != 8 {
					t.Fatalf("pool slot values = %#v, want fresh=12 recycled=8", byType)
				}
				seen[metric.Name] = true
			case "vmd_network_slots_reclaimed_total":
				sum, ok := metric.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("reclaimed data type = %T, want metricdata.Sum[int64]", metric.Data)
				}
				if len(sum.DataPoints) != 2 {
					t.Fatalf("reclaimed datapoints = %d, want 2", len(sum.DataPoints))
				}
				byMode := map[string]int64{}
				for _, dp := range sum.DataPoints {
					attrs := map[string]string{}
					for _, attr := range dp.Attributes.ToSlice() {
						attrs[string(attr.Key)] = attr.Value.AsString()
					}
					byMode[attrs["mode"]] = dp.Value
				}
				if byMode["recycle"] != 2 || byMode["teardown"] != 3 {
					t.Fatalf("reclaimed values = %#v, want recycle=2 teardown=3", byMode)
				}
				seen[metric.Name] = true
			case "vmd_network_slots_reclaimed_paused_total":
				sum, ok := metric.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("paused reclaimed data type = %T, want metricdata.Sum[int64]", metric.Data)
				}
				if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 5 {
					t.Fatalf("paused reclaimed datapoints = %+v, want one value 5", sum.DataPoints)
				}
				seen[metric.Name] = true
			case "vmd_network_controller_pressure_state":
				gauge, ok := metric.Data.(metricdata.Gauge[int64])
				if !ok {
					t.Fatalf("pressure state data type = %T, want metricdata.Gauge[int64]", metric.Data)
				}
				if len(gauge.DataPoints) != 4 {
					t.Fatalf("pressure state datapoints = %+v, want four reason series", gauge.DataPoints)
				}
				byReason := map[string]int64{}
				for _, dp := range gauge.DataPoints {
					attrs := map[string]string{}
					for _, attr := range dp.Attributes.ToSlice() {
						attrs[string(attr.Key)] = attr.Value.AsString()
					}
					byReason[attrs["reason"]] = dp.Value
				}
				if byReason["idle"] != 0 || byReason["slot"] != 0 || byReason["kernel"] != 1 || byReason["both"] != 0 {
					t.Fatalf("pressure state values = %#v, want idle=0 slot=0 kernel=1 both=0", byReason)
				}
				seen[metric.Name] = true
			}
		}
	}

	for _, name := range []string{
		"vmd_network_slots_total",
		"vmd_network_pool_slots",
		"vmd_network_slots_reclaimed_total",
		"vmd_network_slots_reclaimed_paused_total",
		"vmd_network_controller_pressure_state",
	} {
		if !seen[name] {
			t.Fatalf("metric %q not found", name)
		}
	}
}

// RecordLatencyPhase must label every sample with the bounded phase enums,
// fold empties to addressable values, and fall back to the recorder's own
// host identity when the caller has none (vmd/proxy).
func TestRecordLatencyPhaseAttributes(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(ctx) })
	meter := provider.Meter(instrumentationName)

	phaseDuration, err := meter.Float64Histogram("sandbox_phase_duration_seconds")
	if err != nil {
		t.Fatalf("create phase histogram: %v", err)
	}
	recorder := &OTelRecorder{
		provider:      provider,
		serviceName:   "sandbox-vmd",
		environment:   "staging",
		hostID:        "host-abc",
		phaseDuration: phaseDuration,
	}

	recorder.RecordLatencyPhase(ctx, LatencyPhase{
		Plane:    "vmd",
		Op:       "launch",
		Phase:    "wait_socket",
		Duration: 30 * time.Millisecond,
		// Mode, Region, HostID empty: must fold, not vanish.
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var dp *metricdata.HistogramDataPoint[float64]
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "sandbox_phase_duration_seconds" {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok || len(h.DataPoints) != 1 {
				t.Fatalf("want one histogram datapoint, got %T / %d", m.Data, len(h.DataPoints))
			}
			dp = &h.DataPoints[0]
		}
	}
	if dp == nil {
		t.Fatal("phase histogram not collected")
	}
	want := map[string]string{
		"plane":   "vmd",
		"op":      "launch",
		"phase":   "wait_socket",
		"mode":    "none",
		"host_id": "host-abc", // recorder fallback
	}
	for k, v := range want {
		got, ok := dp.Attributes.Value(attribute.Key(k))
		if !ok || got.AsString() != v {
			t.Errorf("attribute %s = %q (present=%v), want %q", k, got.AsString(), ok, v)
		}
	}
	if dp.Sum < 0.029 || dp.Sum > 0.031 {
		t.Errorf("sum = %v, want ~0.030s", dp.Sum)
	}
}

// The phase histogram sits on lifecycle paths; its per-sample cost must stay
// in the microsecond class (in-memory bucket update, no I/O — the OTLP export
// runs on the periodic reader, never on the caller).
func BenchmarkRecordLatencyPhase(b *testing.B) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	b.Cleanup(func() { _ = provider.Shutdown(ctx) })
	meter := provider.Meter(instrumentationName)
	h, err := meter.Float64Histogram("sandbox_phase_duration_seconds")
	if err != nil {
		b.Fatal(err)
	}
	r := &OTelRecorder{provider: provider, hostID: "host-abc", phaseDuration: h}
	p := LatencyPhase{Plane: "vmd", Op: "launch", Phase: "wait_socket", Mode: "direct", Duration: 30 * time.Millisecond}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.RecordLatencyPhase(ctx, p)
	}
}
