package telemetry

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// countingCoverageRecorder counts non-empty snapshot publications from
// the sampler goroutine; everything else is a no-op via the embedded
// recorder. Empty snapshots (a follower clearing its state) are not
// counted, matching what "this replica sampled" means.
type countingCoverageRecorder struct {
	Recorder
	samples atomic.Int64
}

func (r *countingCoverageRecorder) RecordBackupCoverage(_ context.Context, snapshot []BackupCoverage) {
	if len(snapshot) > 0 {
		r.samples.Add(1)
	}
}

func TestStartBackupCoverageSamplerNilGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Neither call may panic or spin up a goroutine that records.
	StartBackupCoverageSampler(ctx, nil, NewNoopRecorder(), time.Second)

	cfg, err := pgxpool.ParseConfig("postgres://user@127.0.0.1:1/none")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()
	StartBackupCoverageSampler(ctx, pool, nil, time.Second)
}

// A pool whose lease claims fail (nothing listens on the address) must
// be logged and survived: no panic, no published samples, and the loop
// keeps running until the context ends.
func TestStartBackupCoverageSamplerSurvivesClaimFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := pgxpool.ParseConfig("postgres://user@127.0.0.1:1/none?connect_timeout=1")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()

	rec := &countingCoverageRecorder{Recorder: NewNoopRecorder()}
	StartBackupCoverageSampler(ctx, pool, rec, 10*time.Millisecond)

	// Outlast the startup jitter (bounded by 1s) so the first tick and
	// several retries actually run and fail to claim the lease.
	time.Sleep(1500 * time.Millisecond)
	cancel()

	if got := rec.samples.Load(); got != 0 {
		t.Fatalf("published samples after failing claims = %d, want 0", got)
	}
}

// Only the real noop recorder is refused lease contention; test fakes
// that embed it (and the OTel recorder) are legitimate exporters.
func TestIsNoopRecorderIdentifiesOnlyTheNoop(t *testing.T) {
	if !isNoopRecorder(NewNoopRecorder()) {
		t.Fatal("the noop recorder was not identified as noop")
	}
	if isNoopRecorder(&countingCoverageRecorder{Recorder: NewNoopRecorder()}) {
		t.Fatal("a recorder embedding the noop was misidentified as noop")
	}
	if isNoopRecorder(&OTelRecorder{}) {
		t.Fatal("the OTel recorder was misidentified as noop")
	}
}

func TestSamplerHolderIDsDistinctWithinProcess(t *testing.T) {
	if samplerHolderID() == samplerHolderID() {
		t.Fatal("two samplers in one process produced the same lease holder id")
	}
}

// The claim-to-publish window must sit well inside the lease, so a
// leader stalled by a slow database can never publish a snapshot on a
// lease another replica has already taken over.
func TestBackupCoverageTickTimeoutStaysInsideLease(t *testing.T) {
	// Production shape: lease (3x interval) dwarfs the query timeout.
	if got := backupCoverageTickTimeout(45 * time.Second); got != backupCoverageQueryTimeout {
		t.Fatalf("timeout(45s lease) = %s, want %s", got, backupCoverageQueryTimeout)
	}
	// Short leases (tests, tight intervals) clamp the whole tick to a
	// third of the lease.
	if got := backupCoverageTickTimeout(150 * time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("timeout(150ms lease) = %s, want 50ms", got)
	}
}

// newCoverageTestRecorder wires an OTelRecorder's coverage instruments
// and callback onto a manual reader, mirroring production registration.
func newCoverageTestRecorder(t *testing.T) (*OTelRecorder, *sdkmetric.ManualReader) {
	t.Helper()
	ctx := context.Background()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(ctx); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})

	meter := provider.Meter(instrumentationName)

	recorder := &OTelRecorder{
		provider:    provider,
		serviceName: "sandbox-controlplane",
		environment: "staging",
	}
	var err error
	if recorder.backupUncoveredPaused, err = meter.Int64ObservableGauge("backup_uncovered_paused_sandboxes"); err != nil {
		t.Fatalf("create uncovered gauge: %v", err)
	}
	if recorder.backupUncoveredOldestAge, err = meter.Float64ObservableGauge("backup_uncovered_oldest_age_seconds"); err != nil {
		t.Fatalf("create oldest age gauge: %v", err)
	}
	if _, err = meter.RegisterCallback(recorder.observeBackupCoverage,
		recorder.backupUncoveredPaused, recorder.backupUncoveredOldestAge); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	return recorder, reader
}

type collectedCoverage struct {
	counts map[string]int64
	ages   map[string]float64
	attrs  map[string]map[string]string
}

func collectCoverage(t *testing.T, reader *sdkmetric.ManualReader) collectedCoverage {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &resourceMetrics); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	out := collectedCoverage{
		counts: map[string]int64{},
		ages:   map[string]float64{},
		attrs:  map[string]map[string]string{},
	}
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, m := range scopeMetrics.Metrics {
			switch m.Name {
			case "backup_uncovered_paused_sandboxes":
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				if !ok {
					t.Fatalf("uncovered data type = %T, want metricdata.Gauge[int64]", m.Data)
				}
				for _, dp := range gauge.DataPoints {
					attrs := map[string]string{}
					for _, attr := range dp.Attributes.ToSlice() {
						attrs[string(attr.Key)] = attr.Value.AsString()
					}
					out.counts[attrs["host_id"]] = dp.Value
					out.attrs[attrs["host_id"]] = attrs
				}
			case "backup_uncovered_oldest_age_seconds":
				gauge, ok := m.Data.(metricdata.Gauge[float64])
				if !ok {
					t.Fatalf("oldest age data type = %T, want metricdata.Gauge[float64]", m.Data)
				}
				for _, dp := range gauge.DataPoints {
					attrs := map[string]string{}
					for _, attr := range dp.Attributes.ToSlice() {
						attrs[string(attr.Key)] = attr.Value.AsString()
					}
					out.ages[attrs["host_id"]] = dp.Value
				}
			}
		}
	}
	return out
}

func TestRecordBackupCoverageEmitsExplicitZeroAndClampsAge(t *testing.T) {
	ctx := context.Background()
	recorder, reader := newCoverageTestRecorder(t)

	recorder.RecordBackupCoverage(ctx, []BackupCoverage{
		{Region: "us-west2", HostID: "usw2", UncoveredPaused: 13600, OldestUncoveredAgeSeconds: 4200},
		// A converged host must publish an explicit zero, and clock
		// skew (negative age) must clamp to zero, not pass through.
		{Region: "us-east4", HostID: "use4", UncoveredPaused: 0, OldestUncoveredAgeSeconds: -3},
	})

	got := collectCoverage(t, reader)
	if got.counts["usw2"] != 13600 {
		t.Fatalf("usw2 uncovered = %d, want 13600", got.counts["usw2"])
	}
	if v, present := got.counts["use4"]; !present || v != 0 {
		t.Fatalf("use4 uncovered = (%d, %v), want an explicit 0 datapoint", v, present)
	}
	if got.ages["usw2"] != 4200 {
		t.Fatalf("usw2 oldest age = %v, want 4200", got.ages["usw2"])
	}
	if v, present := got.ages["use4"]; !present || v != 0 {
		t.Fatalf("use4 oldest age = (%v, %v), want clamped 0", v, present)
	}

	want := map[string]string{
		"service.name": "sandbox-controlplane",
		"environment":  "staging",
		"region":       "us-west2",
		"host_id":      "usw2",
	}
	for key, wantValue := range want {
		if got := got.attrs["usw2"][key]; got != wantValue {
			t.Errorf("attribute %q = %q, want %q; all attributes: %#v", key, got, wantValue, got)
		}
	}
}

// Snapshot replacement is the failover and retirement story: series
// absent from the newest snapshot stop exporting entirely, and an
// empty snapshot (a replica that is not the elected sampler) exports
// nothing. Without this, a stale writer would freeze its last values
// alongside the live leader's.
func TestRecordBackupCoverageSnapshotReplaces(t *testing.T) {
	ctx := context.Background()
	recorder, reader := newCoverageTestRecorder(t)

	recorder.RecordBackupCoverage(ctx, []BackupCoverage{
		{Region: "us-west2", HostID: "usw2", UncoveredPaused: 7},
		{Region: "unknown", HostID: "old-host", UncoveredPaused: 3},
	})
	got := collectCoverage(t, reader)
	if got.counts["usw2"] != 7 || got.counts["old-host"] != 3 {
		t.Fatalf("initial snapshot = %+v, want usw2=7 old-host=3", got.counts)
	}

	// old-host leaves the paused population: its series must vanish,
	// not freeze at 3.
	recorder.RecordBackupCoverage(ctx, []BackupCoverage{
		{Region: "us-west2", HostID: "usw2", UncoveredPaused: 5},
	})
	got = collectCoverage(t, reader)
	if got.counts["usw2"] != 5 {
		t.Fatalf("usw2 after replace = %d, want 5", got.counts["usw2"])
	}
	if _, present := got.counts["old-host"]; present {
		t.Fatalf("old-host still exporting after leaving the snapshot: %+v", got.counts)
	}

	// Lease lost: nothing may export from this replica.
	recorder.RecordBackupCoverage(ctx, nil)
	got = collectCoverage(t, reader)
	if len(got.counts) != 0 || len(got.ages) != 0 {
		t.Fatalf("ex-leader still exporting after clearing: counts=%+v ages=%+v", got.counts, got.ages)
	}
}
