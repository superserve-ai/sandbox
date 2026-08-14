package telemetry

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// A nil recorder is the metrics-disabled configuration; every method must
// be a safe no-op so instrumented code paths never branch on it.
func TestBackupRecorderNilSafe(t *testing.T) {
	ctx := context.Background()
	var r *BackupRecorder
	r.RecordUpload(ctx, BackupUploadVerified, time.Second)
	r.AddUploadBytes(ctx, 1024)
	r.RecordHashDuration(ctx, time.Second)
	r.RecordStageDuration(ctx, time.Second)
	r.RecordPauseHookDuration(ctx, time.Second)
	r.AddNotifyFailure(ctx)
	r.RecordSample(ctx, BackupSample{Enabled: true})
	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("nil recorder Shutdown = %v", err)
	}
}

func TestSafeUploadResultBoundsValues(t *testing.T) {
	for _, result := range []string{BackupUploadVerified, BackupUploadDeduped, BackupUploadAbandoned, BackupUploadFailed} {
		if got := safeUploadResult(result); got != result {
			t.Fatalf("safeUploadResult(%q) = %q", result, got)
		}
	}
	if got := safeUploadResult("gs://bucket/raw-object-name"); got != BackupUploadFailed {
		t.Fatalf("unexpected fallback result: %q", got)
	}
}

func testBackupRecorder(t *testing.T) (*BackupRecorder, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	r, err := NewBackupRecorderWithProvider(provider, BackupOTelConfig{
		OTelConfig: OTelConfig{ServiceName: "sandbox-vmd", Environment: "staging"},
		HostID:     "host-1",
	})
	if err != nil {
		t.Fatalf("create backup recorder: %v", err)
	}
	return r, reader
}

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	out := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func TestBackupRecorderRecordsUploadOutcome(t *testing.T) {
	ctx := context.Background()
	r, reader := testBackupRecorder(t)

	r.RecordUpload(ctx, BackupUploadVerified, 2*time.Second)
	r.AddUploadBytes(ctx, 4096)

	metrics := collectMetrics(t, reader)

	uploads, ok := metrics["backup_upload_total"].Data.(metricdata.Sum[int64])
	if !ok || len(uploads.DataPoints) != 1 {
		t.Fatalf("backup_upload_total = %#v, want one int64 sum point", metrics["backup_upload_total"].Data)
	}
	dp := uploads.DataPoints[0]
	if dp.Value != 1 {
		t.Fatalf("backup_upload_total = %d, want 1", dp.Value)
	}
	attrs := map[string]string{}
	for _, kv := range dp.Attributes.ToSlice() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	for key, want := range map[string]string{
		"service.name": "sandbox-vmd",
		"environment":  "staging",
		"host_id":      "host-1",
		"result":       BackupUploadVerified,
	} {
		if attrs[key] != want {
			t.Fatalf("attribute %q = %q, want %q; all: %#v", key, attrs[key], want, attrs)
		}
	}

	bytesSum, ok := metrics["backup_upload_bytes_total"].Data.(metricdata.Sum[int64])
	if !ok || len(bytesSum.DataPoints) != 1 || bytesSum.DataPoints[0].Value != 4096 {
		t.Fatalf("backup_upload_bytes_total = %#v, want one point of 4096", metrics["backup_upload_bytes_total"].Data)
	}

	hist, ok := metrics["backup_upload_duration_seconds"].Data.(metricdata.Histogram[float64])
	if !ok || len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 || hist.DataPoints[0].Sum != 2 {
		t.Fatalf("backup_upload_duration_seconds = %#v, want one 2s observation", metrics["backup_upload_duration_seconds"].Data)
	}
}

func TestBackupRecorderBoundsUnknownResult(t *testing.T) {
	ctx := context.Background()
	r, reader := testBackupRecorder(t)

	r.RecordUpload(ctx, "raw error: bucket denied for sandbox sb-123", 0)

	metrics := collectMetrics(t, reader)
	uploads := metrics["backup_upload_total"].Data.(metricdata.Sum[int64])
	if len(uploads.DataPoints) != 1 {
		t.Fatalf("datapoints = %d, want 1", len(uploads.DataPoints))
	}
	for _, kv := range uploads.DataPoints[0].Attributes.ToSlice() {
		if string(kv.Key) == "result" && kv.Value.AsString() != BackupUploadFailed {
			t.Fatalf("result = %q, want %q", kv.Value.AsString(), BackupUploadFailed)
		}
	}
}

func TestBackupRecorderRecordsSampleGauges(t *testing.T) {
	ctx := context.Background()
	r, reader := testBackupRecorder(t)

	r.RecordSample(ctx, BackupSample{
		Enabled:             false,
		PendingPause:        3,
		PendingCheckpoint:   2,
		PendingBestEffort:   1,
		PendingOK:           true,
		OldestPauseAge:      90 * time.Second,
		OldestBestEffortAge: 4 * time.Hour,
		OldestPendingAgeOK:  true,
		PendingMarkers:      4,
		PendingMarkersOK:    true,
		OutboxPending:       5,
		OutboxPendingOK:     true,
	})

	metrics := collectMetrics(t, reader)

	enabled := metrics["backup_enabled"].Data.(metricdata.Gauge[int64])
	if len(enabled.DataPoints) != 1 || enabled.DataPoints[0].Value != 0 {
		t.Fatalf("backup_enabled = %#v, want one point of 0", enabled.DataPoints)
	}

	pending := metrics["backup_journal_pending"].Data.(metricdata.Gauge[int64])
	byPriority := map[string]int64{}
	for _, dp := range pending.DataPoints {
		for _, kv := range dp.Attributes.ToSlice() {
			if string(kv.Key) == "priority" {
				byPriority[kv.Value.AsString()] = dp.Value
			}
		}
	}
	want := map[string]int64{
		BackupPriorityPause:      3,
		BackupPriorityCheckpoint: 2,
		BackupPriorityBestEffort: 1,
	}
	for priority, wantValue := range want {
		if byPriority[priority] != wantValue {
			t.Fatalf("backup_journal_pending{priority=%q} = %d, want %d", priority, byPriority[priority], wantValue)
		}
	}

	age := metrics["backup_oldest_pending_age_seconds"].Data.(metricdata.Gauge[float64])
	ageByPriority := map[string]float64{}
	for _, dp := range age.DataPoints {
		for _, kv := range dp.Attributes.ToSlice() {
			if string(kv.Key) == "priority" {
				ageByPriority[kv.Value.AsString()] = dp.Value
			}
		}
	}
	wantAge := map[string]float64{
		BackupPriorityPause:      90,
		BackupPriorityCheckpoint: 0,
		BackupPriorityBestEffort: 4 * 3600,
	}
	for priority, wantValue := range wantAge {
		if ageByPriority[priority] != wantValue {
			t.Fatalf("backup_oldest_pending_age_seconds[%s] = %v, want %v (all: %v)",
				priority, ageByPriority[priority], wantValue, ageByPriority)
		}
	}

	markers := metrics["backup_pending_markers"].Data.(metricdata.Gauge[int64])
	if len(markers.DataPoints) != 1 || markers.DataPoints[0].Value != 4 {
		t.Fatalf("backup_pending_markers = %#v, want one point of 4", markers.DataPoints)
	}

	outbox := metrics["backup_outbox_pending"].Data.(metricdata.Gauge[int64])
	if len(outbox.DataPoints) != 1 || outbox.DataPoints[0].Value != 5 {
		t.Fatalf("backup_outbox_pending = %#v, want one point of 5", outbox.DataPoints)
	}
}

// Clock skew between the sampler and a task's EnqueuedAt must never
// report a negative backlog age.
func TestBackupRecorderClampsNegativeAge(t *testing.T) {
	ctx := context.Background()
	r, reader := testBackupRecorder(t)

	r.RecordSample(ctx, BackupSample{Enabled: true, OldestPauseAge: -time.Minute, OldestPendingAgeOK: true})

	metrics := collectMetrics(t, reader)
	age := metrics["backup_oldest_pending_age_seconds"].Data.(metricdata.Gauge[float64])
	for _, dp := range age.DataPoints {
		if dp.Value != 0 {
			t.Fatalf("backup_oldest_pending_age_seconds = %#v, want every tier clamped to 0", age.DataPoints)
		}
	}
}

// A failed read must drop its gauge from the sample rather than publish a
// zero: a zero backlog age would reset the sustained-backlog alert, and a
// zero outbox depth would suppress the stalled-outbox alert.
func TestBackupRecorderOmitsGaugesOnUnreadFields(t *testing.T) {
	ctx := context.Background()
	r, reader := testBackupRecorder(t)

	r.RecordSample(ctx, BackupSample{Enabled: true})

	metrics := collectMetrics(t, reader)
	for _, name := range []string{
		"backup_journal_pending",
		"backup_oldest_pending_age_seconds",
		"backup_pending_markers",
		"backup_outbox_pending",
	} {
		if _, ok := metrics[name]; ok {
			t.Fatalf("%s was recorded despite its OK flag being false", name)
		}
	}
	if _, ok := metrics["backup_enabled"]; !ok {
		t.Fatal("backup_enabled must always be recorded, even when other reads fail")
	}
}
