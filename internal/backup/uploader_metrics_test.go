package backup

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

func testMetricsRecorder(t *testing.T) (*telemetry.BackupRecorder, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	rec, err := telemetry.NewBackupRecorderWithProvider(provider, telemetry.BackupOTelConfig{HostID: "host-1"})
	if err != nil {
		t.Fatal(err)
	}
	return rec, reader
}

// uploadCounts collects backup_upload_total datapoints keyed by result,
// plus the total bytes counter.
func uploadCounts(t *testing.T, reader *sdkmetric.ManualReader) (map[string]int64, int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	byResult := map[string]int64{}
	var bytes int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "backup_upload_total":
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					for _, kv := range dp.Attributes.ToSlice() {
						if string(kv.Key) == "result" {
							byResult[kv.Value.AsString()] += dp.Value
						}
					}
				}
			case "backup_upload_bytes_total":
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					bytes += dp.Value
				}
			}
		}
	}
	return byResult, bytes
}

func TestUploaderRecordsVerifiedThenDeduped(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	rec, reader := testMetricsRecorder(t)
	u := &Uploader{Journal: j, Store: store, Metrics: rec}

	task := writeTask(t, t.TempDir())
	task.Files = task.Files[1:] // vmstate only: no base dependency needed
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := task.EnqueuedAt.Add(time.Minute)
	if worked, err := u.drainOne(context.Background(), now); err != nil || !worked {
		t.Fatalf("drain: worked=%v err=%v", worked, err)
	}

	byResult, bytes := uploadCounts(t, reader)
	if byResult[telemetry.BackupUploadVerified] != 1 {
		t.Fatalf("verified count = %d, want 1 (all: %v)", byResult[telemetry.BackupUploadVerified], byResult)
	}
	if bytes <= 0 {
		t.Fatalf("upload bytes = %d, want > 0", bytes)
	}

	// An unchanged re-pause re-enqueues the identical generation: every
	// object dedupes against verified history and nothing streams.
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if worked, err := u.drainOne(context.Background(), now.Add(time.Minute)); err != nil || !worked {
		t.Fatalf("re-drain: worked=%v err=%v", worked, err)
	}
	byResult, _ = uploadCounts(t, reader)
	if byResult[telemetry.BackupUploadDeduped] != 1 {
		t.Fatalf("deduped count = %d, want 1 (all: %v)", byResult[telemetry.BackupUploadDeduped], byResult)
	}
}

func TestUploaderRecordsFailedAttempt(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	rec, reader := testMetricsRecorder(t)
	u := &Uploader{Journal: j, Store: store, Metrics: rec}

	task := writeTask(t, t.TempDir())
	task.Files = task.Files[1:]
	store.fail["sandboxes/sb-1/gen-abc/"+packedName(t, task.Files[0].Path, "vmstate.snap")] = errors.New("transient")
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if worked, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil || !worked {
		t.Fatalf("drain: worked=%v err=%v", worked, err)
	}

	byResult, _ := uploadCounts(t, reader)
	if byResult[telemetry.BackupUploadFailed] != 1 {
		t.Fatalf("failed count = %d, want 1 (all: %v)", byResult[telemetry.BackupUploadFailed], byResult)
	}
}

func TestUploaderRecordsAbandonedGeneration(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	rec, reader := testMetricsRecorder(t)
	u := &Uploader{Journal: j, Store: store, Metrics: rec}

	task := writeTask(t, t.TempDir())
	task.Files = task.Files[1:]
	if err := os.Remove(task.Files[0].Path); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if worked, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil || !worked {
		t.Fatalf("drain: worked=%v err=%v", worked, err)
	}

	byResult, _ := uploadCounts(t, reader)
	if byResult[telemetry.BackupUploadAbandoned] != 1 {
		t.Fatalf("abandoned count = %d, want 1 (all: %v)", byResult[telemetry.BackupUploadAbandoned], byResult)
	}
}
