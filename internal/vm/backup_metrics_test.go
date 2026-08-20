package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// The pause hook must observe its synchronous RPC-path time whenever a
// recorder is installed, including with backup disabled: the histogram
// exists precisely to catch work silently creeping onto the pause path.
func TestBackupPauseRecordsHookDuration(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	disk := filepath.Join(dir, "rootfs.ext4")
	for _, path := range []string{snap, disk} {
		if err := os.WriteFile(path, []byte("bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

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

	m := &Manager{}
	m.SetBackupMetrics(rec)
	// Backup disabled (no enqueue hook): the hook returns after the
	// vmstate entry, and the histogram must still see the call.
	m.backupPause(context.Background(), "vm-1", snap, disk, "", "tok-test", zerolog.Nop())

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name != "backup_pause_hook_duration_seconds" {
				continue
			}
			for _, dp := range metric.Data.(metricdata.Histogram[float64]).DataPoints {
				count += dp.Count
			}
		}
	}
	if count != 1 {
		t.Fatalf("backup_pause_hook_duration_seconds count = %d, want 1", count)
	}
}

// A Manager without a recorder (metrics disabled) must run the pause
// hook untouched: the nil recorder is a no-op, never a nil dereference.
func TestBackupPauseNilRecorderSafe(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(snap, []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{}
	if got := m.backupPause(context.Background(), "vm-1", snap, filepath.Join(dir, "rootfs.ext4"), "", "tok-test", zerolog.Nop()); len(got) != 1 {
		t.Fatalf("manifest entries = %d, want the vmstate entry", len(got))
	}
}
