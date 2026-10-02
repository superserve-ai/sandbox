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

// pauseDropCount totals backup_pause_dropped_total across its reasons.
func pauseDropCount(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name != "backup_pause_dropped_total" {
				continue
			}
			for _, dp := range metric.Data.(metricdata.Sum[int64]).DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

// Only a pause with no generation anywhere counts as dropped. A marker
// kept solely so a later sweep can upgrade an already-queued row is
// discarded routinely once the sandbox moves on, and counting those would
// report losses that never happened.
func TestDropPendingBackupCountsOnlyUncoveredPauses(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

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
	m := &Manager{state: st}
	m.SetBackupMetrics(rec)

	// Minted the way a real pause mints it, so the worker's own copy is
	// classifiable: the fast losses are exactly what this counter is for.
	lost := newPendingBackup("vm-lost", "/snap", "/disk", "", "pause-tok")
	if lost.Version != PendingBackupVersion {
		t.Fatal("a freshly minted marker is not versioned, so its worker would suppress the count")
	}
	if err := st.PutPendingBackup(lost); err != nil {
		t.Fatal(err)
	}
	m.dropPendingBackup(context.Background(), lost, zerolog.Nop(), telemetry.BackupDropSuperseded)
	if got := pauseDropCount(t, reader); got != 1 {
		t.Fatalf("uncovered pause counted %d times, want 1", got)
	}

	queued := PendingBackup{VMID: "vm-queued", Token: "tok-queued", Enqueued: true, Version: PendingBackupVersion}
	if err := st.PutPendingBackup(queued); err != nil {
		t.Fatal(err)
	}
	m.dropPendingBackup(context.Background(), queued, zerolog.Nop(), telemetry.BackupDropSuperseded)
	if got := pauseDropCount(t, reader); got != 1 {
		t.Fatalf("a marker whose generation was already queued counted as a drop: total %d, want 1", got)
	}
	if _, ok, err := st.GetPendingBackup("vm-queued"); err != nil || ok {
		t.Fatalf("the marker was not discarded: ok=%v err=%v", ok, err)
	}

	// A marker an older binary wrote cannot be classified: whether its
	// generation reached the journal is unknowable, so it is not a loss.
	legacy := PendingBackup{VMID: "vm-legacy", Token: "tok-legacy"}
	if err := st.PutPendingBackup(legacy); err != nil {
		t.Fatal(err)
	}
	m.dropPendingBackup(context.Background(), legacy, zerolog.Nop(), telemetry.BackupDropSuperseded)
	if got := pauseDropCount(t, reader); got != 1 {
		t.Fatalf("a marker from a binary without the field counted as a drop: total %d, want 1", got)
	}

	// A marker a newer pause now owns is not this pause's loss.
	if err := st.PutPendingBackup(PendingBackup{VMID: "vm-moved", Token: "tok-new"}); err != nil {
		t.Fatal(err)
	}
	m.dropPendingBackup(context.Background(), PendingBackup{VMID: "vm-moved", Token: "tok-old"}, zerolog.Nop(), telemetry.BackupDropSuperseded)
	if got := pauseDropCount(t, reader); got != 1 {
		t.Fatalf("a marker owned by a newer pause counted as a drop: total %d, want 1", got)
	}
}

// The store must distinguish removing our marker from finding nothing of
// ours: a newer pause owning the record is not a discard, and counting it
// would report a loss for a pause whose coverage simply moved on.
func TestDeletePendingBackupIfReportsOnlyItsOwnRemoval(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, deleted, err := st.DeletePendingBackupIf("vm-absent", "tok"); err != nil || deleted {
		t.Fatalf("absent record: deleted=%v err=%v", deleted, err)
	}
	if err := st.PutPendingBackup(PendingBackup{VMID: "vm-1", Token: "tok-new"}); err != nil {
		t.Fatal(err)
	}
	if _, deleted, err := st.DeletePendingBackupIf("vm-1", "tok-old"); err != nil || deleted {
		t.Fatalf("a newer pause's record: deleted=%v err=%v", deleted, err)
	}
	if _, ok, err := st.GetPendingBackup("vm-1"); err != nil || !ok {
		t.Fatalf("the newer pause's marker was removed: ok=%v err=%v", ok, err)
	}
	if _, deleted, err := st.DeletePendingBackupIf("vm-1", "tok-new"); err != nil || !deleted {
		t.Fatalf("own record: deleted=%v err=%v", deleted, err)
	}
}

// The interleaving a direct call cannot reach: a sweep captures the marker
// list, the live worker enqueues, then the sweep runs the real rehash path
// with its pre-enqueue copy. Neither of the worker's two success endings —
// keeping the marker for a staging upgrade, or retiring it outright — may
// leave that stale copy able to report a journaled pause as lost.
func TestDelayedSweepDoesNotReportAnEnqueuedPauseAsDropped(t *testing.T) {
	for _, tc := range []struct {
		name string
		// succeed applies the ending the live worker reached.
		succeed func(*testing.T, *Manager, PendingBackup)
		// inconclusive runs a sweep while a resume has started the unit
		// but not yet cleared the paused status, so the at-rest check
		// can neither trust nor supersede the pause and keeps it.
		inconclusive bool
	}{
		{
			name: "marker kept for a staging upgrade",
			succeed: func(t *testing.T, m *Manager, pb PendingBackup) {
				pb.Enqueued = true
				if err := m.state.PutPendingBackupIfOwner(pb); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:    "marker retired",
			succeed: retireMarker,
		},
		{
			name:         "marker retired, then a sweep finds the resume mid-flight",
			succeed:      retireMarker,
			inconclusive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			snap := filepath.Join(dir, "vmstate.snap")
			disk := filepath.Join(dir, "rootfs.ext4")
			for _, p := range []string{snap, disk} {
				if err := os.WriteFile(p, []byte("bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			st, err := OpenStateStore(filepath.Join(dir, "vmd.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()

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
			// No instance and a dead unit: the rehash sees the pause
			// superseded, the branch that classifies a drop.
			m := &Manager{state: st, vms: map[string]*VMInstance{}, unitDead: func(context.Context, string) bool { return true }}
			m.SetBackupMetrics(rec)

			pb := newPendingBackup("vm-1", snap, disk, "", "pause-tok")
			if err := st.PutPendingBackup(pb); err != nil {
				t.Fatal(err)
			}
			// What a sweep captured before the live worker got its
			// verdict, read the way the sweep reads it.
			captured, err := st.ListPendingBackups()
			if err != nil || len(captured) != 1 {
				t.Fatalf("capture = %+v (%v)", captured, err)
			}
			stale := captured[0]
			tc.succeed(t, m, pb)

			if tc.inconclusive {
				m.vms = map[string]*VMInstance{pb.VMID: {Status: StatusPaused, SnapshotPath: snap}}
				m.unitDead = func(context.Context, string) bool { return false }
				m.rehashPendingBackup(context.Background(), stale, zerolog.Nop())
				m.vms = map[string]*VMInstance{}
				m.unitDead = func(context.Context, string) bool { return true }
			}
			m.rehashPendingBackup(context.Background(), stale, zerolog.Nop())

			if got := pauseDropCount(t, reader); got != 0 {
				t.Fatalf("a pause already in the journal was reported dropped %d times", got)
			}
		})
	}
}

func retireMarker(t *testing.T, m *Manager, pb PendingBackup) {
	m.clearEnqueuedMarker(pb, zerolog.Nop())
	if got, found, err := m.state.GetPendingBackup(pb.VMID); err != nil || found {
		t.Fatalf("marker not retired: %+v (%v)", got, err)
	}
}
