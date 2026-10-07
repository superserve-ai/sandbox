//go:build integration && linux

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	vm "github.com/superserve-ai/sandbox/internal/vm"
	"golang.org/x/sys/unix"
)

func TestRetainedStorageRealFilesystemReachesBillingConsumer(t *testing.T) {
	root := os.Getenv("RETAINED_STORAGE_TEST_DIR")
	if root == "" {
		t.Skip("RETAINED_STORAGE_TEST_DIR must name a qualified Linux reflink filesystem")
	}
	dir, err := os.MkdirTemp(root, "retained-billing-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	f := newStorageReportFixture(t, "paused", false)
	team := sandboxTeamID(t, f.sandboxID)
	child := uuid.New()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib)
 VALUES($1,$2,'example-fork','paused',$3,1,1024,8)`, child, team, f.hostID); err != nil {
		t.Fatal(err)
	}
	state, err := vm.OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	paths := []string{
		filepath.Join(dir, "overlay.ext4"),
		filepath.Join(dir, "vmstate.snap"),
		filepath.Join(dir, "mem.snap"),
	}
	for i, path := range paths {
		data := bytes.Repeat([]byte{byte(i + 1)}, (i+1)*4096)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := vm.VMRecord{ID: f.sandboxID.String(), Status: vm.StatusPaused,
		DiskPath: paths[0], RootfsPath: paths[0], SnapshotPath: paths[1], MemFilePath: paths[2]}
	if err := state.Put(rec); err != nil {
		t.Fatal(err)
	}
	childPaths := make([]string, len(paths))
	for i, path := range paths {
		childPaths[i] = path + ".fork"
		src, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.OpenFile(childPaths[i], os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			src.Close()
			t.Fatal(err)
		}
		err = unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
		if err == nil {
			err = dst.Sync()
		}
		src.Close()
		dst.Close()
		if err != nil {
			t.Fatalf("qualified filesystem reflink: %v", err)
		}
	}
	if err := state.Put(vm.VMRecord{ID: child.String(), Status: vm.StatusPaused,
		DiskPath: childPaths[0], RootfsPath: childPaths[0], SnapshotPath: childPaths[1], MemFilePath: childPaths[2]}); err != nil {
		t.Fatal(err)
	}
	mgr, err := vm.NewManager(vm.ManagerConfig{RunDir: dir, SnapshotDir: filepath.Join(dir, "snapshots")}, nil, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetStateStore(state)
	inv, err := mgr.RetainedStorageInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Owners) != 2 || len(inv.Owners[0].Extents) == 0 {
		t.Fatalf("real filesystem inventory = %#v", inv)
	}
	// The report is the actual FIEMAP-derived payload, not synthetic extents.
	reportID := uuid.New()
	body, err := json.Marshal(map[string]any{
		"incarnation_id": f.incarnation, "report_id": reportID,
		"measurements": []any{map[string]any{"sandbox_id": "", "allocated_bytes": 0, "retained": inv}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := requestStorageReport(f.router, f.hostID, string(body))
	if response.Code != http.StatusCreated {
		t.Fatalf("real inventory report: %d %s", response.Code, response.Body.String())
	}
	ack := decodeStorageReportAck(t, response)
	waitStorageReportState(t, reportID, "processed")
	// Move only the accepted accounting window into the past; preserve the
	// ingested physical extents and receipt identity.
	startTime := ack.ReceivedAt.Truncate(time.Hour).Add(-2 * time.Hour)
	endTime := startTime.Add(time.Hour)
	seedStorageActivation(t, team, startTime)
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	tag, err := tx.Exec(t.Context(), `UPDATE retained_storage_interval SET started_at=$2 WHERE team_id=$1 AND started_at=$3`, team, startTime, ack.ReceivedAt)
	if err != nil || tag.RowsAffected() != 2 {
		t.Fatalf("accepted owner intervals: rows=%d err=%v", tag.RowsAffected(), err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE retained_storage_cutover SET started_at=$2 WHERE team_id=$1`, team, startTime); err != nil {
		t.Fatal(err)
	}
	var got float64
	if err := tx.QueryRow(t.Context(), `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, startTime, endTime).Scan(&got); err != nil {
		t.Fatal(err)
	}
	var extents []retainedstorage.Extent
	var summed int64
	for _, owner := range inv.Owners {
		extents = append(extents, owner.Extents...)
		for _, extent := range owner.Extents {
			summed += extent.Length
		}
	}
	sort.Slice(extents, func(i, j int) bool {
		if extents[i].Device != extents[j].Device {
			return extents[i].Device < extents[j].Device
		}
		return extents[i].Start < extents[j].Start
	})
	total := int64(0)
	var device string
	var end int64
	for _, e := range extents {
		if e.Device != device {
			device, end = e.Device, 0
		}
		start := e.Start
		if start < end {
			start = end
		}
		if e.Start+e.Length > start {
			total += e.Start + e.Length - start
		}
		if e.Start+e.Length > end {
			end = e.Start + e.Length
		}
	}
	if total <= 0 || total >= summed {
		t.Fatalf("reflink union %d must be smaller than owner sum %d", total, summed)
	}
	want := float64(total) / (1 << 20) * endTime.Sub(startTime).Seconds()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("real inventory billing = %v, want %v MiB-seconds", got, want)
	}
	queries := db.New(tx)
	assertNumeric := func(label string, value pgtype.Numeric, scale float64) {
		t.Helper()
		n, err := value.Float64Value()
		if err != nil || !n.Valid || math.Abs(n.Float64*scale-want) > 1e-9 {
			t.Fatalf("%s = %v (%v), want %v MiB-seconds", label, n, err, want)
		}
	}
	usage, err := queries.GetTeamBillingUsage(t.Context(), db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: startTime, PeriodEnd: endTime})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("aggregate", usage.StorageGibSeconds, 1024)
	assertNumeric("payable", usage.BillableStorageGibSeconds, 1024)
	series, err := queries.GetTeamBillingUsageSeries(t.Context(), db.GetTeamBillingUsageSeriesParams{TeamID: team, PeriodStarts: []time.Time{startTime}, PeriodEnds: []time.Time{endTime}})
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 {
		t.Fatalf("series rows = %d", len(series))
	}
	assertNumeric("series", series[0].StorageGibSeconds, 1024)
	assertNumeric("payable series", series[0].BillableStorageGibSeconds, 1024)
	var cpu, memory, storage float64
	if err := tx.QueryRow(t.Context(), billing.ExportRemeasurementSQL, team, startTime, endTime).Scan(&cpu, &memory, &storage); err != nil {
		t.Fatal(err)
	}
	if cpu != 0 || memory != 0 || math.Abs(storage-want) > 1e-9 {
		t.Fatalf("export = %v/%v/%v, want 0/0/%v", cpu, memory, storage, want)
	}
	stamp := func(v time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: v, Valid: true} }
	hourly, err := queries.UpsertTeamBillingUsageHour(t.Context(), db.UpsertTeamBillingUsageHourParams{TeamID: team, HourStart: stamp(startTime), HourEnd: stamp(endTime)})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("hourly", hourly.StorageMibSeconds, 1)
	rollup, err := queries.UpsertTeamBillingUsage(t.Context(), db.UpsertTeamBillingUsageParams{TeamID: team, PeriodStart: stamp(startTime), PeriodEnd: stamp(endTime)})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("rollup", rollup.StorageMibSeconds, 1)

}
