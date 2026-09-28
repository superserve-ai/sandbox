//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

func TestRetainedStorageSeriesPreservesFractionalLegacyArtifacts(t *testing.T) {
	f := newStorageReportFixture(t, "paused", false)
	team := sandboxTeamID(t, f.sandboxID)
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	end := start.Add(384 * time.Second)
	snapshot := uuid.New()
	const path = "/example/fractional-rootfs.ext4"
	exec(`INSERT INTO snapshot(id,sandbox_id,team_id,path,trigger) VALUES($1,$2,$3,$4,'pause')`,
		snapshot, f.sandboxID, team, "/example/fractional-snapshot")
	exec(`UPDATE sandbox SET created_at=$2,snapshot_id=$3,base_path=$4 WHERE id=$1`,
		f.sandboxID, start, snapshot, path)
	exec(`INSERT INTO artifact_manifest(snapshot_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$2,1048576,4096,$3)`, snapshot, path, strings.Repeat("0", 64))
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,0,$3,$4,'deleted')`, f.sandboxID, team, start, end)
	queries := db.New(tx)
	rows, err := queries.GetTeamBillingUsageSeries(ctx, db.GetTeamBillingUsageSeriesParams{
		TeamID:       team,
		PeriodStarts: []time.Time{start, start.Add(128 * time.Second), start.Add(256 * time.Second)},
		PeriodEnds:   []time.Time{start.Add(128 * time.Second), start.Add(256 * time.Second), end},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("series buckets = %d, want 3", len(rows))
	}
	var total float64
	for i, row := range rows {
		n, err := row.StorageGibSeconds.Float64Value()
		if err != nil || !n.Valid || n.Float64*1024 != 0.5 {
			t.Fatalf("bucket %d storage = %v (%v), want 0.5 MiB-seconds", i, n, err)
		}
		total += n.Float64 * 1024
	}
	usage, err := queries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
		TeamID: team, PeriodStart: start, PeriodEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := usage.StorageGibSeconds.Float64Value()
	// The legacy aggregate floors once: three half-MiB-second buckets yield one.
	if err != nil || !n.Valid || n.Float64*1024 != 1 || math.Floor(total) != n.Float64*1024 {
		t.Fatalf("aggregate storage = %v (%v), series total = %v MiB-seconds", n, err, total)
	}
}

func TestRetainedStorageReceiptReplacementAndLegacyIsolation(t *testing.T) {
	f := newStorageReportFixture(t, "paused", true)
	team := sandboxTeamID(t, f.sandboxID)
	ctx := t.Context()
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE host_id=$1`, f.hostID)
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_cutover WHERE host_id=$1`, f.hostID)
	})
	owner := retainedstorage.Owner{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("1", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 200 << 20}}}
	post := func(id uuid.UUID, owners []retainedstorage.Owner, want int) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"incarnation_id": f.incarnation, "report_id": id, "measurements": []map[string]any{{"sandbox_id": "", "allocated_bytes": 0, "retained": retainedstorage.Inventory{Version: 1, Owners: owners}}}})
		if err != nil {
			t.Fatal(err)
		}
		w := requestStorageReport(f.router, f.hostID, string(body))
		if w.Code != want {
			t.Fatalf("report: %d %s", w.Code, w.Body.String())
		}
	}
	first := uuid.New()
	post(first, []retainedstorage.Owner{owner}, http.StatusCreated)
	waitStorageReportState(t, first, "processed")
	var a time.Time
	if err := testPool.QueryRow(ctx, `SELECT received_at FROM host_storage_report WHERE report_id=$1`, first).Scan(&a); err != nil {
		t.Fatal(err)
	}
	post(first, []retainedstorage.Owner{owner}, http.StatusOK)
	conflict := owner
	conflict.Generation = strings.Repeat("f", 64)
	post(first, []retainedstorage.Owner{conflict}, http.StatusConflict)
	second := uuid.New()
	owner.Generation = strings.Repeat("2", 64)
	owner.Extents[0].Length = 300 << 20
	post(second, []retainedstorage.Owner{owner}, http.StatusCreated)
	waitStorageReportState(t, second, "processed")
	var b time.Time
	if err := testPool.QueryRow(ctx, `SELECT received_at FROM host_storage_report WHERE report_id=$1`, second).Scan(&b); err != nil {
		t.Fatal(err)
	}
	// Beginning quantity applies to the entire earlier interval; no averaging.
	var measured float64
	if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3)::float8`, team, a, b).Scan(&measured); err != nil {
		t.Fatal(err)
	}
	if want := 200 * b.Sub(a).Seconds(); math.Abs(measured-want) > 0.0001 {
		t.Fatalf("receipt boundary usage %f want %f", measured, want)
	}
	legacy := uuid.New()
	if w := postStorageReport(t, f, legacy, 1<<20); w.Code != http.StatusCreated {
		t.Fatalf("legacy receipt: %d", w.Code)
	}
	waitStorageReportState(t, legacy, "processed")
	missing := uuid.New()
	post(missing, []retainedstorage.Owner{}, http.StatusCreated)
	waitStorageReportState(t, missing, "terminal")
	var active int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL AND generation=$2`, f.sandboxID, owner.Generation).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatal("legacy or incomplete observation changed retained allocation")
	}
	var cpu, memory, storage float64
	if err := testPool.QueryRow(ctx, billing.ExportRemeasurementSQL, team, a, b).Scan(&cpu, &memory, &storage); err != nil {
		t.Fatal(err)
	}
	if storage != measured || cpu != 0 || memory != 0 {
		t.Fatalf("paused export parity: %v %v %v vs %v", cpu, memory, storage, measured)
	}
	usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: a, PeriodEnd: b})
	if err != nil {
		t.Fatal(err)
	}
	n, err := usage.StorageGibSeconds.Float64Value()
	if err != nil || math.Abs(n.Float64*1024-measured) > 0.0001 {
		t.Fatalf("consumer conversion: %v %v", n, err)
	}
	// An explicit zero is a new generation, while omission above is no change.
	zero := uuid.New()
	owner.Generation = strings.Repeat("3", 64)
	owner.Extents = []retainedstorage.Extent{}
	post(zero, []retainedstorage.Owner{owner}, http.StatusCreated)
	waitStorageReportState(t, zero, "processed")
	if _, err := testQueries.DestroySandbox(ctx, storageRaceDestroyParams(t, f)); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatal("deletion left open retained storage")
	}
	var historical float64
	if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3)::float8`, team, a, b).Scan(&historical); err != nil {
		t.Fatal(err)
	}
	if historical != measured {
		t.Fatal("replacement/deletion rewrote prior storage history")
	}

}

func TestRetainedStorageUnionSurvivesSnapshotAndSourceDeletion(t *testing.T) {
	f := newStorageReportFixture(t, "paused", true)
	team := sandboxTeamID(t, f.sandboxID)
	ctx := t.Context()
	snapshot, child := uuid.New(), uuid.New()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE sandbox SET created_at=$2 WHERE id=$1`, f.sandboxID, start.Add(-time.Minute))
	exec(`UPDATE sandbox_storage_interval SET started_at=$2 WHERE sandbox_id=$1`, f.sandboxID, start)
	exec(`INSERT INTO sandbox_snapshot(id,team_id,sandbox_id,kind,status,host_id,vcpu_count,memory_mib,disk_mib,base_path,overlay_path,ready_at)
 VALUES($1,$2,$3,'fs','ready',$4,1,1024,8,'/example/base.ext4','/example/overlay.ext4',$5)`, snapshot, team, f.sandboxID, f.hostID, start)
	exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib) VALUES($1,$2,'example-fork','paused',$3,1,1024,8)`, child, team, f.hostID)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE host_id=$1`, f.hostID)
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_cutover WHERE host_id=$1`, f.hostID)
	})
	for _, o := range []struct {
		kind string
		id   uuid.UUID
	}{{"sandbox", f.sandboxID}, {"snapshot", snapshot}, {"sandbox", child}} {
		exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at)
   VALUES($1,$2,$3,$4,$5,'[{"device":"fs","start":0,"length":1048576}]',$6)`, f.hostID, team, o.kind, o.id, strings.Repeat("a", 64), start)
	}
	// One extra private MiB on the child; shared baseline stays once.
	exec(`UPDATE retained_storage_interval SET extents=extents||'[{"device":"fs","start":2097152,"length":1048576}]'::jsonb WHERE owner_id=$1`, child)
	d1, d2, d3 := start.Add(10*time.Minute), start.Add(20*time.Minute), start.Add(30*time.Minute)
	exec(`UPDATE sandbox SET destroyed_at=$2 WHERE id=$1`, f.sandboxID, d1)
	exec(`UPDATE sandbox_snapshot SET status='deleting',deleted_at=$2 WHERE id=$1`, snapshot, d2)
	exec(`UPDATE sandbox SET destroyed_at=$2 WHERE id=$1`, child, d3)
	for _, window := range []struct {
		a, b time.Time
		want float64
	}{{start, d1, 1200}, {d1, d2, 1200}, {d2, d3, 1200}, {d3, d3.Add(time.Minute), 0}} {
		var got float64
		if err := testPool.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, window.a, window.b).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != window.want {
			t.Fatalf("shared retention %v-%v: %v want %v", window.a, window.b, got, window.want)
		}
	}
}
