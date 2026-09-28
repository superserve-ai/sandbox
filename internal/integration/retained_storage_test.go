//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
		startBlock := int64(0)
		if o.kind == "snapshot" {
			// Give the retained snapshot a private extent so leaving its
			// interval open cannot be masked by the source's shared baseline.
			startBlock = 1048576
		}
		exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at)
   VALUES($1,$2,$3,$4,$5,jsonb_build_array(jsonb_build_object('device','fs','start',$6::bigint,'length',1048576)),$7)`, f.hostID, team, o.kind, o.id, strings.Repeat("a", 64), startBlock, start)
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
	}{{start, d1, 1800}, {d1, d2, 1800}, {d2, d3, 1200}, {d3, d3.Add(time.Minute), 0}} {
		var got float64
		if err := testPool.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, window.a, window.b).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != window.want {
			t.Fatalf("shared retention %v-%v: %v want %v", window.a, window.b, got, window.want)
		}
	}
	var snapshotEnded time.Time
	if err := testPool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE owner_kind='snapshot' AND owner_id=$1`, snapshot).Scan(&snapshotEnded); err != nil {
		t.Fatal(err)
	}
	if !snapshotEnded.Equal(d2) {
		t.Fatalf("snapshot interval ended at %v, want %v", snapshotEnded, d2)
	}
}

func TestRetainedStorageConsumerParity(t *testing.T) {
	ctx := t.Context()
	team, _ := seedTeamAndKey(t)
	start := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	mid, end := start.Add(30*time.Minute), start.Add(time.Hour)
	host := "example-retained-" + uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE team_id=$1`, team)
	})
	seedPlatformBillingRatesForTest(t, ctx, team, "retained-parity-"+uuid.NewString(), start.Add(-time.Hour))
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true),($1,'tenant_usage_dashboard',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
	first, second := uuid.New(), uuid.New()
	insert := func(id uuid.UUID, a, b time.Time, extents string) {
		exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at) VALUES($1,$2,'sandbox',$3,'fixture',$4::jsonb,$5,$6)`, host, team, id, extents, a, b)
	}
	insert(first, start, mid, `[{"device":"fs","start":0,"length":1073741824}]`)
	insert(first, mid, end, `[{"device":"fs","start":0,"length":2147483648}]`)
	insert(second, start, end, `[{"device":"fs","start":0,"length":1073741824},{"device":"fs","start":2147483648,"length":536870912}]`)
	const want = 7372800.0 // MiB-seconds: (1536 + 2560) * 1800.
	assertNumeric := func(label string, n pgtype.Numeric, scale, want float64) {
		t.Helper()
		v, err := n.Float64Value()
		if err != nil || !v.Valid || math.Abs(v.Float64*scale-want) > 1e-8 {
			t.Fatalf("%s: %v %v, want %v", label, v, err, want)
		}
	}
	usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("aggregate GiB-seconds", usage.StorageGibSeconds, 1024, want)
	assertNumeric("paused CPU", usage.VcpuSeconds, 1, 0)
	assertNumeric("paused memory", usage.MemoryGibSeconds, 1, 0)
	series, err := testQueries.GetTeamBillingUsageSeries(ctx, db.GetTeamBillingUsageSeriesParams{TeamID: team, PeriodStarts: []time.Time{start, mid}, PeriodEnds: []time.Time{mid, end}})
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 2 {
		t.Fatalf("series rows: %d", len(series))
	}
	assertNumeric("first series bucket", series[0].StorageGibSeconds, 1024, 1536*1800)
	assertNumeric("second series bucket", series[1].StorageGibSeconds, 1024, 2560*1800)
	var cpu, memory, storage float64
	if err := testPool.QueryRow(ctx, billing.ExportRemeasurementSQL, team, start, end).Scan(&cpu, &memory, &storage); err != nil {
		t.Fatal(err)
	}
	if cpu != 0 || memory != 0 || storage != want {
		t.Fatalf("export: cpu=%v memory=%v storage=%v", cpu, memory, storage)
	}
	stamp := func(v time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: v, Valid: true} }
	hourly, err := testQueries.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{TeamID: team, HourStart: stamp(start), HourEnd: stamp(end)})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("hourly MiB-seconds", hourly.StorageMibSeconds, 1, want)
	hourlyRows, err := testQueries.ListTeamBillingUsageHourly(ctx, db.ListTeamBillingUsageHourlyParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
	if err != nil {
		t.Fatal(err)
	}
	if len(hourlyRows) != 1 {
		t.Fatalf("hourly rows: %d", len(hourlyRows))
	}
	assertNumeric("hourly reader", hourlyRows[0].StorageMibSeconds, 1, want)
	rollup, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{TeamID: team, PeriodStart: stamp(start), PeriodEnd: stamp(end)})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("rollup writer", rollup.StorageMibSeconds, 1, want)
	persisted, err := testQueries.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
	if err != nil {
		t.Fatal(err)
	}
	assertNumeric("rollup reader", persisted.StorageMibSeconds, 1, want)
	// The trial window and platform request share these exact retained rows.
	exec(`DELETE FROM team_credit_ledger WHERE team_id=$1`, team)
	exec(`DELETE FROM team_credit_grant WHERE team_id=$1`, team)
	exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at) VALUES($1,10,10,'signup trial credit',$2)`, team, start)
	exec(`INSERT INTO team_billing_account(team_id,trial_ended_at) VALUES($1,$2) ON CONFLICT(team_id) DO UPDATE SET trial_ended_at=$2`, team, end)
	trial, err := testQueries.GetTeamTrialBalance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	cost := want / 1024 * 0.00000003
	assertNumeric("trial USD", trial.ConsumedUsd, 1, math.Round(cost*1e6)/1e6)
	router := newInternalRouterWithNow(t, func() time.Time { return end })
	actor := seedPlatformAdminProfile(t)
	for _, sort := range []string{"team_name", "current_charges_usd"} {
		resp := doInternal(router, http.MethodGet, fmt.Sprintf("/internal/billing?search=%s&sort=%s&order=asc", team, sort), actor.String(), "")
		if resp.Code != http.StatusOK {
			t.Fatalf("platform: %d %s", resp.Code, resp.Body.String())
		}
		body := decodePlatformBilling(t, resp.Body.Bytes())
		if len(body.Rows) != 1 || body.Rows[0].Summary == nil {
			t.Fatalf("platform rows: %+v", body.Rows)
		}
		summary := body.Rows[0].Summary
		if got := summary["storage_mib_seconds"].(float64); got != want {
			t.Fatalf("platform MiB-seconds %v want %v", got, want)
		}
		if got := summary["cost_breakdown_usd"].(map[string]any)["storage"].(float64); math.Abs(got-cost) > 1e-12 {
			t.Fatalf("platform USD %v want %v", got, cost)
		}
	}
}

func TestRetainedStorageSweepMatchesPhysicalGrid(t *testing.T) {
	team, _ := seedTeamAndKey(t)
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	var grid [2][2][20][32]bool
	for i := 0; i < 80; i++ {
		host, device := (i/2)%2, i%2
		lo, hi := i%17, i%17+1+i%3
		left, right := (i*7)%24, (i*7)%24+1+i%8
		extents := fmt.Sprintf(`[{"device":"fs-%d","start":%d,"length":%d}]`, device, left*4096, (right-left)*4096)
		if _, err := tx.Exec(ctx, `INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at) VALUES($1,$2,'sandbox',$3,'grid',$4::jsonb,$5,$6)`, fmt.Sprintf("example-host-%d", host), team, uuid.New(), extents, start.Add(time.Duration(lo)*time.Second), start.Add(time.Duration(hi)*time.Second)); err != nil {
			t.Fatal(err)
		}
		for second := lo; second < hi; second++ {
			for block := left; block < right; block++ {
				grid[host][device][second][block] = true
			}
		}
	}
	var want float64
	for host := range grid {
		for device := range grid[host] {
			for second := 3; second < 17; second++ {
				for _, occupied := range grid[host][device][second] {
					if occupied {
						want += 4096.0 / 1048576
					}
				}
			}
		}
	}
	var got float64
	if err := tx.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, start.Add(3*time.Second), start.Add(17*time.Second)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sweep=%v physical grid=%v", got, want)
	}
}

func TestRetainedStorageHistorySweepQualification(t *testing.T) {
	for _, size := range []struct{ owners, epochs int }{{128, 24}, {1024, 288}} {
		t.Run(fmt.Sprintf("owners-%d-epochs-%d", size.owners, size.epochs), func(t *testing.T) {
			ctx := t.Context()
			team, _ := seedTeamAndKey(t)
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='90s'`); err != nil {
				t.Fatal(err)
			}
			start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
			end := start.Add(time.Duration(size.epochs) * 5 * time.Minute)
			if _, err := tx.Exec(ctx, `INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
    SELECT 'example-sweep',$1,'sandbox',md5('owner-'||o)::uuid,'epoch-'||g,
      jsonb_build_array(jsonb_build_object('device','fs','start',0,'length',1048576),
       jsonb_build_object('device','fs','start',1048576+(o+(g%2)*($3::int+1))*4096,'length',4096)),
      $2::timestamptz+g*interval '5 minutes',$2::timestamptz+(g+1)*interval '5 minutes'
    FROM generate_series(1,$3::int) o CROSS JOIN generate_series(0,$4::int-1) g`, team, start, size.owners, size.epochs); err != nil {
				t.Fatal(err)
			}
			for _, window := range []struct {
				name string
				end  time.Time
			}{{"full-history", end}, {"one-bucket", start.Add(time.Hour)}} {
				began := time.Now()
				var got float64
				if err := tx.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, start, window.end).Scan(&got); err != nil {
					t.Fatal(err)
				}
				want := (1 + float64(size.owners)/256) * window.end.Sub(start).Seconds()
				if got != want {
					t.Fatalf("usage=%v want %v", got, want)
				}
				t.Logf("retained sweep qualification: owners=%d epochs=%d historical_rows=%d extents=%d window=%s elapsed=%s MiB_seconds=%v", size.owners, size.epochs, size.owners*size.epochs, 2*size.owners*size.epochs, window.name, time.Since(began), got)
			}
		})
	}
}
