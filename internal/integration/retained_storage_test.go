//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestRetainedStorageLegacyArtifactUnionPreservesPreCutoverHistory(t *testing.T) {
	// Legacy billing applies the maximum allocation per path to the entire
	// union of reference lifetimes, including before the larger reference began.
	for _, tc := range []struct {
		name           string
		separateHosts  bool
		reassign       bool
		secondBytes    int64
		wantMiBSeconds float64
	}{
		{name: "same-host-shared-path", secondBytes: 1 << 20, wantMiBSeconds: 60},
		{name: "different-hosts-same-path", separateHosts: true, secondBytes: 1 << 20, wantMiBSeconds: 60},
		{name: "different-hosts-different-allocations", separateHosts: true, secondBytes: 2 << 20, wantMiBSeconds: 120},
		{name: "reassigned-current-host", separateHosts: true, reassign: true, secondBytes: 2 << 20, wantMiBSeconds: 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStorageReportFixture(t, "paused", false)
			team := sandboxTeamID(t, f.sandboxID)
			ctx := t.Context()
			start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			mid, end := start.Add(40*time.Second), start.Add(60*time.Second)
			otherSandbox, firstSnapshot, secondSnapshot := uuid.New(), uuid.New(), uuid.New()
			otherHost := f.hostID
			if tc.separateHosts {
				otherHost = "legacy-artifact-host-" + uuid.NewString()
			}
			const path = "/example/shared-rootfs.ext4"
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := testPool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,base_path)
 VALUES($1,$2,'legacy-reference','paused',$3,1,1024,8,$4,$5)`, otherSandbox, team, otherHost, mid, path)
			exec(`INSERT INTO snapshot(id,sandbox_id,team_id,path,trigger) VALUES
 ($1,$2,$3,$4,'pause'),($5,$6,$3,$4,'pause')`, firstSnapshot, f.sandboxID, team, path, secondSnapshot, otherSandbox)
			exec(`UPDATE sandbox SET created_at=$2,snapshot_id=$3,base_path=$4 WHERE id=$1`, f.sandboxID, start, firstSnapshot, path)
			exec(`UPDATE sandbox SET snapshot_id=$2 WHERE id=$1`, otherSandbox, secondSnapshot)
			exec(`INSERT INTO artifact_manifest(snapshot_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$3,1048576,1048576,$4),($2,'rootfs.ext4',$3,$5,$5,$4)`, firstSnapshot, secondSnapshot, path, strings.Repeat("0", 64), tc.secondBytes)
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$3,0,$4,$6,'deleted'),($2,$3,0,$5,$6,'deleted')`, f.sandboxID, otherSandbox, team, start, mid, end)
			if tc.reassign {
				// Current host identity must not change the historical path union.
				exec(`UPDATE sandbox SET host_id=$2 WHERE id=$1`, f.sandboxID, otherHost)
			}
			for _, floorArtifacts := range []bool{false, true} {
				var got float64
				if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,$4)::float8`, team, start, end, floorArtifacts).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if math.Abs(got-tc.wantMiBSeconds) > 0.0001 {
					t.Fatalf("legacy artifact union (floor=%t): got %v want %v MiB-seconds", floorArtifacts, got, tc.wantMiBSeconds)
				}
			}
		})
	}
}

func TestRetainedStorageReassignmentClosesLegacyArtifacts(t *testing.T) {
	for _, survivingReference := range []bool{false, true} {
		t.Run(fmt.Sprintf("surviving-reference-%t", survivingReference), func(t *testing.T) {
			f := newStorageReportFixture(t, "paused", false)
			team := sandboxTeamID(t, f.sandboxID)
			ctx := t.Context()
			sourceHost := "legacy-source-" + uuid.NewString()
			start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			mid, historicalEnd := start.Add(10*time.Minute), start.Add(20*time.Minute)
			snapshot := uuid.New()
			const path = "/example/reassigned-rootfs.ext4"
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := testPool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE host_id=$1`, f.hostID)
				_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_cutover WHERE host_id=$1`, f.hostID)
			})
			exec(`INSERT INTO snapshot(id,sandbox_id,team_id,path,trigger) VALUES($1,$2,$3,$4,'pause')`, snapshot, f.sandboxID, team, path)
			exec(`UPDATE sandbox SET host_id=$2,created_at=$3,snapshot_id=$4,base_path=$5 WHERE id=$1`, f.sandboxID, sourceHost, start, snapshot, path)
			exec(`INSERT INTO artifact_manifest(snapshot_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$2,1048576,1048576,$3)`, snapshot, path, strings.Repeat("0", 64))
			// The first sample must stop contributing artifacts at the later
			// handoff too, even though its overlay ended at a measurement.
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,1,$3,$4,'measurement'),($1,$2,2,$4,NULL,NULL)`, f.sandboxID, team, start, mid)
			if survivingReference {
				other := uuid.New()
				exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,snapshot_id,base_path)
 VALUES($1,$2,'remaining-reference','paused',$3,1,1024,8,$4,$5,$6)`, other, team, sourceHost, start, snapshot, path)
				exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at) VALUES($1,$2,0,$3)`, other, team, start)
			}
			usage := func(a, b time.Time) float64 {
				t.Helper()
				var got float64
				if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,false)::float8`, team, a, b).Scan(&got); err != nil {
					t.Fatal(err)
				}
				return got
			}
			before := usage(start, historicalEnd)
			if want := 2*mid.Sub(start).Seconds() + 3*historicalEnd.Sub(mid).Seconds(); before != want {
				t.Fatalf("legacy usage %v want %v", before, want)
			}
			exec(`UPDATE sandbox SET host_id=$2 WHERE id=$1`, f.sandboxID, f.hostID)
			report := uuid.New()
			body, err := json.Marshal(map[string]any{
				"incarnation_id": f.incarnation, "report_id": report,
				"measurements": []map[string]any{{"sandbox_id": "", "allocated_bytes": 0, "retained": retainedstorage.Inventory{
					Version: 1, Owners: []retainedstorage.Owner{{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64),
						Extents: []retainedstorage.Extent{{Device: "fs", Start: 0, Length: 3 << 20}}}},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			response := requestStorageReport(f.router, f.hostID, string(body))
			if response.Code != http.StatusCreated {
				t.Fatalf("destination report: %d %s", response.Code, response.Body.String())
			}
			boundary := decodeStorageReportAck(t, response).ReceivedAt
			waitStorageReportState(t, report, "processed")
			var closedAt, end time.Time
			var reason string
			if err := testPool.QueryRow(ctx, `SELECT ended_at,end_reason FROM sandbox_storage_interval WHERE sandbox_id=$1 AND started_at=$2`, f.sandboxID, mid).Scan(&closedAt, &reason); err != nil {
				t.Fatal(err)
			}
			if !closedAt.Equal(boundary) || reason != "reassigned" {
				t.Fatalf("legacy closure = %v %q, want reassigned at %v", closedAt, reason, boundary)
			}
			var sourceCutovers int
			if err := testPool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_cutover WHERE host_id=$1`, sourceHost).Scan(&sourceCutovers); err != nil || sourceCutovers != 0 {
				t.Fatalf("source cutovers = %d, err = %v", sourceCutovers, err)
			}
			if got := usage(start, historicalEnd); got != before {
				t.Fatalf("handoff rewrote history: %v want %v", got, before)
			}
			if got, want := usage(mid, boundary), 3*boundary.Sub(mid).Seconds(); math.Abs(got-want) > 1e-8 {
				t.Fatalf("pre-handoff usage %v want %v", got, want)
			}
			if err := testPool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&end); err != nil {
				t.Fatal(err)
			}
			if !end.After(boundary) {
				t.Fatal("post-handoff window must be nonempty")
			}
			rate := 3.0
			if survivingReference {
				rate++ // The independent source owner still retains the legacy artifact.
			}
			if got, want := usage(boundary, end), rate*end.Sub(boundary).Seconds(); math.Abs(got-want) > 1e-8 {
				t.Fatalf("combined post-handoff usage %v want %v", got, want)
			}
		})
	}
}

func TestRetainedStorageReassignmentToLegacyClosesSourceInterval(t *testing.T) {
	f := newStorageReportFixture(t, "paused", false)
	team := sandboxTeamID(t, f.sandboxID)
	ctx := t.Context()
	sourceHost := "retained-source-" + uuid.NewString()
	if _, err := testQueries.CreateHost(ctx, db.CreateHostParams{
		ID: sourceHost, VmdAddr: "192.0.2.2:50051", ProxyAddr: "192.0.2.2:5007",
		Region: "example-region", CapacityMemoryMib: 1024, CapacityVcpus: 2,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE host_id=$1`, sourceHost)
		cleanupHost(t, sourceHost)
	})
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET host_id=$2,created_at=$3 WHERE id=$1`,
		f.sandboxID, f.hostID, start); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at)
		VALUES($1,$2,'sandbox',$3,'retained-source','[{"device":"fs","start":0,"length":1048576}]',$4)`,
		sourceHost, team, f.sandboxID, start); err != nil {
		t.Fatal(err)
	}
	reportID := uuid.New()
	response := postStorageReport(t, f, reportID, 3<<20)
	if response.Code != http.StatusCreated {
		t.Fatalf("legacy destination report: %d %s", response.Code, response.Body.String())
	}
	ack := decodeStorageReportAck(t, response)
	waitStorageReportState(t, reportID, "processed")
	var endedAt time.Time
	if err := testPool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE host_id=$1 AND owner_id=$2`, sourceHost, f.sandboxID).Scan(&endedAt); err != nil {
		t.Fatal(err)
	}
	if !endedAt.Equal(ack.ReceivedAt) {
		t.Fatalf("source retained interval ended at %v, want receipt %v", endedAt, ack.ReceivedAt)
	}
	var activeLegacy int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_storage_interval WHERE sandbox_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&activeLegacy); err != nil {
		t.Fatal(err)
	}
	if activeLegacy != 1 {
		t.Fatalf("legacy destination intervals = %d, want one", activeLegacy)
	}
	// A separately retained snapshot/reference remains untouched by the
	// sandbox handoff; only the moved owner's source interval is retired.
	snapshot := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at) VALUES($1,$2,'snapshot',$3,'surviving','[{"device":"fs","start":0,"length":1048576}]',$4)`, sourceHost, team, snapshot, start); err != nil {
		t.Fatal(err)
	}
	var snapshotActive int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE host_id=$1 AND owner_kind='snapshot' AND owner_id=$2 AND ended_at IS NULL`, sourceHost, snapshot).Scan(&snapshotActive); err != nil {
		t.Fatal(err)
	}
	if snapshotActive != 1 {
		t.Fatal("surviving retained reference was closed during sandbox handoff")
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
	if storage != 0 || cpu != 0 || memory != 0 {
		t.Fatalf("paused export before storage activation: %v %v %v", cpu, memory, storage)
	}
	seedStorageActivation(t, team, a)
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
	var zeroGeneration string
	var zeroExtents []byte
	if err := testPool.QueryRow(ctx, `SELECT generation, extents FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&zeroGeneration, &zeroExtents); err != nil {
		t.Fatal(err)
	}
	if zeroGeneration != owner.Generation || string(zeroExtents) != "[]" {
		t.Fatalf("explicit zero interval = generation %q extents %s", zeroGeneration, zeroExtents)
	}
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

func TestRetainedStorageUnionWithThreeForksAndDeletionOrders(t *testing.T) {
	orders := []struct {
		name  string
		order []int
	}{
		{name: "source-first", order: []int{0, 1, 2, 3, 4}},
		{name: "snapshot-first", order: []int{1, 0, 3, 4, 2}},
		{name: "children-first", order: []int{2, 3, 4, 1, 0}},
	}
	for _, tc := range orders {
		t.Run(tc.name, func(t *testing.T) {
			f := newStorageReportFixture(t, "paused", true)
			team := sandboxTeamID(t, f.sandboxID)
			ctx := t.Context()
			start := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
			snapshot := uuid.New()
			children := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
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
			for i, child := range children {
				exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at)
 VALUES($1,$2,$3,'paused',$4,1,1024,8,$5)`, child, team, "fork-"+strconv.Itoa(i), f.hostID, start)
			}
			type retainedForkOwner struct {
				kind string
				id   uuid.UUID
				priv int64
			}
			owners := []retainedForkOwner{
				{kind: "sandbox", id: f.sandboxID, priv: -1},
				{kind: "snapshot", id: snapshot, priv: 1},
			}
			for i, child := range children {
				owners = append(owners, retainedForkOwner{kind: "sandbox", id: child, priv: int64(i + 2)})
			}
			for i, owner := range owners {
				startBlock := int64(0)
				if owner.priv >= 0 {
					startBlock = owner.priv * (1 << 20)
				}
				extents := fmt.Sprintf(`[ {"device":"fs","start":0,"length":1048576} ]`)
				if owner.priv >= 0 {
					extents = fmt.Sprintf(`[{"device":"fs","start":0,"length":1048576},{"device":"fs","start":%d,"length":1048576}]`, startBlock)
				}
				exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at)
 VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, f.hostID, team, owner.kind, owner.id, fmt.Sprintf("generation-%d", i), extents, start)
			}
			active := make(map[int]bool, len(owners))
			for i := range owners {
				active[i] = true
			}
			var initial float64
			if err := testPool.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, start, start.Add(time.Minute)).Scan(&initial); err != nil {
				t.Fatal(err)
			}
			if initial != 5*60 {
				t.Fatalf("initial retained union = %v, want 300", initial)
			}
			deleteOwner := func(index int, at time.Time) {
				o := owners[index]
				if o.kind == "snapshot" {
					exec(`UPDATE sandbox_snapshot SET status='deleting',deleted_at=$2 WHERE id=$1`, o.id, at)
				} else {
					exec(`UPDATE sandbox SET destroyed_at=$2 WHERE id=$1`, o.id, at)
				}
				delete(active, index)
			}
			for step, index := range append([]int(nil), tc.order...) {
				at := start.Add(time.Duration(step+1) * time.Minute)
				deleteOwner(index, at)
				next := at.Add(time.Minute)
				shared := len(active) > 0
				private := 0
				for i := range active {
					if owners[i].priv >= 0 {
						private++
					}
				}
				want := float64(private)
				if shared {
					want++
				}
				var got float64
				if err := testPool.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, team, at, next).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want*60 {
					t.Fatalf("step %d retained union = %v, want %v", step, got, want*60)
				}
			}
			var ended time.Time
			if err := testPool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE owner_kind='snapshot' AND owner_id=$1`, snapshot).Scan(&ended); err != nil {
				t.Fatal(err)
			}
			if !ended.Equal(start.Add(time.Duration(indexOf(tc.order, 1)+1) * time.Minute)) {
				t.Fatalf("snapshot interval ended at %v", ended)
			}
		})
	}
}

func indexOf(values []int, want int) int {
	for i, value := range values {
		if value == want {
			return i
		}
	}
	return -1
}

func TestRetainedStorageConsumerParity(t *testing.T) {
	ctx := t.Context()
	start := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	mid, end := start.Add(30*time.Minute), start.Add(time.Hour)
	host := "example-retained-" + uuid.NewString()
	exec := func(t *testing.T, q string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	teams := make([]uuid.UUID, 2)
	for i := range teams {
		team, _ := seedTeamAndKey(t)
		teams[i] = team
		t.Cleanup(func() {
			_, _ = testPool.Exec(context.Background(), `DELETE FROM retained_storage_interval WHERE team_id=$1`, team)
		})
		seedPlatformBillingRatesForTest(t, ctx, team, "retained-parity-"+uuid.NewString(), start.Add(-time.Hour))
		exec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true),($1,'tenant_usage_dashboard',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
		first, second := uuid.New(), uuid.New()
		insert := func(id uuid.UUID, a, b time.Time, extents string) {
			exec(t, `INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at) VALUES($1,$2,'sandbox',$3,'fixture',$4::jsonb,$5,$6)`, host, team, id, extents, a, b)
		}
		// Both teams occupy identical host/device/extent coordinates. The
		// second team keeps the same allocation instead of growing at mid.
		insert(first, start, mid, `[{"device":"fs","start":0,"length":1073741824}]`)
		if i == 0 {
			insert(first, mid, end, `[{"device":"fs","start":0,"length":2147483648}]`)
		} else {
			insert(first, mid, end, `[{"device":"fs","start":0,"length":1073741824}]`)
		}
		insert(second, start, end, `[{"device":"fs","start":0,"length":1073741824},{"device":"fs","start":2147483648,"length":536870912}]`)
		// An accepted empty extent set is an explicit measured zero, not an
		// unresolved observation. It must not turn the surrounding numeric
		// consumer results into unknown.
		insert(uuid.New(), start, end, `[]`)
	}
	for i, tc := range []struct {
		want, secondBucket float64
	}{
		{7372800, 2560 * 1800}, // (1536 + 2560) MiB * 1800 seconds.
		{5529600, 1536 * 1800}, // 1536 MiB * 3600 seconds.
	} {
		t.Run(fmt.Sprintf("team-%d", i+1), func(t *testing.T) {
			assertNumeric := func(label string, n pgtype.Numeric, scale, want float64) {
				t.Helper()
				v, err := n.Float64Value()
				if err != nil || !v.Valid || math.Abs(v.Float64*scale-want) > 1e-8 {
					t.Fatalf("%s: %v %v, want %v", label, v, err, want)
				}
			}
			team, want := teams[i], tc.want
			var canonical float64
			if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3)::float8`, team, start, end).Scan(&canonical); err != nil {
				t.Fatal(err)
			}
			if canonical != want {
				t.Fatalf("canonical MiB-seconds %v want %v", canonical, want)
			}
			usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
			if err != nil {
				t.Fatal(err)
			}
			assertNumeric("aggregate GiB-seconds", usage.StorageGibSeconds, 1024, want)
			assertNumeric("payable GiB-seconds", usage.BillableStorageGibSeconds, 1024, want)
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
			assertNumeric("second series bucket", series[1].StorageGibSeconds, 1024, tc.secondBucket)
			assertNumeric("first payable series bucket", series[0].BillableStorageGibSeconds, 1024, 1536*1800)
			assertNumeric("second payable series bucket", series[1].BillableStorageGibSeconds, 1024, tc.secondBucket)
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
			exec(t, `DELETE FROM team_credit_ledger WHERE team_id=$1`, team)
			exec(t, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
			exec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at) VALUES($1,10,10,'signup trial credit',$2)`, team, start)
			exec(t, `INSERT INTO team_billing_account(team_id,trial_ended_at) VALUES($1,$2) ON CONFLICT(team_id) DO UPDATE SET trial_ended_at=$2`, team, end)
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
		})
	}

	// Exercise the real tenant and platform consumers with an unresolved
	// full-copy baseline. Both must preserve unknown rather than emitting a
	// successful numeric zero; the measured-zero controls above remain valid.
	unknownTeam, unknownKey := seedTeamAndKey(t)
	seedPlatformBillingRatesForTest(t, ctx, unknownTeam, "retained-unknown-"+uuid.NewString(), start.Add(-time.Hour))
	exec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'tenant_usage_dashboard',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, unknownTeam)
	if _, err := testQueries.CreateHost(ctx, db.CreateHostParams{
		ID: host, VmdAddr: "192.0.2.2:50051", ProxyAddr: "192.0.2.2:5007",
		Region: "example-region", CapacityMemoryMib: 1024, CapacityVcpus: 2,
	}); err != nil {
		t.Fatal(err)
	}
	templateID, unknownSandbox := uuid.New(), uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO template(id,team_id,name,status,build_spec,rootfs_path,snapshot_path,mem_path,vcpu,memory_mib,disk_mib)
 VALUES($1,$2,'unknown-baseline','ready','{}'::jsonb,'/example/unknown/rootfs.ext4','/example/unknown/vmstate.snap','/example/unknown/mem.snap',1,1024,1)`, templateID, unknownTeam); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,template_id)
 VALUES($1,$2,'unknown-baseline','paused',$3,1,1024,1,$4,$5)`, unknownSandbox, unknownTeam, host, start, templateID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$2,$3,0,$4)`, unknownSandbox, unknownTeam, host, start); err != nil {
		t.Fatal(err)
	}
	router := newBillingRouter(t, nil)
	seriesResponse := do(router, http.MethodGet, "/billing/usage-series?start="+start.Format(time.RFC3339)+"&end="+end.Format(time.RFC3339)+"&granularity=hour&timezone=UTC", unknownKey, "")
	if seriesResponse.Code != http.StatusServiceUnavailable || !strings.Contains(seriesResponse.Body.String(), "storage_unavailable") {
		t.Fatalf("unknown storage series response = %d %s, want storage_unavailable", seriesResponse.Code, seriesResponse.Body.String())
	}
	admin := seedPlatformAdminProfile(t)
	platformResponse := doInternal(newInternalRouterWithNow(t, func() time.Time { return end }), http.MethodGet, "/internal/billing?search="+unknownTeam.String(), admin.String(), "")
	if platformResponse.Code != http.StatusOK {
		t.Fatalf("unknown storage platform response = %d %s", platformResponse.Code, platformResponse.Body.String())
	}
	platformBody := decodePlatformBilling(t, platformResponse.Body.Bytes())
	if len(platformBody.Rows) != 1 || platformBody.Rows[0].Error == nil || platformBody.Rows[0].Error.Code != "storage_unavailable" {
		t.Fatalf("unknown storage platform row = %+v, want storage_unavailable error", platformBody.Rows)
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

func TestRetainedStorageRollbackOwnerBoundaries(t *testing.T) {
	t.Run("missing-post-cutover-baseline-proof-fences-settlement", func(t *testing.T) {
		f := newStorageReportFixture(t, "paused", false)
		team := sandboxTeamID(t, f.sandboxID)
		ctx := t.Context()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := tx.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
		cutover := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		start, retainedStart, end := cutover.Add(10*time.Second), cutover.Add(40*time.Second), cutover.Add(time.Minute)
		legacyOwner := uuid.New()
		snapshotA, snapshotB := uuid.New(), uuid.New()
		const path = "/example/rollback-shared-rootfs.ext4"
		exec(`UPDATE sandbox SET created_at=$2,base_path=$3 WHERE id=$1`, f.sandboxID, start, path)
		exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,base_path,snapshot_id)
 VALUES($1,$2,'rollback-legacy-owner','paused',$3,1,1024,2,$4,$5,NULL)`, legacyOwner, team, f.hostID, start, path)
		exec(`INSERT INTO snapshot(id,sandbox_id,team_id,path,trigger) VALUES
	 ($1,$2,$3,$4,'pause'),($5,$6,$3,$4,'pause')`, snapshotA, f.sandboxID, team, path, snapshotB, legacyOwner)
		exec(`UPDATE sandbox SET snapshot_id=$2 WHERE id=$1`, f.sandboxID, snapshotA)
		exec(`UPDATE sandbox SET snapshot_id=$2 WHERE id=$1`, legacyOwner, snapshotB)
		exec(`INSERT INTO artifact_manifest(snapshot_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$3,1048576,1048576,$4),($2,'rootfs.ext4',$3,1048576,1048576,$4)`, snapshotA, snapshotB, path, strings.Repeat("0", 64))
		// Owner A has already established retained provenance. Owner B was
		// created by rollback and has no sandbox_storage_baseline row; matching
		// base_path strings are not generation proof.
		exec(`INSERT INTO retained_storage_cutover(host_id,team_id,started_at) VALUES($1,$2,$3)`, f.hostID, team, cutover)
		exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$2,$3,2,$4),($5,$2,$3,2,$4)`, f.sandboxID, team, f.hostID, start, legacyOwner)
		exec(`INSERT INTO sandbox_storage_baseline(sandbox_id,team_id,host_id,path,generation,allocated_bytes,started_at)
 VALUES($1,$2,$3,$4,$5,$6,$7)`, f.sandboxID, team, f.hostID, path, strings.Repeat("a", 64), 1048576, start)
		exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at,baseline_path,baseline_generation,baseline_allocated_bytes)
 VALUES($1,$2,'sandbox',$3,$4,'[{"device":"fs","start":0,"length":1048576}]',$5,$6,$7,$8,1048576)`, f.hostID, team, f.sandboxID, strings.Repeat("b", 64), retainedStart, end, path, strings.Repeat("a", 64))
		var unknown bool
		if err := tx.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,false) IS NULL`, team, retainedStart, end).Scan(&unknown); err != nil {
			t.Fatal(err)
		}
		if !unknown {
			t.Fatal("post-cutover rollback owner without generation proof was billable")
		}
	})

	for _, reassigned := range []bool{false, true} {
		t.Run(fmt.Sprintf("reassigned-%t", reassigned), func(t *testing.T) {
			f := newStorageReportFixture(t, "paused", false)
			team := sandboxTeamID(t, f.sandboxID)
			ctx := t.Context()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			cutover := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			start, secondStart, retainedStart, end := cutover.Add(10*time.Second), cutover.Add(20*time.Second), cutover.Add(40*time.Second), cutover.Add(time.Minute)
			snapshot, second := uuid.New(), uuid.New()
			const path = "/example/rollback-base.ext4"
			exec(`INSERT INTO snapshot(id,sandbox_id,team_id,path,trigger) VALUES($1,$2,$3,$4,'pause')`, snapshot, f.sandboxID, team, path)
			exec(`UPDATE sandbox SET created_at=$2,snapshot_id=$3,base_path=$4 WHERE id=$1`, f.sandboxID, start, snapshot, path)
			exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,base_path,snapshot_id)
 VALUES($1,$2,'example-rollback','paused',$3,1,1024,2,$4,$5,$6)`, second, team, f.hostID, secondStart, path, snapshot)
			exec(`INSERT INTO artifact_manifest(snapshot_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$2,1048576,1048576,$3)`, snapshot, path, strings.Repeat("0", 64))
			exec(`INSERT INTO retained_storage_cutover(host_id,team_id,started_at) VALUES($1,$2,$3)`, f.hostID, team, cutover)
			if reassigned {
				exec(`UPDATE sandbox SET created_at=$2 WHERE id=$1`, f.sandboxID, cutover.Add(-time.Minute))
				// A prior stay on this host must not clip a later legacy stay.
				exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at,baseline_path,baseline_generation,baseline_allocated_bytes)
 VALUES($1,$2,'sandbox',$3,$4,'[{"device":"fs","start":0,"length":1048576}]',$5,$6,$7,$8,1048576)`, f.hostID, team, f.sandboxID, strings.Repeat("a", 64), cutover, cutover.Add(5*time.Second), path, strings.Repeat("b", 64))
			}
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$3,$4,2,$5),($2,$3,$4,2,$6)`, f.sandboxID, second, team, f.hostID, start, secondStart)
			exec(`INSERT INTO sandbox_storage_baseline(sandbox_id,team_id,host_id,path,generation,allocated_bytes,started_at)
 VALUES($1,$2,$3,$4,$5,1048576,$6),($7,$2,$3,$4,$5,1048576,$8)`, f.sandboxID, team, f.hostID, path, strings.Repeat("b", 64), start, second, secondStart)
			assertUsage := func(from, to time.Time, want float64) {
				t.Helper()
				for _, floor := range []bool{false, true} {
					var got float64
					if err := tx.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,$4)::float8`, team, from, to, floor).Scan(&got); err != nil {
						t.Fatal(err)
					}
					if got != want {
						t.Fatalf("usage [%v,%v) floor=%t = %v, want %v", from, to, floor, got, want)
					}
				}
			}
			// Shared base is charged once; each owner's overlay is separate.
			assertUsage(start, end, 30+40*5)
			before := float64(0)
			if reassigned {
				before = 5
			}
			assertUsage(cutover.Add(-time.Second), end, before+230)
			assertUsage(cutover.Add(-time.Second), start, before)
			// Retained reporting resumes later. Legacy quantities stop exactly
			// at each owner's first observation of this stay, not the host's
			// old permanent cutover or an earlier visit by the same owner.
			for i, id := range []uuid.UUID{f.sandboxID, second} {
				extents := fmt.Sprintf(`[{"device":"fs","start":0,"length":1048576},{"device":"fs","start":%d,"length":1048576}]`, (i+1)*1048576)
				exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at,baseline_path,baseline_generation,baseline_allocated_bytes)
 VALUES($1,$2,'sandbox',$3,$4,$5,$6,$7,$8,$9,1048576)`, f.hostID, team, id, strings.Repeat("b", 64), extents, retainedStart, end, path, strings.Repeat("b", 64))
			}
			assertUsage(start, retainedStart, 30+20*5)
			assertUsage(retainedStart, end, 20*3)
			assertUsage(start, end, 190)
			assertUsage(cutover.Add(-time.Second), end, before+190)
		})
	}
}

func TestRetainedStorageTemplateRebuildKeepsPersistedBaselineGeneration(t *testing.T) {
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
	cutover := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	start, retainedStart, end := cutover.Add(10*time.Second), cutover.Add(40*time.Second), cutover.Add(time.Minute)
	templateID, rollbackOwner := uuid.New(), uuid.New()
	oldSnapshotPath := "/example/snapshotdir/templates/base/build-a/vmstate.snap"
	oldRootfsPath := "/example/rundir/templates/base/build-a/rootfs.ext4"
	newSnapshotPath := "/example/snapshotdir/templates/base/build-b/vmstate.snap"
	newRootfsPath := "/example/rundir/templates/base/build-b/rootfs.ext4"
	// The template row now points at build B, while each owner keeps the
	// build-specific snapshot path it was created from.
	exec(`INSERT INTO template(id,team_id,name,status,build_spec,rootfs_path,snapshot_path,mem_path,vcpu,memory_mib,disk_mib)
 VALUES($1,$2,'example-template','ready','{}'::jsonb,$3,$4,$5,1,1024,1024)`, templateID, team, newRootfsPath, newSnapshotPath, "/example/templates/base/build-b/mem.snap")
	exec(`INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
 VALUES($1,'rootfs.ext4',$2,1048576,1048576,$3),($1,'rootfs.ext4',$4,1048576,1048576,$3)`, templateID, oldRootfsPath, strings.Repeat("0", 64), newRootfsPath)
	exec(`UPDATE sandbox SET created_at=$2,template_id=$3,snapshot_path=$4,base_path=NULL,delta_path=NULL WHERE id=$1`, f.sandboxID, start, templateID, oldSnapshotPath)
	exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,template_id,snapshot_path)
 VALUES($1,$2,'example-rollback-generation','paused',$3,1,1024,2,$4,$5,$6)`, rollbackOwner, team, f.hostID, start.Add(10*time.Second), templateID, newSnapshotPath)
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 VALUES($1,$2,$3,2,$4),($5,$2,$3,2,$6)`, f.sandboxID, team, f.hostID, start, rollbackOwner, start.Add(10*time.Second))
	// The host report persists the exact full-copy roots it measured.  The
	// runtime and snapshot directories are intentionally unrelated; no sibling
	// path inference is valid here.
	exec(`INSERT INTO sandbox_storage_baseline(sandbox_id,team_id,host_id,path,generation,allocated_bytes,started_at)
 VALUES($1,$2,$3,$4,$5,1048576,$6),($7,$2,$3,$8,$9,1048576,$10)`,
		f.sandboxID, team, f.hostID, oldRootfsPath, strings.Repeat("a", 64), start,
		rollbackOwner, newRootfsPath, strings.Repeat("b", 64), start.Add(10*time.Second))
	exec(`INSERT INTO retained_storage_cutover(host_id,team_id,started_at) VALUES($1,$2,$3)`, f.hostID, team, cutover)
	exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at,baseline_path,baseline_generation,baseline_allocated_bytes)
 VALUES($1,$2,'sandbox',$3,'generation-a','[{"device":"fs","start":0,"length":1048576}]',$4,$5,$6,$7,1048576)`,
		f.hostID, team, f.sandboxID, retainedStart, end, oldRootfsPath, strings.Repeat("a", 64))
	var got float64
	if err := tx.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,false)::float8`, team, start, end).Scan(&got); err != nil {
		t.Fatal(err)
	}
	// Derive each interval independently: A overlay 2*30, B overlay 2*40,
	// A baseline 1*30, B baseline 1*40, and retained A 1*20 = 230.
	const want = 230.0
	if got != want {
		t.Fatalf("storage after template rebuild = %v, want %v", got, want)
	}
}

func TestRetainedStorageBaselineProvenance(t *testing.T) {
	f := newStorageReportFixture(t, "paused", false)
	ctx := t.Context()
	genA := strings.Repeat("a", 64)
	genB := strings.Repeat("b", 64)
	path := "/example/provenance/rootfs-a.ext4"
	owner := retainedstorage.Owner{
		Kind: "sandbox", ID: f.sandboxID.String(), Generation: genA,
		Extents:  []retainedstorage.Extent{{Device: "fs", Start: 0, Length: 1 << 20}},
		Baseline: &retainedstorage.Baseline{Path: path, Generation: genA, AllocatedBytes: 1 << 20},
	}
	post := func(id uuid.UUID, o retainedstorage.Owner) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"incarnation_id": f.incarnation,
			"report_id":      id,
			"measurements": []any{map[string]any{"sandbox_id": "", "allocated_bytes": 0,
				"retained": retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{o}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return requestStorageReport(f.router, f.hostID, string(body))
	}
	first := uuid.New()
	if response := post(first, owner); response.Code != http.StatusCreated {
		t.Fatalf("provenance report: %d %s", response.Code, response.Body.String())
	}
	waitStorageReportState(t, first, "processed")
	var gotPath, gotGeneration string
	var gotBytes int64
	if err := testPool.QueryRow(ctx, `SELECT baseline_path,baseline_generation,baseline_allocated_bytes
 FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&gotPath, &gotGeneration, &gotBytes); err != nil {
		t.Fatal(err)
	}
	if gotPath != path || gotGeneration != genA || gotBytes != 1<<20 {
		t.Fatalf("persisted baseline = %q/%q/%d, want %q/%q/%d", gotPath, gotGeneration, gotBytes, path, genA, 1<<20)
	}
	// A same-ID payload change conflicts instead of rewriting the durable
	// provenance or its already accepted interval.
	changed := owner
	changed.Baseline = &retainedstorage.Baseline{Path: "/example/provenance/other.ext4", Generation: genA, AllocatedBytes: 1 << 20}
	if response := post(first, changed); response.Code != http.StatusConflict {
		t.Fatalf("changed provenance retry status = %d, want 409", response.Code)
	}
	var stablePath string
	if err := testPool.QueryRow(ctx, `SELECT baseline_path FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&stablePath); err != nil || stablePath != path {
		t.Fatalf("conflicting retry changed baseline: %q (%v)", stablePath, err)
	}
	// A measured zero is represented explicitly and is not converted to
	// unknown. The new generation closes the prior interval at the receipt.
	zero := owner
	zero.Generation, zero.Extents = genB, []retainedstorage.Extent{}
	zero.Baseline = &retainedstorage.Baseline{Path: path, Generation: genB, AllocatedBytes: 0}
	second := uuid.New()
	if response := post(second, zero); response.Code != http.StatusCreated {
		t.Fatalf("explicit-zero report: %d %s", response.Code, response.Body.String())
	}
	waitStorageReportState(t, second, "processed")
	var zeroBytes int64
	if err := testPool.QueryRow(ctx, `SELECT baseline_allocated_bytes FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2`, f.sandboxID, genB).Scan(&zeroBytes); err != nil || zeroBytes != 0 {
		t.Fatalf("explicit zero baseline = %d (%v), want zero", zeroBytes, err)
	}

	// A full-copy owner without a persisted baseline is unresolved, not zero.
	missing := uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO template(id,team_id,name,status,build_spec,rootfs_path,snapshot_path,mem_path,vcpu,memory_mib,disk_mib)
	 VALUES($1,(SELECT team_id FROM sandbox WHERE id=$2),'provenance-template','ready','{}'::jsonb,'/example/current/rootfs.ext4','/example/current/vmstate.snap','/example/current/mem.snap',1,1024,1024)`, missing, f.sandboxID)
	exec(`INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at,template_id)
	 SELECT $1,team_id,'missing-provenance','paused',host_id,1,1,1,created_at,$3 FROM sandbox WHERE id=$2`, missing, f.sandboxID, missing)
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at)
 SELECT id,team_id,host_id,0,created_at FROM sandbox WHERE id=$1`, missing)
	var unknown bool
	if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds((SELECT team_id FROM sandbox WHERE id=$1),now()-interval '1 hour',now(),false) IS NULL`, missing).Scan(&unknown); err != nil {
		t.Fatal(err)
	}
	if !unknown {
		t.Fatal("missing baseline provenance was treated as a numeric zero")
	}
}

func TestRetainedStorageBaselineReconciliationPlan(t *testing.T) {
	for _, scale := range []int{1, 4} {
		t.Run(fmt.Sprintf("owners-%d", scale), func(t *testing.T) {
			f := newStorageReportFixture(t, "paused", false)
			ctx := t.Context()
			team := sandboxTeamID(t, f.sandboxID)
			start := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
			first := start.Add(60 * time.Second)
			second := start.Add(120 * time.Second)
			end := start.Add(180 * time.Second)
			gen := func(ch byte) string { return strings.Repeat(string(ch), 64) }
			insertRetained := func(host string, owner uuid.UUID, generation, path string, from, to time.Time, device string, offset, length int64) {
				t.Helper()
				if _, err := testPool.Exec(ctx, `INSERT INTO retained_storage_interval
 (host_id,team_id,owner_kind,owner_id,generation,extents,baseline_path,baseline_generation,baseline_allocated_bytes,started_at,ended_at)
 VALUES($1,$2,'sandbox',$3,$4,$5::jsonb,$6,$7,$8,$9,$10)`, host, team, owner, generation,
					fmt.Sprintf(`[{"device":%q,"start":%d,"length":%d}]`, device, offset, length), path, generation, length, from, to); err != nil {
					t.Fatal(err)
				}
			}
			// A and B share one physical baseline; C is a distinct generation on
			// the same host; D is a separate host. The private rows scale the
			// input cardinality without changing the shared-reference semantics.
			insertRetained(f.hostID, uuid.New(), gen('a'), "/example/baseline-a", start, end, "fs", 0, 1<<20)
			insertRetained(f.hostID, uuid.New(), gen('b'), "/example/baseline-a", first, end, "fs", 0, 1<<20)
			insertRetained(f.hostID, uuid.New(), gen('c'), "/example/baseline-c", first, second, "fs", 2<<20, 1<<20)
			insertRetained(f.hostID+"-other", uuid.New(), gen('d'), "/example/baseline-d", start, end, "fs", 0, 512<<10)
			for i := 0; i < scale; i++ {
				insertRetained(f.hostID, uuid.New(), fmt.Sprintf("%064x", i+100), fmt.Sprintf("/example/private-%d", i), first, second, fmt.Sprintf("private-%d", i), 0, 1<<20)
			}
			// Legacy overlay rows exercise the mixed-source bridge. Their expected
			// contribution is independent of the retained extent union below.
			legacyOwner := uuid.New()
			if _, err := testPool.Exec(ctx, `INSERT INTO sandbox(id,team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib,created_at)
 VALUES($1,$2,$3,'paused',$4,1,1024,3,$5)`, legacyOwner, team, "legacy-baseline", f.hostID, start); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,$3,2,$4,$5,'deleted'),($6,$2,$3,3,$4,$5,'deleted')`, f.sandboxID, team, f.hostID, start, end, legacyOwner); err != nil {
				t.Fatal(err)
			}
			var quantity float64
			if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds($1,$2,$3,false)::float8`, team, start, end).Scan(&quantity); err != nil {
				t.Fatal(err)
			}
			// Legacy overlays: (2+3) MiB * 180s. Retained union: host one
			// contributes 1 MiB * 180s + 1 MiB * 60s plus scale private MiB *
			// 60s; the second host contributes 0.5 MiB * 180s.
			want := 5*180 + 180 + 60 + float64(scale)*60 + 0.5*180
			if math.Abs(quantity-want) > 0.0001 {
				t.Fatalf("reconciliation quantity = %v, want independent oracle %v", quantity, want)
			}

			var plan []byte
			if err := testPool.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
 SELECT host_id, count(*) AS interval_count,
        sum(jsonb_array_length(extents)) AS extent_count
 FROM retained_storage_interval
 WHERE team_id=$1 AND started_at<$3 AND COALESCE(ended_at,$3)>$2
 GROUP BY host_id`, team, start, end).Scan(&plan); err != nil {
				t.Fatal(err)
			}
			planText := string(plan)
			if !strings.Contains(planText, `"Plan"`) || !strings.Contains(planText, `"Actual Rows"`) || !strings.Contains(planText, `"Actual Loops"`) || !strings.Contains(planText, `"Shared Read Blocks"`) {
				t.Fatalf("reconciliation input plan omitted cardinality/loop/buffer evidence: %s", planText)
			}
			t.Logf("reconciliation scale=%d expected_mib_seconds=%.2f plan=%s", scale, want, planText)
		})
	}
}
