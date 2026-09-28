//go:build integration

package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

func TestIntegration_RetainedReportOwnershipAndReceiptTransitions(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := func(kind string, id uuid.UUID) retainedstorage.Owner {
		return retainedstorage.Owner{Kind: kind, ID: id.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}}
	}
	apply := func(at time.Time, owners ...retainedstorage.Owner) error {
		t.Helper()
		exec(`UPDATE host_storage_report SET state='processing',next_measurement_index=0 WHERE report_id=$1`, f.reportID)
		return applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, at, []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: owners}}}, 1, 1)
	}
	var sandboxTeam uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&sandboxTeam); err != nil {
		t.Fatal(err)
	}
	teamB := uuid.New()
	snapshotA, snapshotB, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		id, team uuid.UUID
		host     string
	}{{snapshotA, sandboxTeam, f.hostID}, {snapshotB, teamB, f.hostID}, {foreign, teamB, "other-host"}} {
		exec(`INSERT INTO sandbox_snapshot(id,host_id,team_id,status,created_at,ready_at) VALUES($1,$2,$3,'ready',$4,$5)`, row.id, row.host, row.team, f.receivedAt.Add(-time.Minute), f.receivedAt.Add(time.Minute))
	}
	exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at) VALUES('other-host',$1,'snapshot',$2,'previous','[]',$3)`, teamB, foreign, f.receivedAt.Add(-time.Minute))
	// Both snapshots committed while creating; readiness recovery happened
	// after receipt and before this worker acquired their control-plane rows.
	base := owner("sandbox", f.sandboxID)
	a, b, other := owner("snapshot", snapshotA), owner("snapshot", snapshotB), owner("snapshot", foreign)
	if err := apply(f.receivedAt, base, a, b, other); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_kind='snapshot' AND started_at=$1 AND ((owner_id=$2 AND team_id=$4) OR (owner_id=$3 AND team_id=$5))`, f.receivedAt, snapshotA, snapshotB, sandboxTeam, teamB).Scan(&count); err != nil || count != 2 {
		t.Fatalf("snapshot ownership/receipt: %d %v", count, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND host_id=$2`, foreign, f.hostID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign owner accepted: %d %v", count, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND host_id='other-host' AND generation='previous' AND ended_at IS NULL`, foreign).Scan(&count); err != nil || count != 1 {
		t.Fatalf("foreign-host retention changed: %d %v", count, err)
	}
	// Identical receipt boundaries replace exactly once, including replay.
	a.Generation = strings.Repeat("b", 64)
	a.Extents[0].Length = 8192
	for i := 0; i < 2; i++ {
		if err := apply(f.receivedAt, base, a, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2 AND ended_at IS NULL AND extents->0->>'length'='8192'`, snapshotA, a.Generation).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same-boundary replacement: %d %v", count, err)
	}
	// A delayed report is clipped to confirmed deletion, never processing time.
	end := f.receivedAt.Add(2 * time.Minute)
	exec(`UPDATE sandbox_snapshot SET status='deleting',deleted_at=$2 WHERE id=$1`, snapshotA, end)
	a.Generation = strings.Repeat("c", 64)
	if err := apply(f.receivedAt.Add(time.Minute), base, a, b); err != nil {
		t.Fatal(err)
	}
	var ended time.Time
	if err := f.pool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2`, snapshotA, a.Generation).Scan(&ended); err != nil || !ended.Equal(end) {
		t.Fatalf("deletion clipping: %v %v", ended, err)
	}
	if err := apply(end, base, a, b); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND started_at >= $2`, snapshotA, end).Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted owner resurrected: %d %v", count, err)
	}
}

func TestIntegration_RetainedFailedOwnerCutover(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE sandbox SET status='failed' WHERE id=$1`, f.sandboxID)
	healthy := uuid.New()
	exec(`INSERT INTO sandbox SELECT $1,team_id,host_id,'paused',created_at,NULL FROM sandbox WHERE id=$2`, healthy, f.sandboxID)
	owner := func(id uuid.UUID) retainedstorage.Owner {
		return retainedstorage.Owner{Kind: "sandbox", ID: id.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}}
	}
	apply := func(owners ...retainedstorage.Owner) error {
		exec(`UPDATE host_storage_report SET state='processing' WHERE report_id=$1`, f.reportID)
		return applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: owners}}}, 1, 1)
	}
	if err := apply(owner(healthy)); err == nil {
		t.Fatal("omitting failed legacy retention allowed cutover")
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_cutover`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed report advanced cutover: %d %v", n, err)
	}
	if err := apply(owner(healthy), owner(f.sandboxID)); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("measurable failed owner omitted: %d %v", n, err)
	}
	if err := apply(owner(healthy)); err == nil {
		t.Fatal("failed status retired accepted bytes")
	}
}
