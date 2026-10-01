//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

// Share the lease fixture across connections while keeping every row isolated
// from the integration database. Use the migrated production creation trigger.
func newRetainedCreationFixture(t *testing.T) storageLeaseFixture {
	t.Helper()
	f := newStorageLeaseFixture(t)
	schema := pgx.Identifier{"retained_creation_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	if _, err := f.pool.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	source := f.pool
	t.Cleanup(func() {
		if _, err := source.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	for _, table := range []string{"host", "sandbox", "sandbox_snapshot", "sandbox_storage_interval", "retained_storage_interval", "sandbox_storage_baseline", "retained_storage_measurement_obligation", "retained_storage_cutover", "host_storage_report", "feature_flag", "team_feature_flag"} {
		query := fmt.Sprintf(`CREATE TABLE %[1]s.%[2]s (LIKE pg_temp.%[2]s INCLUDING ALL);
 INSERT INTO %[1]s.%[2]s OVERRIDING SYSTEM VALUE SELECT * FROM pg_temp.%[2]s;`, schema, table)
		if _, err := source.Exec(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	cfg := source.Config()
	cfg.MaxConns = 4
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.pool = pool
	for _, table := range []string{"sandbox", "sandbox_snapshot"} {
		if _, err := pool.Exec(t.Context(), `ALTER TABLE `+table+` ALTER COLUMN created_at DROP DEFAULT;
 CREATE TRIGGER fence_retained_storage_owner_creation BEFORE INSERT ON `+table+`
 FOR EACH ROW EXECUTE FUNCTION public.fence_retained_storage_owner_creation()`); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestIntegration_RetainedCutoverFencesOwnerCreation(t *testing.T) {
	for _, kind := range []string{"sandbox", "snapshot"} {
		t.Run(kind, func(t *testing.T) {
			f := newRetainedCreationFixture(t)
			ctx := t.Context()
			creator, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer creator.Rollback(context.Background())
			table, status := "sandbox", "paused"
			if kind == "snapshot" {
				table, status = "sandbox_snapshot", "creating"
			}
			id := uuid.New()
			if _, err := creator.Exec(ctx, `INSERT INTO `+table+`(id,team_id,host_id,status)
 SELECT $1,team_id,host_id,$2 FROM sandbox WHERE id=$3`, id, status, f.sandboxID); err != nil {
				t.Fatal(err)
			}
			// Two creations on the same host must not serialize each other.
			parallel, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer parallel.Rollback(context.Background())
			insertCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err = parallel.Exec(insertCtx, `INSERT INTO `+table+`(id,team_id,host_id,status)
 SELECT $1,team_id,host_id,$2 FROM sandbox WHERE id=$3`, uuid.New(), status, f.sandboxID)
			cancel()
			if err != nil {
				t.Fatalf("concurrent creation was blocked: %v", err)
			}
			if err := parallel.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var at time.Time
			if err := f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
				t.Fatal(err)
			}
			owner := func(kind string, id uuid.UUID) retainedstorage.Owner {
				return retainedstorage.Owner{Kind: kind, ID: id.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}}
			}
			base := owner("sandbox", f.sandboxID)
			apply := func(owners ...retainedstorage.Owner) error {
				return applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, at,
					[]storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: owners}}}, 1, 1)
			}
			before := storageLeaseRow(t, f)
			if err := apply(base); err == nil || storageReportErrorIsTerminal(err) {
				t.Fatalf("uncommitted creation must defer cutover with a retryable error: %v", err)
			}
			if after := storageLeaseRow(t, f); before != after {
				t.Fatal("deferred cutover advanced report progress")
			}
			var count int
			if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM retained_storage_cutover)+(SELECT count(*) FROM retained_storage_interval)`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("deferred report changed retained accounting: count=%d err=%v", count, err)
			}
			if err := creator.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := apply(base); !errors.Is(err, errStorageReportInvalidPayload) {
				t.Fatalf("committed omitted owner must fail completeness: %v", err)
			}
			if err := apply(base, owner(kind, id)); err != nil {
				t.Fatal(err)
			}
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval i JOIN retained_storage_cutover c USING(host_id,team_id) WHERE i.started_at=$1 AND c.started_at=$1`, at).Scan(&count); err != nil || count != 2 {
				t.Fatalf("complete retry did not include both owners at receipt: count=%d err=%v", count, err)
			}
		})
	}
}

func TestIntegration_RetainedCutoverDoesNotBlockLaterOwnerInsert(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		commit bool
	}{{"sandbox", true}, {"sandbox", false}, {"snapshot", true}, {"snapshot", false}} {
		t.Run(fmt.Sprintf("%s/commit=%t", tc.kind, tc.commit), func(t *testing.T) {
			f := newRetainedCreationFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			creator, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer creator.Rollback(context.Background())
			var begun time.Time
			if err := creator.QueryRow(ctx, `SELECT now()`).Scan(&begun); err != nil {
				t.Fatal(err)
			}
			writer, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			var at time.Time
			if err := writer.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
				t.Fatal(err)
			}
			if !begun.Before(at) {
				t.Fatal("creation transaction must predate receipt")
			}
			inv := &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{{
				Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64),
				Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}},
			}}}
			if err := applyRetainedStorage(ctx, writer, f.hostID, at, inv); err != nil {
				t.Fatal(err)
			}
			table, status := "sandbox", "paused"
			if tc.kind == "snapshot" {
				table, status = "sandbox_snapshot", "creating"
			}
			id := uuid.New()
			insertCtx, stopInsert := context.WithTimeout(ctx, 250*time.Millisecond)
			_, err = creator.Exec(insertCtx, `INSERT INTO `+table+`(id,team_id,host_id,status)
 SELECT $1,team_id,host_id,$2 FROM sandbox WHERE id=$3`, id, status, f.sandboxID)
			stopInsert()
			if err != nil {
				t.Fatalf("owner creation waited behind retained report: %v", err)
			}
			otherCreator, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer otherCreator.Rollback(context.Background())
			otherCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			_, err = otherCreator.Exec(otherCtx, `INSERT INTO `+table+`(id,team_id,host_id,status)
 SELECT $1,team_id,'other-host',$2 FROM sandbox WHERE id=$3`, uuid.New(), status, f.sandboxID)
			stop()
			if err != nil {
				t.Fatalf("cutover blocked an unrelated host: %v", err)
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var created time.Time
			if err := creator.QueryRow(ctx, `SELECT created_at FROM `+table+` WHERE id=$1`, id).Scan(&created); err != nil {
				t.Fatal(err)
			}
			if !created.After(at) {
				t.Fatalf("later insert was backdated into inventory: created=%s receipt=%s transaction=%s", created, at, begun)
			}
			// Report A has released its exclusive fence, but the insert that
			// bypassed it is still uncommitted when report B is received.
			var laterReceipt time.Time
			if err := f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&laterReceipt); err != nil {
				t.Fatal(err)
			}
			if !laterReceipt.After(created) {
				t.Fatal("second report must be received after owner insertion")
			}
			if _, err := f.pool.Exec(ctx, `UPDATE host_storage_report SET received_at=$1,next_measurement_index=0`, laterReceipt); err != nil {
				t.Fatal(err)
			}
			inv.Owners[0].Generation = strings.Repeat("b", 64)
			inv.Owners[0].Extents[0].Length = 8192
			apply := func() error {
				return applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, laterReceipt,
					[]storageReportMeasurement{{Retained: inv}}, 1, 1)
			}
			accounting := func() string {
				t.Helper()
				var rows string
				if err := f.pool.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM retained_storage_interval i),
 (SELECT jsonb_agg(to_jsonb(c) ORDER BY host_id,team_id) FROM retained_storage_cutover c))::text`).Scan(&rows); err != nil {
					t.Fatal(err)
				}
				return rows
			}
			beforeReport, beforeAccounting := storageLeaseRow(t, f), accounting()
			if err := apply(); err == nil || storageReportErrorIsTerminal(err) {
				t.Fatalf("second report must retry while the bypassing insert is uncommitted: %v", err)
			}
			if storageLeaseRow(t, f) != beforeReport || accounting() != beforeAccounting {
				t.Fatal("deferred second report changed progress or retained accounting")
			}
			if tc.commit {
				if err := creator.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := apply(); !errors.Is(err, errStorageReportInvalidPayload) {
					t.Fatalf("committed omitted owner must fail second-report completeness: %v", err)
				}
				if storageLeaseRow(t, f) != beforeReport || accounting() != beforeAccounting {
					t.Fatal("incomplete second report changed progress or retained accounting")
				}
				inv.Owners = append(inv.Owners, retainedstorage.Owner{
					Kind: tc.kind, ID: id.String(), Generation: strings.Repeat("a", 64),
					Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}},
				})
			} else if err := creator.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			// The unrelated host's insert remains open and must not defer this
			// report. Commit and rollback both release the same-host marker.
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			var intervals, owners int
			if err := f.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE owner_id=$2)
 FROM retained_storage_interval WHERE started_at=$1 AND ended_at IS NULL`, laterReceipt, id).Scan(&intervals, &owners); err != nil {
				t.Fatal(err)
			}
			wantOwners := 0
			if tc.commit {
				wantOwners = 1
			}
			if intervals != 1+wantOwners || owners != wantOwners {
				t.Fatalf("second report intervals=%d owners=%d, want %d and %d", intervals, owners, 1+wantOwners, wantOwners)
			}
			var state string
			var cursor int
			if err := f.pool.QueryRow(ctx, `SELECT state,next_measurement_index FROM host_storage_report`).Scan(&state, &cursor); err != nil {
				t.Fatal(err)
			}
			if state != "processed" || cursor != 1 {
				t.Fatalf("second report progress: state=%s cursor=%d", state, cursor)
			}
		})
	}
}

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

func attachSnapshotRetentionTrigger(t *testing.T, f storageLeaseFixture) {
	t.Helper()
	// Copy the migrated trigger, including its event columns and WHEN condition.
	var trigger, table string
	if err := f.pool.QueryRow(t.Context(), `SELECT pg_get_triggerdef(oid),tgrelid::regclass::text
 FROM pg_trigger WHERE tgrelid='public.sandbox_snapshot'::regclass
 AND tgname='close_snapshot_retained_storage'`).Scan(&trigger, &table); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), strings.Replace(trigger, " ON "+table+" ", " ON pg_temp.sandbox_snapshot ", 1)); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_RetainedSnapshotFailureAfterReceipt(t *testing.T) {
	for _, status := range []string{"creating", "ready", "deleting"} {
		for _, replacement := range []bool{false, true} {
			for _, cleanup := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/replacement=%t/cleanup=%t", status, replacement, cleanup), func(t *testing.T) {
					f := newStorageLeaseFixture(t)
					ctx := t.Context()
					attachSnapshotRetentionTrigger(t, f)
					exec := func(query string, args ...any) {
						t.Helper()
						if _, err := f.pool.Exec(ctx, query, args...); err != nil {
							t.Fatal(err)
						}
					}
					id := uuid.New()
					exec(`INSERT INTO sandbox_snapshot(id,team_id,host_id,status,created_at)
 SELECT $1,team_id,host_id,$2,created_at FROM sandbox WHERE id=$3`, id, status, f.sandboxID)
					base := retainedstorage.Owner{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64),
						Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}}
					snapshot := retainedstorage.Owner{Kind: "snapshot", ID: id.String(), Generation: strings.Repeat("a", 64),
						Extents: []retainedstorage.Extent{{Device: "fs", Start: 8192, Length: 4096}}}
					apply := func(at time.Time, owners ...retainedstorage.Owner) error {
						t.Helper()
						exec(`UPDATE host_storage_report SET state='processing',next_measurement_index=0`)
						return applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, at,
							[]storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: owners}}}, 1, 1)
					}
					at := f.receivedAt
					if replacement {
						if err := apply(at.Add(-time.Minute), base, snapshot); err != nil {
							t.Fatal(err)
						}
						snapshot.Generation = strings.Repeat("b", 64)
						snapshot.Extents[0].Length = 8192
					}
					exec(`UPDATE sandbox_snapshot SET status='failed' WHERE id=$1`, id)
					var boundary time.Time
					if err := f.pool.QueryRow(ctx, `SELECT retention_ended_at FROM sandbox_snapshot WHERE id=$1`, id).Scan(&boundary); err != nil {
						t.Fatal(err)
					}
					if !boundary.After(at) {
						t.Fatalf("failure boundary %s must follow receipt %s", boundary, at)
					}
					if cleanup {
						exec(`UPDATE sandbox_snapshot SET status='deleting',deleted_at=clock_timestamp() WHERE id=$1`, id)
					}
					if err := apply(at, base); !errors.Is(err, errStorageReportInvalidPayload) {
						t.Fatalf("omitted receipt-time snapshot allowed cutover: %v", err)
					}
					// The first application and replay must retain the same bounded interval.
					for i := 0; i < 2; i++ {
						if err := apply(at, base, snapshot); err != nil {
							t.Fatal(err)
						}
					}
					var started, ended time.Time
					var length int64
					if err := f.pool.QueryRow(ctx, `SELECT started_at,ended_at,(extents->0->>'length')::bigint
 FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2`, id, snapshot.Generation).Scan(&started, &ended, &length); err != nil {
						t.Fatal(err)
					}
					if !started.Equal(at) || !ended.Equal(boundary) || length != snapshot.Extents[0].Length {
						t.Fatalf("lagged snapshot interval: [%s,%s) bytes=%d, want [%s,%s) bytes=%d", started, ended, length, at, boundary, snapshot.Extents[0].Length)
					}
					if replacement {
						if err := f.pool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2`, id, strings.Repeat("a", 64)).Scan(&ended); err != nil || !ended.Equal(at) {
							t.Fatalf("previous generation did not end at receipt: %s, %v", ended, err)
						}
					}
					// Reports at and after failure cannot reopen storage, including
					// when cleanup has moved the row back to the deleting status.
					if err := apply(boundary, base, snapshot); err != nil {
						t.Fatal(err)
					}
					if err := apply(boundary.Add(time.Second), base); err != nil {
						t.Fatal(err)
					}
					var count int
					want := 1
					if replacement {
						want++
					}
					if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1`, id).Scan(&count); err != nil || count != want {
						t.Fatalf("snapshot interval count: %d, want %d, err=%v", count, want, err)
					}
				})
			}
		}
	}
}

func TestIntegration_RetainedSnapshotStatusClosure(t *testing.T) {
	for _, status := range []string{"failed", "ready", "deleting"} {
		t.Run(status, func(t *testing.T) {
			f := newStorageLeaseFixture(t)
			ctx := t.Context()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			attachSnapshotRetentionTrigger(t, f)
			id := uuid.New()
			at := f.receivedAt.Add(-time.Minute)
			exec(`INSERT INTO sandbox_snapshot(id,team_id,host_id,status,created_at)
 SELECT $1,team_id,host_id,'creating',created_at FROM sandbox WHERE id=$2`, id, f.sandboxID)
			owner := func(kind string, id uuid.UUID) retainedstorage.Owner {
				return retainedstorage.Owner{Kind: kind, ID: id.String(), Generation: strings.Repeat("a", 64),
					Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}}
			}
			base, snapshot := owner("sandbox", f.sandboxID), owner("snapshot", id)
			apply := func() {
				t.Helper()
				exec(`UPDATE host_storage_report SET state='processing',next_measurement_index=0`)
				if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, at,
					[]storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{base, snapshot}}}}, 1, 1); err != nil {
					t.Fatal(err)
				}
			}
			apply()
			exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
 SELECT host_id,team_id,'snapshot',$1,'previous','[]',$2,$3 FROM sandbox WHERE id=$4`, id, at.Add(-time.Minute), at, f.sandboxID)
			var before, after time.Time
			if err := f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if status == "failed" {
				if n, err := db.New(f.pool).MarkSandboxSnapshotFailed(ctx, id); err != nil || n != 1 {
					t.Fatalf("mark snapshot failed: rows=%d err=%v", n, err)
				}
			} else {
				exec(`UPDATE sandbox_snapshot SET status=$2 WHERE id=$1`, id, status)
			}
			if err := f.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			var ended *time.Time
			readEnd := func() {
				t.Helper()
				if err := f.pool.QueryRow(ctx, `SELECT ended_at FROM retained_storage_interval WHERE owner_id=$1 AND generation=$2`, id, snapshot.Generation).Scan(&ended); err != nil {
					t.Fatal(err)
				}
			}
			readEnd()
			if status == "failed" {
				if ended == nil || ended.Before(before) || ended.After(after) {
					t.Fatalf("failed snapshot must close at database transition time: ended=%v bounds=[%s,%s]", ended, before, after)
				}
				boundary := *ended
				// A delayed inventory cannot revive the failed snapshot, and a
				// later cleanup must not move its already-closed interval.
				apply()
				exec(`UPDATE sandbox_snapshot SET status='deleting',deleted_at=$2 WHERE id=$1`, id, after)
				readEnd()
				if ended == nil || !ended.Equal(boundary) {
					t.Fatalf("failed interval boundary changed: %v, want %s", ended, boundary)
				}
			} else {
				if ended != nil {
					t.Fatalf("retained status %s closed snapshot early: %s", status, ended)
				}
				exec(`UPDATE sandbox_snapshot SET status='deleting' WHERE id=$1`, id)
				exec(`UPDATE sandbox_snapshot SET deleted_at=$2 WHERE id=$1`, id, after)
				readEnd()
				if ended == nil || !ended.Equal(after) {
					t.Fatalf("confirmed deletion boundary: %v, want %s", ended, after)
				}
			}
			var count int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval
 WHERE (owner_kind='sandbox' AND owner_id=$1 AND ended_at IS NULL)
 OR (owner_kind='snapshot' AND owner_id=$2 AND generation='previous' AND ended_at=$3)`, f.sandboxID, id, at).Scan(&count); err != nil || count != 2 {
				t.Fatalf("snapshot closure changed surviving shared owner or historical interval: count=%d err=%v", count, err)
			}
		})
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

func TestIntegration_RetainedFailedFirstMeasurementBlocksSettlement(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "durable"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			f := newStorageLeaseFixture(t)
			ctx := t.Context()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`CREATE TEMP TABLE legacy_host_storage_report(host_id text,received_at timestamptz)`)
			exec(`DELETE FROM sandbox_storage_interval`)
			exec(`UPDATE sandbox SET status='failed' WHERE id=$1`, f.sandboxID)
			var team uuid.UUID
			if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
				t.Fatal(err)
			}
			inv := &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{{
				Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64),
				Extents: []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}},
			}}}
			measurements := []storageReportMeasurement{{Retained: inv}}
			payload, err := json.Marshal(measurements)
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE host_storage_report SET state='pending',payload=$2,next_measurement_index=0 WHERE report_id=$1`, f.reportID, payload)
			if legacy {
				exec(`UPDATE host_storage_report SET state='terminal' WHERE report_id=$1`, f.reportID)
				exec(`INSERT INTO legacy_host_storage_report VALUES($1,$2)`, f.hostID, f.receivedAt)
			}
			complete := func(want bool) {
				t.Helper()
				var got bool
				if err := f.pool.QueryRow(ctx, `SELECT storage_reports_complete_through($1,$2)`, team, f.receivedAt.Add(time.Minute)).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("settlement complete=%v, want %v", got, want)
				}
			}
			var count int
			if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM retained_storage_interval)+(SELECT count(*) FROM sandbox_storage_interval)`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("first measurement has prior intervals: %d %v", count, err)
			}
			complete(false)
			// Resolving the legacy receipt into the durable stream must keep the
			// same fence until its first measurable retained quantity is applied.
			exec(`DELETE FROM legacy_host_storage_report`)
			exec(`UPDATE host_storage_report SET state='processing' WHERE report_id=$1`, f.reportID)
			complete(false)
			if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, measurements, 1, 1); err != nil {
				t.Fatal(err)
			}
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval WHERE owner_id=$1 AND started_at=$2 AND ended_at IS NULL AND extents->0->>'length'='4096'`, f.sandboxID, f.receivedAt).Scan(&count); err != nil || count != 1 {
				t.Fatalf("first retained measurement was not applied at receipt: %d %v", count, err)
			}
			complete(true)
		})
	}
}

func TestIntegration_RetainedExpectedOwnerDiscoveryBound(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	var team uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
		t.Fatal(err)
	}
	owners := []retainedstorage.Owner{{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 0, Length: 4096}}}}
	for i := 1; i < retainedstorage.MaxOwners; i++ {
		id := uuid.New()
		if _, err := f.pool.Exec(ctx, `INSERT INTO sandbox(id,team_id,host_id,status,created_at,destroyed_at)
 VALUES($1,$2,$3,'paused',$4,NULL)`, id, team, f.hostID, f.receivedAt.Add(-time.Duration(i+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
		owners = append(owners, retainedstorage.Owner{Kind: "sandbox", ID: id.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: int64(i+1) * 4096, Length: 4096}}})
	}
	// Exactly the receiver bound is a complete, schema-valid inventory.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRetainedStorage(ctx, tx, f.hostID, f.receivedAt, &retainedstorage.Inventory{Version: 1, Owners: owners}); err != nil {
		t.Fatalf("exact owner bound rejected a valid inventory: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// A mixed-kind sentinel over the bound must remain retryable. The payload
	// itself stays valid; overflow is discovered from authoritative rows.
	snapshotID := uuid.New()
	if _, err := f.pool.Exec(ctx, `INSERT INTO sandbox_snapshot(id,team_id,host_id,status,created_at)
 VALUES($1,$2,$3,'ready',$4)`, snapshotID, team, f.hostID, f.receivedAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = applyRetainedStorage(ctx, tx, f.hostID, f.receivedAt, &retainedstorage.Inventory{Version: 1, Owners: owners})
	if !errors.Is(err, errStorageReportRetainedIncomplete) {
		t.Fatalf("expected bounded owner discovery to remain retryable, got %v", err)
	}
	if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	var after int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM retained_storage_interval`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("overflow changed retained accounting: before=%d after=%d", before, after)
	}
}

func TestIntegration_RetainedExpectedOwnerDiscoveryPlan(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	var indexName string
	if err := f.pool.QueryRow(ctx, `SELECT indexname FROM pg_indexes
 WHERE schemaname='public' AND indexname='sandbox_retained_receiver_host_lifetime'`).Scan(&indexName); err != nil {
		t.Fatal(err)
	}
	if indexName == "" {
		t.Fatal("receiver host/lifetime index is missing")
	}
	var plan []byte
	if err := f.pool.QueryRow(ctx, `EXPLAIN (FORMAT JSON)
 SELECT id FROM sandbox WHERE host_id=$1 AND created_at<=$2
   AND (destroyed_at IS NULL OR destroyed_at>$2)
 ORDER BY created_at,id LIMIT $3`, f.hostID, f.receivedAt, retainedstorage.MaxOwners+1).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "Limit") {
		t.Fatalf("bounded receiver plan omitted limit: %s", plan)
	}
}

func TestIntegration_RetainedActivationReceiptAtomicity(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	var team uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO retained_storage_measurement_obligation
 (team_id,owner_kind,owner_id,host_id,effective_at) VALUES($1,'sandbox',$2,$3,$4)`, team, f.sandboxID, f.hostID, f.receivedAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owner := retainedstorage.Owner{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 0, Length: 4096}}}
	if err := applyRetainedStorage(ctx, tx, f.hostID, f.receivedAt, &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{owner}}, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var resolvedAt *time.Time
	if err := f.pool.QueryRow(ctx, `SELECT resolved_at FROM retained_storage_measurement_obligation WHERE owner_id=$1`, f.sandboxID).Scan(&resolvedAt); err != nil {
		t.Fatal(err)
	}
	if resolvedAt != nil {
		t.Fatalf("rolled-back receipt resolved activation obligation at %v", resolvedAt)
	}
}

func TestIntegration_RetainedBaselineProvenance(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	gen := strings.Repeat("d", 64)
	owner := retainedstorage.Owner{Kind: "sandbox", ID: f.sandboxID.String(), Generation: gen,
		Extents:  []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 8192}},
		Baseline: &retainedstorage.Baseline{Path: "/example/pinned/rootfs.ext4", Generation: gen, AllocatedBytes: 8192}}
	measurements := []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{owner}}}}
	if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, measurements, 1, 1); err != nil {
		t.Fatal(err)
	}
	var path, generation string
	var allocated int64
	if err := f.pool.QueryRow(ctx, `SELECT baseline_path,baseline_generation,baseline_allocated_bytes
 FROM retained_storage_interval WHERE owner_id=$1 AND ended_at IS NULL`, f.sandboxID).Scan(&path, &generation, &allocated); err != nil {
		t.Fatal(err)
	}
	if path != owner.Baseline.Path || generation != gen || allocated != owner.Baseline.AllocatedBytes {
		t.Fatalf("durable provenance = %q/%q/%d, want %q/%q/%d", path, generation, allocated, owner.Baseline.Path, gen, owner.Baseline.AllocatedBytes)
	}
	// Replay is idempotent and does not create a second interval.
	if _, err := f.pool.Exec(ctx, `UPDATE host_storage_report SET state='processing',next_measurement_index=0 WHERE report_id=$1`, f.reportID); err != nil {
		t.Fatal(err)
	}
	if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, measurements, 1, 1); err != nil {
		t.Fatalf("same provenance replay: %v", err)
	}
	// A report still in processing keeps the settlement fence even when its
	// interval application already succeeded; the processor must finish the
	// durable report before settlement can advance.
	if _, err := f.pool.Exec(ctx, `UPDATE host_storage_report SET state='processing',next_measurement_index=0 WHERE report_id=$1`, f.reportID); err != nil {
		t.Fatal(err)
	}
	var team uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
		t.Fatal(err)
	}
	var complete bool
	if err := f.pool.QueryRow(ctx, `SELECT storage_reports_complete_through($1,$2)`, team, f.receivedAt.Add(time.Minute)).Scan(&complete); err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("settlement fence was cleared while report processing remained open")
	}
}

func TestIntegration_RetainedFailedSnapshotBlocksSettlement(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			f := newStorageLeaseFixture(t)
			ctx := t.Context()
			attachSnapshotRetentionTrigger(t, f)
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`CREATE TEMP TABLE legacy_host_storage_report(host_id text,received_at timestamptz)`)
			var team uuid.UUID
			if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
				t.Fatal(err)
			}
			// Only the snapshot can associate this report with the team, and its
			// first retained interval has not been applied yet.
			exec(`UPDATE sandbox SET destroyed_at=$2 WHERE id=$1`, f.sandboxID, f.receivedAt.Add(-time.Second))
			exec(`DELETE FROM sandbox_storage_interval`)
			id := uuid.New()
			exec(`INSERT INTO sandbox_snapshot(id,team_id,host_id,status,created_at)
 SELECT $1,team_id,host_id,'creating',created_at FROM sandbox WHERE id=$2`, id, f.sandboxID)
			owner := retainedstorage.Owner{Kind: "snapshot", ID: id.String(), Generation: strings.Repeat("a", 64),
				Extents: []retainedstorage.Extent{{Device: "fs", Start: 8192, Length: 8192}}}
			measurements := []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{owner}}}}
			payload, err := json.Marshal(measurements)
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE host_storage_report SET state='pending',payload=$2,next_measurement_index=0 WHERE report_id=$1`, f.reportID, payload)
			if legacy {
				exec(`UPDATE host_storage_report SET state='terminal' WHERE report_id=$1`, f.reportID)
				exec(`INSERT INTO legacy_host_storage_report VALUES($1,$2)`, f.hostID, f.receivedAt)
			}
			complete := func(want bool) {
				t.Helper()
				var got bool
				if err := f.pool.QueryRow(ctx, `SELECT storage_reports_complete_through($1,clock_timestamp()+interval '1 hour')`, team).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("settlement complete=%v, want %v", got, want)
				}
			}
			complete(false)
			exec(`UPDATE sandbox_snapshot SET status='failed' WHERE id=$1`, id)
			var boundary time.Time
			if err := f.pool.QueryRow(ctx, `SELECT retention_ended_at FROM sandbox_snapshot WHERE id=$1`, id).Scan(&boundary); err != nil {
				t.Fatal(err)
			}
			if !boundary.After(f.receivedAt) {
				t.Fatalf("failure boundary %s must follow receipt %s", boundary, f.receivedAt)
			}
			for _, phase := range []string{"failed", "deleting", "deleted"} {
				if phase == "deleting" {
					exec(`UPDATE sandbox_snapshot SET status='deleting' WHERE id=$1`, id)
				} else if phase == "deleted" {
					exec(`UPDATE sandbox_snapshot SET deleted_at=$2 WHERE id=$1`, id, boundary.Add(time.Minute))
				}
				// Compare otherwise identical pending receipts around the retained
				// lifetime's exclusive end, including during later cleanup.
				for _, receipt := range []time.Time{f.receivedAt, boundary, boundary.Add(time.Microsecond)} {
					if legacy {
						exec(`UPDATE legacy_host_storage_report SET received_at=$1`, receipt)
					} else {
						exec(`UPDATE host_storage_report SET received_at=$2 WHERE report_id=$1`, f.reportID, receipt)
					}
					complete(!receipt.Before(boundary))
				}
			}
			// Resolving a legacy receipt must preserve the fence until the durable
			// processor has applied the bounded snapshot interval.
			exec(`DELETE FROM legacy_host_storage_report`)
			exec(`UPDATE host_storage_report SET state='processing',received_at=$2 WHERE report_id=$1`, f.reportID, f.receivedAt)
			complete(false)
			if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, measurements, 1, 1); err != nil {
				t.Fatal(err)
			}
			var started, ended time.Time
			if err := f.pool.QueryRow(ctx, `SELECT started_at,ended_at FROM retained_storage_interval WHERE owner_id=$1`, id).Scan(&started, &ended); err != nil {
				t.Fatal(err)
			}
			if !started.Equal(f.receivedAt) || !ended.Equal(boundary) {
				t.Fatalf("snapshot interval [%s,%s), want [%s,%s)", started, ended, f.receivedAt, boundary)
			}
			complete(true)
		})
	}
}

func TestIntegration_RetainedSnapshotOnlySettlementWaitsForReport(t *testing.T) {
	f := newStorageLeaseFixture(t)
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var team uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT team_id FROM sandbox WHERE id=$1`, f.sandboxID).Scan(&team); err != nil {
		t.Fatal(err)
	}
	// The source sandbox is gone; the saved snapshot is the only retained
	// owner on this host. Settlement must wait for its pending report.
	deleted := f.receivedAt.Add(-time.Second)
	exec(`UPDATE sandbox SET destroyed_at=$2 WHERE id=$1`, f.sandboxID, deleted)
	snapshotID := uuid.New()
	exec(`INSERT INTO sandbox_snapshot(id,team_id,host_id,status,created_at,ready_at)
 SELECT $1,team_id,host_id,'ready',$2,$2 FROM sandbox WHERE id=$3`, snapshotID, f.receivedAt.Add(-time.Minute), f.sandboxID)
	owner := retainedstorage.Owner{Kind: "snapshot", ID: snapshotID.String(), Generation: strings.Repeat("a", 64), Extents: []retainedstorage.Extent{{Device: "fs", Start: 8192, Length: 8192}}}
	measurements := []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{owner}}}}
	payload, err := json.Marshal(measurements)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE host_storage_report SET state='processing',payload=$2,next_measurement_index=0 WHERE report_id=$1`, f.reportID, payload)
	var complete bool
	if err := f.pool.QueryRow(ctx, `SELECT storage_reports_complete_through($1,$2)`, team, f.receivedAt.Add(time.Minute)).Scan(&complete); err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("settlement passed while snapshot report was pending")
	}
	if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, f.receivedAt, measurements, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT storage_reports_complete_through($1,$2)`, team, f.receivedAt.Add(time.Minute)).Scan(&complete); err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("settlement remained blocked after snapshot report processing")
	}
	var amount float64
	if err := f.pool.QueryRow(ctx, `SELECT retained_storage_mib_seconds($1,$2,$3)`, team, f.receivedAt, f.receivedAt.Add(time.Minute)).Scan(&amount); err != nil {
		t.Fatal(err)
	}
	if amount <= 0 {
		t.Fatalf("snapshot-only retained storage = %v, want positive", amount)
	}
}

func TestIntegration_RetainedMixedHistoryFencesDelayedHandoff(t *testing.T) {
	for _, delayedRetained := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed-retained-%t", delayedRetained), func(t *testing.T) {
			f := newStorageLeaseFixture(t)
			ctx := t.Context()
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			t0, t1, t2 := f.receivedAt.Add(-time.Minute), f.receivedAt, f.receivedAt.Add(time.Minute)
			exec(`DELETE FROM sandbox_storage_interval`)
			legacyHost, retainedHost := f.hostID, "other-host"
			legacyStart, legacyEnd, retainedStart, retainedEnd := t0, any(t2), t2, any(nil)
			if delayedRetained {
				legacyHost, retainedHost = retainedHost, legacyHost
				legacyStart, legacyEnd, retainedStart, retainedEnd = t2, nil, t0, t2
			}
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason)
 SELECT id,team_id,$2,8,$3,$4,'reassigned' FROM sandbox WHERE id=$1`, f.sandboxID, legacyHost, legacyStart, legacyEnd)
			exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
 SELECT $2,team_id,'sandbox',id,$3,'[]',$4,$5 FROM sandbox WHERE id=$1`, f.sandboxID, retainedHost, strings.Repeat("a", 64), retainedStart, retainedEnd)
			snapshot := func() string {
				t.Helper()
				var result string
				if err := f.pool.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM sandbox_storage_interval i),
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM retained_storage_interval i))::text`).Scan(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := snapshot()
			measurements := f.measurements
			if delayedRetained {
				measurements = []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("b", 64), Extents: []retainedstorage.Extent{}}}}}}
			}
			for attempt := 0; attempt < 2; attempt++ {
				exec(`UPDATE host_storage_report SET state='processing',next_measurement_index=0 WHERE report_id=$1`, f.reportID)
				err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, t1, measurements, 1, 1)
				if delayedRetained && !errors.Is(err, errStorageReportRetainedIncomplete) {
					t.Fatalf("superseded retained report = %v", err)
				}
				if !delayedRetained && err != nil {
					t.Fatal(err)
				}
				if got := snapshot(); got != before {
					t.Fatalf("delayed report changed handoff history: %s -> %s", before, got)
				}
			}
		})
	}
}

func TestIntegration_RetainedReplacementPreservesKnownEnd(t *testing.T) {
	for _, retained := range []bool{false, true} {
		for _, sameBoundary := range []bool{false, true} {
			t.Run(fmt.Sprintf("retained-%t/same-boundary-%t", retained, sameBoundary), func(t *testing.T) {
				f := newStorageLeaseFixture(t)
				ctx := t.Context()
				exec := func(q string, args ...any) {
					t.Helper()
					if _, err := f.pool.Exec(ctx, q, args...); err != nil {
						t.Fatal(err)
					}
				}
				start, end := f.receivedAt.Add(-time.Minute), f.receivedAt.Add(time.Minute)
				at := f.receivedAt
				if sameBoundary {
					at = start
				}
				measurements := f.measurements
				if retained {
					exec(`DELETE FROM sandbox_storage_interval`)
					exec(`INSERT INTO retained_storage_interval(host_id,team_id,owner_kind,owner_id,generation,extents,started_at,ended_at)
 SELECT host_id,team_id,'sandbox',id,$2,'[]',$3,$4 FROM sandbox WHERE id=$1`, f.sandboxID, strings.Repeat("a", 64), start, end)
					measurements = []storageReportMeasurement{{Retained: &retainedstorage.Inventory{Version: 1, Owners: []retainedstorage.Owner{{Kind: "sandbox", ID: f.sandboxID.String(), Generation: strings.Repeat("b", 64), Extents: []retainedstorage.Extent{}}}}}}
				} else {
					exec(`UPDATE sandbox_storage_interval SET ended_at=$1,end_reason='reassigned'`, end)
				}
				if err := applyStorageReport(ctx, f.pool, f.hostID, f.incarnationID, f.reportID, 2, at, measurements, 1, 1); err != nil {
					t.Fatal(err)
				}
				query := `SELECT ended_at,end_reason FROM sandbox_storage_interval WHERE disk_mib=16`
				if retained {
					query = `SELECT ended_at,'reassigned'::text FROM retained_storage_interval WHERE generation='` + strings.Repeat("b", 64) + `'`
				}
				var got time.Time
				var reason string
				if err := f.pool.QueryRow(ctx, query).Scan(&got, &reason); err != nil || !got.Equal(end) || reason != "reassigned" {
					t.Fatalf("replacement lost handoff boundary: %v %s %v", got, reason, err)
				}
			})
		}
	}
}
