//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

func waitStorageLockWait(t *testing.T, blockerPID int32) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		var waiting bool
		if err := testPool.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE $1::int=ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting); err != nil {
			t.Fatalf("inspect storage lock wait: %v", err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("storage transaction did not reach the held lock")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func storageRaceDestroyParams(t *testing.T, fixture storageReportFixture) db.DestroySandboxParams {
	t.Helper()
	return db.DestroySandboxParams{
		ID: fixture.sandboxID, TeamID: sandboxTeamID(t, fixture.sandboxID),
		StaleTransitionalBefore: time.Now().Add(-time.Hour),
		RevocationExpiresAt:     time.Now().Add(time.Hour),
		LeaseSeconds:            30,
	}
}

func assertStorageDestructionBoundaries(t *testing.T, fixture storageReportFixture, reportID uuid.UUID) {
	t.Helper()
	waitStorageReportState(t, reportID, "processed")
	var total, open, prior, measured int
	if err := testPool.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (WHERE i.ended_at IS NULL),
		       count(*) FILTER (WHERE i.disk_mib=8 AND i.ended_at=r.received_at AND i.end_reason='measurement'),
		       count(*) FILTER (WHERE i.disk_mib=16 AND i.started_at=r.received_at AND i.ended_at=s.destroyed_at AND i.end_reason='deleted')
		FROM sandbox_storage_interval i
		JOIN sandbox s ON s.id=i.sandbox_id
		JOIN host_storage_report r ON r.report_id=$2
		WHERE s.id=$1`, fixture.sandboxID, reportID).Scan(&total, &open, &prior, &measured); err != nil {
		t.Fatalf("read destruction boundaries: %v", err)
	}
	if total != 2 || open != 0 || prior != 1 || measured != 1 {
		t.Fatalf("destruction intervals total=%d open=%d prior=%d measured=%d; want 2, 0, 1, 1", total, open, prior, measured)
	}
}

func TestIntegration_StorageReportWaitsForConcurrentDestruction(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	params := storageRaceDestroyParams(t, fixture)
	reportID := uuid.New()
	// Keep the report unclaimable until destruction holds its locks.
	payload := fmt.Sprintf(`[{"sandbox_id":%q,"allocated_bytes":16777216}]`, fixture.sandboxID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, payload, next_attempt_at)
		VALUES ($1,$2::uuid,$3,1,$4::jsonb,now()+interval '1 hour')`, fixture.hostID, fixture.incarnation, reportID, payload); err != nil {
		t.Fatalf("insert storage report: %v", err)
	}
	destruction, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer destruction.Rollback(ctx)
	if _, err := db.New(destruction).DestroySandbox(ctx, params); err != nil {
		t.Fatalf("destroy sandbox: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE host_storage_report SET next_attempt_at=now() WHERE report_id=$1`, reportID); err != nil {
		t.Fatalf("release report: %v", err)
	}
	waitStorageLockWait(t, int32(destruction.Conn().PgConn().PID()))
	if err := destruction.Commit(ctx); err != nil {
		t.Fatalf("commit destruction: %v", err)
	}
	assertStorageDestructionBoundaries(t, fixture, reportID)
}

func TestIntegration_DestructionWaitsForConcurrentStorageReport(t *testing.T) {
	fixture := newStorageReportFixture(t, "active", true)
	ctx := context.Background()
	params := storageRaceDestroyParams(t, fixture)
	gate, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(ctx)
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,42))`, fixture.sandboxID.String()); err != nil {
		t.Fatal(err)
	}
	functionName := "test_storage_destroy_gate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM set_config('lock_timeout','5s',true);
			PERFORM pg_advisory_xact_lock(hashtextextended(NEW.sandbox_id::text,42));
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s AFTER INSERT ON sandbox_storage_interval
		FOR EACH ROW WHEN (NEW.sandbox_id='%s'::uuid AND NEW.disk_mib=16)
		EXECUTE FUNCTION %s()`, functionName, functionName, fixture.sandboxID, functionName)); err != nil {
		t.Fatalf("install storage insert gate: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(ctx, "DROP FUNCTION "+functionName+"() CASCADE"); err != nil {
			t.Errorf("remove storage insert gate: %v", err)
		}
	})
	reportID := uuid.New()
	if w := postStorageReport(t, fixture, reportID, 16*1024*1024); w.Code != http.StatusCreated {
		t.Fatalf("post report: %d %s", w.Code, w.Body.String())
	}
	waitStorageLockWait(t, int32(gate.Conn().PgConn().PID()))
	// The delete statement starts with a snapshot that cannot see the new
	// interval. It must still close that interval after the worker commits.
	destroyConn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destroyCtx, cancelDestroy := context.WithCancel(ctx)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := db.New(destroyConn).DestroySandbox(destroyCtx, params)
		done <- err
	}()
	defer func() {
		_ = gate.Rollback(ctx)
		cancelDestroy()
		<-finished
		destroyConn.Release()
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var blocked bool
		if err := testPool.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, int32(destroyConn.Conn().PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("destruction did not wait for storage worker")
		}
		time.Sleep(time.Millisecond)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatalf("release storage worker: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concurrent destruction: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("destruction did not finish")
	}
	assertStorageDestructionBoundaries(t, fixture, reportID)
}
