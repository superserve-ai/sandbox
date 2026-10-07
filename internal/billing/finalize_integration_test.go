//go:build integration

package billing

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/db"
)

func finalizationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for finalization integration tests")
	}
	admin, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"finalization_" + uuid.New().String()[:8]}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		admin.Close(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 12
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(t.Context(), `
CREATE TABLE team_billing_period (LIKE public.team_billing_period INCLUDING DEFAULTS INCLUDING INDEXES);
CREATE TABLE billing_rollup_scheduler_lease (LIKE public.billing_rollup_scheduler_lease INCLUDING ALL);
CREATE TABLE completeness_fixture (team_id uuid, period_end timestamptz, complete bool);
CREATE SEQUENCE completeness_calls;
CREATE FUNCTION storage_reports_complete_through(t uuid, boundary timestamptz) RETURNS bool
LANGUAGE plpgsql AS $$
DECLARE result bool;
BEGIN
    PERFORM nextval('completeness_calls');
    SELECT complete INTO result FROM completeness_fixture WHERE team_id=t AND period_end=boundary;
    IF result IS NULL THEN RAISE EXCEPTION 'completeness evaluated for irrelevant period'; END IF;
    RETURN result;
END $$;`); err != nil {
		t.Fatal(err)
	}
	return pool
}

func finalizationFixture(t *testing.T, pool *pgxpool.Pool, team uuid.UUID, end time.Time, status string, complete bool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status)
VALUES($1,$2,$3,$4)`, team, end.Add(-time.Hour), end, status); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO completeness_fixture VALUES($1,$2,$3)`, team, end, complete); err != nil {
		t.Fatal(err)
	}
}

func finalizationCompletenessCalls(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM completeness_calls`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestIntegration_FinalizationDiscoverySkipsUnexportedFleet(t *testing.T) {
	pool := finalizationTestPool(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status)
SELECT gen_random_uuid(), '2026-01-01'::timestamptz, '2026-02-01'::timestamptz, 'open'
FROM generate_series(1,10000)`); err != nil {
		t.Fatal(err)
	}
	rows, err := listExportedBillingPeriods(t.Context(), pool, 25)
	if err != nil || len(rows) != 0 {
		t.Fatalf("discovery = %v, %v; want empty without completeness work", rows, err)
	}
	if calls := finalizationCompletenessCalls(t, pool); calls != 0 {
		t.Fatalf("completeness calls = %d, want zero", calls)
	}
}

func TestIntegration_FinalizationDiscoveryPreservesOrdering(t *testing.T) {
	pool := finalizationTestPool(t)
	ctx := t.Context()
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	blocked, ready, later, finalized := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	finalizationFixture(t, pool, blocked, end, "open", true)
	finalizationFixture(t, pool, blocked, end.Add(time.Hour), "exported", true)
	finalizationFixture(t, pool, ready, end, "open", false)
	finalizationFixture(t, pool, ready, end.Add(time.Hour), "exported", true)
	finalizationFixture(t, pool, ready, end.Add(2*time.Hour), "exported", true)
	finalizationFixture(t, pool, later, end.Add(3*time.Hour), "exported", true)
	finalizationFixture(t, pool, finalized, end, "finalized", true)
	if _, err := pool.Exec(ctx, `UPDATE team_billing_period SET finalized_at=now() WHERE team_id=$1`, finalized); err != nil {
		t.Fatal(err)
	}
	finalizationFixture(t, pool, finalized, end.Add(4*time.Hour), "exported", true)
	// No completeness fixture: evaluating a later open period must fail this test.
	if _, err := pool.Exec(ctx, `INSERT INTO team_billing_period(team_id,period_start,period_end,status)
VALUES($1,$2,$3,'open')`, ready, end.Add(24*time.Hour), end.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.New(pool).ListExportedTeamBillingPeriods(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	want := []uuid.UUID{ready, later, finalized}
	if len(rows) != len(want) {
		t.Fatalf("got %d periods, want %d: %+v", len(rows), len(want), rows)
	}
	for i, row := range rows {
		if row.TeamID != want[i] {
			t.Fatalf("period %d team = %s, want %s", i, row.TeamID, want[i])
		}
	}
	if !rows[0].PeriodEnd.Equal(end.Add(time.Hour)) {
		t.Fatal("discovery skipped the earliest complete exported period")
	}
	rows, err = db.New(pool).ListExportedTeamBillingPeriods(ctx, 1)
	if err != nil || len(rows) != 1 || rows[0].TeamID != ready {
		t.Fatalf("bounded batch = %+v, %v", rows, err)
	}
}

func TestIntegration_FinalizationTenReplicasShareOneTick(t *testing.T) {
	pool := finalizationTestPool(t)
	finalizationFixture(t, pool, uuid.New(), time.Now().UTC().Add(-time.Hour), "exported", false)
	if _, err := pool.Exec(t.Context(), `INSERT INTO billing_rollup_scheduler_lease(name,locked_by,locked_until)
VALUES('hourly','other-scheduler',now()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultBillingFinalizationConfig()
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 10 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			runBillingFinalizationTick(t.Context(), pool, cfg, uuid.NewString())
		}()
	}
	close(start)
	workers.Wait()
	if calls := finalizationCompletenessCalls(t, pool); calls != 1 {
		t.Fatalf("completeness calls from ten replicas = %d, want one", calls)
	}
	var holder string
	if err := pool.QueryRow(t.Context(), `SELECT locked_by FROM billing_rollup_scheduler_lease WHERE name='finalization'`).Scan(&holder); err != nil {
		t.Fatal(err)
	}
	for _, contender := range []string{holder, uuid.NewString()} {
		claimed, err := claimBillingFinalizationLease(t.Context(), pool, contender, time.Minute)
		if err != nil || claimed {
			t.Fatalf("claim during cooldown = %v, %v", claimed, err)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE billing_rollup_scheduler_lease SET locked_until=now()-interval '1 second' WHERE name='finalization'`); err != nil {
		t.Fatal(err)
	}
	claimed, err := claimBillingFinalizationLease(t.Context(), pool, uuid.NewString(), time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim after expiry = %v, %v", claimed, err)
	}
}

func TestIntegration_FinalizationTimeoutRetainsCooldown(t *testing.T) {
	pool := finalizationTestPool(t)
	finalizationFixture(t, pool, uuid.New(), time.Now().UTC().Add(-time.Hour), "exported", false)
	if _, err := pool.Exec(t.Context(), `CREATE OR REPLACE FUNCTION storage_reports_complete_through(t uuid, boundary timestamptz)
RETURNS bool LANGUAGE plpgsql AS $$ BEGIN
PERFORM nextval('completeness_calls'); PERFORM pg_sleep(10); RETURN false; END $$`); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultBillingFinalizationConfig()
	cfg.TickTimeout = 200 * time.Millisecond
	started := time.Now()
	runBillingFinalizationTick(t.Context(), pool, cfg, uuid.NewString())
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("timed-out tick took %v", elapsed)
	}
	runBillingFinalizationTick(t.Context(), pool, cfg, uuid.NewString())
	if calls := finalizationCompletenessCalls(t, pool); calls != 1 {
		t.Fatalf("completeness calls after timeout/retry = %d, want one", calls)
	}
}
