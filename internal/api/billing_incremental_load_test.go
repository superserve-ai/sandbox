//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type billingLoadQuery struct {
	sql      string
	args     []any
	started  time.Time
	duration time.Duration
	rows     int64
	writes   bool
}
type billingLoadTrace struct {
	mu      sync.Mutex
	queries []billingLoadQuery
}
type billingLoadTraceKey struct{}

func (r *billingLoadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, billingLoadTraceKey{}, billingLoadQuery{sql: d.SQL, args: append([]any(nil), d.Args...), started: time.Now()})
}
func (r *billingLoadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	q := ctx.Value(billingLoadTraceKey{}).(billingLoadQuery)
	q.duration = time.Since(q.started)
	q.rows = d.CommandTag.RowsAffected()
	q.writes = d.CommandTag.Insert() || d.CommandTag.Update() || d.CommandTag.Delete()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, q)
}
func (r *billingLoadTrace) take() []billingLoadQuery {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.queries
	r.queries = nil
	return q
}

type billingLoadStripe struct {
	StripeBillingClient
	checkUnlocked func(context.Context) error
}

func (*billingLoadStripe) CountedMeterUsage(context.Context, string, string, time.Time, time.Time) (string, error) {
	return "0", nil
}
func (s *billingLoadStripe) ReportMeterEvent(ctx context.Context, _ StripeReportMeterEventParams) error {
	if err := s.checkUnlocked(ctx); err != nil {
		return err
	}
	return errors.New("example provider unavailable")
}

// The validation wrapper applies the existing integration migration harness first.
// This test must run serially against that disposable database, before the full
// integration suite resets it again.
func TestIntegration_IncrementalWorkerLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL must name the migrated disposable integration database")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	trace := &billingLoadTrace{}
	cfg.ConnConfig.Tracer = trace
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	anchor := now.Add(-10 * 24 * time.Hour)
	provider := &billingLoadStripe{checkUnlocked: func(ctx context.Context) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SELECT team_id FROM team_billing_period FOR UPDATE NOWAIT`); err != nil {
			t.Errorf("provider call held period lock: %v", err)
			return err
		}
		return nil
	}}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	// A future-due fleet makes a full-table scan visible even when a tick is idle.
	teams := make([]uuid.UUID, 512)
	for i := range teams {
		team, err := h.DB.CreateTeam(ctx, fmt.Sprintf("example-load-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		teams[i] = team.ID
		exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,'active',$3)`, team.ID, "cus_example_"+team.ID.String(), anchor)
		exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team.ID)
		exec(`INSERT INTO billing_export_work(team_id,next_run_at,seed_complete,seed_after,next_correction_at) VALUES($1,now()+interval '1 day',true,$2,now()+interval '1 day')`, team.ID, anchor.Add(-time.Hour))
	}
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 SELECT team_id,$2::timestamptz+n*interval '1 hour',$2::timestamptz+(n+1)*interval '1 hour',3600,3686400,0
 FROM unnest($1::uuid[]) team_id CROSS JOIN generate_series(0,239)n`, teams[10:138], anchor)
	exec(`ANALYZE team_billing_usage_hourly`)
	exec(`ANALYZE billing_export_work`)
	exec(`ANALYZE team_billing_account`)
	trace.take()
	report := func(name string, maxQueries int, maxWrites int64) []billingLoadQuery {
		t.Helper()
		queries := trace.take()
		var duration time.Duration
		var writes int64
		for _, q := range queries {
			duration += q.duration
			sql := strings.ToLower(q.sql)
			if strings.Contains(sql, "sandbox_compute_billing_interval") || strings.Contains(sql, "sandbox_storage_interval") {
				t.Errorf("%s rescanned raw usage: %s", name, q.sql)
			}
			if q.writes {
				writes += q.rows
			}
		}
		t.Logf("R16 workload=%s teams=%d queries=%d query_duration=%s statement_rows_affected=%d", name, len(teams), len(queries), duration, writes)
		if len(queries) > maxQueries || writes > maxWrites {
			t.Errorf("%s exceeded bounded work: queries=%d/%d writes=%d/%d", name, len(queries), maxQueries, writes, maxWrites)
		}
		return queries
	}
	worked, n, err := h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || worked || n != 0 {
		t.Fatalf("idle tick: %v %d %v", worked, n, err)
	}
	idle := report("idle", 1, 0)
	// Explain the actual claim captured from the idle tick, not a copied query.
	explainBillingLoadQuery(t, pool, idle[0], 32)
	trace.take()
	// Disabled due work must not acquire a lease or change its scheduling row.
	exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, teams[8])
	exec(`UPDATE billing_export_work SET next_run_at=now() WHERE team_id=$1`, teams[8])
	trace.take()
	worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || worked || n != 0 {
		t.Fatalf("disabled tick: %v %d %v", worked, n, err)
	}
	report("disabled", 1, 0)
	exec(`UPDATE billing_export_work SET next_run_at=now()+interval '1 day' WHERE team_id=$1`, teams[8])
	for i, hours := range []int{1, 240} {
		exec(`UPDATE billing_export_work SET next_run_at=now(),seed_complete=false WHERE team_id=$1`, teams[i])
		exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
   SELECT $1,$2::timestamptz+n*interval '1 hour',$2::timestamptz+(n+1)*interval '1 hour',3600,3686400,0 FROM generate_series(0,$3::int-1)n`, teams[i], anchor, hours)
		// Model pre-enablement aggregates: discovery must seed their queue itself.
		exec(`DELETE FROM billing_export_measurement_queue WHERE team_id=$1`, teams[i])
		explainBillingLoadQuery(t, pool, idle[0], 32)
		trace.take()
		worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
		want := hours
		if want > 48 {
			want = 48
		}
		if err != nil || !worked || n != want {
			t.Fatalf("hours=%d tick: %v %d %v", hours, worked, n, err)
		}
		// Each consumed hour uses a short transaction and bounded point queries;
		// allow 16 queries/writes per hour plus 200 for allocation/reconciliation.
		queries := report(fmt.Sprintf("active-hours-%d", hours), 200+16*want, int64(200+16*want))
		explainCapturedBillingLoadQuery(t, pool, queries, "WITH page AS MATERIALIZED", 48)
		explainCapturedBillingLoadQuery(t, pool, queries, "SELECT hour_start FROM billing_export_measurement_queue", 1)
		explainCapturedBillingLoadQuery(t, pool, queries, "FROM team_billing_usage_hourly WHERE team_id=$1 AND hour_start=$2", 1)
		var delay float64
		if err := pool.QueryRow(ctx, `SELECT extract(epoch FROM(next_run_at-now()))::float8 FROM billing_export_work WHERE team_id=$1`, teams[i]).Scan(&delay); err != nil {
			t.Fatal(err)
		}
		if delay < 55 {
			t.Fatalf("catch-up/retry not paced: %f seconds", delay)
		}
		if hours > 48 {
			var remaining int
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_measurement_queue WHERE team_id=$1 AND pending`, teams[i]).Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if remaining != 0 {
				t.Fatalf("seed batch was not fully consumed: %d", remaining)
			}
			t.Logf("R16 catch_up_processed=48 unseeded=%d", hours-48)
			// A correction behind the committed discovery cursor must be found on
			// the next sweep, even though this page has already been consumed.
			exec(`UPDATE team_billing_usage_hourly SET vcpu_seconds=7200,memory_mib_seconds=7372800
 WHERE team_id=$1 AND hour_start=$2`, teams[i], anchor)
		}
		if hours > 48 && delay > 125 {
			t.Fatalf("catch-up did not schedule bounded continuation: %f seconds", delay)
		}
		t.Logf("R16 workload=active-hours-%d next_tick_seconds=%.1f", hours, delay)
		if hours == 1 {
			var attempts int
			var retryDelay float64
			if err = pool.QueryRow(ctx, `SELECT sum(attempt_count)::int,min(extract(epoch FROM(next_attempt_at-now())))::float8 FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1`, teams[i]).Scan(&attempts, &retryDelay); err != nil {
				t.Fatal(err)
			}
			if attempts != 2 || retryDelay < 590 || retryDelay > 665 {
				t.Fatalf("provider failure pacing: attempts=%d delay=%f", attempts, retryDelay)
			}
			exec(`UPDATE billing_export_work SET next_run_at=now() WHERE team_id=$1`, teams[i])
			trace.take()
			worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
			if err != nil || !worked || n != 0 {
				t.Fatalf("unchanged tick: %v %d %v", worked, n, err)
			}
			report("unchanged-during-provider-backoff", 200, 20)
			var after, eventCount int
			if err = pool.QueryRow(ctx, `SELECT sum(attempt_count)::int,count(*) FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1`, teams[i]).Scan(&after, &eventCount); err != nil {
				t.Fatal(err)
			}
			if after != attempts || eventCount != 2 {
				t.Fatalf("unchanged tick allocated or retried: attempts=%d -> %d events=%d", attempts, after, eventCount)
			}
		}
	}
	// Drain every seed page, including the empty terminal page for an exact
	// multiple of the batch size. Re-reading the first page would stall or double
	// count the accumulated usage even if each individual tick stayed bounded.
	for page := 1; page <= 5; page++ {
		exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, teams[1])
		trace.take()
		worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
		want := 48
		if page == 5 {
			want = 0
		}
		if err != nil || !worked || n != want {
			t.Fatalf("catch-up page %d: worked=%v measurements=%d want=%d err=%v", page, worked, n, want, err)
		}
		queries := report(fmt.Sprintf("catch-up-page-%d", page), 200+16*want, int64(200+16*want))
		explainCapturedBillingLoadQuery(t, pool, queries, "WITH page AS MATERIALIZED", 48)
		var measured int
		var complete, exact bool
		if err = pool.QueryRow(ctx, `SELECT seed_complete,
 (SELECT count(*) FROM billing_export_measurement WHERE team_id=$1),
 (SELECT vcpu_seconds=$2 AND memory_mib_seconds=$2*1024 FROM billing_export_usage WHERE team_id=$1)
 FROM billing_export_work WHERE team_id=$1`, teams[1], min((page+1)*48, 240)*3600).Scan(&complete, &measured, &exact); err != nil {
			t.Fatal(err)
		}
		if measured != min((page+1)*48, 240) || !exact || complete != (page == 5) {
			t.Fatalf("catch-up page %d: measured=%d exact=%v complete=%v", page, measured, exact, complete)
		}
	}
	// Revisit the first page when the independent correction deadline is due.
	exec(`UPDATE billing_export_work SET next_correction_at=$2 WHERE team_id=$1`, teams[1], now)
	exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, teams[1])
	trace.take()
	worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || !worked || n != 1 {
		t.Fatalf("correction behind cursor: worked=%v measurements=%d err=%v", worked, n, err)
	}
	queries := report("historical-correction", 200, 20)
	explainCapturedBillingLoadQuery(t, pool, queries, "WITH page AS MATERIALIZED", 48)
	var corrected bool
	if err = pool.QueryRow(ctx, `SELECT vcpu_seconds=241*3600 AND memory_mib_seconds=241*3686400
 FROM billing_export_usage WHERE team_id=$1`, teams[1]).Scan(&corrected); err != nil || !corrected {
		t.Fatalf("historical correction lost: corrected=%v err=%v", corrected, err)
	}
	// Measure the next unchanged correction page independently of provider
	// retries and reconciliation, which still have outstanding work here.
	correctionNow := now.Add(exportCorrectionPageInterval)
	h.Now = func() time.Time { return correctionNow }
	trace.take()
	complete, err := h.seedExportMeasurements(ctx, teams[1], anchor)
	if err != nil || !complete {
		t.Fatalf("unchanged discovery page: complete=%v err=%v", complete, err)
	}
	n, err = h.consumeExportMeasurements(ctx, teams[1], anchor)
	h.Now = func() time.Time { return now }
	if err != nil || n != 0 {
		t.Fatalf("unchanged discovery page: measurements=%d err=%v", n, err)
	}
	queries = report("unchanged-discovery-page", 20, 1)
	explainCapturedBillingLoadQuery(t, pool, queries, "WITH page AS MATERIALIZED", 48)
	for _, q := range queries {
		if q.writes && q.rows > 0 && !strings.Contains(q.sql, "UPDATE billing_export_work") {
			t.Errorf("unchanged discovery page rewrote billing state: %s", q.sql)
		}
	}
	var correctionAfter, nextCorrection time.Time
	if err = pool.QueryRow(ctx, `SELECT correction_after,next_correction_at FROM billing_export_work WHERE team_id=$1`, teams[1]).Scan(&correctionAfter, &nextCorrection); err != nil {
		t.Fatal(err)
	}
	if !correctionAfter.Equal(anchor.Add(95*time.Hour)) || !nextCorrection.Equal(correctionNow.Add(exportCorrectionPageInterval)) {
		t.Fatalf("unchanged correction page did not advance and pace its cursor: after=%v next=%v", correctionAfter, nextCorrection)
	}
	exec(`UPDATE billing_export_work SET next_run_at=now()+interval '1 day' WHERE team_id=$1`, teams[1])
	// A committed lease must exclude another replica even with no row lock held.
	leaseToken := uuid.New()
	exec(`UPDATE billing_export_work SET next_run_at=now(),lease_token=$2,lease_until=now()+interval '1 hour' WHERE team_id=$1`, teams[7], leaseToken)
	trace.take()
	worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || worked || n != 0 {
		t.Fatalf("live lease: worked=%v measurements=%d err=%v", worked, n, err)
	}
	report("live-lease-idle", 1, 0)
	var preserved bool
	if err = pool.QueryRow(ctx, `SELECT lease_token=$2 AND lease_until>now() FROM billing_export_work WHERE team_id=$1`, teams[7], leaseToken).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("live lease changed: preserved=%v err=%v", preserved, err)
	}
	exec(`UPDATE billing_export_work SET lease_until=now()-interval '1 second' WHERE team_id=$1`, teams[7])
	trace.take()
	worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || !worked || n != 0 {
		t.Fatalf("expired lease recovery: worked=%v measurements=%d err=%v", worked, n, err)
	}
	report("expired-lease-recovery", 20, 2)
	if err = pool.QueryRow(ctx, `SELECT lease_token IS NULL AND lease_until IS NULL AND next_run_at>now() FROM billing_export_work WHERE team_id=$1`, teams[7]).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("expired lease was not released and paced: released=%v err=%v", preserved, err)
	}
	// Multiple replicas must skip a locked due team and claim each other team once.
	exec(`UPDATE billing_export_work SET next_run_at=now() WHERE team_id=ANY($1::uuid[])`, teams[2:7])
	lock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err = lock.Exec(ctx, `SELECT team_id FROM billing_export_work WHERE team_id=$1 FOR UPDATE`, teams[2]); err != nil {
		t.Fatal(err)
	}
	trace.take()
	results := make(chan error, 4)
	var wg sync.WaitGroup
	started := time.Now()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			worked, n, err := h.incrementalBillingTick(c, time.Hour)
			if err == nil && (!worked || n != 0) {
				err = fmt.Errorf("concurrent tick: worked=%v measurements=%d", worked, n)
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	report("concurrent-workers", 80, 8)
	t.Logf("R16 workers=4 held_team_lock=true elapsed=%s pool_wait=%s", time.Since(started), pool.Stat().AcquireDuration())
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_work WHERE team_id=ANY($1::uuid[]) AND next_run_at>now()`, teams[3:7]).Scan(&count); err != nil || count != 4 {
		t.Fatalf("distinct claims=%d: %v", count, err)
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_export_work SET next_run_at=now()+interval '1 day' WHERE team_id=$1`, teams[2])
	trace.take()
	worked, n, err = h.incrementalBillingTick(ctx, time.Hour)
	if err != nil || worked || n != 0 {
		t.Fatalf("paced idle tick: %v %d %v", worked, n, err)
	}
	report("paced-idle", 1, 0)
	// Discovery must page the fleet and leave existing scheduling rows alone.
	exec(`DELETE FROM billing_export_work WHERE team_id=$1`, teams[9])
	exec(`UPDATE billing_export_discovery SET next_run_at=now(),after_team=NULL`)
	trace.take()
	if err = h.discoverIncrementalBillingWork(ctx); err != nil {
		t.Fatal(err)
	}
	discovery := report("discovery-page", 105, 101)
	explainCapturedBillingLoadQuery(t, pool, discovery, "SELECT team_id FROM team_billing_account WHERE team_id>", 100)
	trace.take()
	if err = h.discoverIncrementalBillingWork(ctx); err != nil {
		t.Fatal(err)
	}
	report("discovery-paced-idle", 3, 0)

	t.Run("global re-enablement is paged", func(t *testing.T) {
		exec(`DELETE FROM team_feature_flag WHERE team_id=ANY($1::uuid[]) AND key='billing_export_enabled'`, teams[1:])
		exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, teams[0])
		exec(`INSERT INTO billing_export_work(team_id,seed_after,seed_complete,next_run_at)
 SELECT unnest($1::uuid[]),$2,true,now()+interval '1 day'
 ON CONFLICT(team_id) DO UPDATE SET seed_after=EXCLUDED.seed_after,seed_complete=true,next_run_at=EXCLUDED.next_run_at`, teams, anchor)
		exec(`UPDATE feature_flag SET enabled=false WHERE key='billing_export_enabled'`)
		exec(`UPDATE feature_flag SET enabled=true WHERE key='billing_export_enabled'`)
		resetCount := func() int {
			t.Helper()
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_work
 WHERE team_id=ANY($1::uuid[]) AND seed_after IS NULL AND NOT seed_complete`, teams).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if n := resetCount(); n != 0 {
			t.Fatalf("global trigger synchronously reset %d teams", n)
		}
		var pending bool
		var restarted bool
		if err := pool.QueryRow(ctx, `SELECT reset_existing,after_team IS NULL FROM billing_export_discovery`).Scan(&pending, &restarted); err != nil || !pending || !restarted {
			t.Fatalf("global trigger did not restart discovery: pending=%v restarted=%v err=%v", pending, restarted, err)
		}
		previous := 0
		for page := 0; pending && page < 20; page++ {
			exec(`UPDATE billing_export_discovery SET next_run_at=now()`)
			trace.take()
			if err := h.discoverIncrementalBillingWork(ctx); err != nil {
				t.Fatal(err)
			}
			report("global-reset-page", 105, 101)
			n := resetCount()
			if n-previous > 100 || n < previous {
				t.Fatalf("reset page changed %d teams", n-previous)
			}
			previous = n
			trace.take()
			if err := h.discoverIncrementalBillingWork(ctx); err != nil {
				t.Fatal(err)
			}
			report("global-reset-paced-idle", 3, 0)
			if err := pool.QueryRow(ctx, `SELECT reset_existing FROM billing_export_discovery`).Scan(&pending); err != nil {
				t.Fatal(err)
			}
		}
		if pending || previous != len(teams)-1 {
			t.Fatalf("reset sweep incomplete: pending=%v reset=%d", pending, previous)
		}
		var disabledUnchanged bool
		if err := pool.QueryRow(ctx, `SELECT seed_complete AND seed_after=$2 AND next_run_at>now()+interval '23 hours'
 FROM billing_export_work WHERE team_id=$1`, teams[0], anchor).Scan(&disabledUnchanged); err != nil || !disabledUnchanged {
			t.Fatalf("disabled team was reset: unchanged=%v err=%v", disabledUnchanged, err)
		}
		exec(`UPDATE billing_export_discovery SET next_run_at=now()`)
		trace.take()
		if err := h.discoverIncrementalBillingWork(ctx); err != nil {
			t.Fatal(err)
		}
		report("discovery-after-reset", 105, 1)
	})
	for _, first := range []string{"worker", "manual", "close"} {
		name := "scheduled-manual-race-" + first + "-first"
		if first == "close" {
			name = "scheduled-close-race"
		}
		t.Run(name, func(t *testing.T) {
			// Earlier discovery fixtures must not become claimable during this case.
			exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
			testScheduledManualExportRace(t, pool, first)
		})
	}
	for _, cadence := range []time.Duration{time.Hour, 24 * time.Hour} {
		t.Run("open-period-"+cadence.String(), func(t *testing.T) {
			// Both clocks must be isolated before concurrent reconciliation ticks.
			exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
			testOpenPeriodWorkerExports(t, pool, trace, cadence)
		})
	}
	t.Run("frozen-measurement-catchup", func(t *testing.T) {
		testFrozenMeasurementCatchup(t, pool)
	})
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("older-period-failure/recovery=%v", recovery), func(t *testing.T) {
			exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
			testOlderPeriodFailure(t, pool, recovery)
		})
	}
	t.Run("boundary-storage-enablement", func(t *testing.T) {
		testBoundaryStorageEnablement(t, pool)
	})
	t.Run("measurement-cursors", func(t *testing.T) {
		testMeasurementCursors(t, pool, trace)
	})

}

func explainCapturedBillingLoadQuery(t *testing.T, pool *pgxpool.Pool, queries []billingLoadQuery, fragment string, maxScanned float64) {
	t.Helper()
	for _, q := range queries {
		if strings.Contains(q.sql, fragment) {
			explainBillingLoadQuery(t, pool, q, maxScanned)
			return
		}
	}
	t.Fatalf("workload did not exercise query containing %q", fragment)
}

func explainBillingLoadQuery(t *testing.T, pool *pgxpool.Pool, q billingLoadQuery, maxScanned float64) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var raw []byte
	if err = tx.QueryRow(t.Context(), "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+q.sql, q.args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	t.Logf("R16 query_plan=%s", raw)
	var plans []map[string]any
	if err = json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	var walk func(map[string]any)
	walk = func(n map[string]any) {
		rows, _ := n["Actual Rows"].(float64)
		removed, _ := n["Rows Removed by Filter"].(float64)
		recheck, _ := n["Rows Removed by Index Recheck"].(float64)
		loops, _ := n["Actual Loops"].(float64)
		if (rows+removed+recheck)*loops > maxScanned {
			t.Errorf("query scanned more than %.0f rows: %v", maxScanned, n)
		}
		if children, ok := n["Plans"].([]any); ok {
			for _, child := range children {
				walk(child.(map[string]any))
			}
		}
	}
	walk(plans[0]["Plan"].(map[string]any))
}

type openPeriodStripe struct {
	mu sync.Mutex
	StripeBillingClient
	calls   []StripeReportMeterEventParams
	summary func() (string, error)
	submit  func(context.Context) error
}

type olderPeriodFailureStripe struct {
	openPeriodStripe
	failedStart time.Time
	recovery    bool
	failure     error
}

func (s *olderPeriodFailureStripe) CountedMeterUsage(ctx context.Context, event, customer string, start, end time.Time) (string, error) {
	if start.Equal(s.failedStart) {
		if s.recovery {
			return "1", nil
		}
		return "", s.failure
	}
	return s.openPeriodStripe.CountedMeterUsage(ctx, event, customer, start, end)
}

func testOlderPeriodFailure(t *testing.T, pool *pgxpool.Pool, recovery bool) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	current := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	anchor := current.AddDate(0, -1, 0)
	provider := &olderPeriodFailureStripe{failedStart: anchor, recovery: recovery, failure: errors.New("example summary unavailable")}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, fmt.Sprintf("example-period-failure-%v", recovery))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, "cus_example_"+team.ID.String(), anchor)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',false)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at,next_reconcile_at,seed_complete,next_correction_at)
 VALUES($1,now()-interval '100 years','infinity',true,$2)`, team.ID, now.Add(24*time.Hour))
	for _, start := range []time.Time{anchor, current} {
		end := start.AddDate(0, 1, 0)
		exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team.ID, start, end)
		exec(`INSERT INTO billing_incremental_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team.ID, start, end)
		exec(`INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,0,0)`, team.ID, start, end)
	}
	exec(`INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,3600)`, team.ID, anchor, current)
	exec(`UPDATE team_billing_period SET status='exporting' WHERE team_id=$1 AND period_start=$2`, team.ID, anchor)
	wantErr := provider.failure
	if recovery {
		wantErr = billing.ErrExportRecoveryRequired
	}
	for attempt := 0; attempt < 2; attempt++ {
		exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, team.ID)
		worked, measured, err := h.incrementalBillingTick(ctx, time.Hour)
		if !worked || measured != 0 || !errors.Is(err, wantErr) || !strings.Contains(err.Error(), billingPeriodID(anchor, current)) {
			t.Fatalf("tick: worked=%v measured=%d err=%v", worked, measured, err)
		}
		if len(provider.calls) != 1 || provider.calls[0].Value != "1.000000000000" || provider.calls[0].Timestamp < current.Unix() {
			t.Fatalf("later period must export exactly once despite older failure: %+v", provider.calls)
		}
		var recorded bool
		if err := pool.QueryRow(ctx, `SELECT last_error LIKE '%' || $2 || '%' AND lease_token IS NULL
 AND next_run_at>now() AND next_run_at<now()+interval '12 minutes'
 FROM billing_export_work WHERE team_id=$1`, team.ID, billingPeriodID(anchor, current)).Scan(&recorded); err != nil || !recorded {
			t.Fatalf("period failure and retry backoff not preserved: recorded=%v err=%v", recorded, err)
		}
	}
}

func (s *openPeriodStripe) ReportMeterEvent(ctx context.Context, p StripeReportMeterEventParams) error {
	if s.submit != nil {
		if err := s.submit(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, p)
	return nil
}

func (s *openPeriodStripe) CountedMeterUsage(_ context.Context, event, customer string, start, end time.Time) (string, error) {
	if s.summary != nil {
		return s.summary()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := new(big.Rat)
	for _, p := range s.calls {
		if p.EventName == event && p.CustomerID == customer && p.Timestamp >= start.Unix() && p.Timestamp < end.Unix() {
			value, ok := new(big.Rat).SetString(p.Value)
			if !ok {
				return "", fmt.Errorf("invalid meter quantity %q", p.Value)
			}
			total.Add(total, value)
		}
	}
	return total.FloatString(12), nil
}

type pinnedMeterReader struct {
	t    *testing.T
	want string
}

func (r pinnedMeterReader) CountedMeterUsage(_ context.Context, event, _ string, _, _ time.Time) (string, error) {
	r.t.Helper()
	if event != r.want {
		r.t.Fatalf("reconciliation meter=%s want=%s", event, r.want)
	}
	return "0.5", nil
}

func testOpenPeriodWorkerExports(t *testing.T, pool *pgxpool.Pool, trace *billingLoadTrace, cadence time.Duration) {
	t.Helper()
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	anchor := now.Add(-72 * time.Hour)
	end := anchor.AddDate(0, 1, 0)
	provider := &openPeriodStripe{}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-open-period-"+cadence.String())
	if err != nil {
		t.Fatal(err)
	}
	customer := "cus_example_" + team.ID.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, anchor)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',false),($1,'billing_storage_billing_enabled',false)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=false`, team.ID)
	// Historical aggregates predate enablement and therefore have no queue entries.
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 SELECT $1,$2::timestamptz+n*interval '1 hour',$2::timestamptz+(n+1)*interval '1 hour',3600,3686400,3686400
 FROM generate_series(0,1)n`, team.ID, anchor)
	exec(`UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, team.ID)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at) VALUES($1,now()-interval '100 years') ON CONFLICT(team_id) DO UPDATE SET next_run_at=now()-interval '100 years'`, team.ID)
	seen := map[string]bool{}
	tick := func(measurements, callCount int, quantity string) {
		t.Helper()
		// Advance only this team's durable due time; no wall-clock sleep is needed.
		exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, team.ID)
		trace.take()
		before := time.Now()
		worked, measured, err := h.incrementalBillingTick(ctx, cadence)
		queries := trace.take()
		if err != nil || !worked || measured != measurements {
			t.Fatalf("tick: worked=%v measurements=%d want=%d err=%v", worked, measured, measurements, err)
		}
		if len(provider.calls) != callCount {
			t.Fatalf("submissions=%d want=%d: %+v", len(provider.calls), callCount, provider.calls)
		}
		if measurements == 0 {
			var writes int64
			for _, q := range queries {
				if q.writes && q.rows > 0 {
					writes += q.rows
					if !strings.Contains(q.sql, "UPDATE billing_export_work") {
						t.Errorf("unchanged usage rewrote billing state: %s", q.sql)
					}
				}
				if strings.Contains(q.sql, "sandbox_compute_billing_interval") || strings.Contains(q.sql, "sandbox_storage_interval") {
					t.Errorf("unchanged usage rescanned history: %s", q.sql)
				}
			}
			if writes != 2 {
				t.Errorf("unchanged tick wrote %d rows; expected only claim and release", writes)
			}
		}
		resources := map[string]bool{}
		for _, call := range provider.calls {
			if seen[call.Identifier] {
				continue
			}
			if call.Value != quantity || call.CustomerID != customer || call.Identifier == "" || call.IdempotencyKey == "" || call.Timestamp < anchor.Unix() || call.Timestamp >= now.Unix() {
				t.Fatalf("unexpected delta payload: %+v", call)
			}
			if resources[call.EventName] || (call.EventName != "cpu_vcpu_hours" && call.EventName != "memory_gib_hours") {
				t.Fatalf("unexpected or repeated resource: %+v", call)
			}
			resources[call.EventName] = true
			seen[call.Identifier] = true
		}
		if measurements > 0 && len(resources) != 2 {
			t.Fatalf("new usage did not produce distinct CPU and memory events: %v", resources)
		}
		var status string
		var mutable bool
		if err := pool.QueryRow(ctx, `SELECT status,exported_at IS NULL AND finalized_at IS NULL FROM team_billing_period
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&status, &mutable); err != nil || status != "open" || !mutable {
			t.Fatalf("period froze during accrual: status=%s mutable=%v err=%v", status, mutable, err)
		}
		var next time.Time
		var released bool
		if err := pool.QueryRow(ctx, `SELECT next_run_at,lease_token IS NULL AND lease_until IS NULL AND last_error IS NULL FROM billing_export_work WHERE team_id=$1`, team.ID).Scan(&next, &released); err != nil || !released {
			t.Fatalf("worker did not finish cleanly: released=%v err=%v", released, err)
		}
		if next.Before(before.Add(cadence)) || next.After(time.Now().Add(cadence+time.Minute)) {
			t.Fatalf("next run %s does not follow cadence %s", next, cadence)
		}
	}
	tick(2, 2, "2.000000000000")
	// A configuration rollout must preserve both allocations and observations
	// on the meters that already hold this period's usage.
	h.Config = &config.Config{BillingResources: h.billingConfiguredResources()}
	for i := range h.Config.BillingResources {
		h.Config.BillingResources[i].StripeEventName += "_renamed"
	}
	tick(0, 2, "")
	now = now.Add(cadence)
	// An exporter lock must not block either rollup inserts or corrections.
	queueLock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer queueLock.Rollback(ctx)
	if _, err = queueLock.Exec(ctx, `LOCK TABLE billing_export_measurement_queue IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	rollupCtx, cancelRollup := context.WithTimeout(ctx, 2*time.Second)
	_, err = pool.Exec(rollupCtx, `INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,1800,1843200,3686400)`, team.ID, now.Add(-time.Hour), now)
	if err == nil {
		_, err = pool.Exec(rollupCtx, `UPDATE team_billing_usage_hourly SET vcpu_seconds=3600,memory_mib_seconds=3686400
 WHERE team_id=$1 AND hour_start=$2`, team.ID, now.Add(-time.Hour))
	}
	cancelRollup()
	if err != nil {
		t.Fatalf("rollup depended on export queue lock: %v", err)
	}
	if err = queueLock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_measurement_queue WHERE team_id=$1 AND pending`, team.ID).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("rollup wrote export queue: queued=%d err=%v", queued, err)
	}
	tick(1, 4, "1.000000000000")
	tick(0, 4, "")
	var accrued bool
	if err := pool.QueryRow(ctx, `SELECT vcpu_seconds=10800 AND memory_mib_seconds=11059200 FROM billing_export_usage
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&accrued); err != nil || !accrued {
		t.Fatalf("continued persisted accrual: matched=%v err=%v", accrued, err)
	}
	now = now.Add(cadence)
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,3686400,0)`, team.ID, now.Add(-time.Hour), now)
	inFlightCtx, cancelInFlight := context.WithTimeout(ctx, 10*time.Second)
	defer cancelInFlight()
	entered := make(chan struct{})
	release := make(chan struct{})
	updated := make(chan error, 1)
	var once sync.Once
	provider.submit = func(context.Context) error {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return nil
		case <-inFlightCtx.Done():
			return inFlightCtx.Err()
		}
	}
	defer func() { provider.submit = nil }()
	go func() {
		defer close(release)
		select {
		case <-entered:
		case <-inFlightCtx.Done():
			updated <- inFlightCtx.Err()
			return
		}
		// Commit the authoritative rollup increase before submission can return.
		updateCtx, cancelUpdate := context.WithTimeout(inFlightCtx, 2*time.Second)
		defer cancelUpdate()
		result, err := pool.Exec(updateCtx, `UPDATE team_billing_usage_hourly SET vcpu_seconds=7200,memory_mib_seconds=7372800
 WHERE team_id=$1 AND hour_start=$2`, team.ID, now.Add(-time.Hour))
		if err == nil && result.RowsAffected() != 1 {
			err = fmt.Errorf("in-flight rollup update affected %d rows, want 1", result.RowsAffected())
		}
		updated <- err
	}()
	tick(1, 6, "1.000000000000")
	if err := <-updated; err != nil {
		t.Fatalf("rollup increase during submission: %v", err)
	}
	provider.submit = nil
	// Updates behind the forward cursor are found by the paced correction sweep.
	tick(0, 6, "")
	exec(`UPDATE billing_export_work SET next_correction_at=$2 WHERE team_id=$1`, team.ID, now)
	tick(1, 8, "1.000000000000")
	tick(0, 8, "")
	if err := pool.QueryRow(ctx, `SELECT vcpu_seconds=18000 AND memory_mib_seconds=18432000 FROM billing_export_usage
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&accrued); err != nil || !accrued {
		t.Fatalf("in-flight increase was not measured: matched=%v err=%v", accrued, err)
	}
	for _, event := range []string{"cpu_vcpu_hours", "memory_gib_hours"} {
		if total, err := provider.CountedMeterUsage(ctx, event, customer, anchor, end); err != nil || total != "5.000000000000" {
			t.Fatalf("in-flight increase coverage for %s: total=%s err=%v", event, total, err)
		}
	}
	if cadence == 24*time.Hour {
		testIndependentReconciliation(t, h, provider, team.ID)
	}

}

func testIndependentReconciliation(t *testing.T, h *Handlers, provider *openPeriodStripe, team uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var exportDeadline time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT next_run_at FROM billing_export_work WHERE team_id=$1`, team).Scan(&exportDeadline); err != nil {
		t.Fatal(err)
	}
	assertDeadline := func(failed bool) {
		t.Helper()
		var unchanged, paced bool
		if err := h.Pool.QueryRow(ctx, `SELECT next_run_at=$2,
 next_reconcile_at>now()+CASE WHEN $3 THEN interval '9 minutes' ELSE interval '359 minutes' END
 AND next_reconcile_at<=now()+CASE WHEN $3 THEN interval '11 minutes' ELSE interval '361 minutes' END
 AND (reconcile_error IS NOT NULL)=$3 FROM billing_export_work WHERE team_id=$1`, team, exportDeadline, failed).Scan(&unchanged, &paced); err != nil || !unchanged || !paced {
			t.Fatalf("independent reconciliation deadline: unchanged=%v paced=%v err=%v", unchanged, paced, err)
		}
	}
	// Simulate six hours passing while the daily export is still in the future.
	exec(`UPDATE billing_export_work SET next_reconcile_at=now()-interval '1 second' WHERE team_id=$1`, team)
	beforeCalls := len(provider.calls)
	provider.summary = func() (string, error) { return "0", nil }
	defer func() { provider.summary = nil }()
	// Fresh handler instances share only durable scheduling state.
	results := make(chan bool, 2)
	errorsCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			restarted := &Handlers{Pool: h.Pool, DB: db.New(h.Pool), Stripe: provider, Now: h.Now}
			worked, n, err := restarted.incrementalBillingTick(ctx, 24*time.Hour)
			if n != 0 {
				err = fmt.Errorf("reconciliation consumed %d measurements", n)
			}
			results <- worked
			errorsCh <- err
		}()
	}
	claimed := 0
	for i := 0; i < 2; i++ {
		if <-results {
			claimed++
		}
		if err := <-errorsCh; err != nil {
			t.Fatal(err)
		}
	}
	if claimed != 1 || len(provider.calls) != beforeCalls {
		t.Fatalf("reconciliation claims=%d submissions=%d", claimed, len(provider.calls)-beforeCalls)
	}
	assertDeadline(false)
	var discrepancies int
	if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_observation WHERE team_id=$1 AND counted_quantity=0 AND submitted_quantity>0`, team).Scan(&discrepancies); err != nil || discrepancies != 2 {
		t.Fatalf("provider discrepancy missing: count=%d err=%v", discrepancies, err)
	}
	// A committed lease survives a restart; expiry recovers the same due job.
	exec(`UPDATE billing_export_work SET next_reconcile_at=now()-interval '1 second',lease_token=$2,lease_until=now()+interval '1 hour' WHERE team_id=$1`, team, uuid.New())
	if worked, _, err := h.incrementalBillingTick(ctx, 24*time.Hour); err != nil || worked {
		t.Fatalf("live reconciliation lease: worked=%v err=%v", worked, err)
	}
	exec(`UPDATE billing_export_work SET lease_until=now()-interval '1 second' WHERE team_id=$1`, team)
	provider.summary = func() (string, error) { return "", errors.New("example summary unavailable") }
	if worked, _, err := h.incrementalBillingTick(ctx, 24*time.Hour); !worked || err == nil {
		t.Fatalf("expired reconciliation lease: worked=%v err=%v", worked, err)
	}
	assertDeadline(true)
	// A worker that loses its token during provider I/O cannot acknowledge a
	// successor's lease or overwrite either persisted deadline.
	exec(`UPDATE billing_export_work SET next_reconcile_at=now()-interval '1 second' WHERE team_id=$1`, team)
	successor := uuid.New()
	provider.summary = func() (string, error) {
		_, err := h.Pool.Exec(ctx, `UPDATE billing_export_work SET lease_token=$2,lease_until=now()+interval '1 hour' WHERE team_id=$1`, team, successor)
		return "0", err
	}
	if worked, _, err := h.incrementalBillingTick(ctx, 24*time.Hour); !worked || err != nil {
		t.Fatalf("superseded reconciliation: worked=%v err=%v", worked, err)
	}
	var successorPreserved bool
	if err := h.Pool.QueryRow(ctx, `SELECT lease_token=$2 AND next_reconcile_at<now() AND next_run_at=$3 FROM billing_export_work WHERE team_id=$1`, team, successor, exportDeadline).Scan(&successorPreserved); err != nil || !successorPreserved {
		t.Fatalf("stale acknowledgement changed successor: preserved=%v err=%v", successorPreserved, err)
	}
	exec(`UPDATE billing_export_work SET lease_until=now()-interval '1 second' WHERE team_id=$1`, team)
	provider.summary = func() (string, error) { return "", errors.New("example summary unavailable") }
	if worked, _, err := h.incrementalBillingTick(ctx, 24*time.Hour); !worked || err == nil {
		t.Fatalf("successor recovery: worked=%v err=%v", worked, err)
	}
	assertDeadline(true)
	// Export failures cannot postpone an already scheduled reconciliation retry.
	var reconcileDeadline time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT next_reconcile_at FROM billing_export_work WHERE team_id=$1`, team).Scan(&reconcileDeadline); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_export_work SET next_run_at=now()-interval '1 second' WHERE team_id=$1`, team)
	if worked, _, err := h.incrementalBillingTick(ctx, 24*time.Hour); !worked || err == nil {
		t.Fatalf("export failure: worked=%v err=%v", worked, err)
	}
	var preserved bool
	if err := h.Pool.QueryRow(ctx, `SELECT next_reconcile_at=$2 AND reconcile_error IS NOT NULL AND last_error IS NOT NULL FROM billing_export_work WHERE team_id=$1`, team, reconcileDeadline).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("export retry changed reconciliation: preserved=%v err=%v", preserved, err)
	}
}

func testScheduledManualExportRace(t *testing.T, pool *pgxpool.Pool, first string) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	anchor := now.Add(-72 * time.Hour)
	end := anchor.AddDate(0, 1, 0)
	if first == "close" {
		// PostgreSQL also checks the close boundary using its own clock.
		anchor = anchor.AddDate(0, -1, 0)
		end = anchor.AddDate(0, 1, 0)
		now = end.Add(-24 * time.Hour)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	provider := &openPeriodStripe{submit: func(ctx context.Context) error {
		firstCall := false
		enteredOnce.Do(func() { firstCall = true; close(entered) })
		if !firstCall {
			return nil
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-export-race-"+first)
	if err != nil {
		t.Fatal(err)
	}
	customer := "cus_example_" + team.ID.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, anchor)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',false)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at) VALUES($1,now()-interval '100 years')
 ON CONFLICT(team_id) DO UPDATE SET next_run_at=EXCLUDED.next_run_at`, team.ID)
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,0,0)`, team.ID, anchor, anchor.Add(time.Hour))
	complete, err := h.seedExportMeasurements(ctx, team.ID, anchor)
	if err != nil || !complete {
		t.Fatalf("seed: complete=%v err=%v", complete, err)
	}
	if _, err := h.consumeExportMeasurements(ctx, team.ID, anchor); err != nil {
		t.Fatal(err)
	}
	period := billing.ExportPeriod{TeamID: team.ID, Start: anchor, End: end}
	store := billing.ExportStore{Pool: pool}
	if err := store.Enroll(ctx, period); err != nil {
		t.Fatal(err)
	}
	wantEvents := 1
	if first == "close" {
		wantEvents = 2
		sandbox := uuid.New()
		exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id)
 VALUES($1,$2,'example-close-race','deleted',1,1024,'default')`, sandbox, team.ID)
		exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,1,1024,$3,$4,'deleted')`, sandbox, team.ID, anchor, anchor.Add(time.Hour))
		exec(`UPDATE team_billing_usage_hourly SET memory_mib_seconds=3686400 WHERE team_id=$1`, team.ID)
		if _, err := h.consumeExportMeasurements(ctx, team.ID, anchor); err != nil {
			t.Fatal(err)
		}
	}
	manualHandler := h
	if first == "close" {
		manualHandler = &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return end }}
	}
	router := gin.New()
	// Exercise the export race after authorization, without session identity fixtures.
	router.POST("/internal/teams/:team_id/billing/periods/:period_id/export", manualHandler.exportTeamBillingPeriod)
	wantStatus := http.StatusOK
	manual := func() error {
		req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+team.ID.String()+"/billing/periods/"+billingPeriodID(anchor, end)+"/export", nil).WithContext(ctx)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != wantStatus {
			return fmt.Errorf("manual export: status=%d body=%s", response.Code, response.Body.String())
		}
		return nil
	}
	worker := func() error {
		worked, _, err := h.incrementalBillingTick(ctx, time.Hour)
		if err != nil {
			return err
		}
		if !worked {
			return errors.New("scheduled tick did not claim work")
		}
		return nil
	}
	leading, competing := worker, manual
	if first == "manual" {
		leading, competing = manual, worker
	}
	done := make(chan error, 1)
	var leadingWG sync.WaitGroup
	leadingWG.Add(1)
	go func() {
		defer leadingWG.Done()
		done <- leading()
	}()
	defer func() {
		unblock()
		cancel()
		leadingWG.Wait()
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("leading path finished before provider barrier: %v", err)
	case <-ctx.Done():
		t.Fatal("leading path never reached provider")
	}
	if first == "close" {
		exec(`UPDATE team_billing_period SET status='approved' WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end)
		wantStatus = http.StatusConflict
	}
	// The competing path must finish while the first event is still in flight.
	competingErr := competing()
	if first == "close" {
		if competingErr != nil {
			t.Fatal(competingErr)
		}
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT status='exporting' AND exported_at IS NULL AND finalized_at IS NULL
 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&blocked); err != nil || !blocked {
			t.Fatalf("in-flight close remained blocked=%v err=%v", blocked, err)
		}
		totals, err := store.Totals(ctx, period, "cpu")
		if err != nil || totals.Pending != "1.000000000000" || totals.Submitted != "0" || totals.Reserved != "1.000000000000" {
			t.Fatalf("in-flight coverage: %+v err=%v", totals, err)
		}
		if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, anchor, end); err == nil {
			t.Fatal("finalized while incremental submission was blocked")
		}
		wantStatus = http.StatusOK
	}
	unblock()
	leadingErr := <-done
	if competingErr != nil || leadingErr != nil {
		t.Fatalf("concurrent exports: leading=%v competing=%v", leadingErr, competingErr)
	}
	// Replay the route to refresh reconciliation after both paths finish.
	if err := manual(); err != nil {
		t.Fatal(err)
	}
	var allocations, events, submitted int
	err = pool.QueryRow(ctx, `SELECT count(DISTINCT a.id),count(e.id),count(e.id) FILTER (WHERE e.status='submitted')
 FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id
 WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3`, team.ID, anchor, end).Scan(&allocations, &events, &submitted)
	if err != nil {
		t.Fatal(err)
	}
	if allocations != wantEvents || events != wantEvents || submitted != wantEvents {
		t.Fatalf("allocations=%d events=%d submitted=%d; want %d of each", allocations, events, submitted, wantEvents)
	}
	totals, err := store.Totals(ctx, period, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if totals.Reserved != "1.000000000000" || totals.Submitted != totals.Reserved || totals.Pending != "0" {
		t.Fatalf("unexpected accounting: %+v", totals)
	}
	counted, err := provider.CountedMeterUsage(ctx, "cpu_vcpu_hours", customer, anchor, now)
	if err != nil || counted != "1.000000000000" || len(provider.calls) != wantEvents {
		t.Fatalf("provider counted=%s calls=%+v err=%v", counted, provider.calls, err)
	}
	if first == "close" {
		for _, resource := range []string{"cpu", "memory"} {
			var allocations, events int
			if err := pool.QueryRow(ctx, `SELECT count(DISTINCT a.id),count(e.id)
 FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id
 WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resource_type=$4`, team.ID, anchor, end, resource).Scan(&allocations, &events); err != nil {
				t.Fatal(err)
			}
			if allocations != 1 || events != 1 {
				t.Fatalf("%s: allocations=%d events=%d; want one each", resource, allocations, events)
			}
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := manual(); err != nil {
				t.Fatal(err)
			}
			if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, anchor, end); err != nil {
				t.Fatalf("resolved close finalization: %v", err)
			}
		}
		var finalized bool
		if err := pool.QueryRow(ctx, `SELECT status='finalized' AND finalized_at IS NOT NULL FROM team_billing_period
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&finalized); err != nil || !finalized {
			t.Fatalf("resolved close finalized=%v err=%v", finalized, err)
		}
		if len(provider.calls) != wantEvents {
			t.Fatalf("repeated close resubmitted usage: %+v", provider.calls)
		}
		return
	}
	var open bool
	if err := pool.QueryRow(ctx, `SELECT status='open' AND exported_at IS NULL AND finalized_at IS NULL FROM team_billing_period
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, anchor, end).Scan(&open); err != nil || !open {
		t.Fatalf("period remained open=%v err=%v", open, err)
	}
}

// Exercise cursor persistence with enough history to require multiple pages.
func testMeasurementCursors(t *testing.T, pool *pgxpool.Pool, trace *billingLoadTrace) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	anchor := now.Add(-240 * time.Hour)
	h := &Handlers{Pool: pool, DB: db.New(pool), Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-measurement-cursors")
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO billing_export_work(team_id) VALUES($1)`, team.ID)
	// Leave a hole behind the eventual cursor to model a late committed hour.
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 SELECT $1,$2::timestamptz+n*interval '1 hour',$2::timestamptz+(n+1)*interval '1 hour',3600,0,0
 FROM generate_series(0,239)n WHERE n<>60`, team.ID, anchor)
	seed := func(wantComplete bool, wantRows int64) {
		t.Helper()
		trace.take()
		complete, err := h.seedExportMeasurements(ctx, team.ID, anchor)
		if err != nil || complete != wantComplete {
			t.Fatalf("seed complete=%v want=%v err=%v", complete, wantComplete, err)
		}
		var scanned int64
		for _, q := range trace.take() {
			if strings.Contains(q.sql, "WITH page AS MATERIALIZED") {
				scanned += q.rows
				explainBillingLoadQuery(t, pool, q, 48)
			}
		}
		if scanned != wantRows {
			t.Fatalf("aggregate rows read=%d want=%d", scanned, wantRows)
		}
	}
	for i := 0; i < 4; i++ {
		seed(false, 48)
	}
	seed(true, 47)
	// Mark snapshots consumed without involving allocation or provider behavior.
	exec(`UPDATE billing_export_measurement_queue q SET pending=false,hour_end=u.hour_end,vcpu_seconds=u.vcpu_seconds,
 memory_mib_seconds=u.memory_mib_seconds,storage_mib_seconds=u.storage_mib_seconds
 FROM team_billing_usage_hourly u WHERE q.team_id=$1 AND u.team_id=q.team_id AND u.hour_start=q.hour_start`, team.ID)
	for i := 0; i < 3; i++ {
		seed(true, 0)
	}
	exec(`UPDATE team_billing_usage_hourly SET vcpu_seconds=7200 WHERE team_id=$1 AND hour_start=$2`, team.ID, anchor.Add(55*time.Hour))
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$2::timestamptz+interval '1 hour',3600,0,0)`, team.ID, anchor.Add(60*time.Hour))
	now = now.Add(6 * time.Hour)
	seed(true, 48)
	var correct bool
	if err := pool.QueryRow(ctx, `SELECT correction_after=$2 AND correction_through=$3 AND seed_after=$3
 FROM billing_export_work WHERE team_id=$1`, team.ID, anchor.Add(47*time.Hour), anchor.Add(239*time.Hour)).Scan(&correct); err != nil || !correct {
		t.Fatalf("first correction cursor: %v %v", correct, err)
	}
	// New forward work must not wait for, or extend, the historical sweep.
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$2::timestamptz+interval '1 hour',3600,0,0)`, team.ID, now.Add(-time.Hour))
	seed(true, 1)
	seed(true, 0)
	// A fresh handler resumes persisted correction progress only at its deadline.
	h = &Handlers{Pool: pool, DB: db.New(pool), Now: func() time.Time { return now }}
	now = now.Add(6 * time.Hour)
	seed(true, 48)
	var pending int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_measurement_queue WHERE team_id=$1 AND pending`, team.ID).Scan(&pending); err != nil || pending != 3 {
		t.Fatalf("new, corrected and late hours: pending=%d err=%v", pending, err)
	}
	for i := 0; i < 3; i++ {
		now = now.Add(6 * time.Hour)
		seed(true, 48)
	}
	now = now.Add(6 * time.Hour)
	seed(true, 0)
	if err := pool.QueryRow(ctx, `SELECT correction_after IS NULL AND correction_through IS NULL AND next_correction_at=$2
 FROM billing_export_work WHERE team_id=$1`, team.ID, now.Add(24*time.Hour)).Scan(&correct); err != nil || !correct {
		t.Fatalf("completed correction sweep: %v %v", correct, err)
	}
	seed(true, 0)
	// Re-enablement's existing reset still forces a bounded initial sweep.
	exec(`UPDATE billing_export_work SET seed_after=NULL,seed_complete=false WHERE team_id=$1`, team.ID)
	seed(false, 48)
}

func testFrozenMeasurementCatchup(t *testing.T, pool *pgxpool.Pool) {
	for _, resource := range []string{"vcpu_seconds", "memory_mib_seconds", "storage_mib_seconds"} {
		for _, status := range []string{"exporting", "finalized"} {
			t.Run(resource+"/"+status, func(t *testing.T) {
				ctx := t.Context()
				exec := func(sql string, args ...any) {
					t.Helper()
					if _, err := pool.Exec(ctx, sql, args...); err != nil {
						t.Fatal(err)
					}
				}
				start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				end := start.AddDate(0, 1, 0)
				h := &Handlers{Pool: pool, DB: db.New(pool), Now: func() time.Time { return end.Add(time.Hour) }}
				team, err := h.DB.CreateTeam(ctx, "example-frozen-measurement-"+resource+"-"+status)
				if err != nil {
					t.Fatal(err)
				}
				exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, team.ID, start, end)
				exec(`INSERT INTO billing_incremental_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team.ID, start, end)
				exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,`+resource+`)
 SELECT $1,$2::timestamptz+n*interval '1 hour',$2::timestamptz+(n+1)*interval '1 hour',4 FROM generate_series(0,1)n`, team.ID, start)
				exec(`INSERT INTO billing_export_measurement_queue(team_id,hour_start) SELECT team_id,hour_start FROM team_billing_usage_hourly WHERE team_id=$1`, team.ID)
				if n, err := h.consumeExportMeasurements(ctx, team.ID, start); err != nil || n != 2 {
					t.Fatalf("initial measurement: n=%d err=%v", n, err)
				}
				exec(`INSERT INTO team_billing_usage(team_id,period_start,period_end,`+resource+`) VALUES($1,$2,$3,10)`, team.ID, start, end)
				exec(`UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, team.ID)
				if status == "finalized" {
					// This resource has zero usage; its matching observation permits the
					// fixture's finalization without creating provider events.
					zeroResource := "cpu"
					if resource == "vcpu_seconds" {
						zeroResource = "memory"
					}
					exec(`INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
 local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
 VALUES($1,$2,$3,$4,0,0,0,0,$2,$3)`, team.ID, start, end, zeroResource)
					exec(`UPDATE team_billing_period SET status='finalized',finalized_at=now(),
 gross_charges_usd=1,credits_applied_usd=0.25,net_invoice_amount_usd=0.75 WHERE team_id=$1`, team.ID)
				}
				consume := func() {
					t.Helper()
					// Competing consumers can lock different hours but must serialize
					// their aggregate comparisons under the existing period lock.
					errs := make(chan error, 2)
					for i := 0; i < 2; i++ {
						go func() {
							_, err := h.consumeExportMeasurements(ctx, team.ID, start)
							errs <- err
						}()
					}
					for i := 0; i < 2; i++ {
						if err := <-errs; err != nil {
							t.Fatal(err)
						}
					}
				}
				check := func(quantity string, anomalies int) {
					t.Helper()
					var exact, frozen bool
					var count, events, pending int
					err := pool.QueryRow(ctx, `SELECT
 (SELECT `+resource+`=$2::numeric FROM billing_export_usage WHERE team_id=$1),
 (SELECT `+resource+`=10 FROM team_billing_usage WHERE team_id=$1),
 (SELECT count(*) FROM billing_period_anomaly WHERE team_id=$1 AND resolved_at IS NULL AND kind='usage_after_export_freeze'),
 (SELECT count(*) FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1),
 (SELECT count(*) FROM billing_export_measurement_queue WHERE team_id=$1 AND pending)`, team.ID, quantity).Scan(&exact, &frozen, &count, &events, &pending)
					if err != nil || !exact || !frozen || count != anomalies || events != 0 || pending != 0 {
						t.Fatalf("quantity=%s exact=%v frozen=%v anomalies=%d want=%d events=%d pending=%d err=%v",
							quantity, exact, frozen, count, anomalies, events, pending, err)
					}
				}
				for _, quantity := range []string{"4.5", "5"} {
					exec(`UPDATE team_billing_usage_hourly SET `+resource+`=$2::numeric WHERE team_id=$1`, team.ID, quantity)
					exec(`UPDATE billing_export_measurement_queue SET pending=true WHERE team_id=$1`, team.ID)
					consume()
					want := "9"
					if quantity == "5" {
						want = "10"
					}
					check(want, 0)
					// Reprocessing identical contributions must not add coverage or anomalies.
					exec(`UPDATE billing_export_measurement_queue SET pending=true WHERE team_id=$1`, team.ID)
					consume()
					check(want, 0)
				}
				exec(`UPDATE team_billing_usage_hourly SET `+resource+`=5.000000001 WHERE team_id=$1 AND hour_start=$2`, team.ID, start)
				for i := 0; i < 2; i++ {
					exec(`UPDATE billing_export_measurement_queue SET pending=true WHERE team_id=$1 AND hour_start=$2`, team.ID, start)
					consume()
					check("10.000000001", 1)
				}
				if status == "exporting" {
					_, err := pool.Exec(ctx, `UPDATE team_billing_period SET status='exported' WHERE team_id=$1`, team.ID)
					if err == nil || !strings.Contains(err.Error(), "usage discrepancy requires reviewed correction") {
						t.Fatalf("true correction did not gate close: %v", err)
					}
				}
				actor := uuid.New()
				exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$3)`, actor, "example-admin-"+actor.String()+"@example.com", actor.String())
				exec(`UPDATE billing_period_anomaly SET resolved_at=now(),resolved_by=$2 WHERE team_id=$1`, team.ID, actor)
				exec(`UPDATE team_billing_usage_hourly SET `+resource+`=4 WHERE team_id=$1 AND hour_start=$2`, team.ID, start)
				exec(`UPDATE billing_export_measurement_queue SET pending=true WHERE team_id=$1 AND hour_start=$2`, team.ID, start)
				consume()
				check("9", 1)
			})
		}
	}
}

func testBoundaryStorageEnablement(t *testing.T, pool *pgxpool.Pool) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial-anchor=%v", initial), func(t *testing.T) {
			ctx := t.Context()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			anchor := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)
			boundary := anchor.AddDate(0, 1, 0)
			wantSlices := 2
			if initial {
				boundary = anchor
				wantSlices = 1
			}
			hour := boundary.Truncate(time.Hour)
			now := hour.Add(2 * time.Hour)
			h := &Handlers{Pool: pool, DB: db.New(pool), Now: func() time.Time { return now }}
			team, err := h.DB.CreateTeam(ctx, fmt.Sprintf("example-boundary-storage-%v", initial))
			if err != nil {
				t.Fatal(err)
			}
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_storage_billing_enabled',false)`, team.ID)
			exec(`INSERT INTO billing_export_work(team_id) VALUES($1)`, team.ID)
			sandbox := uuid.New()
			exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id)
 VALUES($1,$2,'example-boundary-storage','deleted',1,1024,'default')`, sandbox, team.ID)
			exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,1,1024,$3,$4,'deleted')`, sandbox, team.ID, hour, hour.Add(time.Hour))
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,1024,$3,$4,'deleted')`, sandbox, team.ID, hour, hour.Add(time.Hour))
			exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,3686400,3686400)`, team.ID, hour, hour.Add(time.Hour))
			measure := func(want int) {
				t.Helper()
				if complete, err := h.seedExportMeasurements(ctx, team.ID, anchor); err != nil || !complete {
					t.Fatalf("discovery: complete=%v err=%v", complete, err)
				}
				if n, err := h.consumeExportMeasurements(ctx, team.ID, anchor); err != nil || n != want {
					t.Fatalf("consumption: n=%d want=%d err=%v", n, want, err)
				}
			}
			check := func(storage, snapshot int) {
				t.Helper()
				var slices int
				var exact, consumed bool
				err := pool.QueryRow(ctx, `SELECT count(*),bool_and(vcpu_seconds=1800 AND memory_mib_seconds=1843200 AND storage_mib_seconds=$2)
 FROM billing_export_usage WHERE team_id=$1`, team.ID, storage).Scan(&slices, &exact)
				if err != nil || slices != wantSlices || !exact {
					t.Fatalf("period slices=%d want=%d exact=%v err=%v", slices, wantSlices, exact, err)
				}
				if err := pool.QueryRow(ctx, `SELECT NOT pending AND storage_mib_seconds=$2 FROM billing_export_measurement_queue
 WHERE team_id=$1 AND hour_start=$3`, team.ID, snapshot, hour).Scan(&consumed); err != nil || !consumed {
					t.Fatalf("consumed snapshot: %v %v", consumed, err)
				}
			}
			measure(1)
			check(0, 0)
			exec(`UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID)
			// Revisit unchanged source values through the paced correction sweep.
			now = now.Add(exportCorrectionPageInterval)
			measure(1)
			check(1843200, 3686400)
			exec(`UPDATE billing_export_measurement_queue SET pending=true WHERE team_id=$1`, team.ID)
			measure(1)
			check(1843200, 3686400)
			now = now.Add(exportCorrectionSweepInterval)
			measure(0)
			check(1843200, 3686400)

			p := billing.ExportPeriod{TeamID: team.ID, Start: boundary, End: boundary.AddDate(0, 1, 0)}
			store := billing.ExportStore{Pool: pool}
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, team.ID)
			if err := store.Enroll(ctx, p); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Reserve(ctx, p, "storage", "0.5", hour.Add(time.Hour), billing.ExportPayload{
				EventName: "storage_gib_hours", CustomerID: "cus_example", Timestamp: hour.Add(time.Hour).Add(-time.Second).Unix(),
			}); err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID)
			exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,storage_mib_seconds)
 VALUES($1,$2,$3,3686400)`, team.ID, hour.Add(time.Hour), hour.Add(2*time.Hour))
			exec(`INSERT INTO billing_export_measurement_queue(team_id,hour_start) VALUES($1,$2)`, team.ID, hour.Add(time.Hour))
			if n, err := h.consumeExportMeasurements(ctx, team.ID, anchor); err != nil || n != 1 {
				t.Fatalf("disabled full-hour consumption: n=%d err=%v", n, err)
			}
			var usage db.TeamBillingUsage
			if err := pool.QueryRow(ctx, `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_usage
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, p.Start, p.End).Scan(&usage.VcpuSeconds, &usage.MemoryMibSeconds, &usage.StorageMibSeconds); err != nil {
				t.Fatal(err)
			}
			quantity, err := billing.MeterUsageQuantity(usage.StorageMibSeconds, "storage_gib")
			if err != nil || quantity != "1.500000000000" {
				t.Fatalf("full-hour measured storage=%s err=%v", quantity, err)
			}
			for _, checkoutDisabled := range []bool{false, true} {
				resources := h.billingResourceStates(true)
				for i := range resources {
					if resources[i].ResourceKey == "storage_gib" {
						resources[i].Billable = checkoutDisabled
						resources[i].CheckoutEnabled = !checkoutDisabled
						resources[i].StripeEventName = "renamed_storage_hours"
					}
				}
				items, err := h.incrementalReconciliationItems(ctx, p, usage, resources)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, item := range items {
					if item.ResourceType == "storage" {
						found = true
						if _, err := h.observeIncrementalResource(ctx, p, item, hour.Add(2*time.Hour), pinnedMeterReader{t, "storage_gib_hours"}, "cus_example"); err != nil {
							t.Fatal(err)
						}
						if item.Quantity != "0.500000000000" {
							t.Fatalf("disabled storage target=%s, want reserved coverage", item.Quantity)
						}
					}
				}
				if !found {
					t.Fatal("disabled storage reservation missing from reconciliation")
				}
			}
		})
	}
}
