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
	// Earlier export and provider-retry fixtures may still be due. Isolate the
	// lease check to the one row whose deadline and lease this case controls.
	exec(`UPDATE billing_export_work SET next_run_at=now()+interval '1 day',next_reconcile_at=now()+interval '1 day' WHERE team_id=ANY($1::uuid[])`, teams)
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
	t.Run("precision-reconciliation", func(t *testing.T) {
		exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
		testMeterPrecisionWorker(t, pool)
	})
	t.Run("precision-growing-worker", func(t *testing.T) {
		exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
		testMeterGrowingDriftWorker(t, pool)
	})
	t.Run("precision-close", func(t *testing.T) {
		testMeterPrecisionClose(t, pool)
	})
	t.Run("frozen-measurement-catchup", func(t *testing.T) {
		testFrozenMeasurementCatchup(t, pool)
	})
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("older-period-failure/recovery=%v", recovery), func(t *testing.T) {
			exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
			testOlderPeriodFailure(t, pool, recovery)
		})
	}
	t.Run("period-attempt-fairness", func(t *testing.T) {
		exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity'`)
		testPeriodAttemptFairness(t, pool)
	})
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
	if !start.After(s.failedStart) {
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

func testPeriodAttemptFairness(t *testing.T, pool *pgxpool.Pool) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	current := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	anchor := current.AddDate(0, -3, 0)
	provider := &olderPeriodFailureStripe{failedStart: current.AddDate(0, -1, 0), failure: errors.New("example summary unavailable")}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-period-fairness")
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, "cus_example_"+team.ID.String(), anchor)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',false)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at,next_reconcile_at,seed_complete,next_correction_at)
 VALUES($1,now()-interval '100 years','infinity',true,$2)`, team.ID, now.Add(24*time.Hour))
	for _, start := range []time.Time{anchor, anchor.AddDate(0, 1, 0), anchor.AddDate(0, 2, 0), current} {
		end := start.AddDate(0, 1, 0)
		exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team.ID, start, end)
		exec(`INSERT INTO billing_incremental_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team.ID, start, end)
		exec(`INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,3600,0,0)`, team.ID, start, end)
	}
	wantErr := provider.failure
	for attempt := 0; attempt < 2; attempt++ {
		exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, team.ID)
		worked, measured, err := h.incrementalBillingTick(ctx, time.Hour)
		if !worked || measured != 0 || err == nil {
			t.Fatalf("tick: worked=%v measured=%d err=%v", worked, measured, err)
		}
		if attempt == 0 && len(provider.calls) != 0 {
			t.Fatalf("first batch unexpectedly submitted: %+v", provider.calls)
		}
		if attempt == 1 && (len(provider.calls) != 1 || provider.calls[0].Timestamp < current.Unix()) {
			t.Fatalf("later period starved behind failed periods: %+v", provider.calls)
		}
	}
	// Reconciliation has its own bounded queue and must also rotate on errors.
	for attempt := 0; attempt < 2; attempt++ {
		if err := h.reconcileIncrementalBillingTeam(ctx, team.ID); !errors.Is(err, wantErr) {
			t.Fatalf("reconcile: %v", err)
		}
	}
	var attempted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_incremental_period WHERE team_id=$1 AND last_reconcile_attempt_at IS NOT NULL`, team.ID).Scan(&attempted); err != nil || attempted != 4 {
		t.Fatalf("reconciliation skipped periods: attempted=%d err=%v", attempted, err)
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
		var delay float64
		if err := pool.QueryRow(ctx, `SELECT next_run_at,lease_token IS NULL AND lease_until IS NULL AND last_error IS NULL,
 extract(epoch FROM(next_run_at-now()))::float8 FROM billing_export_work WHERE team_id=$1`, team.ID).Scan(&next, &released, &delay); err != nil || !released {
			t.Fatalf("worker did not finish cleanly: released=%v err=%v", released, err)
		}
		if delay < cadence.Seconds()-60 || delay > cadence.Seconds()+60 {
			t.Fatalf("next run %s (delay %.1fs) does not follow cadence %s", next, delay, cadence)
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
			for _, mode := range []string{"unbillable", "checkout-disabled", "removed"} {
				resources := h.billingResourceStates(true)
				for i := range resources {
					if resources[i].ResourceKey == "storage_gib" {
						resources[i].Billable = mode == "checkout-disabled"
						resources[i].CheckoutEnabled = mode != "checkout-disabled"
						resources[i].StripeEventName = "renamed_storage_hours"
					}
				}
				if mode == "removed" {
					for i := range resources {
						if resources[i].ResourceKey == "storage_gib" {
							resources = append(resources[:i], resources[i+1:]...)
							break
						}
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

type precisionWorkerStripe struct {
	openPeriodStripe
	mode               string
	drift              *big.Rat
	activeMeter        string
	mappingErr         error
	attempts           []StripeReportMeterEventParams
	buckets, summaries int
	checkUnlocked      func(context.Context) error
	changeLocal        func()
}

func (s *precisionWorkerStripe) MeterID() string {
	if s.activeMeter != "" {
		return s.activeMeter
	}
	return "mtr_example_precision"
}

func (s *precisionWorkerStripe) ActiveMeterID(ctx context.Context, event string) (string, error) {
	if err := s.checkUnlocked(ctx); err != nil {
		return "", err
	}
	if s.mappingErr != nil {
		return "", s.mappingErr
	}
	return s.MeterID(), nil
}

func (s *precisionWorkerStripe) ReportMeterEvent(ctx context.Context, p StripeReportMeterEventParams) error {
	s.attempts = append(s.attempts, p)
	return s.openPeriodStripe.ReportMeterEvent(ctx, p)
}

func (s *precisionWorkerStripe) CountedMeterUsage(ctx context.Context, event, customer string, start, end time.Time) (string, error) {
	s.summaries++
	value, err := s.openPeriodStripe.CountedMeterUsage(ctx, event, customer, start, end)
	if err != nil {
		return "", err
	}
	total, _ := new(big.Rat).SetString(value)
	if total.Sign() == 0 {
		return value, nil
	}
	delta := big.NewRat(1, 1_000_000_000_000)
	if s.drift != nil {
		delta = new(big.Rat).Set(s.drift)
	}
	if s.mode == "exact" {
		delta = new(big.Rat)
	}
	if s.mode == "excess" {
		delta = big.NewRat(1, 1)
	}
	if s.mode == "changing_summary" && s.summaries%2 == 0 {
		delta = big.NewRat(0, 1)
	}
	total.Add(total, delta)
	if s.drift != nil {
		return total.FloatString(18), nil
	}
	return total.FloatString(12), nil
}

func (s *precisionWorkerStripe) BucketedMeterUsage(ctx context.Context, event, customer string, start, end time.Time) ([]meterUsageBucket, error) {
	s.buckets++
	if err := s.checkUnlocked(ctx); err != nil {
		return nil, err
	}
	if s.changeLocal != nil {
		change := s.changeLocal
		s.changeLocal = nil
		change()
	}
	if s.mode == "outage" {
		return nil, fmt.Errorf("example bucket outage")
	}
	windows, err := meterEvidenceWindows(start, end)
	if err != nil {
		return nil, err
	}
	for i := range windows {
		windows[i].Quantity, err = s.openPeriodStripe.CountedMeterUsage(ctx, event, customer, windows[i].Start, windows[i].End)
		if err != nil {
			return nil, err
		}
	}
	if s.mode == "missing" {
		// Empty intervals may be omitted, so remove a bucket with usage.
		for i, window := range windows {
			quantity, err := meterQuantity(window.Quantity)
			if err != nil {
				return nil, err
			}
			if quantity.Sign() > 0 {
				return append(windows[:i], windows[i+1:]...), nil
			}
		}
		return nil, fmt.Errorf("missing-bucket fixture requires nonzero usage")
	}
	if s.mode == "changing_bucket" && s.buckets%2 == 0 {
		windows[0].Quantity = "1"
	}
	return windows, nil
}

func testMeterPrecisionWorker(t *testing.T, pool *pgxpool.Pool) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-72 * time.Hour).Add(2 * time.Minute)
	end := start.AddDate(0, 1, 0)
	provider := &precisionWorkerStripe{checkUnlocked: func(ctx context.Context) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT team_id FROM team_billing_period FOR UPDATE NOWAIT`)
		return err
	}}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-precision-worker")
	if err != nil {
		t.Fatal(err)
	}
	customer := "cus_example_" + team.ID.String()
	p := billing.ExportPeriod{TeamID: team.ID, Start: start, End: end}
	store := billing.ExportStore{Pool: pool}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, start)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',true)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team.ID, start, end)
	if err := store.Enroll(ctx, p); err != nil {
		t.Fatal(err)
	}
	resources := map[string]string{"cpu": "cpu_vcpu_hours", "memory": "memory_gib_hours", "storage": "storage_gib_hours"}
	for resource, event := range resources {
		for part := 0; part < 2; part++ {
			_, err := store.Reserve(ctx, p, resource, "9712.454976049444", now.Add(-2*time.Hour), billing.ExportPayload{EventName: event, CustomerID: customer, Timestamp: now.Add(-2*time.Hour - time.Second).Unix()})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := h.submitIncrementalEvents(ctx, p, 6); err != nil {
		t.Fatal(err)
	}
	var historical []uuid.UUID
	rows, err := pool.Query(ctx, `SELECT id FROM billing_export_event WHERE customer_id=$1`, customer)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		historical = append(historical, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	snapshot := func() string {
		t.Helper()
		var value string
		err := pool.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(e.id,e.identifier,e.idempotency_key,e.event_name,e.customer_id,e.quantity_payload,e.event_timestamp,
 a.id,a.coverage_start,a.coverage_end,a.measured_through) ORDER BY e.id)::text
 FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE e.id=ANY($1)`, historical).Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	exec(`INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,9713.454976049444*3600,9713.454976049444*3686400,9713.454976049444*3686400)`, team.ID, start, end)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at,next_reconcile_at,seed_complete,next_correction_at)
 VALUES($1,now()-interval '100 years','infinity',true,now()+interval '1 day')`, team.ID)
	tick := func(t *testing.T, wantFailure bool) error {
		t.Helper()
		exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, team.ID)
		worked, n, err := h.incrementalBillingTick(ctx, time.Hour)
		if !worked || n != 0 || (err != nil) != wantFailure {
			t.Fatalf("precision worker: worked=%v measured=%d error=%v", worked, n, err)
		}
		var recorded bool
		if err := pool.QueryRow(ctx, `SELECT (last_error IS NOT NULL)=$2 AND lease_token IS NULL AND next_run_at>now() FROM billing_export_work WHERE team_id=$1`, team.ID, wantFailure).Scan(&recorded); err != nil || !recorded {
			t.Fatalf("worker error/retry state: %v %v", recorded, err)
		}
		return err
	}
	initialCalls := len(provider.calls)
	for _, mode := range []string{"excess", "missing", "outage", "changing_summary", "changing_bucket"} {
		provider.mode = mode
		provider.summaries = 0
		provider.buckets = 0
		tick(t, true)
		if len(provider.calls) != initialCalls {
			t.Fatalf("%s authorized export through incomplete evidence", mode)
		}
		var counted string
		if err := pool.QueryRow(ctx, `SELECT counted_quantity::text FROM billing_export_observation WHERE team_id=$1 AND resource_type='cpu'`, team.ID).Scan(&counted); err != nil {
			t.Fatal(err)
		}
		want := "9712.454976049445"
		if mode == "excess" {
			want = "9713.454976049444"
		}
		if counted != want {
			t.Fatalf("decision snapshot replaced by later read: %s want %s", counted, want)
		}
		if provider.buckets > 2 {
			t.Fatalf("fallback exceeded read budget: %d", provider.buckets)
		}
	}
	provider.mode = "complete"
	provider.buckets = 0
	tick(t, false)
	if len(provider.calls) != initialCalls+3 {
		t.Fatalf("catch-up events=%d want=%d", len(provider.calls), initialCalls+3)
	}
	for _, call := range provider.calls[initialCalls:] {
		if call.Value != "1.000000000000" {
			t.Fatalf("catch-up replayed coverage: %+v", call)
		}
	}
	if provider.buckets != 12 {
		t.Fatalf("two bucket reads per gate/observation/resource: %d", provider.buckets)
	}
	tick(t, false)
	if len(provider.calls) != initialCalls+3 {
		t.Fatal("unchanged retry resubmitted usage")
	}
	now = now.Add(time.Hour)
	exec(`UPDATE billing_export_usage SET vcpu_seconds=vcpu_seconds+3600,memory_mib_seconds=memory_mib_seconds+3686400,
 storage_mib_seconds=storage_mib_seconds+3686400,updated_at=clock_timestamp() WHERE team_id=$1`, team.ID)
	tick(t, false)
	if len(provider.calls) != initialCalls+6 {
		t.Fatal("later scheduled pass did not export exactly new usage")
	}
	for resource := range resources {
		totals, err := store.Totals(ctx, p, resource)
		if err != nil || totals.Reserved != "9714.454976049444" || totals.Submitted != totals.Reserved || totals.Pending != "0" {
			t.Fatalf("%s accounting: %+v %v", resource, totals, err)
		}
	}
	rows, err = pool.Query(ctx, `SELECT resource_type,local_quantity::text,submitted_quantity::text,
 reserved_quantity::text,counted_quantity::text,last_error IS NULL
 FROM billing_export_observation WHERE team_id=$1 ORDER BY resource_type`, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var observations int
	for rows.Next() {
		var resource, local, submitted, reserved, counted string
		var clear bool
		if err := rows.Scan(&resource, &local, &submitted, &reserved, &counted, &clear); err != nil {
			t.Fatal(err)
		}
		observations++
		if local != reserved || submitted != reserved || counted != "9714.454976049445" || !clear {
			t.Fatalf("%s observation: local=%s submitted=%s reserved=%s counted=%s clear=%v", resource, local, submitted, reserved, counted, clear)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if observations != len(resources) {
		t.Fatalf("observations=%d want=%d", observations, len(resources))
	}
	// A pending event whose reservation is now above measured usage must be
	// rejected before retry delivery. The existing event identity and payload
	// remain the only coverage; no replacement or provider call is allowed.
	if _, err := store.Reserve(ctx, p, "cpu", "9715.454976049444", now, billing.ExportPayload{
		EventName: resources["cpu"], CustomerID: customer, Timestamp: now.Add(-time.Second).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	var pendingID, pendingPayload string
	if err := pool.QueryRow(ctx, `SELECT e.id::text,e.quantity_payload FROM billing_export_event e
 JOIN billing_export_allocation a ON a.id=e.allocation_id
 WHERE a.team_id=$1 AND a.resource_type='cpu' AND e.status='pending'
 ORDER BY e.created_at DESC LIMIT 1`, team.ID).Scan(&pendingID, &pendingPayload); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_export_usage SET vcpu_seconds=9714.454976049444*3600 WHERE team_id=$1`, team.ID)
	provider.mode = "complete"
	callsBeforeDownward := len(provider.calls)
	tick(t, true)
	if len(provider.calls) != callsBeforeDownward {
		t.Fatal("downward correction delivered stale pending coverage")
	}
	var status, payload string
	if err := pool.QueryRow(ctx, `SELECT status,quantity_payload FROM billing_export_event WHERE id=$1::uuid`, pendingID).Scan(&status, &payload); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || payload != pendingPayload {
		t.Fatalf("pending event changed during downward correction: status=%s payload=%s", status, payload)
	}
	exec(`UPDATE billing_export_usage SET vcpu_seconds=9715.454976049444*3600 WHERE team_id=$1`, team.ID)
	tick(t, false)
	if len(provider.calls) != callsBeforeDownward+1 || provider.calls[len(provider.calls)-1].Value != "1.000000000000" {
		t.Fatalf("pending coverage was not retried after usage recovered: calls=%d", len(provider.calls)-callsBeforeDownward)
	}
	if snapshot() != before {
		t.Fatal("precision recovery mutated historical payload or coverage")
	}
	for index, delivery := range []string{"pending", "uncertain"} {
		t.Run("blocked-"+delivery, func(t *testing.T) {
			target := fmt.Sprintf("%d.454976049444", 9715+index)
			exec(`UPDATE billing_export_usage SET memory_mib_seconds=$2::numeric*3686400,updated_at=clock_timestamp() WHERE team_id=$1`, team.ID, target)
			event, err := store.Reserve(ctx, p, "memory", target, now, billing.ExportPayload{
				EventName: resources["memory"], CustomerID: customer, Timestamp: now.Add(-time.Second).Unix(),
			})
			if err != nil || event == nil {
				t.Fatalf("reserve retry coverage: event=%+v err=%v", event, err)
			}
			wantCall := StripeReportMeterEventParams{Identifier: event.Identifier, IdempotencyKey: event.IdempotencyKey,
				EventName: event.EventName, CustomerID: event.CustomerID, Value: event.Quantity, Timestamp: event.Timestamp}
			provider.mode = "exact"
			if delivery == "uncertain" {
				provider.submit = func(context.Context) error { return errors.New("example delivery timeout") }
				tick(t, false)
				provider.submit = nil
				if provider.attempts[len(provider.attempts)-1] != wantCall {
					t.Fatal("uncertain attempt changed reserved payload")
				}
				// Make the persisted retry due without waiting for wall-clock backoff.
				exec(`UPDATE billing_export_event SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, event.ID)
			}
			reservedSnapshot := meterPrecisionHistorySnapshot(t, pool, team.ID)
			attemptsBefore := len(provider.attempts)
			callsBefore := len(provider.calls)
			var retrySnapshot string
			if err := pool.QueryRow(ctx, `SELECT jsonb_build_array(status,attempt_count,first_attempt_at,next_attempt_at)::text
 FROM billing_export_event WHERE id=$1 AND status=$2`, event.ID, delivery).Scan(&retrySnapshot); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"missing", "excess"} {
				provider.mode = mode
				for attempt := 0; attempt < 2; attempt++ {
					provider.buckets, provider.summaries = 0, 0
					if err := tick(t, true); !errors.Is(err, billing.ErrExportRecoveryRequired) {
						t.Fatalf("%s did not block on reconciliation: %v", mode, err)
					}
					if len(provider.attempts) != attemptsBefore || len(provider.calls) != callsBefore || meterPrecisionHistorySnapshot(t, pool, team.ID) != reservedSnapshot {
						t.Fatalf("%s changed or delivered %s coverage", mode, delivery)
					}
					if provider.buckets > 2 || provider.summaries > 2 || (mode == "missing" && provider.buckets != 1) {
						t.Fatalf("%s evidence calls: buckets=%d summaries=%d", mode, provider.buckets, provider.summaries)
					}
					var unchanged, bounded bool
					if err := pool.QueryRow(ctx, `SELECT jsonb_build_array(status,attempt_count,first_attempt_at,next_attempt_at)::text=$2
 FROM billing_export_event WHERE id=$1`, event.ID, retrySnapshot).Scan(&unchanged); err != nil || !unchanged {
						t.Fatalf("blocked retry state changed: %v %v", unchanged, err)
					}
					if err := pool.QueryRow(ctx, `SELECT next_run_at>now() AND next_run_at<=now()+interval '11 minutes'
 AND lease_token IS NULL AND lease_until IS NULL AND last_error IS NOT NULL FROM billing_export_work WHERE team_id=$1`, team.ID).Scan(&bounded); err != nil || !bounded {
						t.Fatalf("blocked retry not bounded/released: %v %v", bounded, err)
					}
					totals, err := store.Totals(ctx, p, "memory")
					if err != nil || totals.Reserved != target || totals.Submitted != fmt.Sprintf("%d.454976049444", 9714+index) || totals.Pending != "1.000000000000" {
						t.Fatalf("blocked reservation: %+v %v", totals, err)
					}
				}
			}
			provider.mode = "exact"
			tick(t, false)
			tick(t, false)
			if len(provider.attempts) != attemptsBefore+1 || provider.attempts[attemptsBefore] != wantCall || len(provider.calls) != callsBefore+1 {
				t.Fatal("recovery did not retry exactly the original event once")
			}
			var eventCount int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_event WHERE customer_id=$1`, customer).Scan(&eventCount); err != nil || eventCount != callsBefore+1 {
				t.Fatalf("replacement events: count=%d want=%d err=%v", eventCount, callsBefore+1, err)
			}
			totals, err := store.Totals(ctx, p, "memory")
			if err != nil || totals.Reserved != target || totals.Submitted != target || totals.Pending != "0" || meterPrecisionHistorySnapshot(t, pool, team.ID) != reservedSnapshot {
				t.Fatalf("recovered accounting/history: %+v %v", totals, err)
			}
		})
	}
	if snapshot() != before {
		t.Fatal("blocked delivery recovery mutated historical payload or coverage")
	}
	provider.mode = "complete"
	// Full-period observation uses the same evidence policy without changing
	// events. The database independently checks close evidence applicability.
	exec(`INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 SELECT team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_usage WHERE team_id=$1`, team.ID)
	callsBeforeFrozen := len(provider.calls)
	if _, err := h.reconcileFrozenIncrementalPeriod(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(provider.calls) != callsBeforeFrozen || snapshot() != before {
		t.Fatal("frozen observation changed submitted history")
	}
	// A new local reservation during evidence collection must invalidate the
	// snapshot, even if provider bucket quantities remain unchanged.
	provider.changeLocal = func() {
		event, err := store.Reserve(ctx, p, "cpu", "9716.454976049444", now, billing.ExportPayload{EventName: resources["cpu"], CustomerID: customer, Timestamp: now.Add(-time.Second).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		if event == nil || event.Quantity != "1.000000000000" {
			t.Fatalf("concurrent reservation did not create one unit of new coverage: %+v", event)
		}
	}
	totals, err := store.Totals(ctx, p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	counted, err := provider.CountedMeterUsage(ctx, resources["cpu"], customer, start, now)
	if err != nil {
		t.Fatal(err)
	}
	decision := h.assessMeterSummary(ctx, p, incrementalExportItem{ResourceType: "cpu", EventName: resources["cpu"], Quantity: totals.Reserved}, now, provider, customer, counted, totals, nil)
	if decision.Err == nil || !strings.Contains(decision.Err.Error(), "local evidence changed") {
		t.Fatalf("concurrent reservation accepted: %+v", decision)
	}
	exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity' WHERE team_id=$1`, team.ID)
}

func testMeterGrowingDriftWorker(t *testing.T, pool *pgxpool.Pool) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-72 * time.Hour)
	end := start.AddDate(0, 1, 0)
	provider := &precisionWorkerStripe{mode: "complete", checkUnlocked: func(ctx context.Context) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT team_id FROM team_billing_period FOR UPDATE NOWAIT`)
		return err
	}}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-growing-drift")
	if err != nil {
		t.Fatal(err)
	}
	customer := "cus_example_" + team.ID.String()
	p := billing.ExportPeriod{TeamID: team.ID, Start: start, End: end}
	store := billing.ExportStore{Pool: pool}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, start)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',true)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team.ID, start, end)
	if err := store.Enroll(ctx, p); err != nil {
		t.Fatal(err)
	}
	for resource, event := range map[string]string{"cpu": "cpu_vcpu_hours", "memory": "memory_gib_hours", "storage": "storage_gib_hours"} {
		if _, err := store.Reserve(ctx, p, resource, "10000", now.Add(-time.Hour), billing.ExportPayload{
			EventName: event, CustomerID: customer, Timestamp: now.Add(-time.Hour - time.Second).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.submitIncrementalEvents(ctx, p, 6); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 VALUES($1,$2,$3,10000*3600::numeric,10000*3686400::numeric,10000*3686400::numeric)`, team.ID, start, end)
	exec(`INSERT INTO billing_export_work(team_id,next_run_at,next_reconcile_at,seed_complete,next_correction_at)
 VALUES($1,'infinity','infinity',true,now()+interval '1 day')`, team.ID)
	state := func() string {
		t.Helper()
		var snapshot string
		if err := pool.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(to_jsonb(a),to_jsonb(e)) ORDER BY a.id,e.id)::text
 FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id WHERE a.team_id=$1`, team.ID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	// Equal increments keep totals in one binade while a steadily growing
	// residual crosses its exact bound on the fourth scheduled export.
	for iteration := 1; iteration <= 4; iteration++ {
		now = now.Add(time.Hour)
		exec(`UPDATE billing_export_usage SET vcpu_seconds=vcpu_seconds+3600,memory_mib_seconds=memory_mib_seconds+3686400,
 storage_mib_seconds=storage_mib_seconds+3686400,updated_at=clock_timestamp() WHERE team_id=$1`, team.ID)
		provider.drift = big.NewRat(int64(iteration), 2_000_000_000_000)
		bound, err := meterPrecisionBound(big.NewRat(int64(10000+iteration-1), 1))
		if err != nil || (provider.drift.Cmp(bound) > 0) != (iteration == 4) {
			t.Fatalf("fixture does not cross bound on fourth export: %v", err)
		}
		before := state()
		attempts, calls := len(provider.attempts), len(provider.calls)
		for reread := 0; reread < 2; reread++ {
			provider.buckets = 0
			exec(`UPDATE billing_export_work SET next_run_at=now()-interval '100 years' WHERE team_id=$1`, team.ID)
			worked, measured, err := h.incrementalBillingTick(ctx, time.Hour)
			if !worked || measured != 0 {
				t.Fatalf("worker did not export persisted usage: worked=%v measured=%d", worked, measured)
			}
			if iteration == 4 {
				if !errors.Is(err, billing.ErrExportRecoveryRequired) {
					t.Fatalf("out-of-policy export did not require recovery: %v", err)
				}
				if state() != before || len(provider.attempts) != attempts || len(provider.calls) != calls {
					t.Fatal("out-of-policy export allocated, submitted, or changed accounting/delivery state")
				}
				var failed bool
				if err := pool.QueryRow(ctx, `SELECT last_error IS NOT NULL AND lease_token IS NULL AND next_run_at>now()
 FROM billing_export_work WHERE team_id=$1`, team.ID).Scan(&failed); err != nil || !failed {
					t.Fatalf("worker did not persist bounded recovery failure: %v %v", failed, err)
				}
			} else {
				if err != nil || len(provider.calls) != calls+3 || provider.buckets != 12 {
					t.Fatalf("corroborated iteration %d reread %d: calls=%d buckets=%d err=%v", iteration, reread, len(provider.calls)-calls, provider.buckets, err)
				}
				for _, call := range provider.calls[calls:] {
					if call.Value != "1.000000000000" {
						t.Fatalf("growing export replayed coverage: %+v", call)
					}
				}
			}
			want := fmt.Sprintf("%d.000000000000", 10000+min(iteration, 3))
			for _, resource := range []string{"cpu", "memory", "storage"} {
				totals, err := store.Totals(ctx, p, resource)
				if err != nil || totals.Reserved != want || totals.Submitted != want || totals.Pending != "0" {
					t.Fatalf("iteration %d %s accounting: %+v %v", iteration, resource, totals, err)
				}
			}
		}
	}
	exec(`UPDATE billing_export_work SET next_run_at='infinity',next_reconcile_at='infinity' WHERE team_id=$1`, team.ID)
}

func testMeterPrecisionClose(t *testing.T, pool *pgxpool.Pool) {
	ctx := t.Context()
	for _, total := range []string{"0.000000000001", "1", "8191.999999999999", "8192", "9712.454976049444", "1000000000"} {
		var value string
		if err := pool.QueryRow(ctx, `SELECT billing_meter_precision_bound($1::numeric)::text`, total).Scan(&value); err != nil {
			t.Fatal(err)
		}
		local, _ := meterDecimal(total)
		want, _ := meterPrecisionBound(local)
		got, ok := new(big.Rat).SetString(value)
		if !ok || got.Cmp(want) != 0 {
			t.Fatalf("SQL bound for %s = %s, want %s", total, value, want)
		}
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-72*time.Hour).AddDate(0, -2, 0)
	end := start.AddDate(0, 1, 0)
	provider := &precisionWorkerStripe{mode: "complete", checkUnlocked: func(ctx context.Context) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `SELECT team_id FROM team_billing_period FOR UPDATE NOWAIT`)
		return err
	}}
	h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
	team, err := h.DB.CreateTeam(ctx, "example-precision-close")
	if err != nil {
		t.Fatal(err)
	}
	customer := "cus_example_" + team.ID.String()
	p := billing.ExportPeriod{TeamID: team.ID, Start: start, End: end}
	store := billing.ExportStore{Pool: pool}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, start)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true),($1,'billing_storage_billing_enabled',true)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, team.ID)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, team.ID, start, end)
	if err := store.Enroll(ctx, p); err != nil {
		t.Fatal(err)
	}
	sandbox := uuid.New()
	exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id)
 VALUES($1,$2,'example-precision-close','deleted',100,102400,'default')`, sandbox, team.ID)
	exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,100,102400,$3,$4,'deleted')`, sandbox, team.ID, start, start.Add(100*time.Hour))
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,102400,$3,$4,'deleted')`, sandbox, team.ID, start, start.Add(100*time.Hour))
	for resource, event := range map[string]string{"cpu": "cpu_vcpu_hours", "memory": "memory_gib_hours", "storage": "storage_gib_hours"} {
		if _, err := store.Reserve(ctx, p, resource, "10000", end, billing.ExportPayload{
			EventName: event, CustomerID: customer, Timestamp: end.Add(-time.Second).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.submitIncrementalEvents(ctx, p, 6); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string { return meterPrecisionHistorySnapshot(t, pool, team.ID) }
	before := snapshot()
	assertHistory := func() {
		t.Helper()
		if snapshot() != before || len(provider.attempts) != 3 || len(provider.calls) != 3 {
			t.Fatal("close changed historical events/coverage or duplicated delivery")
		}
		for _, resource := range []string{"cpu", "memory", "storage"} {
			totals, err := store.Totals(ctx, p, resource)
			if err != nil || totals.Reserved != "10000" || totals.Submitted != totals.Reserved || totals.Pending != "0" {
				t.Fatalf("%s close accounting: %+v %v", resource, totals, err)
			}
		}
	}
	result, err := h.exportIncrementalPeriod(ctx, p)
	if err != nil || result.Status != "exported" {
		t.Fatalf("persistent drift close: %+v %v", result, err)
	}
	assertHistory()
	var evidenceCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_meter_reconciliation WHERE team_id=$1
 AND local_quantity=10000 AND reserved_quantity=10000 AND submitted_quantity=10000
 AND provider_quantity=10000.000000000001 AND difference=0.000000000001
 AND query_start=$2 AND query_end=$3`, team.ID, start, end).Scan(&evidenceCount); err != nil || evidenceCount != 3 {
		t.Fatalf("persistent raw residual history: count=%d err=%v", evidenceCount, err)
	}

	// A scope change after network evidence collection must also be rejected
	// before it can replace the latest observation.
	totals, err := store.Totals(ctx, p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	item := incrementalExportItem{ResourceType: "cpu", EventName: "cpu_vcpu_hours", Quantity: "10000"}
	counted, err := provider.CountedMeterUsage(ctx, item.EventName, customer, start, end)
	if err != nil {
		t.Fatal(err)
	}
	decision := h.assessMeterSummary(ctx, p, item, end, provider, customer, counted, totals, nil)
	if decision.Err != nil || decision.CloseEvidence == nil {
		t.Fatalf("collect close evidence: %+v", decision)
	}
	exec(`UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team.ID, "cus_changed_"+team.ID.String())
	if err := h.recordMeterObservation(ctx, p, item, end, totals, counted, nil, time.Now(), decision.CloseEvidence, provider.MeterID()); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("concurrent scope change persisted stale evidence: %v", err)
	}
	exec(`UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team.ID, customer)

	// Exercise the actual finalization transaction with bad evidence. Each
	// mutation rolls back, so the original immutable history remains intact.
	for _, mode := range []string{"missing", "stale", "wrong_scope", "wrong_meter", "wrong_snapshot", "wrong_policy", "wrong_window", "incomplete", "unstable", "excess", "provider_lag", "unresolved", "changed_accounting", "changed_customer", "old_writer", "boundary", "beyond_boundary", "mapping_missing", "mapping_expired"} {
		t.Run(mode, func(t *testing.T) {
			mapping, err := billing.RevalidateMeterCloseMapping(ctx, pool, p, h.ResolveActiveBillingMeter)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if mode != "mapping_missing" {
				if err := mapping.Bind(ctx, tx); err != nil {
					t.Fatal(err)
				}
			}
			// Disable only the history immutability trigger for fixture corruption.
			if _, err = tx.Exec(ctx, `ALTER TABLE billing_meter_reconciliation DISABLE TRIGGER billing_meter_reconciliation_immutable`); err != nil {
				t.Fatal(err)
			}
			var mutation string
			switch mode {
			case "mapping_missing", "mapping_expired":
				mutation = `SELECT $1::uuid`
				if mode == "mapping_expired" {
					if _, err := tx.Exec(ctx, `SELECT set_config('billing.close_meter_mapping',
 jsonb_set(current_setting('billing.close_meter_mapping')::jsonb,'{checked_at}',to_jsonb(clock_timestamp()-interval '31 seconds'))::text,true)`); err != nil {
						t.Fatal(err)
					}
				}
			case "missing":
				mutation = `DELETE FROM billing_meter_reconciliation WHERE team_id=$1`
			case "stale":
				mutation = `UPDATE billing_meter_reconciliation SET collected_at=now()-interval '3 hours' WHERE team_id=$1`
			case "wrong_scope":
				mutation = `UPDATE billing_meter_reconciliation SET customer_id='cus_wrong' WHERE team_id=$1`
			case "wrong_meter":
				mutation = `UPDATE billing_meter_reconciliation SET meter_id='mtr_old_precision' WHERE team_id=$1`
			case "wrong_snapshot":
				mutation = `UPDATE billing_meter_reconciliation SET accounting_snapshot='{}' WHERE team_id=$1`
			case "wrong_policy":
				mutation = `UPDATE billing_meter_reconciliation SET policy='unknown' WHERE team_id=$1`
			case "wrong_window":
				mutation = `UPDATE billing_meter_reconciliation SET query_start=query_start+interval '1 minute' WHERE team_id=$1`
			case "incomplete":
				mutation = `UPDATE billing_meter_reconciliation SET bucket_passes='[[],[]]' WHERE team_id=$1`
			case "unstable":
				mutation = `UPDATE billing_meter_reconciliation SET bucket_passes=jsonb_set(bucket_passes,'{1,0,quantity}','"1"') WHERE team_id=$1`
			case "excess":
				mutation = `UPDATE billing_export_observation SET counted_quantity=local_quantity+1 WHERE team_id=$1`
			case "provider_lag":
				mutation = `UPDATE billing_export_observation SET counted_quantity=local_quantity-0.000000000001 WHERE team_id=$1`
			case "unresolved":
				mutation = `UPDATE billing_export_event SET status='uncertain',updated_at=now() WHERE allocation_id IN (SELECT id FROM billing_export_allocation WHERE team_id=$1)`
			case "changed_accounting":
				mutation = `UPDATE billing_export_event SET updated_at=clock_timestamp() WHERE allocation_id IN (SELECT id FROM billing_export_allocation WHERE team_id=$1)`
			case "changed_customer":
				mutation = `UPDATE team_billing_account SET stripe_customer_id='cus_changed_precision' WHERE team_id=$1`
			case "old_writer":
				mutation = `UPDATE billing_export_observation SET observed_at=now() WHERE team_id=$1`
			}
			if mode == "boundary" || mode == "beyond_boundary" {
				factor := 1
				if mode == "beyond_boundary" {
					factor = 2
				}
				if _, err = tx.Exec(ctx, `UPDATE billing_meter_reconciliation SET
 difference=billing_meter_precision_bound(reserved_quantity)*$2,
 provider_quantity=reserved_quantity+billing_meter_precision_bound(reserved_quantity)*$2 WHERE team_id=$1`, team.ID, factor); err != nil {
					t.Fatal(err)
				}
				mutation = `UPDATE billing_export_observation o SET counted_quantity=e.provider_quantity
 FROM billing_meter_reconciliation e WHERE o.team_id=$1 AND e.team_id=o.team_id
 AND e.period_start=o.period_start AND e.period_end=o.period_end AND e.resource_type=o.resource_type AND e.observed_at=o.observed_at`
			}
			if _, err = tx.Exec(ctx, mutation, team.ID); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `UPDATE team_billing_period SET status='finalized',finalized_at=now(),
 gross_charges_usd=0,credits_applied_usd=0,net_invoice_amount_usd=0
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end)
			if mode == "boundary" {
				if err != nil {
					t.Fatalf("exact inclusive precision boundary blocked: %v", err)
				}
			} else {
				want := "incremental export requires fresh matching Stripe reconciliation"
				if mode == "unresolved" {
					want = "incremental export has unresolved events"
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("%s evidence did not fail at reconciliation guard: %v", mode, err)
				}
			}
		})
	}
	// Mapping changes happen after evidence is stored, independently of both
	// historical meter IDs. Neither missing readers nor outages may bypass it.
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, start, end); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("missing current mapping reader authorized close: %v", err)
	}
	provider.mappingErr = errors.New("example mapping outage")
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, start, end, h.ResolveActiveBillingMeter); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("mapping outage authorized close: %v", err)
	}
	provider.mappingErr = nil
	var oldEvidence string
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(e) ORDER BY id)::text FROM billing_meter_reconciliation e WHERE team_id=$1`, team.ID).Scan(&oldEvidence); err != nil {
		t.Fatal(err)
	}
	provider.activeMeter = "mtr_example_remapped"
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, start, end, h.ResolveActiveBillingMeter); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("remap after evidence collection authorized finalization: %v", err)
	}
	var stillExported bool
	if err := pool.QueryRow(ctx, `SELECT status='exported' AND finalized_at IS NULL FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end).Scan(&stillExported); err != nil || !stillExported {
		t.Fatalf("blocked remap changed period: %v %v", stillExported, err)
	}
	assertHistory()
	if _, err := h.reconcileFrozenIncrementalPeriod(ctx, p); err != nil {
		t.Fatalf("fresh remapped evidence: %v", err)
	}
	var retainedEvidence string
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(e) ORDER BY id)::text FROM billing_meter_reconciliation e WHERE team_id=$1 AND meter_id='mtr_example_precision'`, team.ID).Scan(&retainedEvidence); err != nil || retainedEvidence != oldEvidence {
		t.Fatalf("remap rewrote historical evidence: %v", err)
	}
	t.Run("observation-replaced-during-mapping", func(t *testing.T) {
		var evidenceIDs []uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT array_agg(id) FROM billing_meter_reconciliation
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end).Scan(&evidenceIDs); err != nil {
			t.Fatal(err)
		}
		lookupCalls := 0
		resolve := func(ctx context.Context, eventName string) (string, error) {
			lookupCalls++
			if lookupCalls == 1 {
				// The mapping query has captured the old IDs before this callback.
				if _, err := h.reconcileFrozenIncrementalPeriod(ctx, p); err != nil {
					t.Fatalf("replace observations with valid evidence: %v", err)
				}
			}
			return h.ResolveActiveBillingMeter(ctx, eventName)
		}
		_, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, start, end, resolve)
		if err == nil || !strings.Contains(err.Error(), "incremental export requires fresh matching Stripe reconciliation") {
			t.Fatalf("mapping bound to replaced evidence did not fail at reconciliation guard: %v", err)
		}
		if lookupCalls != 3 {
			t.Fatalf("active meter lookups=%d, want 3", lookupCalls)
		}
		var replaced int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_export_observation o
 JOIN billing_meter_reconciliation e USING(team_id,period_start,period_end,resource_type,observed_at)
 WHERE o.team_id=$1 AND o.period_start=$2 AND o.period_end=$3 AND e.id<>ALL($4::uuid[])`, team.ID, start, end, evidenceIDs).Scan(&replaced); err != nil || replaced != 3 {
			t.Fatalf("replacement observations: count=%d err=%v", replaced, err)
		}
		if err := pool.QueryRow(ctx, `SELECT status='exported' AND finalized_at IS NULL FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end).Scan(&stillExported); err != nil || !stillExported {
			t.Fatalf("replaced evidence changed period: %v %v", stillExported, err)
		}
		assertHistory()
	})
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, start, end, h.ResolveActiveBillingMeter); err != nil {
			t.Fatalf("persistent drift finalization: %v", err)
		}
		assertHistory()
	}
	var finalized bool
	if err := pool.QueryRow(ctx, `SELECT status='finalized' AND exported_at IS NOT NULL AND finalized_at IS NOT NULL
 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end).Scan(&finalized); err != nil || !finalized {
		t.Fatalf("persistent drift finalized=%v err=%v", finalized, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE billing_meter_reconciliation SET policy=policy WHERE team_id=$1`, team.ID); err == nil {
		t.Fatal("reconciliation history is mutable")
	}
	testMeterEvidenceEventBudgetDatabase(t, pool)

	// The following commercial period starts from zero coverage, obtains its
	// own evidence, and closes with its own persistent residual.
	second := billing.ExportPeriod{TeamID: team.ID, Start: end, End: end.AddDate(0, 1, 0)}
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, team.ID, second.Start, second.End)
	if err := store.Enroll(ctx, second); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,100,102400,$3,$4,'deleted')`, sandbox, team.ID, second.Start, second.Start.Add(200*time.Hour))
	exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
 VALUES($1,$2,102400,$3,$4,'deleted')`, sandbox, team.ID, second.Start, second.Start.Add(200*time.Hour))
	for resource, event := range map[string]string{"cpu": "cpu_vcpu_hours", "memory": "memory_gib_hours", "storage": "storage_gib_hours"} {
		totals, err := store.Totals(ctx, second, resource)
		if err != nil || totals.Reserved != "0" {
			t.Fatalf("prior residual became opening coverage: %+v %v", totals, err)
		}
		if _, err := store.Reserve(ctx, second, resource, "20000", second.End, billing.ExportPayload{
			EventName: event, CustomerID: customer, Timestamp: second.End.Add(-time.Second).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.submitIncrementalEvents(ctx, second, 6); err != nil {
		t.Fatal(err)
	}
	// The first period's evidence must not authorize a later period. Before
	// collecting second-period evidence, the close trigger must reject an
	// attempted export rather than selecting the retained prior history.
	if _, err := pool.Exec(ctx, `UPDATE team_billing_period SET status='exported',exported_at=now()
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, second.Start, second.End); err == nil {
		t.Fatal("prior-period reconciliation evidence authorized second-period close")
	}
	beforeSecondClose := snapshot()
	if _, err := h.exportIncrementalPeriod(ctx, second); err != nil {
		t.Fatalf("independent second close: %v", err)
	}
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, pool, team.ID, second.Start, second.End, h.ResolveActiveBillingMeter); err != nil {
		t.Fatalf("independent second finalization: %v", err)
	}
	if beforeSecondClose != snapshot() || len(provider.attempts) != 6 {
		t.Fatal("following period changed or replayed historical usage")
	}
	var retained, independent int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE period_start=$2 AND local_quantity=10000 AND difference=0.000000000001),
 count(*) FILTER (WHERE period_start=$3 AND local_quantity=20000 AND difference=0.000000000001)
 FROM billing_meter_reconciliation WHERE team_id=$1`, team.ID, start, second.Start).Scan(&retained, &independent); err != nil || retained != 9 || independent != 3 {
		t.Fatalf("independent retained period evidence: first=%d second=%d err=%v", retained, independent, err)
	}
}

func testMeterEvidenceEventBudgetDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("event-budget-%d", count), func(t *testing.T) {
			ctx := t.Context()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Truncate(time.Hour)
			start := now.Add(-72*time.Hour).AddDate(0, -2, 0)
			end := start.AddDate(0, 1, 0)
			team, err := db.New(pool).CreateTeam(ctx, fmt.Sprintf("example-meter-event-budget-%d", count))
			if err != nil {
				t.Fatal(err)
			}
			customer := "cus_example_" + team.ID.String()
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,commercial_billing_anchor)
 VALUES($1,$2,'active',$3)`, team.ID, customer, start)
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)
 ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team.ID)
			exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, team.ID, start, end)
			p := billing.ExportPeriod{TeamID: team.ID, Start: start, End: end}
			store := billing.ExportStore{Pool: pool}
			if err := store.Enroll(ctx, p); err != nil {
				t.Fatal(err)
			}
			// Start after measurement has frozen so a rejected export cannot
			// legitimately change the period or its measurement snapshot.
			exec(`INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds)
 VALUES($1,$2,$3,$4::numeric*3600)`, team.ID, start, end, count)
			exec(`UPDATE team_billing_period SET status='exporting' WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end)

			timestamp := end.Add(-2 * time.Minute).Unix()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `ALTER TABLE billing_export_allocation DISABLE TRIGGER billing_export_allocation_validate`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO billing_export_allocation
 (team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through)
 SELECT $1,$2,$3,'cpu',(n-1)::numeric,n::numeric,$3
 FROM generate_series(1,$4::integer) AS n`, team.ID, start, end, count); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `ALTER TABLE billing_export_allocation ENABLE TRIGGER billing_export_allocation_validate`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO billing_export_event
 (id,allocation_id,identifier,idempotency_key,event_name,customer_id,quantity,quantity_payload,
  event_timestamp,source,status)
 SELECT gen_random_uuid(),a.id,$5||a.coverage_start::text,
        $5||a.coverage_start::text,'cpu_vcpu_hours',$2,1,'1',$6,'export','submitted'
 FROM billing_export_allocation a
 WHERE a.team_id=$1 AND a.period_start=$4 AND a.period_end=$3
   AND a.resource_type='cpu' ORDER BY a.coverage_start`, team.ID, customer, end, start, "meter-budget-"+team.ID.String()+"-", timestamp); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			provider := &precisionWorkerStripe{
				mode: "complete", drift: big.NewRat(1, 10_000_000_000_000),
				checkUnlocked: func(context.Context) error { return nil },
			}
			for i := 0; i < count; i++ {
				provider.calls = append(provider.calls, StripeReportMeterEventParams{
					EventName: "cpu_vcpu_hours", CustomerID: customer, Value: "1", Timestamp: timestamp,
				})
			}
			h := &Handlers{Pool: pool, DB: db.New(pool), Stripe: provider, Now: func() time.Time { return now }}
			quantity := fmt.Sprint(count)
			counted, err := provider.CountedMeterUsage(ctx, "cpu_vcpu_hours", customer, start, end)
			if err != nil {
				t.Fatal(err)
			}
			numeric, needsEvidence := compareMeterSummary(counted, quantity)
			if !needsEvidence || numeric.Outcome != "incomplete" || numeric.Difference != provider.drift.RatString() {
				t.Fatalf("fixture did not reach evidence gate: %+v", numeric)
			}
			var withinBound bool
			if err := pool.QueryRow(ctx, `SELECT $1::numeric>0 AND $1::numeric<=billing_meter_precision_bound($2::numeric)`, "0.0000000000001", quantity).Scan(&withinBound); err != nil || !withinBound {
				t.Fatalf("fixture residual exceeds SQL policy: %v %v", withinBound, err)
			}
			events, err := h.meterLocalEvidence(ctx, p, "cpu")
			if count == 4096 {
				if err != nil || len(events) != count {
					t.Fatalf("at-limit local evidence: events=%d err=%v", len(events), err)
				}
			} else if err == nil || err.Error() != "local meter evidence exceeds event budget" || events != nil {
				t.Fatalf("over-limit local evidence: events=%d err=%v", len(events), err)
			}

			// Seed complete evidence even for the over-limit inventory. This
			// unbounded test-only snapshot differs from the production query
			// solely in its inventory limit, so missing evidence cannot mask it.
			var fullSnapshot string
			var collected time.Time
			if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'events',(SELECT jsonb_agg(jsonb_build_array(a.id,a.coverage_start,a.coverage_end,a.measured_through,a.correction_id,
 e.id,e.accounting_sequence,e.active,e.status,e.event_name,e.customer_id,e.quantity_payload,
 e.event_timestamp,e.updated_at,e.recovery_outcome,e.recovery_evidence) ORDER BY a.coverage_end,e.id)
 FROM billing_export_allocation a LEFT JOIN billing_export_event e ON e.allocation_id=a.id
 WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resource_type='cpu'),
 'correction_version',(SELECT correction_version FROM billing_incremental_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3),
 'measurement',(SELECT jsonb_build_array(vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
 FROM team_billing_usage WHERE team_id=$1 AND period_start=$2 AND period_end=$3),
 'customer',(SELECT stripe_customer_id FROM team_billing_account WHERE team_id=$1))::text,clock_timestamp()`, team.ID, start, end).Scan(&fullSnapshot, &collected); err != nil {
				t.Fatal(err)
			}
			var boundedSnapshot *string
			if err := pool.QueryRow(ctx, `SELECT billing_meter_accounting_snapshot($1,$2,$3,'cpu')::text`, team.ID, start, end).Scan(&boundedSnapshot); err != nil {
				t.Fatal(err)
			}
			if count == 4096 {
				if boundedSnapshot == nil || *boundedSnapshot != fullSnapshot {
					t.Fatal("at-limit SQL snapshot is incomplete or differs from full inventory")
				}
			} else if boundedSnapshot != nil {
				t.Fatal("over-limit SQL snapshot is not NULL")
			}
			evidence := meterCloseEvidence{
				MeterID: provider.MeterID(), EventName: "cpu_vcpu_hours", Customer: customer,
				Snapshot: fullSnapshot, CollectedAt: collected,
			}
			for pass := 0; pass < 2; pass++ {
				buckets, err := provider.BucketedMeterUsage(ctx, evidence.EventName, customer, start, end)
				if err != nil {
					t.Fatal(err)
				}
				for _, bucket := range buckets {
					want := new(big.Rat)
					if timestamp >= bucket.Start.Unix() && timestamp < bucket.End.Unix() {
						want.SetInt64(int64(count))
					}
					got, err := meterDecimal(bucket.Quantity)
					if err != nil || got.Cmp(want) != 0 {
						t.Fatalf("provider pass %d does not match persisted events: %+v %v", pass, bucket, err)
					}
				}
				evidence.Passes = append(evidence.Passes, completeMeterBuckets(buckets, start, end))
			}
			item := incrementalExportItem{ResourceType: "cpu", EventName: evidence.EventName, Quantity: quantity}
			totals, err := store.Totals(ctx, p, "cpu")
			if err != nil {
				t.Fatal(err)
			}
			for _, through := range []time.Time{end.Add(-time.Minute), end} {
				decision := h.assessMeterSummary(ctx, p, item, through, provider, customer, counted, totals, nil)
				if count == 4096 {
					if decision.Err != nil || decision.Outcome != "explained_precision" {
						t.Fatalf("at-limit export decision: %+v", decision)
					}
				} else {
					want := "local meter evidence exceeds event budget"
					if through.Equal(end) {
						want = "incomplete bounded accounting snapshot"
					}
					if !errors.Is(decision.Err, billing.ErrExportRecoveryRequired) || decision.Outcome != "incomplete" || !strings.Contains(decision.Err.Error(), want) || decision.CloseEvidence != nil {
						t.Fatalf("over-limit export rejected for wrong reason: %+v", decision)
					}
				}
			}
			exec(`INSERT INTO billing_export_observation
 (team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,
 counted_quantity,query_start,query_end,meter_id)
 VALUES($1,$2,$3,'cpu',$4,$4,$4,$5,$2,$3,$6)`, team.ID, start, end, quantity, counted, provider.MeterID())
			tx, err = pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err := persistMeterCloseEvidence(ctx, tx, p, "cpu", evidence); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			state := func() string {
				t.Helper()
				var value string
				if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'allocations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM billing_export_allocation a WHERE team_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM billing_export_event e
 JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1),
 'periods',(SELECT jsonb_agg(to_jsonb(p) ORDER BY period_start) FROM team_billing_period p WHERE team_id=$1),
 'incremental',(SELECT jsonb_agg(to_jsonb(p) ORDER BY period_start) FROM billing_incremental_period p WHERE team_id=$1),
 'usage',(SELECT jsonb_agg(to_jsonb(u) ORDER BY period_start) FROM team_billing_usage u WHERE team_id=$1),
 'export_usage',(SELECT jsonb_agg(to_jsonb(u) ORDER BY period_start) FROM billing_export_usage u WHERE team_id=$1),
 'history',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM billing_meter_reconciliation r WHERE team_id=$1))::text`, team.ID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := state()
			mapping, err := billing.RevalidateMeterCloseMapping(ctx, pool, p, h.ResolveActiveBillingMeter)
			if err != nil {
				t.Fatal(err)
			}
			tx, err = pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err := mapping.Bind(ctx, tx); err != nil {
				t.Fatal(err)
			}
			var mapped bool
			if err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(
 current_setting('billing.close_meter_mapping')::jsonb->'meters'->>r.id::text=r.meter_id)
 FROM billing_meter_reconciliation r WHERE team_id=$1`, team.ID).Scan(&mapped); err != nil || !mapped {
				t.Fatalf("close fixture lacks current evidence mapping: %v %v", mapped, err)
			}
			var matches bool
			if err := tx.QueryRow(ctx, `SELECT billing_meter_close_evidence_matches(o) FROM billing_export_observation o
 WHERE team_id=$1 AND resource_type='cpu'`, team.ID).Scan(&matches); err != nil || matches != (count == 4096) {
				t.Fatalf("close evidence applicability: matches=%v err=%v", matches, err)
			}
			_, closeErr := tx.Exec(ctx, `UPDATE team_billing_period SET status='exported',exported_at=now()
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team.ID, start, end)
			if count == 4096 {
				if closeErr != nil {
					t.Fatalf("at-limit database close: %v", closeErr)
				}
			} else if closeErr == nil || !strings.Contains(closeErr.Error(), "incremental export requires fresh matching Stripe reconciliation") {
				t.Fatalf("over-limit close rejected for wrong reason: %v", closeErr)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if state() != before {
				t.Fatal("close attempt changed accounting, payloads, coverage, period or history")
			}

			result, exportErr := h.exportIncrementalPeriod(ctx, p)
			if count == 4096 {
				if exportErr != nil || result.Status != "exported" {
					t.Fatalf("at-limit actual export/close: %+v %v", result, exportErr)
				}
			} else {
				if !errors.Is(exportErr, billing.ErrExportRecoveryRequired) || !strings.Contains(exportErr.Error(), "incomplete bounded accounting snapshot") {
					t.Fatalf("over-limit actual export rejected for wrong reason: %+v %v", result, exportErr)
				}
				if state() != before {
					t.Fatal("rejected export changed accounting, payloads, coverage, period or history")
				}
			}
			if len(provider.attempts) != 0 || len(provider.calls) != count {
				t.Fatal("event-budget decision replayed historical usage")
			}
		})
	}
}

func meterPrecisionHistorySnapshot(t *testing.T, pool *pgxpool.Pool, team uuid.UUID) string {
	t.Helper()
	var value string
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_agg(jsonb_build_array(e.id,e.identifier,e.idempotency_key,e.event_name,e.customer_id,e.quantity,e.quantity_payload,e.event_timestamp,
 a.id,a.coverage_start,a.coverage_end,a.measured_through) ORDER BY e.id)::text
 FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1`, team).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
