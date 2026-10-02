//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_BillingRollupCompletenessDoesNotExhaustAttempts(t *testing.T) {
	const maxAttempts = 3
	for _, admissionBusy := range []bool{false, true} {
		for _, priorFailures := range []int{0, maxAttempts - 1} {
			t.Run(fmt.Sprintf("admission_busy_%t/prior_failures_%d", admissionBusy, priorFailures), func(t *testing.T) {
				ctx := t.Context()
				fixture := newStorageReportFixture(t, "active", false)
				teamID := sandboxTeamID(t, fixture.sandboxID)
				if _, err := testPool.Exec(ctx, `
				INSERT INTO team_feature_flag(team_id, key, enabled)
				VALUES ($1, 'billing_hourly_rollups', true)
				ON CONFLICT (team_id, key) DO UPDATE SET enabled=true`, teamID); err != nil {
					t.Fatalf("enable hourly rollups: %v", err)
				}

				// Give this worker a private queue while exercising the real report
				// completeness gate and hourly usage query against the fixture.
				poolConfig := testPool.Config()
				poolConfig.MaxConns = 1
				poolConfig.MinConns = 0
				pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
				if err != nil {
					t.Fatalf("create isolated rollup pool: %v", err)
				}
				t.Cleanup(pool.Close)
				if _, err := pool.Exec(ctx, `CREATE TEMP TABLE billing_rollup_job
				(LIKE public.billing_rollup_job INCLUDING ALL)`); err != nil {
					t.Fatalf("create private rollup queue: %v", err)
				}

				reportID := uuid.New()
				var receivedAt time.Time
				var releaseReceipt func()
				if admissionBusy {
					tx, err := testPool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, fixture.hostID); err != nil {
						t.Fatal(err)
					}
					if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&receivedAt); err != nil {
						t.Fatal(err)
					}
					releaseReceipt = func() {
						if err := tx.Commit(ctx); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					if err := testPool.QueryRow(ctx, `
				INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, payload, next_attempt_at)
				VALUES ($1, $2::uuid, $3, 1, '[]'::jsonb, now()+interval '1 hour')
				RETURNING received_at`, fixture.hostID, fixture.incarnation, reportID).Scan(&receivedAt); err != nil {
						t.Fatalf("insert unresolved report: %v", err)
					}
					releaseReceipt = func() {
						if _, err := testPool.Exec(ctx, `UPDATE host_storage_report
						SET state='processed', payload=NULL, processed_at=now() WHERE report_id=$1`, reportID); err != nil {
							t.Fatalf("resolve storage report: %v", err)
						}
					}
				}
				hourStart := receivedAt.UTC().Truncate(time.Hour)
				var jobID uuid.UUID
				if err := pool.QueryRow(ctx, `
				INSERT INTO billing_rollup_job(team_id, hour_start, hour_end, status, attempt_count)
				VALUES ($1, $2, $3, 'failed', $4) RETURNING id`,
					teamID, hourStart, hourStart.Add(time.Hour), priorFailures).Scan(&jobID); err != nil {
					t.Fatalf("insert rollup job: %v", err)
				}
				cfg := billing.HourlyRollupConfig{BatchSize: 1, MaxAttempts: maxAttempts, LockDuration: time.Minute}
				q := db.New(pool)
				for i := 0; i < maxAttempts*2; i++ {
					if _, err := pool.Exec(ctx, `UPDATE billing_rollup_job SET next_attempt_at=now() WHERE id=$1`, jobID); err != nil {
						t.Fatalf("make deferred job due: %v", err)
					}
					billing.ProcessJobsForTest(ctx, pool, q, cfg, "completeness-worker")
					var status, lastError string
					var attempts int
					if err := pool.QueryRow(ctx, `SELECT status, attempt_count, COALESCE(last_error,'')
					FROM billing_rollup_job WHERE id=$1`, jobID).Scan(&status, &attempts, &lastError); err != nil {
						t.Fatalf("read deferred rollup: %v", err)
					}
					if status != "pending" || attempts != priorFailures || lastError != "storage reports incomplete" {
						t.Fatalf("deferral %d: status=%s attempts=%d error=%q; want pending with %d prior failures",
							i+1, status, attempts, lastError, priorFailures)
					}
				}

				releaseReceipt()
				if _, err := pool.Exec(ctx, `UPDATE billing_rollup_job SET next_attempt_at=now() WHERE id=$1`, jobID); err != nil {
					t.Fatalf("make recovered job due: %v", err)
				}
				billing.ProcessJobsForTest(ctx, pool, q, cfg, "completeness-worker")
				var status string
				var attempts int
				if err := pool.QueryRow(ctx, `SELECT status, attempt_count FROM billing_rollup_job WHERE id=$1`, jobID).Scan(&status, &attempts); err != nil {
					t.Fatalf("read recovered rollup: %v", err)
				}
				if status != "completed" || attempts != priorFailures+1 {
					t.Fatalf("recovered rollup status=%s attempts=%d; want completed with %d attempts", status, attempts, priorFailures+1)
				}
				var rolledUp bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_usage_hourly WHERE team_id=$1 AND hour_start=$2)`, teamID, hourStart).Scan(&rolledUp); err != nil {
					t.Fatalf("read recovered hourly usage: %v", err)
				}
				if !rolledUp {
					t.Fatal("recovered job did not persist hourly usage")
				}
			})
		}
	}
}
