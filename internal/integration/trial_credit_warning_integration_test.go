//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestRecentTrialBurnSampleClampsOverlappingIntervals(t *testing.T) {
	for _, resource := range []string{"compute", "storage"} {
		for _, tc := range []struct {
			name        string
			endHoursAgo int
			intervals   int
			wantSeconds float64
		}{
			{name: "open", wantSeconds: 21600},
			{name: "closed inside window", endHoursAgo: 1, wantSeconds: 18000},
			{name: "ended at boundary", endHoursAgo: 6},
			{name: "ended before boundary", endHoursAgo: 7},
			{name: "large open fleet", intervals: 256, wantSeconds: 21600},
			{name: "large closed fleet", intervals: 256, endHoursAgo: 1, wantSeconds: 18000},
			{name: "oversized open fleet", intervals: 1025},
			{name: "oversized closed fleet", intervals: 1025, endHoursAgo: 1},
		} {
			t.Run(resource+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				teamID := mustCreateTeam(t, ctx, "trial-overlap-"+uuid.NewString()[:8])
				backdateWarningSampleGrant(t, teamID)
				tx, err := testPool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				// Transaction time fixes the window boundary and interval endpoints.
				var now time.Time
				if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				planKey := "trial-overlap-" + uuid.NewString()
				if _, err := tx.Exec(ctx, `INSERT INTO pricing_plan (key, name, currency, active)
					VALUES ($1, 'Trial test pricing', 'USD', true)`, planKey); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
					VALUES ($1, 'vcpu', 'second', 1, now() - interval '1 day'),
					       ($1, 'storage_gib', 'second', 1, now() - interval '1 day')`, planKey); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
					VALUES ($1, $2, now() - interval '1 day')`, teamID, planKey); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO team_feature_flag (team_id, key, enabled)
					VALUES ($1, 'billing_storage_billing_enabled', true)
					ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled`, teamID); err != nil {
					t.Fatal(err)
				}
				var endedAt *time.Time
				if tc.endHoursAgo > 0 {
					end := now.Add(-time.Duration(tc.endHoursAgo) * time.Hour)
					endedAt = &end
				}
				intervals := tc.intervals
				if intervals == 0 {
					intervals = 1
				}
				if _, err := tx.Exec(ctx, `UPDATE team SET max_sandboxes = $2 WHERE id = $1`, teamID, intervals); err != nil {
					t.Fatalf("set fleet sandbox quota: %v", err)
				}
				fleet := `WITH fleet AS (
					INSERT INTO sandbox (id, team_id, name, status, host_id)
					SELECT gen_random_uuid(), $2, 'trial-overlap', 'active', $1
					FROM generate_series(1, $5::int)
					RETURNING id, team_id
				) `
				query := fleet + `INSERT INTO sandbox_compute_billing_interval
					(sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
					SELECT id, team_id, 1, 1, $3, $4, CASE WHEN $4::timestamptz IS NULL THEN NULL ELSE 'paused' END FROM fleet`
				if resource == "storage" {
					query = fleet + `INSERT INTO sandbox_storage_interval
						(sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason)
						SELECT id, team_id, 1024, $3, $4, CASE WHEN $4::timestamptz IS NULL THEN NULL ELSE 'deleted' END FROM fleet`
				}
				if _, err := tx.Exec(ctx, query, testDefaultHostID, teamID, now.Add(-8*time.Hour), endedAt, intervals); err != nil {
					t.Fatal(err)
				}
				sample, err := db.New(tx).GetRecentTrialBurnSample(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				spent, err := sample.SpentUsd.Float64Value()
				if err != nil || !spent.Valid || spent.Float64 != tc.wantSeconds*float64(intervals) {
					t.Fatalf("sample spend = %v, error = %v, want %v USD", spent, err, tc.wantSeconds*float64(intervals))
				}
				if intervals > 1024 {
					return // Capped samples carry no spend and cannot trigger a forecast.
				}
				if tc.wantSeconds == 0 {
					if sample.StartedAt != nil || sample.EndedAt != nil || sample.ElapsedSeconds.Valid {
						t.Fatalf("nonoverlapping sample has bounds: %+v", sample)
					}
					return
				}
				started, ok := sample.StartedAt.(time.Time)
				if !ok || !started.Equal(now.Add(-6*time.Hour)) {
					t.Fatalf("sample start = %v, want six-hour boundary", sample.StartedAt)
				}
				elapsed, err := sample.ElapsedSeconds.Float64Value()
				if err != nil || !elapsed.Valid || elapsed.Float64 != tc.wantSeconds {
					t.Fatalf("sample elapsed = %v, error = %v, want %v seconds", elapsed, err, tc.wantSeconds)
				}
			})
		}
	}
}

// The sample query is deliberately integration-tested because its forecast
// inputs depend on SQL filtering and aggregation, not only Go arithmetic.
func TestRecentTrialBurnSampleUsesFreshWallClockWindow(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "trial-warning-sample-"+uuid.NewString()[:8])
	backdateWarningSampleGrant(t, teamID)
	sandboxID := seedPrivatePreviewSandbox(t, teamID, testDefaultHostID, "trial-warning-sample")
	now := time.Now().UTC()

	// Two overlapping intervals must use min(start)..max(end) as elapsed wall
	// time; summing their runtimes would produce a materially different rate.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval
		  (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1, $2, 1, 1, $3, $4, 'paused'),
		       ($1, $2, 1, 1, $5, $6, 'paused')
	`, sandboxID, teamID, now.Add(-20*time.Minute), now.Add(-10*time.Minute), now.Add(-15*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("seed overlapping usage: %v", err)
	}
	sample, err := testQueries.GetRecentTrialBurnSample(ctx, teamID)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample: %v", err)
	}
	started, ok := sample.StartedAt.(time.Time)
	if !ok {
		t.Fatalf("started_at = %T, want time.Time", sample.StartedAt)
	}
	ended, ok := sample.EndedAt.(time.Time)
	if !ok {
		t.Fatalf("ended_at = %T, want time.Time", sample.EndedAt)
	}
	if ended.Sub(started) < 14*time.Minute || ended.Sub(started) > 16*time.Minute {
		t.Fatalf("sample elapsed = %s, want about 15m wall-clock span", ended.Sub(started))
	}

	// Paused sandboxes retain open storage intervals. Unbilled storage must
	// not dilute a recent compute burst's rate or extend its freshness.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_storage_billing_enabled', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable storage billing: %v", err)
	}
	pausedSandbox := seedPrivatePreviewSandbox(t, teamID, testDefaultHostID, "trial-warning-paused")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib, started_at)
		VALUES ($1, $2, 10240, $3)
	`, pausedSandbox, teamID, now.Add(-8*time.Hour)); err != nil {
		t.Fatalf("seed paused storage: %v", err)
	}
	disabled, err := testQueries.GetRecentTrialBurnSample(ctx, teamID)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample storage disabled: %v", err)
	}
	disabledStart, startOK := disabled.StartedAt.(time.Time)
	disabledEnd, endOK := disabled.EndedAt.(time.Time)
	if !startOK || !endOK || !disabledStart.Equal(started) || !disabledEnd.Equal(ended) {
		t.Fatalf("unbilled storage changed sample bounds: (%v, %v), want (%v, %v)", disabled.StartedAt, disabled.EndedAt, started, ended)
	}
	elapsed, err := disabled.ElapsedSeconds.Float64Value()
	if err != nil || !elapsed.Valid || elapsed.Float64 != 900 {
		t.Fatalf("storage-disabled elapsed seconds = %v, error = %v, want 900", elapsed, err)
	}
	spent, err := disabled.SpentUsd.Float64Value()
	baselineSpent, baselineErr := sample.SpentUsd.Float64Value()
	if err != nil || baselineErr != nil || !spent.Valid || !baselineSpent.Valid || spent.Float64 <= 0 || spent.Float64 != baselineSpent.Float64 {
		t.Fatalf("storage-disabled spend = %v, want positive compute-only spend %v (errors: %v, %v)", spent, baselineSpent, err, baselineErr)
	}

	// An open interval that predates the window still overlaps it and must be
	// clamped to the six-hour boundary rather than discarded.
	longTeam := mustCreateTeam(t, ctx, "trial-warning-long-"+uuid.NewString()[:8])
	backdateWarningSampleGrant(t, longTeam)
	longSandbox := seedPrivatePreviewSandbox(t, longTeam, testDefaultHostID, "trial-warning-long")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval
		  (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1, $2, 1, 1, $3, NULL, NULL)
	`, longSandbox, longTeam, now.Add(-8*time.Hour)); err != nil {
		t.Fatalf("seed long-running usage: %v", err)
	}
	longSample, err := testQueries.GetRecentTrialBurnSample(ctx, longTeam)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample long-running: %v", err)
	}
	longStarted, ok := longSample.StartedAt.(time.Time)
	if !ok || time.Since(longStarted) < 5*time.Hour || time.Since(longStarted) > 6*time.Hour+time.Minute {
		t.Fatalf("long-running sample start = %v, want six-hour boundary", longSample.StartedAt)
	}

	// A team with no recent signal must remain sparse/unavailable.
	emptyTeam := mustCreateTeam(t, ctx, "trial-warning-empty-"+uuid.NewString()[:8])
	backdateWarningSampleGrant(t, emptyTeam)
	empty, err := testQueries.GetRecentTrialBurnSample(ctx, emptyTeam)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample empty: %v", err)
	}
	if empty.StartedAt != nil || empty.EndedAt != nil {
		t.Fatalf("empty sample timestamps = (%v, %v), want nil", empty.StartedAt, empty.EndedAt)
	}

	// Usage outside the bounded freshness window must not become a signal.
	staleTeam := mustCreateTeam(t, ctx, "trial-warning-stale-"+uuid.NewString()[:8])
	backdateWarningSampleGrant(t, staleTeam)
	staleSandbox := seedPrivatePreviewSandbox(t, staleTeam, testDefaultHostID, "trial-warning-stale")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval
		  (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1, $2, 1, 1, $3, $4, 'paused')
	`, staleSandbox, staleTeam, now.Add(-72*time.Hour), now.Add(-71*time.Hour)); err != nil {
		t.Fatalf("seed stale usage: %v", err)
	}
	stale, err := testQueries.GetRecentTrialBurnSample(ctx, staleTeam)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample stale: %v", err)
	}
	if stale.StartedAt != nil || stale.EndedAt != nil {
		t.Fatalf("stale sample timestamps = (%v, %v), want nil", stale.StartedAt, stale.EndedAt)
	}
}

func backdateWarningSampleGrant(t *testing.T, teamID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE team_credit_grant
		SET created_at = now() - interval '1 day'
		WHERE team_id = $1 AND reason = 'signup trial credit'`, teamID); err != nil {
		t.Fatal(err)
	}
}

func TestRecentTrialBurnSampleStartsAtLatestSignupGrant(t *testing.T) {
	for _, resource := range []string{"compute", "storage"} {
		t.Run(resource, func(t *testing.T) {
			ctx := context.Background()
			team := mustCreateTeam(t, ctx, "trial-lifecycle-sample-"+uuid.NewString()[:8])
			backdateWarningSampleGrant(t, team)
			sandbox := seedPrivatePreviewSandbox(t, team, testDefaultHostID, "trial-lifecycle-sample")
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var now time.Time
			if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO team_feature_flag (team_id, key, enabled)
				VALUES ($1, 'billing_storage_billing_enabled', true)
				ON CONFLICT (team_id, key) DO UPDATE SET enabled = true`, team); err != nil {
				t.Fatal(err)
			}
			query := `INSERT INTO sandbox_compute_billing_interval
				(sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
				VALUES ($1, $2, 2, 1024, now()-interval '2 hours', now()-interval '1 minute', 'paused')`
			if resource == "storage" {
				query = `INSERT INTO sandbox_storage_interval
					(sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason)
					VALUES ($1, $2, 1024, now()-interval '2 hours', now()-interval '1 minute', 'deleted')`
			}
			if _, err := tx.Exec(ctx, query, sandbox, team); err != nil {
				t.Fatal(err)
			}
			queries := db.New(tx)
			before, err := queries.GetRecentTrialBurnSample(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			// Only the portion after the newest grant belongs to its lifecycle.
			if _, err := tx.Exec(ctx, `INSERT INTO team_credit_grant
				(team_id, amount_usd, remaining_usd, reason, created_at)
				VALUES ($1, 5, 5, 'signup trial credit', now()-interval '30 minutes')`, team); err != nil {
				t.Fatal(err)
			}
			after, err := queries.GetRecentTrialBurnSample(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			started, ok := after.StartedAt.(time.Time)
			if !ok || !started.Equal(now.Add(-30*time.Minute)) {
				t.Fatalf("sample start = %v, want newest grant boundary", after.StartedAt)
			}
			oldSpend, _ := before.SpentUsd.Float64Value()
			newSpend, _ := after.SpentUsd.Float64Value()
			if !oldSpend.Valid || !newSpend.Valid || newSpend.Float64 <= 0 || newSpend.Float64 >= oldSpend.Float64 {
				t.Fatalf("spend before=%v after=%v, want positive truncated spend", oldSpend, newSpend)
			}
			// A grant newer than all activity must not inherit the old burn rate.
			if _, err := tx.Exec(ctx, `INSERT INTO team_credit_grant
				(team_id, amount_usd, remaining_usd, reason)
				VALUES ($1, 5, 5, 'signup trial credit')`, team); err != nil {
				t.Fatal(err)
			}
			empty, err := queries.GetRecentTrialBurnSample(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			spent, _ := empty.SpentUsd.Float64Value()
			if !spent.Valid || spent.Float64 != 0 || empty.StartedAt != nil || empty.EndedAt != nil {
				t.Fatalf("pre-lifecycle activity produced sample: %+v", empty)
			}
		})
	}
}
