//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The sample query is deliberately integration-tested because its forecast
// inputs depend on SQL filtering and aggregation, not only Go arithmetic.
func TestRecentTrialBurnSampleUsesFreshWallClockWindow(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "trial-warning-sample-"+uuid.NewString()[:8])
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
	empty, err := testQueries.GetRecentTrialBurnSample(ctx, emptyTeam)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample empty: %v", err)
	}
	if empty.StartedAt != nil || empty.EndedAt != nil {
		t.Fatalf("empty sample timestamps = (%v, %v), want nil", empty.StartedAt, empty.EndedAt)
	}

	// Usage outside the bounded freshness window must not become a signal.
	staleTeam := mustCreateTeam(t, ctx, "trial-warning-stale-"+uuid.NewString()[:8])
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
