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
