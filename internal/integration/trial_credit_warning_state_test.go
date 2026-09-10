//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialCreditWarningStateClaimCompleteRelease(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "trial-warning-state-"+uuid.NewString()[:8])

	// Two workers racing for the same team may produce at most one claim.
	const workers = 8
	tokens := make(chan pgtype.UUID, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := testQueries.ClaimTrialCreditWarning(ctx, teamID)
			if err == nil {
				tokens <- token
			} else if err != pgx.ErrNoRows {
				t.Errorf("ClaimTrialCreditWarning: %v", err)
			}
		}()
	}
	wg.Wait()
	close(tokens)

	var token pgtype.UUID
	if got := len(tokens); got != 1 {
		t.Fatalf("concurrent claims = %d, want exactly 1", got)
	}
	for token = range tokens {
	}
	// A duplicate claim while the first delivery is in flight is suppressed
	// at the database boundary, not merely by caller coordination.
	if _, err := testQueries.ClaimTrialCreditWarning(ctx, teamID); err != pgx.ErrNoRows {
		t.Fatalf("duplicate claim while claimed = %v, want pgx.ErrNoRows", err)
	}

	if err := testQueries.CompleteTrialCreditWarning(ctx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: token}); err != nil {
		t.Fatalf("CompleteTrialCreditWarning: %v", err)
	}
	var status string
	if err := testPool.QueryRow(ctx, `SELECT status FROM trial_credit_warning_state WHERE team_id = $1`, teamID).Scan(&status); err != nil {
		t.Fatalf("read completed warning status: %v", err)
	}
	if status != "sent" {
		t.Fatalf("completed warning status = %q, want sent", status)
	}
	if _, err := testQueries.ClaimTrialCreditWarning(ctx, teamID); err != pgx.ErrNoRows {
		t.Fatalf("claim after completion = %v, want pgx.ErrNoRows", err)
	}

	// A provider failure releases the claim, allowing a later pass to retry.
	teamID = mustCreateTeam(t, ctx, "trial-warning-release-"+uuid.NewString()[:8])
	retryToken, err := testQueries.ClaimTrialCreditWarning(ctx, teamID)
	if err != nil {
		t.Fatalf("initial claim for release case: %v", err)
	}
	if err := testQueries.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: retryToken}); err != nil {
		t.Fatalf("ReleaseTrialCreditWarning: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT status FROM trial_credit_warning_state WHERE team_id = $1`, teamID).Scan(&status); err != nil {
		t.Fatalf("read released warning status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("released warning status = %q, want pending", status)
	}
	newToken, err := testQueries.ClaimTrialCreditWarning(ctx, teamID)
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	if newToken == retryToken {
		t.Fatal("claim after release reused the prior claim token")
	}
	// A stale worker must not be able to mutate the replacement generation.
	if err := testQueries.ReleaseTrialCreditWarning(ctx, db.ReleaseTrialCreditWarningParams{TeamID: teamID, ClaimToken: retryToken}); err != nil {
		t.Fatalf("stale release: %v", err)
	}
	if err := testQueries.CompleteTrialCreditWarning(ctx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: retryToken}); err != nil {
		t.Fatalf("stale complete: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT status FROM trial_credit_warning_state WHERE team_id = $1`, teamID).Scan(&status); err != nil {
		t.Fatalf("read claim status: %v", err)
	}
	if status != "claimed" {
		t.Fatalf("stale claim changed state to %q", status)
	}
	if err := testQueries.CompleteTrialCreditWarning(ctx, db.CompleteTrialCreditWarningParams{TeamID: teamID, ClaimToken: newToken}); err != nil {
		t.Fatalf("current complete: %v", err)
	}
}

func TestTrialCreditWarningLifecycleSuppressesIneligibleTrials(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		grant    string
		activate bool
	}{
		{name: "no grant"},
		{name: "exhausted", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason) VALUES ($1, 5, 0, 'signup trial credit')`},
		{name: "stripe activation", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason) VALUES ($1, 5, 5, 'signup trial credit')`, activate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			teamID := mustCreateTeam(t, ctx, "trial-warning-lifecycle-"+uuid.NewString()[:8])
			// Team creation seeds the standard signup grant. Remove it so each
			// case below exercises the explicitly described lifecycle state.
			if _, err := testPool.Exec(ctx, `DELETE FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'`, teamID); err != nil {
				t.Fatalf("clear seeded trial grant: %v", err)
			}
			if tc.grant != "" {
				if _, err := testPool.Exec(ctx, tc.grant, teamID); err != nil {
					t.Fatalf("seed trial grant: %v", err)
				}
			}
			if tc.activate {
				if _, err := testPool.Exec(ctx, `
					INSERT INTO team_billing_account (team_id, trial_ended_at, stripe_subscription_status)
					VALUES ($1, now(), 'active')
					ON CONFLICT (team_id) DO UPDATE
					SET trial_ended_at = EXCLUDED.trial_ended_at,
					    stripe_subscription_status = EXCLUDED.stripe_subscription_status
				`, teamID); err != nil {
					t.Fatalf("activate billing: %v", err)
				}
			}
			balance, err := testQueries.GetTeamTrialBalance(ctx, teamID)
			if err != nil {
				t.Fatalf("GetTeamTrialBalance: %v", err)
			}
			if balance.Eligible && balance.State == "active" && balance.RemainingUsd.Valid {
				t.Fatalf("lifecycle %q remained warning-eligible: state=%q remaining=%v", tc.name, balance.State, balance.RemainingUsd)
			}
		})
	}
}

func TestRecentTrialBurnSampleUsesWallClockAndRejectsStaleData(t *testing.T) {
	ctx := context.Background()
	teamID := mustCreateTeam(t, ctx, "trial-warning-sample-"+uuid.NewString()[:8])
	sandboxID := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO sandbox (id, team_id, name, status, host_id) VALUES ($1,$2,'sample','active',$3)`, sandboxID, teamID, testDefaultHostID); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	// Two overlapping intervals provide spend over a two-hour wall-clock span;
	// the query must not sum their concurrent runtime as the denominator.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1,$2,1,1024,now()-interval '2 hours',now()-interval '1 hour','paused'),
		       ($1,$2,1,1024,now()-interval '90 minutes',now(),'paused')`, sandboxID, teamID); err != nil {
		t.Fatalf("insert sample intervals: %v", err)
	}
	sample, err := testQueries.GetRecentTrialBurnSample(ctx, teamID)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample: %v", err)
	}
	if sample.StartedAt == nil || sample.EndedAt == nil || !sample.ElapsedSeconds.Valid {
		t.Fatal("expected wall-clock bounds for recent sample")
	}
	seconds, err := sample.ElapsedSeconds.Float64Value()
	if err != nil || !seconds.Valid {
		t.Fatalf("elapsed seconds numeric value: %+v (err=%v)", seconds, err)
	}
	if seconds.Float64 < 7100 || seconds.Float64 > 7300 {
		t.Fatalf("elapsed seconds = %v, want about 7200", seconds.Float64)
	}

	teamID = mustCreateTeam(t, ctx, "trial-warning-stale-"+uuid.NewString()[:8])
	sandboxID = uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO sandbox (id, team_id, name, status, host_id) VALUES ($1,$2,'stale','active',$3)`, sandboxID, teamID, testDefaultHostID); err != nil {
		t.Fatalf("create stale sandbox: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1,$2,1,1024,now()-interval '8 hours',now()-interval '7 hours','paused')`, sandboxID, teamID); err != nil {
		t.Fatalf("insert stale interval: %v", err)
	}
	stale, err := testQueries.GetRecentTrialBurnSample(ctx, teamID)
	if err != nil {
		t.Fatalf("GetRecentTrialBurnSample stale: %v", err)
	}
	if stale.StartedAt != nil || stale.EndedAt != nil {
		t.Fatal("stale sample should have unavailable bounds")
	}
}
