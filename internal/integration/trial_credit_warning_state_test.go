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
	rows, err := testQueries.RecordTrialCreditWarningDelivery(ctx, db.RecordTrialCreditWarningDeliveryParams{
		TeamID: teamID, ClaimToken: retryToken, Recipient: "billing@example.com",
	})
	if err != nil || rows != 0 {
		t.Fatalf("stale recipient delivery write = %d rows, error = %v", rows, err)
	}
	rows, err = testQueries.RecordTrialCreditWarningDelivery(ctx, db.RecordTrialCreditWarningDeliveryParams{
		TeamID: teamID, ClaimToken: newToken, Recipient: "billing@example.com",
	})
	if err != nil || rows != 1 {
		t.Fatalf("current recipient delivery write = %d rows, error = %v", rows, err)
	}
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
		usage    bool
		activate bool
		state    string
	}{
		{name: "no grant", state: "no_grant"},
		{name: "exhausted without expiry", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at) VALUES ($1, 0.000001, 0, 'signup trial credit', now()-interval '3 hours')`, usage: true, state: "exhausted"},
		{name: "exhausted before expiry", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at, expires_at) VALUES ($1, 0.000001, 0, 'signup trial credit', now()-interval '3 hours', now()+interval '1 day')`, usage: true, state: "exhausted"},
		{name: "expired with credit", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, expires_at) VALUES ($1, 5, 5, 'signup trial credit', now()-interval '1 hour')`, state: "expired"},
		{name: "expired and exhausted", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at, expires_at) VALUES ($1, 0.000001, 0, 'signup trial credit', now()-interval '3 hours', now()-interval '1 minute')`, usage: true, state: "expired"},
		{name: "stripe activation", grant: `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason) VALUES ($1, 5, 5, 'signup trial credit')`, activate: true, state: "ended_by_billing_activation"},
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
			if tc.usage {
				sandboxID := seedPrivatePreviewSandbox(t, teamID, testDefaultHostID, "trial-lifecycle")
				if _, err := testPool.Exec(ctx, `
					INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
					VALUES ($1,$2,2,1024,now()-interval '2 hours',now()-interval '1 hour','paused')`, sandboxID, teamID); err != nil {
					t.Fatalf("seed trial consumption: %v", err)
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
			if balance.State != tc.state {
				t.Fatalf("trial state = %q, want %q", balance.State, tc.state)
			}
			if balance.Eligible != tc.activate {
				t.Fatalf("trial eligibility = %t, want %t", balance.Eligible, tc.activate)
			}
			remaining, err := balance.RemainingUsd.Float64Value()
			if err != nil || !remaining.Valid || remaining.Float64 != 0 {
				t.Fatalf("terminal trial remaining = %+v, err = %v, want zero", remaining, err)
			}
			if tc.state == "expired" {
				consumed, err := balance.ConsumedUsd.Float64Value()
				if err != nil || !consumed.Valid || consumed.Float64 != 0 {
					t.Fatalf("expired trial consumption = %+v, err = %v, want zero", consumed, err)
				}
			} else if tc.usage {
				consumed, err := balance.ConsumedUsd.Float64Value()
				if err != nil || !consumed.Valid || consumed.Float64 < 0.000001 {
					t.Fatalf("trial consumption = %+v, err = %v, want at least the grant amount", consumed, err)
				}
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
