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
	const workers = 2
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
	newToken, err := testQueries.ClaimTrialCreditWarning(ctx, teamID)
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	if newToken == retryToken {
		t.Fatal("claim after release reused the prior claim token")
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
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET trial_ended_at = now(), stripe_subscription_status = 'active' WHERE team_id = $1`, teamID); err != nil {
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
