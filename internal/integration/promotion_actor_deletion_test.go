//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegration_PendingStripePromotionProtectsActorDeletion(t *testing.T) {
	for _, state := range []string{"pending", "released", "finalized", "signup_only", "transition_in_progress"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			teamID, userID := uuid.New(), uuid.New()
			if _, err := testPool.Exec(ctx, `INSERT INTO team (id, name) VALUES ($1, $2)`, teamID, "pending-promotion-"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, userID.String()+"@example.com"); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_subscription_status) VALUES ($1, 'active')`, teamID); err != nil {
				t.Fatal(err)
			}
			assertDeleteFails := func(code string) {
				t.Helper()
				deleteCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				_, err := testPool.Exec(deleteCtx, `DELETE FROM profile WHERE id = $1`, userID)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != code {
					t.Fatalf("profile deletion error = %v, want PostgreSQL %s", err, code)
				}
			}
			if state == "signup_only" {
				if _, err := testPool.Exec(ctx, `INSERT INTO user_signup_trial_claim (user_id, team_id) VALUES ($1, $2)`, userID, teamID); err != nil {
					t.Fatal(err)
				}
				if _, err := testPool.Exec(ctx, `INSERT INTO user_promotion_entitlement (user_id, signup_trial_claimed_at, signup_trial_team_id) VALUES ($1, now(), $2)`, userID, teamID); err != nil {
					t.Fatal(err)
				}
			} else {
				tx, err := testPool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if state == "transition_in_progress" {
					if _, err := tx.Exec(ctx, `SELECT lock_stripe_promotion($1, $2)`, teamID, userID); err != nil {
						t.Fatal(err)
					}
					// Deletion must fail immediately instead of waiting with a
					// profile row lock needed by this reservation's foreign keys.
					assertDeleteFails("55P03")
				}
				var acquired string
				if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1, $2, $3)`, teamID, userID, "evt_"+teamID.String()).Scan(&acquired); err != nil || acquired != "acquired" {
					t.Fatalf("reserve promotion = %q, error=%v", acquired, err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "pending", "transition_in_progress":
				assertDeleteFails("23503")
				var preserved bool
				if err := testPool.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM profile p
					JOIN user_promotion_entitlement u ON u.user_id = p.id
					JOIN team_billing_account a ON a.team_id = u.stripe_redemption_reserved_team_id
					WHERE p.id = $1 AND a.team_id = $2 AND a.stripe_activation_user_id = p.id
					  AND a.stripe_activation_credit_reserved_at IS NOT NULL
					  AND a.stripe_activation_credit_reservation_event_id = $3
				)`, userID, teamID, "evt_"+teamID.String()).Scan(&preserved); err != nil || !preserved {
					t.Fatalf("pending user/team pair lost after rejected deletion: preserved=%v error=%v", preserved, err)
				}
				return
			case "released":
				if _, err := testPool.Exec(ctx, `SELECT release_stripe_promotion_for_event($1, $2, $3)`, teamID, userID, "evt_"+teamID.String()); err != nil {
					t.Fatal(err)
				}
			case "finalized":
				// Existing signup history avoids creating a separate ledger
				// actor reference with its own, unrelated deletion policy.
				if _, err := testPool.Exec(ctx, `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason) VALUES ($1, 5, 0, 'signup trial credit')`, teamID); err != nil {
					t.Fatal(err)
				}
				if _, err := testPool.Exec(ctx, `SELECT activate_team_billing($1, $2, 'credit_finalized')`, teamID, userID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := testPool.Exec(ctx, `DELETE FROM profile WHERE id = $1`, userID); err != nil {
				t.Fatalf("profile deletion after %s: %v", state, err)
			}
			var remains bool
			if err := testPool.QueryRow(ctx, `SELECT
				EXISTS(SELECT 1 FROM profile WHERE id = $1)
				OR EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id = $1)
				OR EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id = $1)`, userID).Scan(&remains); err != nil || remains {
				t.Fatalf("normal actor cascade after %s: rows remain=%v error=%v", state, remains, err)
			}
			if state == "finalized" {
				account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil || !account.StripeActivationCreditGrantedAt.Valid || derefString(account.StripeActivationCreditGrantID) != "credit_finalized" {
					t.Fatalf("profile deletion lost team redemption marker: %+v error=%v", account, err)
				}
			}
		})
	}
}
