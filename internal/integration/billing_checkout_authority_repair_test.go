//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_CheckoutLegacyGenerationAfterTrustedHistory(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, retained := range []bool{false, true} {
			t.Run(fmt.Sprintf("canonical_%t_retained_%t", enabled, retained), func(t *testing.T) {
				ctx := context.Background()
				tx := localIdentityTransaction(t, enabled)
				actor, team := uuid.New(), uuid.New()
				localIdentityWrite(t, tx, actor, actor.String()+"@example.com", true, time.Now(), time.Now())
				rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,'example-team')`, team)
				rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
				firstAttempt := uuid.New()
				rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','trusted','standard',$4)`, team, actor, uuid.New(), firstAttempt)
				q := db.New(tx)
				a, err := q.GetTeamBillingCheckoutForRecovery(ctx, team)
				if err != nil {
					t.Fatal(err)
				}
				if err = q.FinishFailedTeamBillingCheckoutAttempt(ctx, db.FinishFailedTeamBillingCheckoutAttemptParams{TeamID: team, LeaseStartedAt: a.CheckoutInitializingAt, AttemptID: firstAttempt, MayExist: false}); err != nil {
					t.Fatal(err)
				}
				a, err = q.BeginTeamBillingCheckout(ctx, db.BeginTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: repairStringPtr("legacy"), AttemptID: uuid.New()})
				if err != nil {
					t.Fatal(err)
				}
				sub := "sub_" + team.String()
				if retained {
					rolloutExec(t, tx, `UPDATE team_billing_account SET checkout_subscription_id=$2 WHERE team_id=$1`, team, sub)
					// Finish clears the lease, while retaining the captured payer identity.
					if err = q.FinishTeamBillingCheckout(ctx, team); err != nil {
						t.Fatal(err)
					}
				}
				var state string
				if err = tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'event',$3,$4,$5)`, team, actor, sub, a.CheckoutInitializingAt, !retained).Scan(&state); err != nil || state != "acquired" {
					t.Fatalf("valid legacy generation denied: %s %v", state, err)
				}
			})
		}
	}
}

func TestIntegration_CheckoutProjectionDoesNotProveGeneration(t *testing.T) {
	ctx := context.Background()
	tx := localIdentityTransaction(t, false)
	actor, team := uuid.New(), uuid.New()
	rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,'example-team')`, team)
	rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','trusted','standard',$4)`, team, actor, uuid.New(), uuid.New())
	rolloutExec(t, tx, `UPDATE team_billing_account SET stripe_subscription_id='sub_unproven' WHERE team_id=$1`, team)
	for _, hasGeneration := range []bool{false, true} {
		var state string
		err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'event','sub_unproven',$3,$4)`, team, actor, time.Now().Add(time.Hour), hasGeneration).Scan(&state)
		if err != nil || state != "authority_unavailable" {
			t.Fatalf("projected subscription accepted: %s %v", state, err)
		}
	}
}

func TestIntegration_CheckoutRetrySaturationRetainsUncertainty(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprintf("trusted_%t", trusted), func(t *testing.T) {
			ctx := context.Background()
			tx := localIdentityTransaction(t, false)
			q := db.New(tx)
			actor, team, operation, first := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
			rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,'example-team')`, team)
			rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			begin := func(attempt uuid.UUID) {
				t.Helper()
				if trusted {
					rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','request','publication_failed',$4)`, team, actor, operation, attempt)
					return
				}
				if attempt == first {
					_, err := q.BeginTeamBillingCheckout(ctx, db.BeginTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: repairStringPtr("request"), AttemptID: attempt})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					_, err := q.ResumeTeamBillingCheckout(ctx, db.ResumeTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: repairStringPtr("request"), AttemptID: attempt})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			begin(first)
			original, err := q.GetTeamBillingCheckoutForRecovery(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 31; i++ {
				begin(uuid.New())
			}
			replay := uuid.New()
			begin(replay)
			a, err := q.GetTeamBillingCheckoutForRecovery(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.CheckoutPendingAttemptIds) != 1 || !a.CheckoutMayExist || a.CheckoutInitializingAt != original.CheckoutInitializingAt {
				t.Fatalf("compaction lost generation or uncertainty: %+v", a)
			}
			// A definitive failure of the newest request cannot release the older
			// unknown Stripe obligation, even after its attempt ID is compacted away.
			for _, attempt := range []uuid.UUID{replay, first} {
				if err = q.FinishFailedTeamBillingCheckoutAttempt(ctx, db.FinishFailedTeamBillingCheckoutAttemptParams{TeamID: team, LeaseStartedAt: a.CheckoutInitializingAt, AttemptID: attempt, MayExist: false}); err != nil {
					t.Fatal(err)
				}
			}
			a, err = q.GetTeamBillingCheckoutForRecovery(ctx, team)
			if err != nil || !a.CheckoutInitializingAt.Valid || !a.CheckoutMayExist {
				t.Fatalf("late settlement released uncertain generation: %+v %v", a, err)
			}
			for i := 0; i < 32; i++ {
				begin(uuid.New())
			}
			replay = uuid.New()
			begin(replay)
			if _, err = q.SetTeamBillingCheckoutSession(ctx, db.SetTeamBillingCheckoutSessionParams{TeamID: team, LeaseStartedAt: a.CheckoutInitializingAt, AttemptID: replay, SessionID: repairStringPtr("cs_original")}); err != nil {
				t.Fatal(err)
			}
			a, err = q.GetTeamBillingCheckoutForRecovery(ctx, team)
			if err != nil || a.CheckoutSessionID == nil || *a.CheckoutSessionID != "cs_original" || a.CheckoutInitializingAt != original.CheckoutInitializingAt {
				t.Fatalf("original generation could not persist recovered session: %+v %v", a, err)
			}
		})
	}
}

func repairStringPtr(s string) *string { return &s }

func TestIntegration_CheckoutRetainedNullEvidenceWithCanonicalOff(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		for _, retained := range []bool{false, true} {
			t.Run(fmt.Sprintf("trusted_%t_retained_%t", trusted, retained), func(t *testing.T) {
				ctx := context.Background()
				tx := localIdentityTransaction(t, false)
				q := db.New(tx)
				actor, team := uuid.New(), uuid.New()
				rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
				rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,'example-team')`, team)
				rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
				if trusted {
					rolloutExec(t, tx, `SELECT begin_stripe_checkout_with_publication_decision($1,$2,$3,'use','request','standard',$4)`, team, actor, uuid.New(), uuid.New())
				} else {
					if _, err := q.BeginTeamBillingCheckout(ctx, db.BeginTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: repairStringPtr("legacy"), AttemptID: uuid.New()}); err != nil {
						t.Fatal(err)
					}
				}
				a, err := q.GetTeamBillingCheckoutForRecovery(ctx, team)
				if err != nil {
					t.Fatal(err)
				}
				if a.StripeCheckoutIdentityEvidenceVersion.Valid {
					t.Fatal("fixture unexpectedly captured evidence")
				}
				// Later published evidence must not rewrite the captured NULL.
				localIdentityWrite(t, tx, actor, actor.String()+"@example.com", true, time.Now(), time.Now())
				sub := "sub_" + team.String()
				if retained {
					rolloutExec(t, tx, `UPDATE team_billing_account SET checkout_subscription_id=$2 WHERE team_id=$1`, team, sub)
					if err = q.FinishTeamBillingCheckout(ctx, team); err != nil {
						t.Fatal(err)
					}
				}
				var state string
				err = tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'event',$3,$4,$5)`, team, actor, sub, a.CheckoutInitializingAt, !retained).Scan(&state)
				if err != nil || state != "acquired" {
					t.Fatalf("legacy gate-off eligibility lost: %s %v", state, err)
				}
				a, err = q.GetTeamBillingCheckoutForRecovery(ctx, team)
				if err != nil {
					t.Fatal(err)
				}
				if a.StripeActivationIdentityEvidenceVersion.Valid {
					t.Fatal("reservation recaptured later evidence")
				}
			})
		}
	}
}
