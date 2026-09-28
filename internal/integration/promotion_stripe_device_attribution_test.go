//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_StripeDeviceGrantSurvivesLateEvidenceAndDeletion(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		for _, explicitRecording := range []bool{false, true} {
			t.Run(fmt.Sprintf("canonical=%t/explicitRecording=%t", canonical, explicitRecording), func(t *testing.T) {
				ctx := context.Background()
				tx := localIdentityTransaction(t, canonical)
				rolloutExec(t, tx, `SELECT set_promotion_device_policy(false,false)`)
				owner, recipient, team, ownerTeam := uuid.New(), uuid.New(), uuid.New(), uuid.New()
				fingerprint, event, grant := "visitor-"+uuid.NewString(), "evt-"+uuid.NewString(), "grant-"+uuid.NewString()
				for _, user := range []uuid.UUID{owner, recipient} {
					localIdentityWrite(t, tx, user, user.String()+"@example.com", true, time.Now(), time.Now())
				}
				for _, id := range []uuid.UUID{team, ownerTeam} {
					rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, id, "promotion-"+id.String())
					rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, id)
				}
				register := func(user uuid.UUID, want string) {
					t.Helper()
					var result string
					if err := tx.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
						user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&result); err != nil || result != want {
						t.Fatalf("registration = %q, want %q: %v", result, want, err)
					}
				}
				register(owner, "owner")
				var result string
				if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
					team, recipient, event).Scan(&result); err != nil || result != "acquired" {
					t.Fatalf("reservation = %q: %v", result, err)
				}
				reservationSnapshot := func() string {
					t.Helper()
					var snapshot string
					if err := tx.QueryRow(ctx, `SELECT jsonb_build_array(to_jsonb(a),to_jsonb(u),to_jsonb(i))::text
						FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=$2
						JOIN promotion_identity i ON i.identity_key=a.stripe_activation_identity_key
						WHERE a.team_id=$1`, team, recipient).Scan(&snapshot); err != nil {
						t.Fatal(err)
					}
					return snapshot
				}
				before := reservationSnapshot()
				finalize := func() {
					t.Helper()
					rolloutExec(t, tx, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, recipient, grant)
					if explicitRecording {
						rolloutExec(t, tx, `SELECT record_stripe_promotion_device_grant($1,$2)`, team, recipient)
					}
				}
				assertGrant := func() {
					t.Helper()
					var retained bool
					if err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(user_id=$2 AND fingerprint IS NULL)
						FROM promotion_device_grant WHERE promotion='stripe' AND team_id=$1`, team, recipient).
						Scan(&retained); err != nil || !retained {
						t.Fatalf("immutable evidence-free grant attribution: %t, %v", retained, err)
					}
				}
				rolloutExec(t, tx, `SAVEPOINT before_finalization`)
				finalize()
				assertGrant()
				rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT before_finalization`)
				if after := reservationSnapshot(); after != before {
					t.Fatalf("finalization rollback changed reservation pins or consumption: before=%s after=%s", before, after)
				}
				var consumed bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_device_grant WHERE team_id=$1)
					OR EXISTS(SELECT 1 FROM team_credit_grant WHERE team_id=$1)
					OR EXISTS(SELECT 1 FROM promotion_identity_history WHERE team_id=$1 AND grant_state='granted')`, team).
					Scan(&consumed); err != nil || consumed {
					t.Fatalf("rolled-back finalization retained a grant: %t, %v", consumed, err)
				}
				finalize()
				assertGrant()
				register(recipient, "owner_conflict")
				finalize()
				// Replays cannot attribute the existing team's grant to another actor.
				rolloutExec(t, tx, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, owner, "grant-"+uuid.NewString())
				assertGrant()
				var settled bool
				if err := tx.QueryRow(ctx, `SELECT a.stripe_activation_credit_grant_id=$3
					AND a.stripe_activation_user_id=$2 AND a.stripe_activation_credit_reserved_at IS NULL
					AND u.stripe_redemption_at IS NOT NULL AND u.stripe_redemption_reserved_team_id IS NULL
					AND (SELECT count(*)=1 AND sum(amount_usd)=95 AND sum(remaining_usd)=0
						FROM team_credit_grant WHERE team_id=$1 AND reason='stripe promotional credit')
					FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=$2
					WHERE a.team_id=$1`, team, recipient, grant).Scan(&settled); err != nil || !settled {
					t.Fatalf("finalization replay changed grant or settlement: %t, %v", settled, err)
				}
				if !canonical {
					rolloutExec(t, tx, `UPDATE promotion_identity_enforcement
						SET enabled=true, enabled_at=now(), readiness_reference='isolated test fixture' WHERE singleton`)
				}
				rolloutExec(t, tx, `SELECT set_promotion_device_policy(true,true)`)
				assertOwnerDenied := func() {
					t.Helper()
					if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
						ownerTeam, owner, "evt-"+uuid.NewString()).Scan(&result); err != nil || result != "device_already_redeemed" {
						t.Fatalf("owner reservation = %q: %v", result, err)
					}
					if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement
						WHERE user_id=$1 AND (stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
						OR EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$1 AND promotion='stripe')`, owner).
						Scan(&consumed); err != nil || consumed {
						t.Fatalf("denied owner consumed or reserved credit: %t, %v", consumed, err)
					}
				}
				assertOwnerDenied()
				rolloutExec(t, tx, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
				rolloutExec(t, tx, `DELETE FROM team WHERE id=$1`, team)
				rolloutExec(t, tx, `DELETE FROM profile WHERE id=$1`, recipient)
				var cascaded bool
				if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1)
					AND EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$1 AND fingerprint=$2)
					AND EXISTS(SELECT 1 FROM promotion_device_owner WHERE fingerprint=$2 AND user_id=$3)`, recipient, fingerprint, owner).
					Scan(&cascaded); err != nil || !cascaded {
					t.Fatalf("deletion did not retain evidence and original owner: %t, %v", cascaded, err)
				}
				assertGrant()
				assertOwnerDenied()
			})
		}
	}
}

func TestIntegration_StripeDeviceLegacySettlementSurvivesDeletion(t *testing.T) {
	migration, err := os.ReadFile("../../supabase/migrations/20260925195248_canonical_stripe_promotion_fences.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "CREATE OR REPLACE FUNCTION finalize_stripe_promotion(")
	end := strings.Index(string(migration), "CREATE OR REPLACE FUNCTION activate_team_billing(")
	if start < 0 || end <= start {
		t.Fatal("legacy Stripe finalization function not found")
	}
	for _, canonical := range []bool{false, true} {
		t.Run(fmt.Sprintf("canonical=%t", canonical), func(t *testing.T) {
			ctx := context.Background()
			tx := localIdentityTransaction(t, canonical)
			// Restore the deployed settlement path only within this rolled-back transaction.
			rolloutExec(t, tx, string(migration[start:end]))
			rolloutExec(t, tx, `SELECT set_promotion_device_policy(false,false)`)
			owner, recipient, team, ownerTeam := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			fingerprint := "visitor-" + uuid.NewString()
			for _, user := range []uuid.UUID{owner, recipient} {
				localIdentityWrite(t, tx, user, user.String()+"@example.com", true, time.Now(), time.Now())
				rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
					user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
			}
			for _, id := range []uuid.UUID{team, ownerTeam} {
				rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, id, "promotion-"+id.String())
				rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, id)
			}
			var result string
			if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
				team, recipient, "evt-"+uuid.NewString()).Scan(&result); err != nil || result != "acquired" {
				t.Fatalf("legacy reservation = %q: %v", result, err)
			}
			rolloutExec(t, tx, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, recipient, "grant-"+uuid.NewString())
			var settled bool
			if err := tx.QueryRow(ctx, `SELECT
				EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND stripe_redemption_at IS NOT NULL)
				AND (SELECT count(*)=1 AND sum(amount_usd)=95 FROM team_credit_grant
					WHERE team_id=$1 AND reason='stripe promotional credit')
				AND NOT EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$2)`, team, recipient).
				Scan(&settled); err != nil || !settled {
				t.Fatalf("legacy settlement without device grant = %t: %v", settled, err)
			}
			rolloutExec(t, tx, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
			rolloutExec(t, tx, `DELETE FROM team WHERE id=$1`, team)
			rolloutExec(t, tx, `DELETE FROM profile WHERE id=$1`, recipient)
			var retained bool
			if err := tx.QueryRow(ctx, `SELECT
				NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1)
				AND EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$1 AND fingerprint=$2)
				AND EXISTS(SELECT 1 FROM promotion_device_owner WHERE user_id=$3 AND fingerprint=$2)
				AND CASE WHEN $4 THEN
					EXISTS(SELECT 1 FROM promotion_identity_binding b JOIN promotion_identity i USING(identity_key)
						WHERE b.user_id=$1 AND i.stripe_redemption_at IS NOT NULL)
					AND NOT EXISTS(SELECT 1 FROM promotion_identity_history WHERE user_id=$1 AND promotion='stripe')
				ELSE EXISTS(SELECT 1 FROM promotion_identity_history
					WHERE user_id=$1 AND promotion='stripe' AND grant_state='granted') END`, recipient, fingerprint, owner, canonical).
				Scan(&retained); err != nil || !retained {
				t.Fatalf("legacy consumption retained after deletion = %t: %v", retained, err)
			}
			if !canonical {
				rolloutExec(t, tx, `UPDATE promotion_identity_enforcement
					SET enabled=true, enabled_at=now(), readiness_reference='isolated test fixture' WHERE singleton`)
			}
			rolloutExec(t, tx, `SELECT set_promotion_device_policy(true,true)`)
			if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'stripe')`, owner).
				Scan(&result); err != nil || result != "device_already_redeemed" {
				t.Fatalf("owner decision after legacy recipient deletion = %q: %v", result, err)
			}
			if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
				ownerTeam, owner, "evt-"+uuid.NewString()).Scan(&result); err != nil || result != "device_already_redeemed" {
				t.Fatalf("owner reservation after legacy recipient deletion = %q: %v", result, err)
			}
			var consumed bool
			if err := tx.QueryRow(ctx, `SELECT
				EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1
					AND (stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
				OR EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$1 AND promotion='stripe')
				OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$2
					AND stripe_activation_credit_reserved_at IS NOT NULL)`, owner, ownerTeam).
				Scan(&consumed); err != nil || consumed {
				t.Fatalf("denied owner consumed or reserved credit = %t: %v", consumed, err)
			}
		})
	}
}

func TestIntegration_StripeDeviceDecisionUsesRetainedGrantHistory(t *testing.T) {
	for _, state := range []string{"granted", "pending", "released"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			tx := localIdentityTransaction(t, true)
			owner, recipient := uuid.New(), uuid.New()
			fingerprint := "visitor-" + uuid.NewString()
			for _, user := range []uuid.UUID{owner, recipient} {
				localIdentityWrite(t, tx, user, user.String()+"@example.com", true, time.Now(), time.Now())
				rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
					user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
			}
			// Model retained history from finalization before device-grant recording existed.
			rolloutExec(t, tx, `INSERT INTO promotion_identity_history(history_key,promotion,user_id,team_id,claimed_at,grant_state)
				VALUES($1,'stripe',$2,$3,now(),$4)`, "stripe-user:"+recipient.String(), recipient, uuid.New(), state)
			rolloutExec(t, tx, `DELETE FROM profile WHERE id=$1`, recipient)
			rolloutExec(t, tx, `SELECT set_promotion_device_policy(true,true)`)
			want := "eligible"
			if state == "granted" {
				want = "device_already_redeemed"
			}
			var result string
			if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'stripe')`, owner).
				Scan(&result); err != nil || result != want {
				t.Fatalf("decision with %s history = %q, want %q: %v", state, result, want, err)
			}
		})
	}
}
