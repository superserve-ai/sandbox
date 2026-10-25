//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestFundingAccessSourcesAndFingerprint(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	eligible := func(want bool) {
		t.Helper()
		got, err := h.DB.IsTeamSandboxBillingEligible(ctx, team)
		if err != nil || got != want {
			t.Fatalf("eligible=%v want=%v error=%v", got, want, err)
		}
	}
	exec(`INSERT INTO team_billing_account(team_id,stripe_subscription_status,trial_ended_at) VALUES($1,'canceled',now())`, team)
	exec(`INSERT INTO billing_yc_operation(team_id,approved_by,evidence_reference,request,resource_terms,state,revoked_at,revoked_by) VALUES($1::uuid,'operator','fixture',jsonb_build_object('company_identity',$1::uuid::text),'{}','ended',now(),'operator')`, team)
	// Writers can prepare observations without changing existing enforcement.
	exec(`UPDATE billing_funding_account SET credit_usd=10,credit_valid_until=now()+interval '1 minute',observed_generation=generation WHERE team_id=$1`, team)
	eligible(false)
	exec(`UPDATE billing_funding_account SET observe=true,enforce=true WHERE team_id=$1`, team)
	exec(`UPDATE billing_funding_account SET observed_generation=generation WHERE team_id=$1`, team)
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, team)
	})
	eligible(true)
	exec(`UPDATE billing_funding_account SET credit_valid_until=now()-interval '1 second' WHERE team_id=$1`, team)
	eligible(false)
	// A reused or unknown device needs cash collection when relying on a card.
	exec(`UPDATE billing_funding_account SET payment_method_ready=true,collection_ready=true,provider_valid_until=now()+interval '5 minutes' WHERE team_id=$1`, team)
	eligible(false)
	actor, owner := uuid.New(), uuid.New()
	fingerprint := uuid.NewString()
	exec(`INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	exec(`UPDATE team_signup_trial_provenance SET creator_user_id=$2,creator_bound_at=now() WHERE team_id=$1`, team, actor)
	exec(`INSERT INTO promotion_device_owner(fingerprint,user_id) VALUES($1,$2)`, fingerprint, owner)
	exec(`INSERT INTO promotion_signup_device_evidence(user_id,source_attempt_id,source_event_id,fingerprint) VALUES($1,$2,$3,$4)`, actor, uuid.New(), uuid.NewString(), fingerprint)
	eligible(false)
	exec(`UPDATE billing_funding_account SET cash_collected=true WHERE team_id=$1`, team)
	eligible(true)
	exec(`UPDATE billing_funding_account SET cash_collected=false,credit_usd=1,credit_valid_until=now()+interval '1 minute',collection_ready=false WHERE team_id=$1`, team)
	eligible(true)
	// Explicit abuse blocks override both sources.
	exec(`INSERT INTO abuse_restrictions(subject_type,subject_value,subject_team_id,action,source,reason) VALUES('team',$1,$2,'create','operator','fixture')`, team.String(), team)
	eligible(false)
	exec(`UPDATE abuse_restrictions SET released_at=now() WHERE subject_team_id=$1`, team)
	eligible(true)
	// Old observations cannot authorize against a changed balance or mapping.
	exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,1,1,'fixture')`, team)
	eligible(false)
	exec(`UPDATE billing_funding_account SET observed_generation=generation WHERE team_id=$1`, team)
	eligible(true)
	exec(`UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, "cus_"+team.String())
	exec(`UPDATE billing_funding_account SET observed_generation=generation WHERE team_id=$1`, team)
	eligible(false)
}

func TestFundingAccessClearFingerprintCardAndFreshness(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	actor := uuid.New()
	exec(`INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
	exec(`UPDATE team_signup_trial_provenance SET creator_user_id=$2,creator_bound_at=now() WHERE team_id=$1`, team, actor)
	exec(`SELECT register_promotion_signup_device($1,$2,$3,$4)`, actor, uuid.New(), uuid.NewString(), uuid.NewString())
	exec(`INSERT INTO team_billing_account(team_id,stripe_subscription_status) VALUES($1,'active')`, team)
	exec(`UPDATE billing_funding_account SET observe=true,enforce=true,observed_generation=generation,payment_method_ready=true,collection_ready=true,provider_valid_until=now()+interval '5 minutes' WHERE team_id=$1`, team)
	exec(`UPDATE billing_funding_account SET observed_generation=generation WHERE team_id=$1`, team)
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, team)
	})
	got, err := h.DB.IsTeamSandboxBillingEligible(ctx, team)
	if err != nil || !got {
		t.Fatalf("verified card on clear device: %v %v", got, err)
	}
	exec(`UPDATE billing_funding_account SET provider_valid_until=now()-interval '1 second' WHERE team_id=$1`, team)
	got, err = h.DB.IsTeamSandboxBillingEligible(ctx, team)
	if err != nil || got {
		t.Fatalf("stale card observation: %v %v", got, err)
	}
}

func TestFundingCohortBudgetAndOptInInvalidation(t *testing.T) {
	h, first := fundingTransitionFixture(t)
	_, second := fundingTransitionFixture(t)
	ctx := t.Context()
	var budget int32
	if err := h.Pool.QueryRow(ctx, `SELECT max_observed_teams FROM billing_funding_policy WHERE singleton`).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_funding_policy SET max_observed_teams=1 WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=ANY($1::uuid[])`, []uuid.UUID{first, second})
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=$1 WHERE singleton`, budget)
	})
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_funding_account SET observed_generation=generation,credit_usd=1,credit_valid_until=now()+interval '1 minute' WHERE team_id=$1`, first); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_funding_account SET observe=true,enforce=true WHERE team_id=$1`, first); err != nil {
		t.Fatal(err)
	}
	allowed, err := h.DB.IsTeamSandboxBillingEligible(ctx, first)
	if err != nil || allowed {
		t.Fatalf("opt-in reused pre-cohort authority: %v %v", allowed, err)
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_funding_account SET observe=true WHERE team_id=$1`, second); err == nil {
		t.Fatal("cohort exceeded refresh budget")
	}
}

func TestFundingReconciliationNoOpsKeepUsableEvidence(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	customer, subscription := "cus_"+team.String(), "sub_"+team.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status) VALUES($1,$2,$3,'active')`, team, customer, subscription)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id) VALUES($1,$2,$3,'price_round','round','meter_round')`, team, customer, subscription)
	exec(`UPDATE billing_funding_account SET observe=true,enforce=true WHERE team_id=$1`, team)
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, team)
	})
	exec(`UPDATE billing_funding_account SET customer_id=$2,subscription_id=$3,observed_generation=generation,credit_usd=10,credit_valid_until=now()+interval '1 minute' WHERE team_id=$1`, team, customer, subscription)
	exec(`UPDATE team_billing_account SET stripe_subscription_status='active',stripe_subscription_event_at=now() WHERE team_id=$1`, team)
	exec(`UPDATE billing_invoice_account SET last_attempt_at=now(),last_error='retry' WHERE team_id=$1`, team)
	allowed, err := h.DB.IsTeamSandboxBillingEligible(ctx, team)
	if err != nil || !allowed {
		t.Fatalf("reconciliation invalidated unchanged authority: %v %v", allowed, err)
	}
	exec(`UPDATE billing_invoice_account SET adjustment_price_id='price_changed' WHERE team_id=$1`, team)
	allowed, err = h.DB.IsTeamSandboxBillingEligible(ctx, team)
	if err != nil || allowed {
		t.Fatalf("changed enrollment retained authority: %v %v", allowed, err)
	}
}
