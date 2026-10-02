//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_StripeSettledPromotionAmbiguousOwnerAllowsPaidUpdates(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	otherUser := uuid.New()
	rolloutExec(t, testPool, `INSERT INTO profile(id,email) VALUES($1,$2)`, otherUser, otherUser.String()+"@example.com")
	rolloutExec(t, testPool, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, teamID, otherUser)
	rolloutExec(t, testPool, `INSERT INTO user_role_assignments(team_id,user_id,role_id,scope_type)
		SELECT $1,$2,id,'team' FROM roles WHERE name='team_owner'`, teamID, otherUser)
	customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
	created := time.Now().UTC().Truncate(time.Second)
	grantedAt := created.Add(-24 * time.Hour)
	// Historical grants can lack activation provenance even when consumption is known.
	rolloutExec(t, testPool, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,
		stripe_subscription_status,stripe_activation_credit_grant_id,stripe_activation_credit_granted_at)
		VALUES($1,$2,$3,'paused',$4,$5)`, teamID, customerID, subscriptionID, "credgrant_"+teamID.String(), grantedAt)
	rolloutExec(t, testPool, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_by)
		VALUES($1,95,17,'stripe promotional credit',$2)`, teamID, userID)
	rolloutExec(t, testPool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
		VALUES($1,$2,$3)`, userID, grantedAt, teamID)
	snapshot := func() string {
		t.Helper()
		var state string
		if err := testPool.QueryRow(ctx, `SELECT jsonb_build_object(
			'activation', (SELECT jsonb_object_agg(key,value) FROM jsonb_each(to_jsonb(a))
				WHERE key LIKE 'stripe_activation_%'),
			'credits', (SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM team_credit_grant g WHERE g.team_id=$1),
			'entitlements', (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.user_id) FROM user_promotion_entitlement e
				WHERE e.user_id IN ($2,$3)),
			'device_grants', (SELECT jsonb_agg(to_jsonb(d) ORDER BY d.user_id,d.promotion) FROM promotion_device_grant d
				WHERE d.team_id=$1 OR d.user_id IN ($2,$3)))::text
			FROM team_billing_account a WHERE a.team_id=$1`, teamID, userID, otherUser).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := snapshot()
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	for i, transition := range []struct{ eventType, status string }{
		{"customer.subscription.updated", "active"},
		{"customer.subscription.paused", "paused"},
		{"customer.subscription.resumed", "active"},
	} {
		eventID := "evt_" + uuid.NewString()
		eventAt := created.Add(time.Duration(i) * time.Second)
		payload := stripeSubscriptionWebhookPayload(t, eventID, transition.eventType,
			subscriptionID, customerID, transition.status, eventAt, created, created.AddDate(0, 1, 0))
		for replay := 0; replay < 2; replay++ {
			req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Stripe-Signature", stripeSignature(t, payload, eventAt))
			if response := doRequest(router, req); response.Code != http.StatusOK {
				t.Fatalf("%s replay=%d: got %d: %s", transition.eventType, replay, response.Code, response.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || derefString(account.StripeSubscriptionStatus) != transition.status ||
				!account.TrialEndedAt.Valid || !account.CurrentPeriodStart.Valid || !account.CurrentPeriodEnd.Valid {
				t.Fatalf("paid transition not applied: account=%+v err=%v", account, err)
			}
			if snapshot() != before || len(stripe.creditGrantCalls) != 0 {
				t.Fatal("paid transition changed historical promotion state or issued another grant")
			}
		}
		var processed bool
		if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id=$1`,
			eventID).Scan(&processed); err != nil || !processed {
			t.Fatalf("transition not processed: processed=%v err=%v", processed, err)
		}
	}
}

func TestIntegration_StripeUnsettledPromotionRequiresActor(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	teamID := uuid.New()
	rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, teamID, "activation-"+teamID.String())
	rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id,stripe_subscription_status) VALUES($1,'active')`, teamID)
	for _, query := range []string{
		`SELECT activate_team_billing($1,NULL::uuid,'credgrant_unreserved')`,
		`SELECT activate_team_billing($1,'credgrant_unreserved')`,
		`SELECT finalize_stripe_promotion($1,NULL::uuid,'credgrant_unreserved')`,
	} {
		localIdentityError(t, tx, "55000", query, teamID)
	}
}

func TestIntegration_StripeActivationRequiresUnambiguousOwnerFallback(t *testing.T) {
	type member struct {
		legacyOwner  bool
		currentOwner bool
		revoked      bool
		inactive     bool
	}
	for _, tc := range []struct {
		name      string
		members   []member
		wantOwner int
	}{
		{name: "single member is not an actor", members: []member{{}}, wantOwner: -1},
		{name: "multiple members are not actors", members: []member{{}, {}}, wantOwner: -1},
		{name: "unique legacy owner", members: []member{{}, {legacyOwner: true}}, wantOwner: 1},
		{name: "unique current owner", members: []member{{}, {currentOwner: true}}, wantOwner: 1},
		{name: "matching owner across models", members: []member{{}, {legacyOwner: true, currentOwner: true}}, wantOwner: 1},
		{name: "multiple legacy owners", members: []member{{legacyOwner: true}, {legacyOwner: true}}, wantOwner: -1},
		{name: "multiple current owners", members: []member{{currentOwner: true}, {currentOwner: true}}, wantOwner: -1},
		{name: "conflicting owner models", members: []member{{legacyOwner: true}, {currentOwner: true}}, wantOwner: -1},
		{name: "revoked owner", members: []member{{currentOwner: true, revoked: true}, {}}, wantOwner: -1},
		{name: "inactive owner", members: []member{{currentOwner: true, inactive: true}, {}}, wantOwner: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			teamID := uuid.New()
			if _, err := testPool.Exec(ctx, `INSERT INTO team (id, name) VALUES ($1, $2)`, teamID, "activation-provenance-"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			users := make([]uuid.UUID, len(tc.members))
			for i, m := range tc.members {
				users[i] = uuid.New()
				if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, users[i], users[i].String()+"@example.com"); err != nil {
					t.Fatal(err)
				}
				if _, err := testPool.Exec(ctx, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, teamID, users[i]); err != nil {
					t.Fatal(err)
				}
				if m.legacyOwner {
					if _, err := testPool.Exec(ctx, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, teamID, users[i]); err != nil {
						t.Fatal(err)
					}
				}
				if m.currentOwner {
					if _, err := testPool.Exec(ctx, `INSERT INTO user_role_assignments (team_id, user_id, role_id, scope_type)
						SELECT $1, $2, id, 'team' FROM roles WHERE name = 'team_owner'`, teamID, users[i]); err != nil {
						t.Fatal(err)
					}
				}
				if m.revoked {
					if _, err := testPool.Exec(ctx, `UPDATE user_role_assignments SET revoked_at = now() WHERE team_id = $1 AND user_id = $2`, teamID, users[i]); err != nil {
						t.Fatal(err)
					}
				}
				if m.inactive {
					if _, err := testPool.Exec(ctx, `UPDATE team_memberships SET status = 'inactive' WHERE team_id = $1 AND user_id = $2`, teamID, users[i]); err != nil {
						t.Fatal(err)
					}
				}
			}
			customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
				VALUES ($1, $2, $3, 'incomplete')`, teamID, customerID, subscriptionID); err != nil {
				t.Fatal(err)
			}
			stripe := &fakeStripeClient{}
			router := newBillingRouter(t, stripe)
			now := time.Now().UTC().Truncate(time.Second)
			payload := stripeSubscriptionWebhookPayload(t, "evt_"+teamID.String(), "customer.subscription.updated", subscriptionID, customerID, "active", now, now, now.AddDate(0, 1, 0))
			for attempt := 0; attempt < 2; attempt++ {
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("activation attempt %d: %d %s", attempt, w.Code, w.Body.String())
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if derefString(account.StripeSubscriptionStatus) != "active" || !account.TrialEndedAt.Valid || !account.CurrentPeriodStart.Valid || !account.CurrentPeriodEnd.Valid {
				t.Fatalf("billing did not activate: %+v", account)
			}
			wantGrants := 0
			if tc.wantOwner >= 0 {
				wantGrants = 1
				if !account.StripeActivationUserID.Valid || uuid.UUID(account.StripeActivationUserID.Bytes) != users[tc.wantOwner] {
					t.Fatalf("promotion actor = %v, want %v", account.StripeActivationUserID, users[tc.wantOwner])
				}
			} else if account.StripeActivationUserID.Valid || account.StripeActivationCreditGrantedAt.Valid || account.StripeActivationCreditGrantID != nil {
				t.Fatalf("ambiguous activation attributed a promotion: %+v", account)
			}
			if len(stripe.creditGrantCalls) != wantGrants {
				t.Fatalf("Stripe grants = %d, want %d", len(stripe.creditGrantCalls), wantGrants)
			}
			for i, userID := range users {
				var redeemed, reserved bool
				if err := testPool.QueryRow(ctx, `SELECT
					EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL),
					EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id = $1 AND stripe_redemption_reserved_at IS NOT NULL)`, userID).Scan(&redeemed, &reserved); err != nil {
					t.Fatal(err)
				}
				if redeemed != (i == tc.wantOwner) || reserved {
					t.Fatalf("member %d entitlement: redeemed=%v reserved=%v, want redeemed=%v and no reservation", i, redeemed, reserved, i == tc.wantOwner)
				}
			}
		})
	}
}
