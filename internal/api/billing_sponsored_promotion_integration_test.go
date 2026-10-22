//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestSponsoredPromotionRecovery(t *testing.T) {
	for _, scenario := range []string{"unused", "concurrent", "ambiguous_creation", "lost_void_response", "partial", "consumed", "reserved", "unknown", "invoice_applied", "unattempted", "unattempted_resume", "unattempted_stale", "wrong_mode", "missing_grant"} {
		t.Run(scenario, func(t *testing.T) {
			h, team := fundingTransitionFixture(t)
			ctx := t.Context()
			h.Config = &config.Config{TeamCreationRegion: "use"}
			actor, operator, sponsor := uuid.New(), uuid.New(), uuid.New()
			customer, subscription, event := "cus_"+team.String(), "sub_"+team.String(), "evt_"+team.String()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := h.Pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
			exec(`INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',date_trunc('second',clock_timestamp()))`, team, customer, subscription)
			exec(`INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,'customer.subscription.created','{}')`, event)
			var state string
			if err := h.Pool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`, team, actor, event, subscription).Scan(&state); err != nil || state != "acquired" {
				t.Fatalf("ordinary promotion reservation: %s %v", state, err)
			}
			grant := activationRevocationGrant(team)
			grant.ID, grant.Customer = "cred_"+team.String(), customer
			if !strings.HasPrefix(scenario, "unattempted") {
				_, err := h.DB.MarkStripePromotionAttempt(ctx, db.MarkStripePromotionAttemptParams{TeamID: pgtype.UUID{Bytes: team, Valid: true}, UserID: actor, EventID: &event})
				if err != nil {
					t.Fatal(err)
				}
				if scenario != "ambiguous_creation" && scenario != "missing_grant" {
					if err = h.DB.FinalizeStripePromotion(ctx, db.FinalizeStripePromotionParams{TeamID: team, UserID: actor, StripeGrantID: grant.ID}); err != nil {
						t.Fatal(err)
					}
				}
			}
			exec(`INSERT INTO billing_sponsored_operation(id,team_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id,state) VALUES($1,$2,'fixture','{}','{}',$3,'fixture','fixture',$4,$5,'active')`, sponsor, team, operator, customer, subscription)
			beforeAccount, err := h.DB.GetTeamBillingAccount(ctx, team)
			if err != nil {
				t.Fatal(err)
			}
			available, ledger := int64(9500), int64(9500)
			switch scenario {
			case "partial":
				available, ledger = 5000, 5000
			case "consumed":
				available, ledger = 0, 0
			case "reserved":
				available = 0
			case "unknown":
				grant.Metadata["activation_identity"] = "unrelated"
			}
			var mu sync.Mutex
			voids, expires := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
				switch {
				case r.URL.Path == "/v1/account":
					out(map[string]any{"id": "acct_fixture"})
				case strings.HasSuffix(r.URL.Path, "/void"):
					voids++
					if scenario == "invoice_applied" {
						http.Error(w, "grant previously applied to invoice", 400)
						return
					}
					stamp := time.Now().Unix()
					grant.VoidedAt = &stamp
					if scenario == "lost_void_response" {
						http.Error(w, "response lost", 500)
						return
					}
					out(grant)
				case strings.HasSuffix(r.URL.Path, "/expire"):
					expires++
					http.Error(w, "forbidden expiry", 500)
				case r.URL.Path == "/v1/billing/credit_grants":
					grants := []billing.StripeActivationGrant{grant}
					if scenario == "missing_grant" {
						grants = nil
					}
					out(map[string]any{"data": grants})
				case r.URL.Path == "/v1/billing/credit_grants/"+grant.ID:
					out(grant)
				case r.URL.Path == "/v1/billing/credit_balance_summary":
					if r.URL.Query().Get("filter[credit_grant]") != grant.ID || r.URL.Query().Get("customer") != customer {
						t.Error("balance read is not scoped to the owned grant")
					}
					out(map[string]any{"customer": customer, "balances": []any{map[string]any{"available_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": available}}, "ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": ledger}}}}})
				default:
					t.Errorf("unexpected provider request %s", r.URL)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
			live := false
			r := sponsoredPromotionRequest{Key: "recovery", Merchant: "acct_fixture", Live: &live, Customer: customer, Subscription: subscription, User: actor, Event: event, Reason: "approved unused activation recovery", Reference: "fixture"}
			if scenario == "wrong_mode" {
				wrong := true
				r.Live = &wrong
				if e := h.recoverSponsoredPromotion(ctx, team, sponsor, operator, r); e == nil {
					t.Fatal("wrong mode accepted")
				}
				var count int
				if e := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_sponsored_promotion_recovery WHERE team_id=$1`, team).Scan(&count); e != nil || count != 0 {
					t.Fatal("invalid input pinned recovery", count, e)
				}
				r.Live = &live
			}
			if scenario == "unattempted_resume" || scenario == "unattempted_stale" {
				raw, _ := json.Marshal(r)
				exec(`INSERT INTO billing_sponsored_promotion_recovery(team_id,sponsorship_id,idempotency_key,request,approved_by,reason,reference,customer_id,subscription_id,user_id,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, team, sponsor, r.Key, raw, operator, r.Reason, r.Reference, customer, subscription, actor, event)
				tx, e := h.Pool.Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				q := h.DB.WithTx(tx)
				if e = q.LockStripePromotion(ctx, db.LockStripePromotionParams{TeamID: team, UserID: actor}); e != nil {
					t.Fatal(e)
				}
				if _, e = q.LockTeamBillingAccount(ctx, team); e != nil {
					t.Fatal(e)
				}
				if scenario == "unattempted_stale" {
					a, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, &customer)
					if err != nil {
						t.Fatal(err)
					}
					e = h.settleStaleStripePromotion(ctx, tx, a, event, customer)
				} else {
					e = prepareStripePromotionGrant(ctx, tx, team, actor, event, customer)
				}
				if e != nil {
					t.Fatal("late unattempted webhook", e)
				}

				if e = tx.Commit(ctx); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "concurrent" {
				results := make(chan error, 2)
				for range 2 {
					go func() { results <- h.recoverSponsoredPromotion(ctx, team, sponsor, operator, r) }()
				}
				for range 2 {
					if e := <-results; e != nil {
						t.Fatal("concurrent recovery", e)
					}
				}
			}
			err = h.recoverSponsoredPromotion(ctx, team, sponsor, operator, r)
			wantSuccess := scenario == "unused" || scenario == "concurrent" || scenario == "ambiguous_creation" || scenario == "lost_void_response" || scenario == "wrong_mode" || strings.HasPrefix(scenario, "unattempted")
			if (err == nil) != wantSuccess {
				t.Fatalf("recovery: %v", err)
			}
			if wantSuccess {
				if err = h.recoverSponsoredPromotion(ctx, team, sponsor, operator, r); err != nil {
					t.Fatal("retry", err)
				}
				r.Reason = "different request"
				if err = h.recoverSponsoredPromotion(ctx, team, sponsor, operator, r); err == nil {
					t.Fatal("changed recovery terms accepted")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			wantVoids := 0
			if wantSuccess && !strings.HasPrefix(scenario, "unattempted") || scenario == "invoice_applied" {
				wantVoids = 1
			}
			if expires != 0 || voids != wantVoids {
				t.Fatalf("unexpected provider mutation: void=%d expire=%d", voids, expires)
			}
			after, err := h.DB.GetTeamBillingAccount(ctx, team)
			if err != nil || after.CommercialBillingAnchor != beforeAccount.CommercialBillingAnchor || derefString(after.StripeSubscriptionID) != subscription {
				t.Fatal("original association/calendar changed", err)
			}
			var auditCount int
			var auditDone, correctActor bool
			if err = h.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(bool_and(completed_at IS NOT NULL),false),COALESCE(bool_and(approved_by=$2),true) FROM billing_sponsored_promotion_recovery WHERE team_id=$1`, team, operator).Scan(&auditCount, &auditDone, &correctActor); err != nil || auditDone != wantSuccess || !correctActor {
				t.Fatal("audit state", auditCount, auditDone, err)
			}
			wantAudit := 0
			if wantSuccess || scenario == "invoice_applied" {
				wantAudit = 1
			}
			if auditCount != wantAudit {
				t.Fatal("unexpected recovery intent", auditCount)
			}

			if wantSuccess && !strings.HasPrefix(scenario, "unattempted") {
				var redeemed bool
				if err = h.Pool.QueryRow(ctx, `SELECT stripe_redemption_at IS NOT NULL FROM user_promotion_entitlement WHERE user_id=$1`, actor).Scan(&redeemed); err != nil || !redeemed || derefString(after.StripeActivationCreditGrantID) != grant.ID {
					t.Fatal("redemption history lost", err)
				}
			}
			if err = h.Pool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`, team, actor, "evt_late_"+team.String(), subscription).Scan(&state); err != nil || state == "acquired" {
				t.Fatal("late promotion acquired", state, err)
			}
		})
	}
}

func TestSponsoredPromotionFreshAndExpiredSuppression(t *testing.T) {
	for _, state := range []string{"approved", "active", "expired", "revoked", "revoked_unbound"} {
		t.Run(state, func(t *testing.T) {
			h, team := fundingTransitionFixture(t)
			ctx := t.Context()
			actor := uuid.New()
			if _, err := h.Pool.Exec(ctx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com"); err != nil {
				t.Fatal(err)
			}
			storedState := state
			if state == "revoked_unbound" {
				storedState = "revoked"
			}
			if _, err := h.Pool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id) VALUES($1,'cus_'||$1::uuid::text,'sub_'||$1::uuid::text)`, team); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_sponsored_operation(team_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id,state) VALUES($1,'fixture','{}','{}',$2,'fixture','fixture',CASE WHEN $4 THEN NULL ELSE 'cus_'||$1::uuid::text END,CASE WHEN $4 THEN NULL ELSE 'sub_'||$1::uuid::text END,$3)`, team, actor, storedState, state == "revoked_unbound"); err != nil {
				t.Fatal(err)
			}
			var got string
			want := "sponsored"
			if state == "revoked_unbound" {
				want = "acquired"
			}
			if err := h.Pool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'evt_fresh','sub_'||$1::uuid::text,NULL,false)`, team, actor).Scan(&got); err != nil || got != want {
				t.Fatal(got, err)
			}
			var reserved bool
			if err := h.Pool.QueryRow(ctx, `SELECT stripe_activation_credit_reserved_at IS NOT NULL FROM team_billing_account WHERE team_id=$1`, team).Scan(&reserved); err != nil || reserved != (want == "acquired") {
				t.Fatal("fresh grant reserved", err)
			}
		})
	}
}
