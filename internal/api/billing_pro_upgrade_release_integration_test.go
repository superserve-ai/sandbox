//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProUpgradeReleaseVerifiesFrozenBaseAndRefreshesCashReview(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	anchor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := anchor.AddDate(0, 1, 0)
	u := proUpgrade{ID: uuid.New(), Team: team, Actor: uuid.New(), Customer: "cus_" + uuid.NewString(), Subscription: stringPtr("sub_" + uuid.NewString()), Offer: "pro_monthly", Anchor: anchor, Start: anchor, End: end, Quoted: now, Amount: 12500, Session: stringPtr("cs_" + strings.ReplaceAll(uuid.NewString(), "-", ""))}
	contract := uuid.New()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4) ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id=$2,stripe_subscription_id=$3,stripe_subscription_status='active',commercial_billing_anchor=$4`, team, u.Customer, *u.Subscription, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_monthly',$3,$4,$5,'price_pro',25000,1,'metered_usage',25000,'monthly',$3)`, contract, team, anchor, u.Customer, *u.Subscription); err != nil {
		t.Fatal(err)
	}
	params := StripeCreateCheckoutSessionParams{OperationID: u.ID, CustomerID: u.Customer, ClientReferenceID: team.String(), BasePriceID: "price_pro", Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}, PlanTerms: &StripeCheckoutPlanTerms{Amount: 25000, Months: 1, Credit: 25000}}
	payload, _ := json.Marshal(params)
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,session_id,payment_evidence,grant_id,contract_id,payment_review_required) VALUES($1,$2,$3,$4,$5,'pro_monthly',$6,$7,$7,$8,$9,12500,'active',$10,'{}',$11,$12,true)`, u.ID, team, u.Actor, u.Customer, *u.Subscription, payload, anchor, end, now, *u.Session, "cred_"+uuid.NewString(), contract); err != nil {
		t.Fatal(err)
	}
	var session StripeRetrievedCheckoutSession
	session.ID, session.Mode, session.CustomerID, session.ClientReferenceID, session.Status = *u.Session, "payment", u.Customer, team.String(), "complete"
	session.Currency, session.AmountSubtotal, session.AmountTotal, session.InvoiceID, session.PaymentStatus = "usd", u.Amount, 0, "in_"+uuid.NewString(), "no_payment_required"
	session.TotalDetails.Discount = u.Amount
	session.Metadata = map[string]string{"pro_upgrade_id": u.ID.String()}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/checkout/sessions/" + session.ID:
			_ = json.NewEncoder(w).Encode(session)
		case "/v1/invoices/" + session.InvoiceID:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","amount_paid":0,"amount_due":0,"amount_remaining":0,"ending_balance":0,"status_transitions":{"paid_at":%d},"lines":{"data":[{"amount":12500,"currency":"usd","quantity":1}]}}`, session.InvoiceID, u.Customer, now.Unix())
		case "/v1/customers/" + u.Customer:
			fmt.Fprintf(w, `{"id":%q}`, u.Customer)
		default:
			t.Errorf("unexpected provider path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	var sub invoiceSubscription
	if err := json.Unmarshal([]byte(`{"billing_mode":{"type":"flexible"},"items":{"data":[{"id":"si_base","quantity":1,"price":{"id":"price_pro","currency":"usd","unit_amount_decimal":"25000","billing_scheme":"per_unit","recurring":{"usage_type":"licensed","interval":"month","interval_count":1}}}]}}`), &sub); err != nil {
		t.Fatal(err)
	}
	sub.ID, sub.Customer, sub.Status = *u.Subscription, u.Customer, "canceled"
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	wrong := sub
	wrong.Items.Data = nil
	if _, err = h.proUpgradeRelease(t.Context(), tx, teamPlanChange{Team: team}, teamPlan{ContractID: &contract}, wrong); err == nil {
		t.Fatal("missing frozen licensed item accepted")
	}
	evidence, err := h.proUpgradeRelease(t.Context(), tx, teamPlanChange{Team: team}, teamPlan{ContractID: &contract}, sub)
	if err != nil || evidence == nil {
		t.Fatalf("verified upgrade release: %v", err)
	}
	var cleared bool
	if err = tx.QueryRow(t.Context(), `SELECT NOT payment_review_required AND payment_review_checked_at IS NOT NULL FROM billing_pro_upgrade WHERE id=$1`, u.ID).Scan(&cleared); err != nil || !cleared {
		t.Fatalf("stale review flag survives fresh source proof: %v %v", cleared, err)
	}
}
