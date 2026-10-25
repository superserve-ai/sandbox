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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/config"
)

func TestReleasedProInvoiceIsDurableBeforeAcknowledgmentAndNewPurchaseDispatch(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	f.committedCheckout(t)
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_rounding','rounding','meter_rounding',clock_timestamp()-interval '2 months')`, f.team, f.stripe.customer, f.stripe.sub); err != nil {
		t.Fatal(err)
	}
	c, err := f.request(t, "starter", "released-invoice")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.status, s.endedAt = "canceled", time.Now().Add(-time.Minute).Unix() })
	f.tick(t)
	c = f.reload(t, c.ID)
	if c.State != "completed" {
		t.Fatalf("source release: %+v", c)
	}
	current := f.plan(t)
	var ended int64
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT (provider_evidence->'invoice_account'->'Base'->>'TerminatedAt')::bigint FROM billing_plan_release WHERE plan_change_id=$1`, c.ID).Scan(&ended); err != nil || ended != f.stripe.endedAt {
		t.Fatalf("release snapshot omitted provider termination: %d %v", ended, err)
	}
	id, eventID := "in_"+uuid.NewString(), "evt_"+uuid.NewString()
	object, _ := json.Marshal(map[string]any{"id": id, "customer": f.stripe.customer, "parent": map[string]any{"subscription_details": map[string]any{"subscription": f.stripe.sub}}})
	event := stripeEventEnvelope{ID: eventID, Type: "invoice.paid", Data: stripeEventEnvelopeData{Object: object}}
	payload, _ := json.Marshal(event)
	if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,$2,$3)`, event.ID, event.Type, payload); err != nil {
		t.Fatal(err)
	}
	newer := uuid.New()
	now := time.Now().UTC()
	if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,next_check_at) VALUES($1,$2,$3,$4,'pro_monthly','{}',$5,$5,$6,$5,12500,'infinity')`, newer, f.team, f.actor, f.stripe.customer, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	conn, err := f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `CREATE FUNCTION pg_temp.fail_released_invoice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected durable queue failure'; END $$;
 CREATE TRIGGER released_invoice_fault BEFORE INSERT ON billing_pro_released_invoice FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_released_invoice()`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(t.Context(), `DROP TRIGGER IF EXISTS released_invoice_fault ON billing_pro_released_invoice`)
	})
	handled, err := f.h.processProWebhook(t.Context(), event)
	if !handled || err == nil || !strings.Contains(err.Error(), "injected durable queue failure") {
		conn.Release()
		t.Fatalf("queue failure acknowledged: %v %v", handled, err)
	}
	if _, err = conn.Exec(t.Context(), `DROP TRIGGER released_invoice_fault ON billing_pro_released_invoice`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	conn.Release()
	var processed bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id=$1`, eventID).Scan(&processed); err != nil || processed {
		t.Fatalf("failed enqueue acknowledged: %v %v", processed, err)
	}
	for range 2 {
		if handled, err = f.h.processProWebhook(t.Context(), event); err != nil || !handled {
			t.Fatalf("released invoice: %v %v", handled, err)
		}
	}
	var safe bool
	err = f.h.Pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*)=1 FROM billing_pro_released_invoice WHERE invoice_id=$1 AND contract_id IS NOT NULL AND state='pending')
 AND (SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id=$2)
 AND (SELECT next_check_at='infinity'::timestamptz FROM billing_pro_upgrade WHERE id=$3)
 AND (SELECT stripe_subscription_id IS NULL FROM team_billing_account WHERE team_id=$4)
 AND (SELECT effective_to IS NULL FROM team_plan_assignment WHERE id=$5)`, id, eventID, newer, f.team, current.ID).Scan(&safe)
	if err != nil || !safe {
		t.Fatalf("invoice loss, duplicate or authority reactivation: %v %v", safe, err)
	}
	var before, after int64
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT revision FROM billing_pro_released_invoice WHERE invoice_id=$1`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_released_invoice SET state='recorded',receipt='{}',payment_reference='prior',credit_state='covered',verified_revision=revision,next_check_at='infinity' WHERE invoice_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if handled, err = f.h.processProWebhook(t.Context(), event); err != nil || !handled {
		t.Fatalf("later observation enqueue: %v %v", handled, err)
	}
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT revision,verified_revision<revision AND next_check_at<=clock_timestamp() AND receipt='{}'::jsonb FROM billing_pro_released_invoice WHERE invoice_id=$1`, id).Scan(&after, &safe); err != nil || !safe || after <= before {
		t.Fatalf("completed invoice observation lost: %d %d %v %v", before, after, safe, err)
	}

	if err = f.h.reconcileReleasedUsageInvoice(t.Context(), f.h.Stripe.(*stripeHTTPClient), id, f.team, after, proPaidInvoice{}); err == nil {
		t.Fatal("unseen usage invoice bypassed its missing frozen close plan")
	}

}

func TestReleasedProLateCashRetainsExpiredCreditLiabilityAndRepeatProvenance(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	f.committedCheckout(t)
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_signup_choice SET request_payload=jsonb_set(request_payload,'{PlanTerms}','{"Amount":25000,"Months":1,"Credit":25000}'::jsonb) WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	source := f.plan(t)
	c, err := f.request(t, "starter", "late-cash-release")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.status, s.endedAt = "canceled", time.Now().Add(-time.Minute).Unix() })
	f.tick(t)
	c = f.reload(t, c.ID)
	if c.State != "completed" {
		t.Fatalf("release: %+v", c)
	}
	current := f.plan(t)
	release, err := proReleaseForReentry(t.Context(), f.h.Pool, f.team, f.stripe.customer)
	if err != nil || release == nil {
		t.Fatalf("current released Starter blocks repeat proof: %v", err)
	}
	var start, end time.Time
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT billing_anniversary_boundary(entitlement_anchor,1),billing_anniversary_boundary(entitlement_anchor,2) FROM billing_commercial_contract WHERE id=$1`, source.ContractID).Scan(&start, &end); err != nil {
		t.Fatal(err)
	}
	if !end.Before(time.Now()) {
		t.Fatal("late credit fixture has not expired")
	}
	invoice := "in_" + uuid.NewString()
	intent, charge := "pi_"+uuid.NewString(), "ch_"+uuid.NewString()
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writes++
			t.Errorf("late recovery wrote provider: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		switch r.URL.Path {
		case "/v1/invoices/" + invoice:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","subtotal":25000,"total":25000,"amount_paid":25000,"amount_due":25000,"amount_remaining":0,"ending_balance":0,"status_transitions":{"paid_at":%d},"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"amount":25000,"quantity":1,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":"price_pro"}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, invoice, f.stripe.customer, time.Now().Unix(), f.stripe.sub, start.Unix(), end.Unix(), f.stripe.sub)
		case "/v1/invoice_payments":
			fmt.Fprintf(w, `{"data":[{"id":"inpay_fixture","invoice":%q,"status":"paid","currency":"usd","amount_paid":25000,"payment":{"type":"payment_intent","payment_intent":%q}}]}`, invoice, intent)
		case "/v1/payment_intents/" + intent:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"succeeded","currency":"usd","amount_received":25000,"latest_charge":%q}`, intent, f.stripe.customer, charge)
		case "/v1/charges/" + charge:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"payment_intent":%q,"currency":"usd","paid":true,"captured":true,"amount_captured":25000}`, charge, f.stripe.customer, intent)
		default:
			t.Errorf("unexpected provider request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f.h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	f.h.Config = &config.Config{StripeWebhookSecret: "whsec_fixture"}
	object, _ := json.Marshal(map[string]any{"id": invoice, "customer": f.stripe.customer, "parent": map[string]any{"subscription_details": map[string]any{"subscription": f.stripe.sub}}})
	event := stripeEventEnvelope{ID: "evt_" + uuid.NewString(), Type: "invoice.paid", Data: stripeEventEnvelopeData{Object: object}}
	payload, _ := json.Marshal(event)
	router := gin.New()
	router.POST("/stripe/webhook", f.h.HandleStripeWebhook)
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Stripe-Signature", stripeWebhookTestSignature(payload, time.Now().UTC(), "whsec_fixture"))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("durable late webhook: %d %s", response.Code, response.Body.String())
		}
	}
	for range 2 {
		err = f.h.reconcileReleasedProInvoice(t.Context(), f.h.Stripe.(*stripeHTTPClient), invoice)
		if err == nil || !strings.Contains(err.Error(), "requires operator resolution") {
			t.Fatalf("expired credit silently resolved: %v", err)
		}
	}
	var preserved bool
	err = f.h.Pool.QueryRow(t.Context(), `SELECT j.state='recorded' AND j.credit_state='review_required' AND j.last_error LIKE '%requires operator resolution%'
 AND j.receipt IS NOT NULL AND r.previous_choice->'request_payload'->'PlanTerms'->>'Credit'='25000'
 AND (SELECT count(*)=1 FROM billing_contract_payment WHERE invoice_id=$1)
 AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE contract_id=$2)
 AND (SELECT status='ended' FROM billing_commercial_contract WHERE id=$2)
 AND (SELECT stripe_subscription_id IS NULL AND trial_ended_at IS NOT NULL FROM team_billing_account WHERE team_id=$3)
 AND (SELECT effective_to IS NULL FROM team_plan_assignment WHERE id=$4)
 FROM billing_pro_released_invoice j JOIN billing_plan_release r ON r.id=j.release_id WHERE j.invoice_id=$1`, invoice, source.ContractID, f.team, current.ID).Scan(&preserved)
	if err != nil || !preserved || writes != 0 {
		t.Fatalf("late payment lost liability or reactivated authority: %v %v writes=%d", preserved, err, writes)
	}
	newer, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("free", planKindFree, 1, nil), Source: planSourcePlanChange, Reason: "newer independent assignment"})
	if err != nil {
		t.Fatal(err)
	}
	if newer.ID == current.ID {
		t.Fatal("fixture did not move assignment")
	}
	if release, err = proReleaseForReentry(t.Context(), f.h.Pool, f.team, f.stripe.customer); err != nil || release != nil {
		t.Fatalf("historical release authorized newer unrelated assignment: %v %v", release, err)
	}
}

func TestReleasedAnnualCashUsesOriginalMonthlyCreditExpiry(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	anchor := time.Now().UTC().AddDate(0, -2, 0).Truncate(time.Second)
	customer, sub := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, customer, sub, anchor); err != nil {
		t.Fatal(err)
	}
	contract := uuid.New()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_annual',$3,$4,$5,'price_annual',1200000,12,'metered_usage',100000,'monthly',$3)`, contract, team, anchor, customer, sub); err != nil {
		t.Fatal(err)
	}
	covered, expired, err := releasedProCreditCoverage(t.Context(), h.Pool, contract, anchor, 12, time.Now())
	if err != nil || covered || !expired {
		t.Fatalf("annual fee hid expired original monthly liability: covered=%v expired=%v err=%v", covered, expired, err)
	}
	covered, expired, err = releasedProCreditCoverage(t.Context(), h.Pool, contract, anchor, 12, anchor.Add(time.Hour))
	if err != nil || covered || expired {
		t.Fatalf("unexpired monthly liability classified incorrectly: covered=%v expired=%v err=%v", covered, expired, err)
	}
}
