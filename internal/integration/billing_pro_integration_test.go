//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type proProviderFixture struct {
	rounded, held                                  bool
	failEnrollment, failChargeLookup               bool
	holdResumesAt                                  int64
	creditNote, refund                             int64
	mu                                             sync.Mutex
	team                                           uuid.UUID
	customer, sub, session, offer, price, interval string
	amount                                         int64
	anchor, baseStart, baseEnd                     int64
	metadata                                       map[string]string
	status                                         string
	paid, failCreate                               bool
	rejection                                      int
	subStatus                                      string
	wrongRate, wrongMeter                          bool
	payOnTerminalInventory                         bool
	handlers                                       *api.Handlers
	creates                                        int
	keys                                           []string
}

func newProFixture(t *testing.T, offer string) (*proProviderFixture, *gin.Engine, string) {
	t.Helper()
	team, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
	f := &proProviderFixture{team: team, customer: "cus_" + team.String(), sub: "sub_" + team.String(), session: "cs_" + strings.ReplaceAll(team.String(), "-", ""), offer: offer, price: "price_" + offer, interval: "month", amount: 120000, status: "open"}
	anchor := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	f.anchor, f.baseStart, f.baseEnd = anchor.Unix(), anchor.Unix(), anchor.AddDate(0, 1, 0).Unix()
	if offer == "pro_annual" {
		f.interval = "year"
		f.amount = 1200000
		f.baseEnd = anchor.AddDate(1, 0, 0).Unix()
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	cfg := &config.Config{SystemTeamID: testSystemTeamID.String(), StripeSecretKey: "sk_test_example", StripeAPIBaseURL: srv.URL, StripeAPIVersion: "2026-07-29.dahlia", StripeWebhookSecret: testStripeWebhookSecret, StripeProMonthlyPriceID: "price_pro_monthly", StripeProAnnualPriceID: "price_pro_annual", StripeCheckoutPriceIDs: []string{"price_cpu", "price_memory", "price_storage"}, AppAllowedOrigins: []string{"https://app.superserve.test"}}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	h.Pool = testPool
	h.Stripe = api.NewStripeBillingClient(cfg)
	f.handlers = h
	return f, api.SetupRouter(t.Context(), h, testPool), key
}
func (f *proProviderFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	basePrice := map[string]any{"id": f.price, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": fmt.Sprint(f.amount), "recurring": map[string]any{"usage_type": "licensed", "interval": f.interval, "interval_count": 1}}
	switch {
	case r.URL.Path == "/v1/prices":
		write(map[string]any{"data": []any{map[string]any{"id": "price_round"}}})
	case r.URL.Path == "/v1/billing/credit_grants":
		write(map[string]any{"data": []any{}})
	case r.URL.Path == "/v1/subscription_items":
		if f.failEnrollment {
			http.Error(w, "injected enrollment failure", 500)
			return
		}
		f.rounded = true
		write(map[string]any{"id": "si_round"})
	case r.URL.Path == "/v1/subscriptions":
		write(map[string]any{"data": []any{map[string]any{"id": f.sub, "status": f.subscriptionStatus()}}})
	case r.URL.Path == "/v1/subscriptions/"+f.sub && r.Method == "POST":
		_ = r.ParseForm()
		f.held = r.Form.Get("pause_collection[behavior]") == "keep_as_draft"
		write(map[string]any{})
	case r.URL.Path == "/v1/prices/"+f.price:
		write(basePrice)
	case strings.HasPrefix(r.URL.Path, "/v1/prices/price_"):
		p := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
		write(map[string]any{"id": p, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": f.resourceRate(p), "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": f.resourceMeter(p)}})
	case r.URL.Path == "/v1/customers":
		write(map[string]any{"id": f.customer})
	case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
		_ = r.ParseForm()
		f.creates++
		f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
		if r.Form.Get("subscription_data[billing_mode][type]") != "flexible" {
			http.Error(w, "missing flexible billing", 400)
			return
		}
		f.metadata = map[string]string{}
		for _, k := range []string{"checkout_generation", "activation_user_id", "commercial_offer"} {
			f.metadata[k] = r.Form.Get("metadata[" + k + "]")
		}
		if f.rejection != 0 {
			http.Error(w, "rejected", f.rejection)
			return
		}
		if f.failCreate {
			http.Error(w, "lost response", 500)
			return
		}
		write(map[string]any{"id": f.session, "url": "https://checkout.stripe.test/example"})
	case r.URL.Path == "/v1/checkout/sessions/"+f.session+"/expire":
		f.status = "expired"
		write(map[string]any{"id": f.session})
	case r.URL.Path == "/v1/checkout/sessions/"+f.session:
		sub := ""
		paid := "unpaid"
		if f.status == "complete" {
			sub = f.sub
		}
		if f.paid {
			paid = "paid"
		}
		write(map[string]any{"id": f.session, "customer": f.customer, "client_reference_id": f.team.String(), "mode": "subscription", "status": f.status, "payment_status": paid, "subscription": sub, "metadata": f.metadata})
	case r.URL.Path == "/v1/subscriptions/"+f.sub:
		items := []any{map[string]any{"id": "si_base", "quantity": 1, "price": basePrice, "current_period_start": f.baseStart, "current_period_end": f.baseEnd}}
		resourcePrices := []string{"price_cpu", "price_memory", "price_storage"}
		if f.rounded {
			resourcePrices = append(resourcePrices, "price_round")
		}
		for _, p := range resourcePrices {
			items = append(items, map[string]any{"id": "si_" + p, "price": map[string]any{"id": p, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": f.resourceRate(p), "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": f.resourceMeter(p)}}, "current_period_start": f.anchor, "current_period_end": time.Unix(f.anchor, 0).UTC().AddDate(0, 1, 0).Unix()})
		}
		write(map[string]any{"id": f.sub, "latest_invoice": "in_" + strings.ReplaceAll(f.team.String(), "-", "") + fmt.Sprint(f.baseStart), "customer": f.customer, "status": f.subscriptionStatus(), "pause_collection": func() any {
			if f.held {
				return map[string]any{"behavior": "keep_as_draft", "resumes_at": f.holdResumesAt}
			}
			return nil
		}(), "start_date": f.anchor, "billing_cycle_anchor": f.anchor, "billing_mode": map[string]any{"type": "flexible"}, "metadata": f.metadata, "items": map[string]any{"data": items}})
	case r.URL.Path == "/v1/billing/meters":
		meters := []any{}
		for p, event := range map[string]string{"price_cpu": "cpu_vcpu_hours", "price_memory": "memory_gib_hours", "price_storage": "storage_gib_hours", "price_round": "invoice_rounding_cents_v1"} {
			meters = append(meters, map[string]any{"id": "meter_" + p, "event_name": event, "status": "active", "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
		}
		write(map[string]any{"data": meters})
	case r.URL.Path == "/v1/invoices":
		if f.payOnTerminalInventory && r.URL.Query().Get("status") == "" {
			f.paid = true
			f.payOnTerminalInventory = false
		}
		ids := []any{}
		if f.paid {
			ids = append(ids, map[string]any{"id": "in_" + strings.ReplaceAll(f.team.String(), "-", "") + fmt.Sprint(f.baseStart), "status": "paid", "amount_paid": f.amount})
		}
		write(map[string]any{"data": ids})
	case strings.HasPrefix(r.URL.Path, "/v1/invoices/in_"):
		invoiceStart, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/invoices/in_"+strings.ReplaceAll(f.team.String(), "-", "")), 10, 64)
		months := 1
		if f.interval == "year" {
			months = 12
		}
		invoiceEnd := time.Unix(invoiceStart, 0).UTC().AddDate(0, months, 0).Unix()
		write(map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/invoices/"), "customer": f.customer, "status": func() string {
			if f.paid {
				return "paid"
			}
			return "open"
		}(), "currency": "usd", "total": f.amount, "amount_due": f.amount, "ending_balance": 0, "amount_paid": f.amount, "amount_remaining": 0, "post_payment_credit_notes_amount": f.creditNote, "status_transitions": map[string]any{"paid_at": time.Now().Unix()}, "parent": map[string]any{"subscription_details": map[string]any{"subscription": f.sub}}, "lines": map[string]any{"data": []any{map[string]any{"quantity": 1, "amount": f.amount, "currency": "usd", "period": map[string]any{"start": invoiceStart, "end": invoiceEnd}, "pricing": map[string]any{"price_details": map[string]any{"price": f.price}}, "parent": map[string]any{"subscription_item_details": map[string]any{"subscription": f.sub}}}}}})
	case r.URL.Path == "/v1/invoice_payments":
		write(map[string]any{"data": []any{map[string]any{"id": "inpay_example", "invoice": r.URL.Query().Get("invoice"), "status": "paid", "currency": "usd", "amount_paid": f.amount, "payment": map[string]any{"type": "payment_intent", "payment_intent": "pi_example"}}}})
	case r.URL.Path == "/v1/payment_intents/pi_example":
		write(map[string]any{"id": "pi_example", "customer": f.customer, "status": "succeeded", "currency": "usd", "amount_received": f.amount, "latest_charge": "ch_example"})
	case r.URL.Path == "/v1/charges/ch_example":
		if f.failChargeLookup {
			http.Error(w, "injected charge lookup failure", 500)
			return
		}
		write(map[string]any{"id": "ch_example", "customer": f.customer, "payment_intent": "pi_example", "currency": "usd", "paid": true, "captured": true, "amount_captured": f.amount, "amount_refunded": f.refund})
	case r.URL.Path == "/v1/credit_notes":
		write(map[string]any{"data": []any{map[string]any{"status": "issued", "invoice": r.URL.Query().Get("invoice"), "customer": f.customer, "currency": "usd", "post_payment_amount": f.creditNote, "lines": map[string]any{"data": []any{map[string]any{"type": "invoice_line_item", "invoice_line_item": "il_base"}}}}}})
	default:
		http.Error(w, "unexpected provider request "+r.URL.Path, 500)
	}
}
func proCheckoutBody(offer string) string {
	return fmt.Sprintf(`{"offer":%q,"success_url":"https://app.superserve.test/success","cancel_url":"https://app.superserve.test/cancel"}`, offer)
}
func assertProResponse(t *testing.T, r *gin.Engine, key, path, body string, status int, contains string) {
	t.Helper()
	w := do(r, "POST", path, key, body)
	if w.Code != status || !strings.Contains(w.Body.String(), contains) {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
}
func TestIntegration_ProPaidActivationAndRenewal(t *testing.T) {
	for _, offer := range []string{"pro_monthly", "pro_annual"} {
		t.Run(offer, func(t *testing.T) {
			f, r, key := newProFixture(t, offer)
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 200, f.session)
			assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 409, "plan_conflict")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("free"), 409, "plan_conflict")
			f.mu.Lock()
			f.status = "complete"
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "payment_confirmation_pending")
			var active bool
			if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status='active')`, f.team).Scan(&active); err != nil || active {
				t.Fatalf("unpaid activation: %v %v", active, err)
			}
			f.mu.Lock()
			f.paid = true
			f.mu.Unlock()
			for range 2 {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			}
			var receipts int
			var ended, promo bool
			if err := testPool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1),trial_ended_at IS NOT NULL,stripe_activation_credit_grant_id IS NOT NULL OR stripe_activation_credit_reserved_at IS NOT NULL FROM team_billing_account WHERE team_id=$1`, f.team).Scan(&receipts, &ended, &promo); err != nil || receipts != 1 || !ended || promo {
				t.Fatalf("paid effects: receipts=%d ended=%v promotion=%v err=%v", receipts, ended, promo, err)
			}
			assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 409, "plan_conflict")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 409, "plan_conflict")
			// Paid future renewal is recorded once without changing the original anniversary.
			f.mu.Lock()
			f.baseStart = f.baseEnd
			if offer == "pro_annual" {
				f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(1, 0, 0).Unix()
			} else {
				f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
			}
			f.mu.Unlock()
			for range 2 {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			}
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&receipts); err != nil || receipts != 2 {
				t.Fatalf("renewal count=%d err=%v", receipts, err)
			}
		})
	}
}
func TestIntegration_ProUncertainAndSafeRestart(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.failCreate = true
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 202, "payment_confirmation_pending")
	assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 409, "plan_conflict")
	f.mu.Lock()
	f.failCreate = false
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{"restart":true}`, 200, "retryable")
	if len(f.keys) != 2 || f.keys[0] != f.keys[1] {
		t.Fatalf("recovery changed provider identity: %v", f.keys)
	}
	assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 200, "committed")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 409, "plan_conflict")
}
func TestIntegration_ProRejectsExistingAndCommittedFree(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			if existing {
				if _, err := testPool.Exec(t.Context(), `DELETE FROM billing_signup_choice WHERE team_id=$1`, f.team); err != nil {
					t.Fatal(err)
				}
			} else {
				assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 200, "committed")
			}
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 409, "plan_conflict")
			if f.creates != 0 {
				t.Fatal("created payment-capable session for ineligible customer")
			}
		})
	}
}

func (f *proProviderFixture) resourceRate(p string) string {
	if f.wrongRate && p == "price_cpu" {
		return "100"
	}
	return map[string]string{"price_cpu": "5.04", "price_memory": "1.62", "price_storage": "0.0108", "price_round": "1"}[p]
}
func (f *proProviderFixture) resourceMeter(p string) string {
	if f.wrongMeter && p == "price_cpu" {
		return "meter_other"
	}
	return "meter_" + p
}
func (f *proProviderFixture) subscriptionStatus() string {
	if f.subStatus != "" {
		return f.subStatus
	}
	return "active"
}

func TestIntegration_ProReviewRecoveryCases(t *testing.T) {
	t.Run("definitive rejection", func(t *testing.T) {
		f, r, key := newProFixture(t, "pro_monthly")
		f.rejection = 400
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 400, "checkout_rejected")
		assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 200, "committed")
	})
	t.Run("terminal unpaid", func(t *testing.T) {
		f, r, key := newProFixture(t, "pro_monthly")
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
		f.mu.Lock()
		f.status = "complete"
		f.subStatus = "incomplete_expired"
		f.mu.Unlock()
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{"restart":true}`, 200, "retryable")
		assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 200, "committed")
	})
	for _, wrong := range []string{"rate", "meter"} {
		t.Run("changed "+wrong, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
			f.mu.Lock()
			f.status = "complete"
			f.paid = true
			f.wrongRate = wrong == "rate"
			f.wrongMeter = wrong == "meter"
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
			var count int
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid resource contract accepted: %d %v", count, err)
			}
		})
	}
	t.Run("paid cancellation retains coverage", func(t *testing.T) {
		f, r, key := newProFixture(t, "pro_annual")
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
		f.mu.Lock()
		f.status = "complete"
		f.paid = true
		f.mu.Unlock()
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
		f.mu.Lock()
		f.subStatus = "canceled"
		f.mu.Unlock()
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{"restart":true}`, 200, "active")
		assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 409, "plan_conflict")
	})
	t.Run("missed webhook worker recovery", func(t *testing.T) {
		f, r, key := newProFixture(t, "pro_monthly")
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
		f.mu.Lock()
		f.status = "complete"
		f.paid = true
		f.mu.Unlock()
		// Give this owned fixture priority without contacting other fixture providers.
		if _, err := testPool.Exec(t.Context(), `UPDATE billing_signup_choice SET next_check_at=CASE WHEN team_id=$1 THEN '-infinity'::timestamptz ELSE 'infinity'::timestamptz END`, f.team); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f.handlers.StartProPaymentReconciliation(ctx)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var active bool
			err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status='active')`, f.team).Scan(&active)
			if err != nil {
				t.Fatal(err)
			}
			if active {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("worker did not recover the paid purchase")
	})
	t.Run("webhook retries failed local activation", func(t *testing.T) {
		f, r, key := newProFixture(t, "pro_monthly")
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
		f.mu.Lock()
		f.status = "complete"
		f.paid = true
		f.mu.Unlock()
		statement := fmt.Sprintf(`CREATE FUNCTION test_fail_pro_activation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.team_id='%s'::uuid AND NEW.trial_ended_at IS NOT NULL THEN RAISE EXCEPTION 'injected activation failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_fail_pro_activation BEFORE UPDATE ON team_billing_account FOR EACH ROW EXECUTE FUNCTION test_fail_pro_activation();`, f.team)
		if _, err := testPool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
		cleanup := func() {
			_, err := testPool.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_fail_pro_activation ON team_billing_account; DROP FUNCTION IF EXISTS test_fail_pro_activation();`)
			if err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(cleanup)
		payload := stripeInvoiceWebhookPayload(t, "evt_"+uuid.NewString(), "invoice.paid", f.customer, f.sub, "paid", time.Now())
		send := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", "/stripe/webhook", bytes.NewReader(payload))
			req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now()))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w
		}
		if w := send(); w.Code != 500 {
			t.Fatalf("expected failed transaction: %d %s", w.Code, w.Body.String())
		}
		var count int
		if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 1 {
			t.Fatalf("verified receipt was lost during failed activation: %d %v", count, err)
		}
		var observed bool
		if err := testPool.QueryRow(t.Context(), `SELECT paid_observed_at IS NOT NULL AND paid_observed_until>clock_timestamp() FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&observed); err != nil || !observed {
			t.Fatalf("paid activation failure lost monitoring evidence: %v %v", observed, err)
		}
		cleanup()
		for range 2 {
			if w := send(); w.Code != 200 {
				t.Fatalf("webhook recovery failed: %d %s", w.Code, w.Body.String())
			}
		}
		if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 1 {
			t.Fatalf("receipt convergence: %d %v", count, err)
		}
	})
}

func TestIntegration_ProPaymentDuringTerminalInventoryRemainsRecoverable(t *testing.T) {
	f, r, key := newProFixture(t, "pro_annual")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status = "complete"
	f.subStatus = "canceled"
	f.payOnTerminalInventory = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "payment_confirmation_pending")
	var scheduled bool
	if err := testPool.QueryRow(t.Context(), `SELECT isfinite(next_check_at) FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&scheduled); err != nil || !scheduled {
		t.Fatalf("late payment retired recovery: %v %v", scheduled, err)
	}
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	assertTerminalPaidPending(t, f)
}

func assertTerminalPaidPending(t *testing.T, f *proProviderFixture) {
	t.Helper()
	var preserved bool
	err := testPool.QueryRow(t.Context(), `SELECT c.status='pending' AND s.state='pending'
        AND s.last_error LIKE '%requires support%' AND a.trial_ended_at IS NULL
        AND s.paid_observed_at IS NOT NULL AND isfinite(s.next_check_at)
        AND (SELECT count(*) FROM billing_contract_payment WHERE contract_id=c.id)=1
        FROM billing_commercial_contract c JOIN billing_signup_choice s USING(team_id)
        JOIN team_billing_account a USING(team_id) WHERE c.team_id=$1`, f.team).Scan(&preserved)
	if err != nil || !preserved {
		t.Fatalf("terminal purchase lost payment or bypassed pending activation: %v %v", preserved, err)
	}
}

func TestIntegration_ProTerminalPaymentBeforeActivationRemainsFenced(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status, f.subStatus, f.paid = "complete", "canceled", true
	f.mu.Unlock()
	for range 2 {
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{"restart":true}`, 202, "payment_confirmation_pending")
		assertTerminalPaidPending(t, f)
	}
	assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 409, "plan_conflict")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 409, "plan_conflict")
}

func TestIntegration_ProCheckoutTermsSurviveConfigurationChange(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	// Simulate deployment of a new catalog while the original session is payable.
	f.handlers.Config.StripeCheckoutPriceIDs = []string{"price_new_cpu", "price_new_memory"}
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	poolConfig := testPool.Config()
	poolConfig.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	f.handlers.Pool, f.handlers.DB = pool, db.New(pool)
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	f.mu.Lock()
	protected := f.rounded && f.held
	f.mu.Unlock()
	if !protected {
		t.Fatal("frozen purchase did not install invoice protections")
	}
}

func TestIntegration_ProInvoiceWebhookPreservesStatus(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status = "complete"
	f.mu.Unlock()
	for _, tc := range []struct{ kind, status, subscription, want string }{
		{"invoice.payment_failed", "open", f.sub, "open"},
		{"invoice.finalized", "open", f.sub, "open"},
		{"invoice.paid", "paid", f.sub, "paid"},
		{"invoice.finalized", "open", f.sub, "paid"},
		{"invoice.payment_failed", "open", "sub_unrelated", "paid"},
	} {
		f.mu.Lock()
		f.paid = tc.want == "paid"
		f.mu.Unlock()
		payload := stripeInvoiceWebhookPayload(t, "evt_"+uuid.NewString(), tc.kind, f.customer, tc.subscription, tc.status, time.Now())
		req := httptest.NewRequest("POST", "/stripe/webhook", bytes.NewReader(payload))
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now()))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("invoice webhook failed: %d %s", w.Code, w.Body.String())
		}
		var status string
		if err := testPool.QueryRow(t.Context(), `SELECT stripe_invoice_status FROM team_billing_account WHERE team_id=$1`, f.team).Scan(&status); err != nil || status != tc.want {
			t.Fatalf("invoice status %q, want %q: %v", status, tc.want, err)
		}
	}
}

func TestIntegration_ProCachedPaymentsAreRevalidated(t *testing.T) {
	for _, adjustment := range []string{"credit_note", "refund"} {
		t.Run(adjustment, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
			f.mu.Lock()
			f.status, f.paid = "complete", true
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			if _, err := testPool.Exec(t.Context(), `UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=statement_timestamp(),collection_valid_until=statement_timestamp()+interval '5 minutes',collection_evidence='{"test":"collection"}',revision=revision+1 WHERE team_id=$1`, f.team); err != nil {
				t.Fatal(err)
			}
			eligible := func() bool {
				var v bool
				err := testPool.QueryRow(t.Context(), `SELECT billing_contract_eligible(c,p.service_period_start,p.service_period_end) FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE c.team_id=$1`, f.team).Scan(&v)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			if !eligible() {
				t.Fatal("verified receipt was not eligible")
			}
			f.mu.Lock()
			if adjustment == "credit_note" {
				f.creditNote = 100
			} else {
				f.refund = 100
			}
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
			if eligible() {
				t.Fatal("adjusted cached receipt still authorizes new credit")
			}
			var preserved bool
			if err := testPool.QueryRow(t.Context(), `SELECT c.status='active' AND a.trial_ended_at IS NOT NULL AND v.review_required AND (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1)=1 FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id JOIN billing_pro_payment_verification v USING(invoice_id) JOIN team_billing_account a ON a.team_id=c.team_id WHERE c.team_id=$1`, f.team).Scan(&preserved); err != nil || !preserved {
				t.Fatalf("review altered historical payment/activation: %v %v", preserved, err)
			}
			_, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency) SELECT c.team_id,c.id,p.id,c.entitlement_kind,p.service_period_start,p.service_period_end,c.entitlement_amount_cents,c.currency FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE c.team_id=$1`, f.team)
			if err == nil {
				t.Fatal("held payment authorized an entitlement claim")
			}
			if adjustment == "credit_note" {
				// A voided note restores provider evidence without replacing the receipt.
				f.mu.Lock()
				f.creditNote = 0
				f.mu.Unlock()
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
				if !eligible() {
					t.Fatal("cleared payment review did not restore eligibility")
				}
			}
		})
	}
}

func TestIntegration_ProPaymentReviewsDoNotStarveOtherPeriods(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status, f.paid = "complete", true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	f.mu.Lock()
	f.baseStart = f.baseEnd
	f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	f.mu.Lock()
	f.creditNote = 100
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	var count int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_payment_verification v JOIN billing_contract_payment p USING(invoice_id) WHERE p.team_id=$1 AND v.review_required`, f.team).Scan(&count); err != nil || count != 2 {
		t.Fatalf("one payment review starved another: %d %v", count, err)
	}
	f.mu.Lock()
	f.creditNote = 0
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_payment_verification v JOIN billing_contract_payment p USING(invoice_id) WHERE p.team_id=$1 AND v.review_required`, f.team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("reviews failed to converge independently: %d %v", count, err)
	}
}

func TestIntegration_ProPastDuePurchaseWaitsForActiveSubscription(t *testing.T) {
	f, r, key := newProFixture(t, "pro_annual")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status, f.paid, f.subStatus = "complete", true, "past_due"
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	var pending bool
	if err := testPool.QueryRow(t.Context(), `SELECT c.status='pending' AND a.trial_ended_at IS NULL AND s.state='pending' AND (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1)=1 FROM billing_commercial_contract c JOIN team_billing_account a USING(team_id) JOIN billing_signup_choice s USING(team_id) WHERE c.team_id=$1`, f.team).Scan(&pending); err != nil || !pending {
		t.Fatalf("past-due payment was lost or activated early: %v %v", pending, err)
	}
	f.mu.Lock()
	f.subStatus = "active"
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var queued bool
	if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1)`, f.team).Scan(&queued); err != nil || !queued {
		t.Fatalf("active purchase did not finish enrollment: %v %v", queued, err)
	}
}

func TestIntegration_ProActivationRequiresInvoiceProtection(t *testing.T) {
	for _, offer := range []string{"pro_monthly", "pro_annual"} {
		t.Run(offer, func(t *testing.T) {
			f, r, key := newProFixture(t, offer)
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 200, f.session)
			f.mu.Lock()
			f.status, f.paid = "complete", true
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			var enrolled bool
			if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1 AND subscription_id=$2)`, f.team, f.sub).Scan(&enrolled); err != nil || !enrolled {
				t.Fatalf("activated without durable enrollment: %v %v", enrolled, err)
			}
			f.mu.Lock()
			protected := f.held && f.rounded
			f.subStatus = "canceled"
			f.mu.Unlock()
			if !protected {
				t.Fatal("activated before installing provider protection")
			}
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1 AND subscription_id=$2)`, f.team, f.sub).Scan(&enrolled); err != nil || !enrolled {
				t.Fatalf("cancellation lost final-settlement enrollment: %v %v", enrolled, err)
			}
		})
	}
}

func TestIntegration_ProFailedEnrollmentPreservesPendingPurchase(t *testing.T) {
	for _, cancelPurchase := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_%v", cancelPurchase), func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_annual")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
			f.mu.Lock()
			f.status, f.paid, f.failEnrollment = "complete", true, true
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
			var pending bool
			if err := testPool.QueryRow(t.Context(), `SELECT c.status='pending' AND a.trial_ended_at IS NULL AND s.state='pending' AND (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1)=1 FROM billing_commercial_contract c JOIN team_billing_account a USING(team_id) JOIN billing_signup_choice s USING(team_id) WHERE c.team_id=$1`, f.team).Scan(&pending); err != nil || !pending {
				t.Fatalf("enrollment failure lost payment or activated early: %v %v", pending, err)
			}
			f.mu.Lock()
			f.failEnrollment = false
			if cancelPurchase {
				f.subStatus = "canceled"
			}
			f.mu.Unlock()
			if cancelPurchase {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
				assertTerminalPaidPending(t, f)
			} else {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			}
		})
	}
}

func TestIntegration_ProEnrollmentRetryRequiresFreshPayment(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status, f.paid, f.failEnrollment = "complete", true, true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	f.mu.Lock()
	f.failEnrollment, f.failChargeLookup = false, true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	assertProActivationPending(t, f)
	f.mu.Lock()
	f.failChargeLookup = false
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var receipts int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("payment duplicated during enrollment retry: %d %v", receipts, err)
	}
}

func assertProActivationPending(t *testing.T, f *proProviderFixture) {
	t.Helper()
	var pending bool
	if err := testPool.QueryRow(t.Context(), `SELECT c.status='pending' AND a.trial_ended_at IS NULL AND s.state='pending' AND (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1)=1 AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE team_id=$1) FROM billing_commercial_contract c JOIN team_billing_account a USING(team_id) JOIN billing_signup_choice s USING(team_id) WHERE c.team_id=$1`, f.team).Scan(&pending); err != nil || !pending {
		t.Fatalf("uncertain activation lost payment or ended trial: %v %v", pending, err)
	}
}

func TestIntegration_ProActivationRetryRechecksInvoiceProtection(t *testing.T) {
	for _, drift := range []string{"missing_hold", "resuming_hold", "missing_rounding"} {
		t.Run(drift, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
			f.mu.Lock()
			f.status, f.paid = "complete", true
			f.mu.Unlock()
			statement := fmt.Sprintf(`CREATE FUNCTION test_fail_pro_activation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.team_id='%s'::uuid AND NEW.trial_ended_at IS NOT NULL THEN RAISE EXCEPTION 'injected activation failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_fail_pro_activation BEFORE UPDATE ON team_billing_account FOR EACH ROW EXECUTE FUNCTION test_fail_pro_activation();`, f.team)
			if _, err := testPool.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
			cleanup := func() {
				if _, err := testPool.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_fail_pro_activation ON team_billing_account; DROP FUNCTION IF EXISTS test_fail_pro_activation();`); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(cleanup)
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
			cleanup()
			var enrolled bool
			if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1)`, f.team).Scan(&enrolled); err != nil || !enrolled {
				t.Fatalf("missing committed enrollment: %v %v", enrolled, err)
			}
			f.mu.Lock()
			switch drift {
			case "missing_hold":
				f.held = false
			case "resuming_hold":
				f.holdResumesAt = time.Now().Add(time.Hour).Unix()
			case "missing_rounding":
				f.rounded = false
			}
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
			assertProActivationPending(t, f)
			f.mu.Lock()
			f.held, f.rounded, f.holdResumesAt = true, true, 0
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
		})
	}
}
