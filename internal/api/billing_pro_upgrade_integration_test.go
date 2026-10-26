//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestProUpgradeRecurringReplayKeepsFutureContractAndLimits(t *testing.T) {
	testProUpgradeFutureCredit(t, 25000)
}

func TestProUpgradeFutureContractFreezesIndependentMonthlyCredit(t *testing.T) {
	for _, credit := range []int64{50000, 10000, 1} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) { testProUpgradeFutureCredit(t, credit) })
	}
}

func testProUpgradeFutureCredit(t *testing.T, monthlyCredit int64) {
	h, team := newPlanAssignmentFixture(t)
	cfg := h.Pool.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.Pool, h.DB = pool, db.New(pool)
	now := time.Now().UTC().Truncate(time.Second)
	anchor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := anchor.AddDate(0, 1, 0)
	h.Now = func() time.Time { return now }
	if _, err = h.Pool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version='v2' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	})
	key := publishProCreditTestOffer(t, h, monthlyCredit)
	terms, err := h.planTermsForPricingVersion(t.Context(), key, "v2")
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_upgrade", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Limits: &terms.Limits, Grants: terms.Grants, Allowance: terms.Allowance, PricingV2: true}
	u := proUpgrade{ID: uuid.New(), Team: team, Actor: uuid.New(), Customer: "cus_" + uuid.NewString(), Subscription: stringPtr("sub_" + uuid.NewString()), Offer: offer.Key, Anchor: anchor, Start: anchor, End: end, Quoted: now, Amount: 12500, Grant: stringPtr("grant_" + uuid.NewString())}
	initial, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 2, nil), Source: "signup", Reason: "accepted Free predecessor"})
	if err != nil {
		t.Fatal(err)
	}
	u.InitialAssignment = &initial.ID
	if monthlyCredit != 25000 {
		u.BridgeCredit = ptrProCredit(monthlyCredit / 2)
	}
	if monthlyCredit == 1 {
		u.Grant = nil
	}
	params := StripeCreateCheckoutSessionParams{OperationID: u.ID, CustomerID: u.Customer, ClientReferenceID: team.String(), BasePriceID: offer.Price, AllowPromotionCodes: true, Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}, PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants, PredecessorKnown: true, InitialAssignment: u.InitialAssignment}}
	u.Payload, _ = json.Marshal(params)
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO billing_signup_choice(team_id,state) VALUES($1,'selecting') ON CONFLICT(team_id) DO NOTHING`, team); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO profile(id,email,provider) VALUES($1,$2,'google')`, u.Actor, u.Actor.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, u.Actor); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO user_role_assignments(team_id,user_id,scope_type,role_id) SELECT $1,$2,'team',id FROM roles WHERE name='team_owner'`, team, u.Actor); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'tenant_usage_dashboard',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team); err != nil {
		t.Fatal(err)
	}
	token := uuid.New()
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4) ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id=$2,stripe_subscription_id=$3,stripe_subscription_status='active',commercial_billing_anchor=$4`, team, u.Customer, *u.Subscription, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,grant_id,payment_evidence,bridge_credit_cents) VALUES($1,$2,$3,$4,$5,$6,$12,$7,$7,$8,$9,12500,'credited',$10,'{}',$11)`, u.ID, team, u.Actor, u.Customer, *u.Subscription, offer.Key, anchor, end, now, u.Grant, u.BridgeCredit, u.Payload); err != nil {
		t.Fatal(err)
	}
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(t.Context(), db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token}); err != nil {
		t.Fatal(err)
	}
	var sub invoiceSubscription
	sub.ID, sub.Customer, sub.Status, sub.DefaultPaymentMethod = *u.Subscription, u.Customer, "active", "pm_example"
	sub.BillingMode.Type = "flexible"
	sub.StartDate, sub.BillingCycleAnchor = anchor.Unix(), end.Unix()
	if err = json.Unmarshal([]byte(`{"behavior":"keep_as_draft"}`), &sub.PauseCollection); err != nil {
		t.Fatal(err)
	}
	base := invoiceSubscriptionItem{ID: "si_base", Created: now.Unix(), Quantity: 1, Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}}
	if err = json.Unmarshal([]byte(`{"id":"price_upgrade","currency":"usd","unit_amount_decimal":"25000","billing_scheme":"per_unit","recurring":{"usage_type":"licensed","interval":"month","interval_count":1}}`), &base.Price); err != nil {
		t.Fatal(err)
	}
	base.Price.UnitAmountDecimal = fmt.Sprint(offer.Amount)
	resource := invoiceSubscriptionItem{ID: "si_cpu", Start: anchor.Unix(), End: end.Unix()}
	resource.Price.ID = "price_cpu"
	sub.Items.Data = []invoiceSubscriptionItem{base, resource}
	requests := 0
	invoice, intent, charge := "in_"+uuid.NewString(), "pi_"+uuid.NewString(), "ch_"+uuid.NewString()
	u.Session = stringPtr("cs_fixture" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	session := StripeRetrievedCheckoutSession{ID: *u.Session, Mode: "payment", CustomerID: u.Customer, ClientReferenceID: team.String(), Status: "complete", PaymentStatus: "paid", Currency: "usd", AmountSubtotal: u.Amount, AmountTotal: u.Amount, InvoiceID: invoice, PaymentIntentID: intent, Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}}
	var grant entitlementGrant
	grant.ID, grant.Customer, grant.Category, grant.Priority = derefString(u.Grant), u.Customer, "paid", 50
	grant.Amount.Type, grant.Amount.Monetary.Currency, grant.Amount.Monetary.Value = "monetary", "usd", u.bridgeCreditAmount()
	grant.Applicability.Scope.PriceType = "metered"
	grant.Metadata = map[string]string{"pro_upgrade_id": u.ID.String()}
	grant.EffectiveAt = now.Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/subscriptions/"+sub.ID && (monthlyCredit == 1 || monthlyCredit == 50000) {
			_ = r.ParseForm()
			sub.CancelAtPeriodEnd = r.Form.Get("cancel_at_period_end") == "true"
			sub.Metadata = map[string]string{"plan_change_cancellation": r.Form.Get("metadata[plan_change_cancellation]")}
			_ = json.NewEncoder(w).Encode(sub)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("replay mutated provider: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/checkout/sessions/" + session.ID:
			_ = json.NewEncoder(w).Encode(session)
		case "/v1/invoices":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/v1/subscriptions/" + sub.ID:
			requests++
			_ = json.NewEncoder(w).Encode(sub)
		case "/v1/invoices/" + invoice:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","amount_paid":12500,"amount_due":12500,"amount_remaining":0,"ending_balance":0,"status_transitions":{"paid_at":%d},"lines":{"data":[{"amount":12500,"currency":"usd","quantity":1}]}}`, invoice, u.Customer, now.Unix())
		case "/v1/payment_intents/" + intent:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"succeeded","currency":"usd","amount_received":12500,"latest_charge":%q,"payment_method":"pm_example","setup_future_usage":"off_session","metadata":{"pro_upgrade_id":%q}}`, intent, u.Customer, charge, u.ID.String())
		case "/v1/charges/" + charge:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"payment_intent":%q,"currency":"usd","paid":true,"captured":true,"amount_captured":12500}`, charge, u.Customer, intent)
		case "/v1/payment_methods/pm_example":
			fmt.Fprintf(w, `{"id":"pm_example","customer":%q,"type":"card"}`, u.Customer)
		case "/v1/billing/credit_grants/" + grant.ID:
			_ = json.NewEncoder(w).Encode(grant)
		default:
			t.Errorf("unexpected provider read %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	h.Stripe = client
	conn, err := h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if conn != nil {
			conn.Release()
		}
	}()
	assertView := func(key string, max int32) {
		t.Helper()
		conn.Release()
		conn = nil
		router := gin.New()
		router.GET("/billing/plan", func(c *gin.Context) { c.Set("team_id", team.String()); c.Set("actor_id", u.Actor); h.GetBillingPlan(c) })
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/billing/plan", nil))
		var wire struct {
			Plan   *customerPlan         `json:"plan"`
			Period customerBillingPeriod `json:"period"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.Plan == nil || wire.Plan.PlanKey != key || wire.Plan.Limits.MaxConcurrent == nil || *wire.Plan.Limits.MaxConcurrent != max || !wire.Period.Start.Equal(anchor) || !wire.Period.End.Equal(end) {
			t.Fatalf("paid plan wire mismatch: %d %s", response.Code, response.Body.String())
		}
		var acquireErr error
		conn, acquireErr = h.Pool.Acquire(t.Context())
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
	}
	method, evidence, err := h.verifyProUpgradePayment(t.Context(), conn, client, u, session, true)
	if err != nil || method != "pm_example" {
		t.Fatalf("one-off provider payment proof: %s %v", method, err)
	}
	if _, err = conn.Exec(t.Context(), `UPDATE billing_pro_upgrade SET payment_evidence=$2,payment_method_id=$3,session_id=$4 WHERE id=$1`, u.ID, evidence, method, u.Session); err != nil {
		t.Fatal(err)
	}
	if err = h.issueProUpgradeCredit(t.Context(), conn, &u, client); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `CREATE FUNCTION pg_temp.reject_pro_assignment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source='checkout' THEN RAISE EXCEPTION 'injected assignment failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER pro_assignment_fault BEFORE INSERT ON team_plan_assignment FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_pro_assignment()`); err != nil {
		t.Fatal(err)
	}
	if err = h.commitProUpgrade(t.Context(), conn, &u, sub, offer, "pm_example", client, token); err == nil {
		t.Fatal("assignment failure committed paid authority")
	}
	if _, err = conn.Exec(t.Context(), `DROP TRIGGER pro_assignment_fault ON team_plan_assignment`); err != nil {
		t.Fatal(err)
	}
	var rolledBack bool
	if err = conn.QueryRow(t.Context(), `SELECT NOT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1) AND EXISTS(SELECT 1 FROM team_plan_assignment WHERE id=$2 AND effective_to IS NULL) AND (SELECT max_sandboxes=2 FROM team WHERE id=$1)`, team, initial.ID).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatalf("partial paid activation: %v %v", rolledBack, err)
	}
	var paidDurable bool
	if err = conn.QueryRow(t.Context(), `SELECT u.payment_evidence->'Invoice'->>'id'=$2 AND ((u.grant_id=$3 AND p.expires_at=0) OR (u.bridge_credit_cents=0 AND u.grant_id IS NULL)) FROM billing_pro_upgrade u LEFT JOIN billing_provider_credit p ON p.customer_id=u.customer_id AND p.grant_id=u.grant_id WHERE u.id=$1`, u.ID, invoice, u.Grant).Scan(&paidDurable); err != nil || !paidDurable {
		t.Fatalf("activation rollback lost verified payment/credit: %v %v", paidDurable, err)
	}
	assertView("free", 2)
	for range 2 {
		if err = h.commitProUpgrade(t.Context(), conn, &u, sub, offer, "pm_example", client, token); err != nil {
			t.Fatal(err)
		}
	}
	assertView(offer.Key, *terms.Limits.MaxConcurrent)
	var frozenCredit int64
	if err = conn.QueryRow(t.Context(), `SELECT entitlement_amount_cents FROM billing_commercial_contract WHERE id=$1`, u.Contract).Scan(&frozenCredit); err != nil || frozenCredit != monthlyCredit {
		t.Fatalf("future monthly credit: %d %v", frozenCredit, err)
	}
	var starts, storedAnchor time.Time
	var state string
	var assignments int
	if err = conn.QueryRow(t.Context(), `SELECT starts_at,entitlement_anchor,status FROM billing_commercial_contract WHERE id=$1`, u.Contract).Scan(&starts, &storedAnchor, &state); err != nil {
		t.Fatal(err)
	}
	if !starts.Equal(end) || !storedAnchor.Equal(anchor) || state != "pending" {
		t.Fatalf("premature or moved contract: %s %s %s", starts, storedAnchor, state)
	}
	if _, err = conn.Exec(t.Context(), `UPDATE team SET home_region='use' WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	var reportAt time.Time
	if err = conn.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&reportAt); err != nil {
		t.Fatal(err)
	}
	bridgeTeams := func() int64 {
		t.Helper()
		var count int64
		if err := conn.QueryRow(t.Context(), `SELECT COALESCE(sum(count),0)::bigint FROM (`+mrrContractGroupsQuery+`) groups WHERE offer_key=$4`, reportAt, "use", "", offer.Key).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	beforeActivation := bridgeTeams()
	// The reconciliation completion records the paid upgrade as active while
	// its producer-created recurring contract stays pending until renewal.
	conn.Release()
	conn = nil
	if _, _, e := h.planChangeSubscription(t.Context(), team, *u.Contract); e == nil {
		t.Fatal("unactivated pending contract admitted for downgrade")
	}
	if outcome, e := h.activateProUpgrade(t.Context(), u, params); e != nil || outcome != "active" {
		t.Fatalf("activation: %s %v", outcome, e)
	}
	conn, err = h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := bridgeTeams(); got != beforeActivation+1 {
		t.Fatalf("producer-created pending contract and pro_monthly assignment omitted from MRR: before=%d after=%d", beforeActivation, got)
	}
	if err = conn.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_assignment WHERE team_id=$1`, team).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	if assignments != 2 || requests != 3 {
		t.Fatalf("replay duplicated assignment or mutation: assignments=%d reads=%d", assignments, requests)
	}
	var max int32
	if err = conn.QueryRow(t.Context(), `SELECT max_sandboxes FROM team WHERE id=$1`, team).Scan(&max); err != nil {
		t.Fatal(err)
	}
	if max != *terms.Limits.MaxConcurrent {
		t.Fatalf("paid limits delayed: %d", max)
	}
	if monthlyCredit == 1 || monthlyCredit == 50000 {
		conn.Release()
		conn = nil
		if err = h.DB.ReleaseStripeWebhookProcessingLease(t.Context(), db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token}); err != nil {
			t.Fatal(err)
		}
		testProUpgradeReleaseReentry(t, h, team, u, &sub, monthlyCredit)
		return
	}
	tx, e := conn.Begin(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	newer, e := assignTeamPlan(t.Context(), tx, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 1, nil), Source: "plan_change", Reason: "later Free"})
	if e != nil {
		tx.Rollback(t.Context())
		t.Fatal(e)
	}
	if e = tx.Commit(t.Context()); e != nil {
		t.Fatal(e)
	}
	if err = h.commitProUpgrade(t.Context(), conn, &u, sub, offer, "pm_example", client, token); err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err = conn.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE id=$1 AND effective_to IS NULL) AND (SELECT max_sandboxes=1 FROM team WHERE id=$2)`, newer.ID, team).Scan(&retained); err != nil || !retained {
		t.Fatalf("replay overwrote newer plan: %v %v", retained, err)
	}
	assertView("free", 1)
	if _, err = conn.Exec(context.WithoutCancel(t.Context()), `SELECT 1`); err != nil {
		t.Fatal(err)
	}
}

func TestProUpgradeCreditRecoversLostAcknowledgmentWithoutExpiry(t *testing.T) {
	for _, credit := range []*int64{nil, ptrProCredit(25000), ptrProCredit(5000), ptrProCredit(0)} {
		label := "legacy"
		if credit != nil {
			label = fmt.Sprint(*credit)
		}
		t.Run(label, func(t *testing.T) { testProUpgradeCreditRecovery(t, credit) })
	}
}

func ptrProCredit(n int64) *int64 { return &n }

func testProUpgradeCreditRecovery(t *testing.T, credit *int64) {
	h, team := newPlanAssignmentFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	u := proUpgrade{ID: uuid.New(), Team: team, Actor: uuid.New(), Customer: "cus_" + uuid.NewString(), Offer: "pro_monthly", Anchor: now, Start: now, End: now.Add(24 * time.Hour), Quoted: now, Amount: 12500, BridgeCredit: credit}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence,bridge_credit_cents) VALUES($1,$2,$3,$4,$5,'{}',$6,$6,$7,$6,$8,'paid','{}',$9)`, u.ID, team, u.Actor, u.Customer, u.Offer, now, u.End, u.Amount, credit); err != nil {
		t.Fatal(err)
	}
	loaded, err := h.proUpgrade(t.Context(), team)
	if err != nil {
		t.Fatal(err)
	}
	u = loaded
	if _, err = h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade SET bridge_credit_cents=COALESCE(bridge_credit_cents,0)+1 WHERE id=$1`, u.ID); err == nil {
		t.Fatal("repriced an accepted credit quote")
	}
	var g entitlementGrant
	g.ID, g.Customer, g.Category, g.Priority = "cred_"+uuid.NewString(), u.Customer, "paid", 50
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", u.bridgeCreditAmount()
	g.Applicability.Scope.PriceType = "metered"
	g.Metadata = map[string]string{"pro_upgrade_id": u.ID.String()}
	g.EffectiveAt = now.Unix()
	cash := int64(6250)
	if credit != nil && *credit > u.Amount {
		cash = 0
	}
	invoice := "in_" + uuid.NewString()
	session := StripeRetrievedCheckoutSession{Currency: "usd", AmountSubtotal: u.Amount, AmountTotal: cash, PaymentStatus: "paid", InvoiceID: invoice, PaymentIntentID: "pi_fixture"}
	session.TotalDetails.Discount = u.Amount - cash
	creates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/invoices/" + invoice:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","amount_paid":%d,"amount_due":%d,"amount_remaining":0,"ending_balance":0,"status_transitions":{"paid_at":%d},"lines":{"data":[{"amount":%d,"currency":"usd","quantity":1}]}}`, invoice, u.Customer, cash, cash, now.Unix(), u.Amount)
		case "/v1/payment_intents/pi_fixture":
			fmt.Fprintf(w, `{"id":"pi_fixture","customer":%q,"status":"succeeded","currency":"usd","amount_received":%d,"latest_charge":"ch_fixture","payment_method":"pm_fixture","setup_future_usage":"off_session","metadata":{"pro_upgrade_id":%q}}`, u.Customer, cash, u.ID.String())
		case "/v1/charges/ch_fixture":
			fmt.Fprintf(w, `{"id":"ch_fixture","customer":%q,"payment_intent":"pi_fixture","currency":"usd","paid":true,"captured":true,"amount_captured":%d}`, u.Customer, cash)
		case "/v1/customers/" + u.Customer:
			fmt.Fprintf(w, `{"id":%q,"invoice_settings":{"default_payment_method":"pm_fixture"}}`, u.Customer)
		case "/v1/invoices":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/v1/billing/credit_grants":
			if r.Method == http.MethodPost {
				creates++
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Has("expires_at") || r.Form.Get("category") != "paid" || r.Form.Get("amount[monetary][value]") != fmt.Sprint(u.bridgeCreditAmount()) || r.Form.Get("applicability_config[scope][price_type]") != "metered" {
					t.Error("credit is expiring, promotional, or mismatched")
				}
				http.Error(w, "lost acknowledgement", 503)
			} else if creates == 0 {
				_, _ = w.Write([]byte(`{"data":[]}`))
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []entitlementGrant{g}})
			}
		case "/v1/billing/credit_grants/" + g.ID:
			_ = json.NewEncoder(w).Encode(g)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	if method, _, err := client.verifyProUpgradePayment(t.Context(), u, session, false); err != nil || method != "pm_fixture" {
		t.Fatalf("coupon cash proof: %s %v", method, err)
	}
	conn, release, err := h.proUpgradeInvoiceLock(t.Context(), team)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err = h.issueProUpgradeCredit(t.Context(), conn, &u, client); u.bridgeCreditAmount() > 0 && err == nil {
		t.Fatal("expected lost acknowledgement")
	}
	u.Grant = nil
	if err = h.issueProUpgradeCredit(t.Context(), conn, &u, client); err != nil {
		t.Fatal(err)
	}
	if u.bridgeCreditAmount() == 0 {
		if creates != 0 {
			t.Fatal("zero credit called provider")
		}
		var credited bool
		if err = conn.QueryRow(t.Context(), `SELECT state='credited' AND grant_id IS NULL AND bridge_credit_cents=0 FROM billing_pro_upgrade WHERE id=$1`, u.ID).Scan(&credited); err != nil || !credited {
			t.Fatalf("zero credit lacks durable proof: %v %v", credited, err)
		}
		return
	}
	if creates != 1 {
		t.Fatalf("duplicate paid credit: %d", creates)
	}
	var expires int64
	if err = conn.QueryRow(t.Context(), `SELECT expires_at FROM billing_provider_credit WHERE customer_id=$1 AND grant_id=$2`, u.Customer, g.ID).Scan(&expires); err != nil || expires != 0 {
		t.Fatalf("non-expiring credit inventory: %d %v", expires, err)
	}
}

func TestProUpgradePaymentReviewSurvivesProviderFailure(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	u := proUpgrade{ID: uuid.New(), Team: team, Actor: uuid.New(), Customer: "cus_" + uuid.NewString(), Session: stringPtr("cs_example_" + uuid.NewString()), Offer: "pro_monthly", Amount: 12500}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence,session_id) VALUES($1,$2,$3,$4,$5,'{}',$6,$6,$7,$6,$8,'paid','{}',$9)`, u.ID, team, u.Actor, u.Customer, u.Offer, now, now.Add(time.Hour), u.Amount, u.Session); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "temporary provider failure", 503) }))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	s := StripeRetrievedCheckoutSession{ID: *u.Session, CustomerID: u.Customer, ClientReferenceID: team.String(), Mode: "payment", Currency: "usd", AmountSubtotal: 12501, AmountTotal: 12500, InvoiceID: "in_example", PaymentStatus: "paid", Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}}
	conn, err := h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, _, err = h.verifyProUpgradePayment(t.Context(), conn, client, u, s, false); err == nil {
		t.Fatal("accepted changed payment amount")
	}
	var review bool
	if err = conn.QueryRow(t.Context(), `SELECT payment_review_required FROM billing_pro_upgrade WHERE id=$1`, u.ID).Scan(&review); err != nil || !review {
		t.Fatalf("missing durable payment review: %v %v", review, err)
	}
	s.AmountSubtotal = 12500
	if _, _, err = h.verifyProUpgradePayment(t.Context(), conn, client, u, s, false); err == nil {
		t.Fatal("accepted unavailable provider evidence")
	}
	if err = conn.QueryRow(t.Context(), `SELECT payment_review_required FROM billing_pro_upgrade WHERE id=$1`, u.ID).Scan(&review); err != nil || !review {
		t.Fatalf("transport failure cleared review: %v %v", review, err)
	}
}

func TestProAcceptedPaymentWithoutPriorAssignmentRecoversWithEntryOff(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, customer, subscription, now); err != nil {
		t.Fatal(err)
	}
	terms, err := h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
	if err != nil {
		t.Fatal(err)
	}
	contract, err := h.DB.CreateCommercialContract(t.Context(), db.CreateCommercialContractParams{TeamID: team, OfferKey: "pro_monthly", StartsAt: now, CustomerID: customer, SubscriptionID: subscription, BasePriceID: "price_recovered", ChargeAmountCents: terms.FeeCents, ChargeIntervalMonths: 1, EntitlementKind: "metered_usage", EntitlementAmountCents: terms.MonthlyCreditCents, EntitlementCadence: "monthly", EntitlementAnchor: now})
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: "pro_monthly", Name: terms.DisplayName, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, Limits: &terms.Limits, Grants: terms.Grants, Allowance: terms.Allowance, PredecessorKnown: true}
	choice := proChoice{Team: team, Actor: uuid.New(), Offer: "pro_monthly", Generation: now}
	if on, err := h.pricingV2Enabled(t.Context()); err != nil || on {
		t.Fatalf("fixture must recover with entry OFF: %v %v", on, err)
	}
	var id uuid.UUID
	for range 2 {
		tx, err := h.Pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = assignCheckoutPlan(t.Context(), tx, choice, offer, contract.ID); err != nil {
			tx.Rollback(t.Context())
			t.Fatal(err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		current, assigned, err := currentTeamPlan(t.Context(), h.Pool, team)
		if err != nil || !assigned || current.PlanKey != "pro_monthly" || id != uuid.Nil && id != current.ID {
			t.Fatalf("absent predecessor replay changed paid assignment: %+v %v", current, err)
		}
		id = current.ID
	}
	var atomic bool
	if err = h.Pool.QueryRow(t.Context(), `SELECT count(*)=1 AND bool_and(contract_id=$2) AND (SELECT max_sandboxes=$3 FROM team WHERE id=$1) FROM team_plan_assignment WHERE team_id=$1`, team, contract.ID, *terms.Limits.MaxConcurrent).Scan(&atomic); err != nil || !atomic {
		t.Fatalf("OFF recovery omitted assignment limits: %v %v", atomic, err)
	}
}

func testProUpgradeReleaseReentry(t *testing.T, h *Handlers, team uuid.UUID, u proUpgrade, sub *invoiceSubscription, monthlyCredit int64) {
	t.Helper()
	h.Now = func() time.Time { return time.Now().UTC() }
	actualCustomer := sub.Customer
	sub.Customer = "cus_other"
	if _, _, err := h.planChangeSubscription(t.Context(), team, *u.Contract); err == nil {
		t.Fatal("pending bridge trusted a different provider customer")
	}
	sub.Customer = actualCustomer
	actualEnd := sub.Items.Data[1].End
	sub.Items.Data[1].End++
	if _, _, err := h.planChangeSubscription(t.Context(), team, *u.Contract); err == nil {
		t.Fatal("pending bridge accepted a changed provider billing period")
	}
	sub.Items.Data[1].End = actualEnd
	f := planChangeV2Fixture{h: h, team: team, actor: u.Actor}
	change, err := f.request(t, "starter", "zero-bridge-release")
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	change = f.reload(t, change.ID)
	if change.State != "scheduled" || change.ProviderCancelAt == nil || !sub.CancelAtPeriodEnd || !change.EffectiveAt.Equal(u.End) {
		t.Fatalf("fresh bridge cancellation: %+v", change)
	}
	h.Now = func() time.Time { return u.End.Add(time.Second) }
	sub.Status = "canceled"
	sub.EndedAt = u.End.Unix()
	f.tick(t)
	change = f.reload(t, change.ID)
	if change.State != "completed" {
		t.Fatalf("zero bridge release: %+v", change)
	}
	released, err := proReleaseForReentry(t.Context(), h.Pool, team, u.Customer)
	if err != nil || released == nil {
		t.Fatalf("zero bridge reentry: %v %v", released, err)
	}
	var preserved bool
	if err = h.Pool.QueryRow(t.Context(), `SELECT u.state='ended' AND u.bridge_credit_cents=$3 AND (u.grant_id IS NOT NULL OR (u.bridge_credit_cents=0 AND r.provider_evidence#>>'{pro_upgrade,upgrade,BridgeCredit}'='0')) AND c.entitlement_amount_cents=$4 FROM billing_pro_upgrade u JOIN billing_commercial_contract c ON c.id=u.contract_id JOIN billing_plan_release r ON r.id=$2 WHERE u.id=$1`, u.ID, released, monthlyCredit/2, monthlyCredit).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("zero release proof or future entitlement changed: %v %v", preserved, err)
	}
	var epoch uuid.UUID
	if err = h.Pool.QueryRow(t.Context(), `SELECT epoch FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	system := uuid.New()
	evidence, _ := json.Marshal(map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": system.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "disposable-fixture", "worker_reference": "disposable-fixture"})
	if _, err = h.Pool.Exec(t.Context(), `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2 WHERE singleton`, system, evidence); err != nil {
		t.Fatal(err)
	}
	admission, err := h.publicPricingState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(u.Payload, &params); err != nil {
		t.Fatal(err)
	}
	offer, err := frozenProOffer(u.Offer, params)
	if err != nil {
		t.Fatal(err)
	}
	offer.Price = params.BasePriceID
	params.OperationID = uuid.New()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "temporarily unavailable", 503) }))
	defer provider.Close()
	h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client()}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/stripe/pro-checkout", nil)
	h.createProUpgrade(c, team, u.Actor, offer, params, admission)
	if response.Code != http.StatusAccepted {
		t.Fatalf("released bridge cannot reenter: %d %s", response.Code, response.Body.String())
	}
	accepted, err := h.proUpgrade(t.Context(), team)
	if err != nil || accepted.ID != params.OperationID || accepted.BridgeCredit == nil || *accepted.BridgeCredit != monthlyCredit {
		t.Fatalf("reentry lost new monthly terms: %+v %v", accepted, err)
	}
	var releaseBound bool
	if err = h.Pool.QueryRow(t.Context(), `SELECT request_payload->>'ReleaseID'=$2 FROM billing_pro_upgrade WHERE id=$1`, accepted.ID, released.String()).Scan(&releaseBound); err != nil || !releaseBound {
		t.Fatalf("reentry release provenance: %v %v", releaseBound, err)
	}
}
