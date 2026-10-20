//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

func testSponsoredAnnualAdoption(t *testing.T, h *Handlers, team uuid.UUID, sponsor sponsoredOperation, sub invoiceSubscription, grant entitlementGrant, recoverActivation bool) {
	t.Helper()
	ctx := t.Context()
	var mu sync.Mutex
	p := storagePrice{ID: "price_annual", Product: "prod_annual", Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1200000"}
	p.Recurring.UsageType = "licensed"
	p.Recurring.Interval = "year"
	p.Recurring.IntervalCount = 1
	item := invoiceSubscriptionItem{ID: "si_annual_" + team.String(), Quantity: 1, Price: p, Start: sponsor.Anchor.Time.Unix(), End: sponsor.End.Time.Unix()}
	sub.Items.Data = append(sub.Items.Data, item)
	// This is an observed remaining balance, not a fresh grant or reset balance.
	remaining := int64(2876543)
	var activationGrant = activationRevocationGrant(team)
	activationGrant.ID, activationGrant.Customer = "cred_"+team.String(), sub.Customer
	recoveryVoids := 0
	writes := 0
	debt := false
	var history []StripeInvoiceAmounts
	providerPreview := StripeInvoiceAmounts{ID: "upcoming_in_fixture", Customer: sub.Customer}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.Method != http.MethodGet && r.URL.Path != "/v1/invoices/create_preview" && r.URL.Path != "/v1/billing/credit_grants/"+activationGrant.ID+"/void" {
			writes++
			t.Errorf("adoption wrote provider %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1/account":
			out(map[string]any{"id": "acct_fixture"})
		case "/v1/subscriptions/" + sub.ID:
			out(sub)
		case "/v1/invoices":
			if debt && r.URL.Query().Get("status") == "open" {
				out(map[string]any{"data": []any{map[string]any{"id": "in_debt", "customer": sub.Customer, "status": "open"}}})
				return
			}
			if r.URL.Query().Get("status") != "" {
				out(map[string]any{"data": []any{}})
				return
			}
			out(map[string]any{"data": history})
		case "/v1/invoiceitems":
			out(map[string]any{"data": []any{}})
		case "/v1/billing/credit_grants":
			grants := []any{grant}
			if recoverActivation {
				grants = append(grants, activationGrant)
			}
			out(map[string]any{"data": grants})
		case "/v1/billing/credit_grants/" + activationGrant.ID:
			out(activationGrant)
		case "/v1/billing/credit_grants/" + activationGrant.ID + "/void":
			recoveryVoids++
			stamp := time.Now().Unix()
			activationGrant.VoidedAt = &stamp
			out(activationGrant)
		case "/v1/billing/credit_balance_summary":
			if r.URL.Query().Get("filter[credit_grant]") == activationGrant.ID {
				out(map[string]any{"customer": sub.Customer, "balances": []any{map[string]any{"available_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": 9500}}, "ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": 9500}}}}})
				return
			}
			out(map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": remaining}}}}})
		case "/v1/invoices/create_preview":
			out(providerPreview)
		default:
			t.Errorf("unexpected annual provider request %s", r.URL.String())
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	live := false
	r := sponsoredAnnualRequest{Merchant: "acct_fixture", Key: "annual", Sponsorship: sponsor.ID, Customer: sub.Customer, Subscription: sub.ID, Item: item.ID, Price: p.ID, Live: &live, Reason: "approved annual waiver", Reference: "fixture"}
	call := func(apply bool, r sponsoredAnnualRequest) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(r)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "team_id", Value: team.String()}}
		c.Set("actor_id", uuid.New())
		h.sponsoredAnnualApply(c, apply)
		return w
	}
	historyStart := sponsor.Anchor.Time.AddDate(0, -2, 0)
	historyEnd := sponsor.Anchor.Time.AddDate(0, -1, 0)
	if _, err := h.DB.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{TeamID: team, PeriodStart: historyStart, PeriodEnd: historyEnd, Status: "open"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state,verified_at,finalized_evidence) VALUES($1,$2,$3,$4,'{"expected_cents":12345,"credit_before_cents":3000000}','verified',clock_timestamp(),'{"credit_applied_cents":12345,"credit_remaining_cents":2987655}')`, team, historyStart, historyEnd, "in_history_"+team.String()); err != nil {
		t.Fatal(err)
	}
	var historyBefore, historyAfter []byte
	if err := h.Pool.QueryRow(ctx, `SELECT to_jsonb(c) FROM billing_invoice_close c WHERE team_id=$1`, team).Scan(&historyBefore); err != nil {
		t.Fatal(err)
	}
	before, err := h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: team, Kind: "metered_usage"})
	if err != nil {
		t.Fatal(err)
	}
	if recoverActivation {
		if w := call(false, r); w.Code != 409 || !strings.Contains(w.Body.String(), "unrecognized unexpired credit") {
			t.Fatal("existing activation conflict not observed", w.Code, w.Body.String())
		}
		if recoveryVoids != 0 {
			t.Fatal("preflight mutated activation grant")
		}
		a, e := h.DB.GetTeamBillingAccount(ctx, team)
		if e != nil {
			t.Fatal(e)
		}
		recovery := sponsoredPromotionRequest{Key: "recover", Merchant: r.Merchant, Live: r.Live, Customer: r.Customer, Subscription: r.Subscription, User: uuid.UUID(a.StripeActivationUserID.Bytes), Event: *a.StripeActivationCreditReservationEventID, Grant: activationGrant.ID, Reason: "unused activation correction", Reference: "fixture"}
		if e = h.recoverSponsoredPromotion(ctx, team, sponsor.ID, uuid.New(), recovery); e != nil {
			t.Fatal(e)
		}
		if e = h.recoverSponsoredPromotion(ctx, team, sponsor.ID, uuid.New(), recovery); e != nil || recoveryVoids != 1 {
			t.Fatal("recovery replay", recoveryVoids, e)
		}
	} else {
		actor := uuid.New()
		if _, e := h.Pool.Exec(ctx, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com"); e != nil {
			t.Fatal(e)
		}
		var decision string
		if e := h.Pool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,'evt_fresh',$3,NULL,false)`, team, actor, sub.ID).Scan(&decision); e != nil || decision != "sponsored" {
			t.Fatal("fresh signup promotion not suppressed", decision, e)
		}
	}
	mu.Lock()
	sub.BillingSchedules = json.RawMessage(`[{"bill_until":{"timestamp":123}}]`)
	mu.Unlock()
	if w := call(false, r); w.Code != 409 || !strings.Contains(w.Body.String(), "billing_schedules") {
		t.Fatal("unknown override accepted", w.Code, w.Body.String())
	}
	mu.Lock()
	sub.BillingSchedules = nil
	debt = true
	mu.Unlock()
	if w := call(false, r); w.Code != 409 {
		t.Fatal("debt accepted", w.Body.String())
	}
	mu.Lock()
	debt = false
	mu.Unlock()
	originalGrant, _ := json.Marshal(grant)
	for _, change := range []func(){
		func() { grant.VoidedAt = time.Now().Unix(); remaining = 0 },
		func() { grant.Applicability.Scope.Prices[0].ID = "price_changed" },
		func() { grant.EffectiveAt++ },
	} {
		mu.Lock()
		change()
		mu.Unlock()
		if w := call(false, r); w.Code != 409 {
			t.Fatal("changed grant accepted", w.Body.String())
		}
		mu.Lock()
		_ = json.Unmarshal(originalGrant, &grant)
		remaining = 2876543
		mu.Unlock()
	}
	mu.Lock()
	remaining = 0
	mu.Unlock()
	if w := call(false, r); w.Code != 200 {
		t.Fatal("fully consumed unchanged grant rejected", w.Body.String())
	}
	annualHistory := StripeInvoiceAmounts{ID: "in_zero", Customer: sub.Customer, Status: "draft"}
	rawHistory, _ := json.Marshal(map[string]any{"id": "in_zero", "customer": sub.Customer, "status": "draft", "parent": map[string]any{"subscription_details": map[string]any{"subscription": sub.ID}}, "lines": map[string]any{"data": []any{map[string]any{"amount": 0, "pricing": map[string]any{"price_details": map[string]any{"price": p.ID}}, "parent": map[string]any{"subscription_item_details": map[string]any{"subscription": sub.ID, "subscription_item": item.ID}}}}}})
	_ = json.Unmarshal(rawHistory, &annualHistory)
	mu.Lock()
	remaining = 2876543
	history = []StripeInvoiceAmounts{annualHistory}
	mu.Unlock()
	if w := call(false, r); w.Code != 409 {
		t.Fatal("unresolved zero-fee draft accepted", w.Body.String())
	}
	mu.Lock()
	history[0].Status = "paid"
	mu.Unlock()
	if w := call(false, r); w.Code != 200 {
		t.Fatal("completed zero-fee history rejected", w.Body.String())
	}
	mu.Lock()
	history[0].Lines.Data[0].Period.End = sponsor.End.Time.Unix() + 86400
	mu.Unlock()
	if w := call(false, r); w.Code != 409 {
		t.Fatal("historical extra renewal day accepted", w.Body.String())
	}
	mu.Lock()
	history[0].Lines.Data[0].Period.End = 0
	mu.Unlock()
	w := call(false, r)
	if w.Code != 200 {
		t.Fatal("preflight", w.Code, w.Body.String())
	}
	var preview struct {
		Fingerprint string `json:"preflight_fingerprint"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	r.Fingerprint = preview.Fingerprint
	for _, status := range []string{"paid", "draft"} {
		for _, amount := range []int64{0, 1200000} {
			mu.Lock()
			history[0].Status = status
			history[0].Lines.Data[0].Amount = amount
			history[0].Lines.Data[0].Pricing.PriceDetails.Price = "price_previous_annual"
			mu.Unlock()
			for _, apply := range []bool{false, true} {
				if w := call(apply, r); w.Code != 409 || !strings.Contains(w.Body.String(), "historical annual item price differs") {
					t.Fatalf("previous annual item price accepted (%s, %d, apply=%v): %d %s", status, amount, apply, w.Code, w.Body.String())
				}
			}
		}
	}
	mu.Lock()
	history[0].Status = "paid"
	history[0].Lines.Data[0].Amount = 0
	history[0].Lines.Data[0].Parent.SubscriptionItemDetails.SubscriptionItem = "si_previous_annual"
	history[0].Lines.Data[0].Period.End = sponsor.End.Time.Unix() + 86400
	mu.Unlock()
	for _, historicalPrice := range []string{"price_previous_annual", ""} {
		mu.Lock()
		history[0].Lines.Data[0].Pricing.PriceDetails.Price = historicalPrice
		mu.Unlock()
		for _, apply := range []bool{false, true} {
			if w := call(apply, r); w.Code != 409 || !strings.Contains(w.Body.String(), "unrecognized historical invoice price") {
				t.Fatalf("replaced annual item history accepted (%q, apply=%v): %d %s", historicalPrice, apply, w.Code, w.Body.String())
			}
		}
	}
	// Recognized resource usage and rounding history remain adoptable.
	for _, usageItem := range sub.Items.Data {
		if usageItem.ID == item.ID {
			continue
		}
		mu.Lock()
		history[0].Lines.Data[0].Pricing.PriceDetails.Price = usageItem.Price.ID
		history[0].Lines.Data[0].Amount = 123
		mu.Unlock()
		if w := call(false, r); w.Code != 200 {
			t.Fatalf("recognized usage history rejected (%s): %d %s", usageItem.Price.ID, w.Code, w.Body.String())
		}
	}
	mu.Lock()
	history[0].Lines.Data[0].Parent.SubscriptionItemDetails.SubscriptionItem = item.ID
	history[0].Lines.Data[0].Period.End = 0
	history[0].Lines.Data[0].Amount = 0
	history[0].Lines.Data[0].Pricing.PriceDetails.Price = p.ID
	previewBytes, _ := json.Marshal(history[0])
	_ = json.Unmarshal(previewBytes, &providerPreview)
	providerPreview.ID = "upcoming_in_fixture"
	providerPreview.Lines.Data[0].Pricing.PriceDetails.Price = "price_previous_annual"
	mu.Unlock()
	for _, previewItem := range []string{item.ID, "si_previous_annual"} {
		mu.Lock()
		providerPreview.Lines.Data[0].Parent.SubscriptionItemDetails.SubscriptionItem = previewItem
		mu.Unlock()
		for _, apply := range []bool{false, true} {
			if w := call(apply, r); w.Code != 409 || !strings.Contains(w.Body.String(), "first-year preview includes") {
				t.Fatalf("old annual price preview accepted (%s, apply=%v): %d %s", previewItem, apply, w.Code, w.Body.String())
			}
		}
	}
	mu.Lock()
	providerPreview = StripeInvoiceAmounts{ID: "upcoming_in_fixture", Customer: sub.Customer}
	mu.Unlock()
	validItems := append([]invoiceSubscriptionItem(nil), sub.Items.Data...)
	for _, invalid := range []string{"missing", "duplicate", "licensed", "amount", "meter"} {
		mu.Lock()
		sub.Items.Data = nil
		for _, original := range validItems {
			candidate := original
			if candidate.Price.ID == "price_round" {
				switch invalid {
				case "missing":
					continue
				case "duplicate":
					sub.Items.Data = append(sub.Items.Data, candidate)
				case "licensed":
					candidate.Price.Recurring.UsageType = "licensed"
				case "amount":
					candidate.Price.UnitAmountDecimal = "2"
				case "meter":
					candidate.Price.Recurring.Meter = ""
				}
			}
			sub.Items.Data = append(sub.Items.Data, candidate)
		}
		mu.Unlock()
		for _, apply := range []bool{false, true} {
			if w := call(apply, r); w.Code != 409 || !strings.Contains(w.Body.String(), "rounding adjustment item") {
				t.Fatalf("%s rounding item accepted (apply=%v): %d %s", invalid, apply, w.Code, w.Body.String())
			}
		}
	}
	mu.Lock()
	sub.Items.Data = validItems
	mu.Unlock()
	var count int
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_sponsored_annual_authority WHERE team_id=$1`, team).Scan(&count); err != nil || count != 0 {
		t.Fatal("preflight wrote authority", count, err)
	}
	mu.Lock()
	sub.Metadata["changed"] = "yes"
	mu.Unlock()
	if w = call(true, r); w.Code != 409 {
		t.Fatal("drift accepted", w.Body.String())
	}
	mu.Lock()
	delete(sub.Metadata, "changed")
	remaining -= 123
	mu.Unlock()
	if w = call(true, r); w.Code != 200 {
		t.Fatal("adopt", w.Code, w.Body.String())
	}
	if w = call(true, r); w.Code != 200 {
		t.Fatal("replay", w.Code, w.Body.String())
	}
	changed := r
	changed.Reason = "changed"
	if w = call(true, changed); w.Code != 409 {
		t.Fatal("changed request accepted")
	}
	after, err := h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: team, Kind: "metered_usage"})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatal("adoption rewrote issued credit history")
	}
	if err := h.Pool.QueryRow(ctx, `SELECT to_jsonb(c) FROM billing_invoice_close c WHERE team_id=$1`, team).Scan(&historyAfter); err != nil || !bytes.Equal(historyBefore, historyAfter) {
		t.Fatal("adoption changed completed invoice history", err)
	}
	var limits int
	if err = h.Pool.QueryRow(ctx, `SELECT max_sandboxes FROM team WHERE id=$1`, team).Scan(&limits); err != nil || limits != 1000 {
		t.Fatal("Pro limits missing", limits, err)
	}
	plan, err := h.DB.GetCurrentCommercialPlan(ctx, team)
	if err != nil || plan.OfferKey != "pro_annual" || plan.ChargeAmountCents != 0 || plan.PeriodAmountCents == nil || *plan.PeriodAmountCents != 3000000 {
		t.Fatal("wrong composed plan", plan, err)
	}
	display := billingPlanFromContract(plan)
	if !display.BaseFeeWaived || display.RenewalPriceUSD == nil || *display.RenewalPriceUSD != 12000 {
		t.Fatal("waiver or renewal omitted", display)
	}
	account, enrolled, err := h.invoiceAccount(ctx, team)
	if err != nil || !enrolled || account.Base.Item != item.ID {
		t.Fatal("base not recognized", account, err)
	}
	if err = h.validateInvoiceEnrollmentSubscription(ctx, team, account, h.Stripe.(*stripeHTTPClient), sub, h.Pool); err != nil {
		t.Fatal("mixed calendar rejected", err)
	}
	invoiceID := "in_history_" + team.String()
	if _, err = h.Pool.Exec(ctx, `INSERT INTO billing_invoice_collection(invoice_id,customer_id,subscription_id,livemode,settlement_hash,idempotency_key,payment_authorized) VALUES($1,$2,$3,false,'fixture',$1,false)`, invoiceID, sub.Customer, sub.ID); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"open", "paid"} {
		eventType := "invoice.payment_failed"
		if status == "paid" {
			eventType = "invoice.paid"
		}
		object, _ := json.Marshal(map[string]any{"id": invoiceID, "customer": sub.Customer, "status": status, "parent": map[string]any{"subscription_details": map[string]any{"subscription": sub.ID}}})
		event := stripeEventEnvelope{ID: "evt_" + uuid.NewString(), Type: eventType, Data: stripeEventEnvelopeData{Object: object}}
		payload, _ := json.Marshal(event)
		if _, err = h.Pool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,$2,$3)`, event.ID, event.Type, payload); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET next_check_at=clock_timestamp()+interval '1 hour' WHERE team_id=$1`, team); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_invoice_collection SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE invoice_id=$1`, invoiceID); err != nil {
			t.Fatal(err)
		}
		if err = h.processRecordedStripeWebhook(ctx, event); err != nil {
			t.Fatal("annual invoice webhook", err)
		}
		var projected string
		var annualDue, collectionDue, processed, pending bool
		if err = h.Pool.QueryRow(ctx, `SELECT b.stripe_invoice_status,a.next_check_at<=clock_timestamp(),c.next_attempt_at<=clock_timestamp(),e.processed_at IS NOT NULL,c.state='pending' AND a.state='active' FROM team_billing_account b JOIN billing_sponsored_annual_authority a USING(team_id) JOIN billing_invoice_collection c ON c.invoice_id=$2 JOIN stripe_webhook_event e ON e.event_id=$3 WHERE b.team_id=$1`, team, invoiceID, event.ID).Scan(&projected, &annualDue, &collectionDue, &processed, &pending); err != nil {
			t.Fatal(err)
		}
		if projected != status || !annualDue || !collectionDue || !processed || !pending {
			t.Fatalf("annual invoice event lost generic handling or supplied payment authority: %s %v %v %v %v", projected, annualDue, collectionDue, processed, pending)
		}
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET item_id='si_replacement' WHERE team_id=$1`, team); err == nil {
		t.Fatal("immutable binding rewritten")
	}
	if err = h.commitFreeFundingPlan(ctx, team, uuid.New()); err == nil {
		t.Fatal("active annual authority released")
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=clock_timestamp() WHERE team_id=$1`, team); err == nil {
		t.Fatal("checkout bypassed annual fence")
	}
	if err = h.reconcileSponsoredAnnual(ctx, team); err != nil {
		t.Fatal("active reconciliation", err)
	}
	if writes != 0 || remaining != 2876420 {
		t.Fatal("provider or balance was mutated", writes, remaining)
	}
	// A user-set limit remains authoritative when the adopted benefit ends.
	if _, err = h.Pool.Exec(ctx, `UPDATE team SET max_sandboxes=777 WHERE id=$1`, team); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	sub.Status = "canceled"
	sub.EndedAt = time.Now().Unix()
	mu.Unlock()
	if err = h.reconcileSponsoredAnnual(ctx, team); err == nil {
		t.Fatal("unexpected waived-term cancellation did not request recovery")
	}
	var status, annualState string
	if err = h.Pool.QueryRow(ctx, `SELECT a.stripe_subscription_status,b.state FROM team_billing_account a JOIN billing_sponsored_annual_authority b ON b.team_id=a.team_id WHERE a.team_id=$1`, team).Scan(&status, &annualState); err != nil || status != "canceled" || annualState != "active" {
		t.Fatal("canceled lifecycle projection or bounded term lost", status, annualState, err)
	}
	if err = h.Pool.QueryRow(ctx, `SELECT max_sandboxes FROM team WHERE id=$1`, team).Scan(&limits); err != nil || limits != 777 {
		t.Fatal("custom limits overwritten", limits, err)
	}
}

// A real database-clock boundary proves the original sponsor expires before the
// successor is inserted, without disabling history guards or rewriting dates.
func TestSponsoredAnnualRenewalBoundary(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
	start := end.AddDate(-1, 0, 0)
	customer, subscription := "cus_"+team.String(), "sub_"+team.String()
	op, contract := uuid.New(), uuid.New()
	exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team, customer, subscription, start)
	historicalID := "in_waiver_" + team.String()
	historical := StripeInvoiceAmounts{ID: historicalID, Customer: customer, Status: "paid"}
	historyRaw, _ := json.Marshal(map[string]any{"waiver_inventory": []StripeInvoiceAmounts{historical}})
	seed := func(op, contract uuid.UUID, subscription, key string, evidence []byte) {
		exec(`INSERT INTO billing_sponsored_operation(id,team_id,contract_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id,anchor,starts_at,ends_at) VALUES($1,$2,$3,$9,'{}','{}',$4,'fixture','fixture',$5,$6,$7,$7,$8)`, op, team, contract, uuid.New(), customer, subscription, start, end, key)
		exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_kind,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'sponsored_usage',$3,$4,$5,$6,'','sponsored_entitlement',0,1,'metered_usage',3000000,'scheduled',$3)`, contract, team, start, end, customer, subscription)
		exec(`INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,CASE WHEN m<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) m`, team, contract)
		if _, err := h.DB.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: team, ContractID: contract}); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE billing_sponsored_operation SET state='active' WHERE id=$1`, op)
		exec(`INSERT INTO billing_sponsored_annual_authority(team_id,sponsorship_id,contract_id,idempotency_key,request,approved_by,customer_id,subscription_id,item_id,base_price_id,base_product_id,live_mode,home_region,starts_at,waiver_ends_at,provider_evidence) VALUES($1,$2,$3,$10,'{}',$4,$5,$6,'si_annual_'||$6::text,'price_annual','prod_annual',false,'use',$7,$8,$9)`, team, op, contract, uuid.New(), customer, subscription, start, end, evidence, key)
	}
	oldSub := subscription + "_old"
	exec(`UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, team, oldSub)
	oldOp, oldContract := uuid.New(), uuid.New()
	seed(oldOp, oldContract, oldSub, "old", []byte(`{}`))
	exec(`UPDATE billing_sponsored_annual_authority SET state='ended',invoice_cursor='in_old_cursor' WHERE team_id=$1`, team)
	var oldBefore, oldAfter []byte
	if err := h.Pool.QueryRow(ctx, `SELECT to_jsonb(a) FROM billing_sponsored_annual_authority a WHERE team_id=$1`, team).Scan(&oldBefore); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1`, oldContract)
	exec(`UPDATE billing_sponsored_operation SET state='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, oldOp, uuid.New())
	exec(`UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, team, subscription)
	seed(op, contract, subscription, "annual", historyRaw)
	o, err := h.sponsoredAnnualAuthority(ctx, team, h.Pool)
	if err != nil {
		t.Fatal(err)
	}
	p := storagePrice{ID: o.Price, Product: o.Product, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1200000"}
	p.Recurring.UsageType = "licensed"
	p.Recurring.Interval = "year"
	p.Recurring.IntervalCount = 1
	sub := invoiceSubscription{ID: subscription, Customer: customer, Status: "active"}
	sub.BillingMode.Type = "flexible"
	sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{ID: o.Item, Quantity: 1, Price: p, Start: end.Unix(), End: annualBoundary(start, 24).Unix()})
	invoiceID := "in_renewal_" + team.String()
	monthly := map[string]StripeInvoiceAmounts{}
	var monthlyIDs []string
	for n := range 23 {
		id := fmt.Sprintf("in_month_%02d_%s", n, team)
		var inv StripeInvoiceAmounts
		_ = json.Unmarshal([]byte(fmt.Sprintf(`{"id":%q,"customer":%q,"status":"paid","parent":{"subscription_details":{"subscription":%q}}}`, id, customer, subscription)), &inv)
		monthly[id] = inv
		monthlyIDs = append(monthlyIDs, id)
	}
	var paid, refunded, prorated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("renewal attempted financial write %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/invoices":
			all := []map[string]any{}
			if paid.Load() {
				all = append(all, map[string]any{"id": invoiceID, "status": "paid", "amount_paid": 1200000})
			}
			for _, id := range monthlyIDs {
				all = append(all, map[string]any{"id": id, "status": "paid", "amount_paid": 0})
			}
			all = append(all, map[string]any{"id": historicalID, "status": "paid", "amount_paid": 0})
			offset := 0
			if cursor := r.URL.Query().Get("starting_after"); cursor != "" {
				for n, x := range all {
					if x["id"] == cursor {
						offset = n + 1
						break
					}
				}
			}
			limit := len(all)
			if r.URL.Query().Get("limit") == "10" {
				limit = 10
			}
			stop := min(len(all), offset+limit)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": all[offset:stop], "has_more": stop < len(all)})
		case "/v1/invoices/" + historicalID:
			_ = json.NewEncoder(w).Encode(historical)
		case "/v1/invoices/" + invoiceID:
			if prorated.Load() {
				fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","total":1196721,"amount_due":1196721,"amount_paid":1196721,"amount_remaining":0,"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"quantity":1,"amount":1196721,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":"price_annual","product":"prod_annual"}},"parent":{"subscription_item_details":{"subscription":%q,"subscription_item":%q,"proration":true}}}]}}`, invoiceID, customer, subscription, end.Unix()+86400, annualBoundary(start, 24).Unix(), subscription, o.Item)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","total":1200000,"amount_due":1200000,"starting_balance":0,"ending_balance":0,"amount_paid":1200000,"amount_remaining":0,"status_transitions":{"paid_at":%d},"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"quantity":1,"amount":1200000,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"1200000","price_details":{"price":"price_annual","product":"prod_annual"}},"parent":{"subscription_item_details":{"subscription":%q,"subscription_item":%q}}}]}}`, invoiceID, customer, end.Unix(), subscription, end.Unix(), annualBoundary(start, 24).Unix(), subscription, o.Item)
		case "/v1/credit_notes":
			fmt.Fprint(w, `{"data":[]}`)
		case "/v1/invoice_payments":
			fmt.Fprintf(w, `{"data":[{"id":"inpay_fixture","invoice":%q,"status":"paid","currency":"usd","amount_paid":1200000,"payment":{"type":"payment_intent","payment_intent":"pi_fixture"}}]}`, invoiceID)
		case "/v1/payment_intents/pi_fixture":
			fmt.Fprintf(w, `{"id":"pi_fixture","status":"succeeded","customer":%q,"currency":"usd","amount_received":1200000,"latest_charge":"ch_fixture"}`, customer)
		case "/v1/charges/ch_fixture":
			fmt.Fprintf(w, `{"id":"ch_fixture","customer":%q,"payment_intent":"pi_fixture","currency":"usd","paid":true,"captured":true,"amount_captured":1200000,"amount_refunded":%d,"disputed":false}`, customer, func() int {
				if refunded.Load() {
					return 1200000
				}
				return 0
			}())
		default:
			if inv, ok := monthly[strings.TrimPrefix(r.URL.Path, "/v1/invoices/")]; ok {
				_ = json.NewEncoder(w).Encode(inv)
				return
			}
			t.Errorf("unexpected renewal request %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	token := uuid.New()
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customer, Token: token}); err != nil {
		t.Fatal(err)
	}
	defer h.DB.ReleaseStripeWebhookProcessingLease(ctx, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: customer, Token: token})
	if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err == nil {
		t.Fatal("renewal before original boundary")
	}
	time.Sleep(time.Until(end.Add(20 * time.Millisecond)))
	// Exercise service startup: a missing provider must not disable local expiry.
	if h.Stripe != nil {
		t.Fatal("fixture unexpectedly has a provider")
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	h.StartUsageEntitlementService(workerCtx)
	var limits int
	for deadline := time.Now().Add(10 * time.Second); ; {
		var finished bool
		if err = h.Pool.QueryRow(ctx, `SELECT t.max_sandboxes,a.state='renewal_pending' AND a.lease_token IS NULL AND a.last_error IS NOT NULL FROM team t JOIN billing_sponsored_annual_authority a ON a.team_id=t.id WHERE t.id=$1 AND a.id=$2`, team, o.ID).Scan(&limits, &finished); err != nil {
			t.Fatal(err)
		}
		if limits != 1000 && finished {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waived benefits survived service startup without provider", limits, finished)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopWorker()
	for range 2 {
		if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err != nil {
			t.Fatal("unpaid renewal/replay", err)
		}
	}
	var contracts, payments, grants int
	var state string
	if err = h.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended'),(SELECT count(*) FROM billing_contract_payment WHERE team_id=$1),(SELECT count(*) FROM billing_usage_entitlement WHERE team_id=$1),state FROM billing_sponsored_annual_authority WHERE team_id=$1 AND id=$2`, team, o.ID).Scan(&contracts, &payments, &grants, &state); err != nil || contracts != 1 || payments != 0 || grants != 0 || state != "renewal_pending" {
		t.Fatal("unpaid renewal created cash/credit or duplicates", contracts, payments, grants, state, err)
	}
	c, err := h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: o.Renewal})
	if err != nil || c.Status != "pending" || !c.StartsAt.Equal(end) || !c.EntitlementAnchor.Equal(start) || c.EntitlementAmountCents != 100000 {
		t.Fatal("successor terms differ", c, err)
	}
	paid.Store(true)
	sub.LatestInvoice = invoiceID
	prorated.Store(true)
	if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err == nil {
		t.Fatal("residual one-day-late annual proration accepted")
	}
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1`, o.Renewal).Scan(&payments); err != nil || payments != 0 {
		t.Fatal("residual proration conferred coverage", payments, err)
	}
	prorated.Store(false)
	sub.Status = "canceled"
	if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err == nil {
		t.Fatal("terminal before activation did not require recovery")
	}
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1`, o.Renewal).Scan(&payments); err != nil || payments != 1 {
		t.Fatal("late canceled receipt lost", payments, err)
	}
	sub.Status = "active"
	for range 2 {
		if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err != nil {
			t.Fatal("paid renewal/replay", err)
		}
	}
	if err = h.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1),state FROM billing_sponsored_annual_authority WHERE team_id=$1 AND id=$2`, team, o.ID).Scan(&payments, &state); err != nil || payments != 1 || state != "renewed" {
		t.Fatal("paid renewal not singular/active", payments, state, err)
	}
	c, err = h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: o.Renewal})
	if err != nil || c.Status != "active" {
		t.Fatal("verified annual payment did not activate", c.Status, err)
	}

	sub.Status = "canceled"
	if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err != nil {
		t.Fatal("paid cancellation", err)
	}
	c, err = h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: o.Renewal})
	if err != nil || c.Status != "active" {
		t.Fatal("cancellation forfeited paid term", c.Status, err)
	}
	for range 3 {
		if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err != nil {
			t.Fatal("multi-page terminal recovery", err)
		}
	}
	closed, err := h.proInvoicesClosed(ctx, client, team, customer, subscription, nil)
	if err != nil || !closed {
		t.Fatal("verified intermediate invoice pages were forgotten", closed, err)
	}
	if err = h.Pool.QueryRow(ctx, `SELECT to_jsonb(a) FROM billing_sponsored_annual_authority a WHERE team_id=$1 AND state='ended'`, team).Scan(&oldAfter); err != nil || !bytes.Equal(oldBefore, oldAfter) {
		t.Fatal("renewal touched ended authority history", err)
	}
	refunded.Store(true)
	if err = h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token); err == nil {
		t.Fatal("canceled receipt refund was not reviewed")
	}
	var review bool
	if err = h.Pool.QueryRow(ctx, `SELECT review_required FROM billing_pro_payment_verification WHERE invoice_id=$1`, invoiceID).Scan(&review); err != nil || !review {
		t.Fatal("refund review not durable", review, err)
	}

}
