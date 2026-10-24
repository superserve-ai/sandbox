//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

type matchingFixture struct {
	t             *testing.T
	f             *entitlementFixture
	client        *stripeHTTPClient
	mu            sync.Mutex
	invoices      map[string]StripeInvoiceAmounts
	grants        map[string]entitlementGrant
	byKey         map[string]string
	posts         []url.Values
	keys          []string
	lose          int
	refunded      bool
	unpaid        map[string]bool
	paid          map[string]int64
	prices        any
	planSub       string
	periodEnd     time.Time
	endingBalance *int64
}

func newMatchingFixture(t *testing.T, matchingBps int32, capCents, prior int64) *matchingFixture {
	t.Helper()
	m := &matchingFixture{t: t, f: newEntitlementFixture(t), invoices: map[string]StripeInvoiceAmounts{}, grants: map[string]entitlementGrant{}, byKey: map[string]string{}, unpaid: map[string]bool{}, paid: map[string]int64{}}
	m.periodEnd = m.f.start
	srv := httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(srv.Close)
	m.client = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	m.f.h.Stripe = m.client
	if err := insertContractMatchingRule(t.Context(), m.f.h.Pool, matchingRule{ContractID: m.f.c.ID, TeamID: m.f.c.TeamID, Terms: matchingTerms{MatchingBps: matchingBps, CapCents: capCents}, PriorMatchedCents: prior, EffectiveFrom: m.f.c.StartsAt, Source: "plan"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.retire)
	return m
}

// The sweep is fleet-wide, so a finished test parks its rows where later
// tests' sweeps cannot reach them.
func (m *matchingFixture) retire() {
	ctx := context.Background()
	conn, err := m.f.h.Pool.Acquire(ctx)
	if err != nil {
		m.t.Error(err)
		return
	}
	defer conn.Release()
	for _, sql := range []string{
		`SET session_replication_role=replica`,
		`UPDATE billing_contract_matching_rule SET effective_from='9999-01-01' WHERE contract_id=$1`,
		`UPDATE billing_matching_credit SET next_attempt_at='9999-01-01',review_checked_at='9999-01-01' WHERE contract_id=$1`,
		`SET session_replication_role=origin`,
	} {
		var args []any
		if strings.Contains(sql, "$1") {
			args = append(args, m.f.c.ID)
		}
		if _, err = conn.Exec(ctx, sql, args...); err != nil {
			m.t.Error(err)
		}
	}
}

func (m *matchingFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/invoices/in_"):
		inv, ok := m.invoices[strings.TrimPrefix(r.URL.Path, "/v1/invoices/")]
		if !ok {
			http.Error(w, "missing", 404)
			return
		}
		if m.unpaid[inv.ID] {
			inv.Status = "open"
			remaining := int64(100)
			inv.AmountRemaining = &remaining
		}
		raw, _ := json.Marshal(inv)
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		doc["amount_paid"] = m.cashPaid(inv.ID)
		json.NewEncoder(w).Encode(doc)
	case r.URL.Path == "/v1/billing/credit_grants" && r.Method == http.MethodPost:
		if err := r.ParseForm(); err != nil {
			m.t.Error(err)
		}
		key := r.Header.Get("Idempotency-Key")
		m.posts = append(m.posts, r.Form)
		m.keys = append(m.keys, key)
		id, ok := m.byKey[key]
		if !ok {
			id = "credgr_match_" + uuid.NewString()
			var g entitlementGrant
			g.ID, g.Customer, g.Category, g.Priority = id, r.Form.Get("customer"), r.Form.Get("category"), 50
			g.Created, g.EffectiveAt = time.Now().Unix(), time.Now().Unix()
			g.Amount.Type, g.Amount.Monetary.Currency = "monetary", "usd"
			fmt.Sscan(r.Form.Get("amount[monetary][value]"), &g.Amount.Monetary.Value)
			g.Applicability.Scope.PriceType = r.Form.Get("applicability_config[scope][price_type]")
			g.Metadata = map[string]string{"matching_credit_id": r.Form.Get("metadata[matching_credit_id]"), "invoice_id": r.Form.Get("metadata[invoice_id]")}
			m.grants[id] = g
			m.byKey[key] = id
		}
		if m.lose > 0 {
			m.lose--
			http.Error(w, `{"error":{"message":"response lost"}}`, 503)
			return
		}
		json.NewEncoder(w).Encode(m.grants[id])
	case r.URL.Path == "/v1/billing/credit_grants":
		data := []entitlementGrant{}
		for _, g := range m.grants {
			data = append(data, g)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	case strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/"):
		json.NewEncoder(w).Encode(m.grants[strings.TrimPrefix(r.URL.Path, "/v1/billing/credit_grants/")])
	case r.URL.Path == "/v1/invoice_payments":
		inv := r.URL.Query().Get("invoice")
		data := []any{}
		if paid := m.cashPaid(inv); paid > 0 {
			data = append(data, map[string]any{"invoice": inv, "amount_paid": paid, "payment": map[string]string{"type": "payment_intent", "payment_intent": "pi_match"}})
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.URL.Path == "/v1/payment_intents/pi_match":
		fmt.Fprint(w, `{"id":"pi_match","latest_charge":"ch_match"}`)
	case r.URL.Path == "/v1/charges/ch_match":
		refunded := 0
		if m.refunded {
			refunded = 100
		}
		var captured int64
		for id := range m.invoices {
			captured = max(captured, m.cashPaid(id))
		}
		fmt.Fprintf(w, `{"id":"ch_match","customer":%q,"payment_intent":"pi_match","currency":"usd","paid":true,"captured":true,"amount_captured":%d,"amount_refunded":%d}`, m.f.c.CustomerID, captured, refunded)
	default:
		m.t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", 500)
	}
}

func (m *matchingFixture) cashPaid(id string) int64 {
	if paid, ok := m.paid[id]; ok {
		return paid
	}
	var paid int64
	for _, line := range m.invoices[id].Lines.Data {
		paid += line.Amount
		for _, credit := range line.PretaxCredits {
			paid -= credit.Amount
		}
	}
	return paid
}

func usageLine(price string, amount int64, credits ...StripeInvoicePretaxCredit) StripeInvoiceAmountLine {
	var line StripeInvoiceAmountLine
	line.ID, line.Amount, line.Currency = "il_"+uuid.NewString(), amount, "usd"
	line.Pricing.PriceDetails = &struct {
		Price   string `json:"price"`
		Product string `json:"product"`
	}{Price: price}
	line.PretaxCredits = credits
	return line
}

func applied(amount int64) StripeInvoicePretaxCredit {
	return StripeInvoicePretaxCredit{Type: "credit_balance_transaction", Amount: amount, CreditBalanceTransaction: "cbtxn_" + uuid.NewString()}
}

// paidInvoice stages one released, collected usage invoice for the next
// monthly period and returns its ID.
func (m *matchingFixture) paidInvoice(collection string, lines ...StripeInvoiceAmountLine) string {
	m.t.Helper()
	start := m.periodEnd
	end := start.AddDate(0, 1, 0)
	m.periodEnd = end
	return m.invoiceFor(start, end, "released", collection, lines...)
}

func (m *matchingFixture) invoiceFor(start, end time.Time, closeState, collection string, lines ...StripeInvoiceAmountLine) string {
	m.t.Helper()
	id := "in_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	zero := int64(0)
	inv := StripeInvoiceAmounts{ID: id, Customer: m.f.c.CustomerID, Currency: "usd", Status: "paid", AmountRemaining: &zero, BillingReason: "subscription_cycle", PeriodStart: start.Unix(), PeriodEnd: end.Unix(), CollectionMethod: "charge_automatically"}
	inv.EndingBalance = m.endingBalance
	inv.Parent.SubscriptionDetails = &struct {
		Subscription string `json:"subscription"`
	}{Subscription: m.f.c.SubscriptionID}
	inv.Lines.Data = lines
	m.mu.Lock()
	m.invoices[id] = inv
	m.mu.Unlock()
	var prices any = []string{"price_cpu", "price_memory", "price_round", "price_storage"}
	if m.prices != nil {
		prices = m.prices
	}
	subscription := m.f.c.SubscriptionID
	if m.planSub != "" {
		subscription = m.planSub
	}
	plan := map[string]any{"customer": m.f.c.CustomerID, "subscription": subscription, "credit_version": 1, "credit_prices": prices, "base_cents": 100000, "expected_cents": 0, "credit_before_cents": 0, "resources": []any{}}
	raw, _ := json.Marshal(plan)
	m.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, m.f.c.TeamID, start, end)
	m.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,$6,clock_timestamp(),$5,'{}')`, m.f.c.TeamID, start, end, id, raw, closeState)
	m.exec(`INSERT INTO billing_invoice_collection(invoice_id,customer_id,subscription_id,livemode,settlement_hash,idempotency_key,payment_authorized,state) VALUES($1,$2,$3,false,$4,$5,true,$6)`, id, m.f.c.CustomerID, m.f.c.SubscriptionID, invoiceSettlementHash(inv), "billing-invoice-pay:v1:"+id, collection)
	return id
}

func (m *matchingFixture) exec(sql string, args ...any) {
	m.t.Helper()
	if _, err := m.f.h.Pool.Exec(m.t.Context(), sql, args...); err != nil {
		m.t.Fatal(err)
	}
}

func (m *matchingFixture) tick() error {
	m.exec(`UPDATE billing_matching_credit SET next_attempt_at=clock_timestamp() WHERE contract_id=$1`, m.f.c.ID)
	return m.f.h.matchingCreditTick(m.t.Context(), m.client)
}

type matchingRow struct {
	State, Skip                    string
	Usage, Credit, Matchable, Paid int64
	Grant                          string
	Flag                           string
}

func (m *matchingFixture) row(invoice string) matchingRow {
	m.t.Helper()
	var r matchingRow
	err := m.f.h.Pool.QueryRow(m.t.Context(), `SELECT state,COALESCE(skip_reason,''),usage_cents,credit_applied_cents,matchable_cents,amount_cents,COALESCE(stripe_credit_grant_id,''),COALESCE(flag_reason,'') FROM billing_matching_credit WHERE invoice_id=$1`, invoice).
		Scan(&r.State, &r.Skip, &r.Usage, &r.Credit, &r.Matchable, &r.Paid, &r.Grant, &r.Flag)
	if err != nil {
		m.t.Fatalf("matching row for %s: %v", invoice, err)
	}
	return r
}

func TestMatchingCreditProWorkedExample(t *testing.T) {
	m := newMatchingFixture(t, 5000, 1_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_base", 100000), usageLine("price_cpu", 50000, applied(25000)))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	r := m.row(invoice)
	if r.State != "issued" || r.Usage != 50000 || r.Credit != 25000 || r.Matchable != 25000 || r.Paid != 12500 {
		t.Fatalf("fee or credited usage was matched: %+v", r)
	}
	if len(m.posts) != 1 || m.keys[0] != "matching-credit:v1:"+invoice {
		t.Fatalf("grant identity not derived from invoice: %v", m.keys)
	}
	form := m.posts[0]
	for k, want := range map[string]string{"amount[monetary][value]": "12500", "applicability_config[scope][price_type]": "metered", "priority": "50", "category": "promotional", "metadata[invoice_id]": invoice, "customer": m.f.c.CustomerID} {
		if form.Get(k) != want {
			t.Fatalf("wire %s = %q, want %q", k, form.Get(k), want)
		}
	}
	if form.Has("expires_at") || form.Has("effective_at") || form.Has("applicability_config[scope][prices][0][id]") {
		t.Fatal("matched credit must not expire and must cover all metered usage", form)
	}
	g := m.grants[r.Grant]
	kept, err := m.f.h.withoutLedgerOwnedGrants(t.Context(), []billing.InvoiceCreditGrant{{ID: g.ID}, {ID: "credgr_other"}})
	if err != nil || len(kept) != 1 || kept[0].ID != "credgr_other" {
		t.Fatal("matching grant offered for adoption by another flow", kept, err)
	}
	if err := m.f.h.verifyOwnedEntitlementGrant(t.Context(), g); err != nil {
		t.Fatal("issued matching grant rejected by invoice credit ownership check", err)
	}
	if err := creditScope(g, m.f.c.CustomerID, time.Now().Add(400*24*time.Hour).Unix(), []string{"price_cpu"}); err != nil {
		t.Fatal("invoice close rejects matching grant scope", err)
	}
	g.Amount.Monetary.Value++
	if err := m.f.h.verifyOwnedEntitlementGrant(t.Context(), g); err == nil {
		t.Fatal("altered matching grant accepted")
	}
	g.ID = "credgr_unknown"
	if err := m.f.h.verifyOwnedEntitlementGrant(t.Context(), g); err == nil {
		t.Fatal("unconfirmed matching grant accepted")
	}
}

func TestMatchingCreditLegacyYCSchedule(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	first := m.paidInvoice("paid", usageLine("price_cpu", 500000, applied(500000)))
	second := m.paidInvoice("paid", usageLine("price_cpu", 400000, applied(400000)), usageLine("price_memory", 300000, applied(200000)))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(first); r.State != "skipped" || r.Paid != 0 || r.Skip != "" {
		t.Fatalf("fully credited month matched: %+v", r)
	}
	if r := m.row(second); r.State != "issued" || r.Matchable != 100000 || r.Paid != 100000 {
		t.Fatalf("customer-paid usage not matched: %+v", r)
	}
	consumed := m.paidInvoice("paid", usageLine("price_cpu", 100000, applied(100000)))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(consumed); r.State != "skipped" || r.Paid != 0 {
		t.Fatalf("usage covered by earlier matching credit compounded: %+v", r)
	}
	if len(m.posts) != 1 {
		t.Fatalf("expected one grant, got %d", len(m.posts))
	}
}

func TestMatchingCreditReplayAndDuplicates(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	m.lose = 1
	if err := m.tick(); err == nil {
		t.Fatal("expected lost provider response")
	}
	if r := m.row(invoice); r.State != "uncertain" {
		t.Fatalf("lost response not durable: %+v", r)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.f.h.matchingCreditTick(context.WithoutCancel(t.Context()), m.client)
		}()
	}
	wg.Wait()
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.State != "issued" || r.Paid != 70000 {
		t.Fatalf("replay did not settle: %+v", r)
	}
	if len(m.grants) != 1 {
		t.Fatalf("replay created %d grants", len(m.grants))
	}
	for i := range m.posts {
		if m.keys[i] != m.keys[0] || m.posts[i].Encode() != m.posts[0].Encode() {
			t.Fatal("replay changed the frozen request")
		}
	}
	var rows int
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_matching_credit WHERE contract_id=$1`, m.f.c.ID).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("invoice matched more than once", rows, err)
	}
	posts := len(m.posts)
	m.exec(`UPDATE billing_invoice_collection SET next_attempt_at=clock_timestamp() WHERE invoice_id=$1`, invoice)
	if err := m.tick(); err != nil || len(m.posts) != posts {
		t.Fatal("duplicate paid event re-issued", err)
	}
}

func TestMatchingCreditRequiresFullPayment(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	open := m.paidInvoice("processing", usageLine("price_cpu", 70000))
	partial := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	m.unpaid[partial] = true
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_matching_credit WHERE contract_id=$1`, m.f.c.ID).Scan(&rows); err != nil || rows != 1 || len(m.posts) != 0 {
		t.Fatal("matched before full payment", rows, err)
	}
	m.exec(`UPDATE billing_invoice_collection SET state='paid' WHERE invoice_id=$1`, open)
	m.mu.Lock()
	delete(m.unpaid, partial)
	m.mu.Unlock()
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if m.row(open).Paid != 70000 {
		t.Fatal("settled invoice was not matched")
	}
	if r := m.row(partial); r.State != "skipped" || r.Flag == "" || r.Paid != 0 {
		t.Fatalf("payment discrepancy was not held for staff: %+v", r)
	}
}

func TestMatchingCreditCapAcrossOutOfOrderInvoices(t *testing.T) {
	m := newMatchingFixture(t, 10000, 150000, 20000)
	first := m.paidInvoice("processing", usageLine("price_cpu", 100000))
	second := m.paidInvoice("processing", usageLine("price_cpu", 100000))
	third := m.paidInvoice("paid", usageLine("price_cpu", 100000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	m.exec(`UPDATE billing_invoice_collection SET state='paid' WHERE invoice_id IN ($1,$2)`, first, second)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	total := m.row(first).Paid + m.row(second).Paid + m.row(third).Paid
	if m.row(third).Paid != 100000 || total != 130000 {
		t.Fatalf("cap overshot or misallocated: %d", total)
	}
	if r := m.row(second); r.State != "skipped" || r.Paid != 0 {
		t.Fatalf("exhausted cap still matched: %+v", r)
	}
}

func TestMatchingCreditWaitsForEndedPeriodsToRelease(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	prior, ended := m.f.start.AddDate(0, -2, 0), m.f.start.AddDate(0, -1, 0)
	m.exec(`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, m.f.c.TeamID, prior)
	m.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, m.f.c.TeamID, ended, m.f.start)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.State != "pending" || len(m.posts) != 0 {
		t.Fatalf("grant issued while an ended period has no close: %+v", r)
	}
	closing := "in_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	m.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'verified',clock_timestamp(),'{}','{}')`, m.f.c.TeamID, ended, m.f.start, closing)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.State != "pending" || len(m.posts) != 0 {
		t.Fatalf("grant issued before the ended period was released: %+v", r)
	}
	m.exec(`UPDATE billing_invoice_close SET state='released' WHERE invoice_id=$1`, closing)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.State != "issued" {
		t.Fatalf("grant not issued after every ended period was released: %+v", r)
	}
}

func TestMatchingCreditConcurrentInsertsShareTheCap(t *testing.T) {
	m := newMatchingFixture(t, 10000, 1000, 0)
	first := m.paidInvoice("paid", usageLine("price_cpu", 800))
	second := m.paidInvoice("paid", usageLine("price_cpu", 800))
	insert := `INSERT INTO billing_matching_credit(team_id,contract_id,invoice_id,customer_id,period_start,period_end,usage_cents,credit_applied_cents,discount_cents,unpaid_cents,matchable_cents,amount_cents,invoice_evidence,state,idempotency_key)
 SELECT team_id,$2,invoice_id,$3,period_start,period_end,800,0,0,0,0,0,'{}','skipped','' FROM billing_invoice_close WHERE invoice_id=$1`
	ctx := t.Context()
	tx, err := m.f.h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, insert, first, m.f.c.ID, m.f.c.CustomerID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := m.f.h.Pool.Exec(ctx, insert, second, m.f.c.ID, m.f.c.CustomerID)
		done <- err
	}()
	select {
	case err = <-done:
		t.Fatalf("second insert did not wait for the rule lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if a, b := m.row(first).Paid, m.row(second).Paid; a != 800 || b != 200 {
		t.Fatalf("concurrent matches overshot the cap: %d + %d", a, b)
	}
}

func TestMatchingCreditFlagsReversals(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	noted := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	refunded := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	inv := m.invoices[noted]
	inv.PostPaymentCreditNotes = 5000
	m.invoices[noted] = inv
	m.refunded = true
	m.mu.Unlock()
	m.exec(`UPDATE billing_matching_credit SET review_checked_at=NULL WHERE contract_id=$1`, m.f.c.ID)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	for _, invoice := range []string{noted, refunded} {
		if r := m.row(invoice); r.Flag == "" || r.State != "issued" || r.Paid != 70000 {
			t.Fatalf("reversal not flagged or credit clawed back: %+v", r)
		}
	}
	changed := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	m.mu.Lock()
	inv = m.invoices[changed]
	inv.Total = 1
	m.invoices[changed] = inv
	m.mu.Unlock()
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(changed); r.State != "skipped" || r.Skip == "" || r.Flag == "" {
		t.Fatalf("changed settlement was matched: %+v", r)
	}
}

func TestMatchingCreditDiscoveryAfterReplayWindow(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	m.lose = 1
	_ = m.tick()
	conn, err := m.f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `UPDATE billing_matching_credit SET first_attempt_at=first_attempt_at-interval '1 day' WHERE invoice_id=$1`, invoice); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=origin`); err != nil {
		t.Fatal(err)
	}
	posts := len(m.posts)
	if err = m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.State != "issued" || len(m.posts) != posts {
		t.Fatalf("expired replay window resent instead of discovering: %+v", r)
	}
}

func TestMatchingCreditLedgerIsImmutable(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE billing_matching_credit SET amount_cents=amount_cents+1 WHERE invoice_id=$1`,
		`UPDATE billing_matching_credit SET state='pending' WHERE invoice_id=$1`,
		`DELETE FROM billing_matching_credit WHERE invoice_id=$1`,
	} {
		if _, err := m.f.h.Pool.Exec(t.Context(), sql, invoice); err == nil {
			t.Fatalf("ledger accepted %s", sql)
		}
	}
	for _, sql := range []string{
		`UPDATE billing_contract_matching_rule SET cap_cents=cap_cents+1 WHERE contract_id=$1`,
		`DELETE FROM billing_contract_matching_rule WHERE contract_id=$1`,
	} {
		if _, err := m.f.h.Pool.Exec(t.Context(), sql, m.f.c.ID); err == nil {
			t.Fatalf("rule accepted %s", sql)
		}
	}
	unpaid := m.invoiceFor(m.periodEnd, m.periodEnd.AddDate(0, 1, 0), "released", "processing", usageLine("price_cpu", 1))
	if _, err := m.f.h.Pool.Exec(t.Context(), `INSERT INTO billing_matching_credit(team_id,contract_id,invoice_id,customer_id,period_start,period_end,usage_cents,credit_applied_cents,discount_cents,unpaid_cents,matchable_cents,amount_cents,invoice_evidence,state,idempotency_key)
 SELECT team_id,$2,invoice_id,$3,period_start,period_end,1,0,0,0,0,0,'{}','skipped','' FROM billing_invoice_close WHERE invoice_id=$1`, unpaid, m.f.c.ID, m.f.c.CustomerID); err == nil {
		t.Fatal("ledger accepted an unpaid invoice")
	}
}

func TestMatchingCreditWithholdsReversedPayments(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	m.refunded = true
	early := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(early); r.State != "skipped" || r.Paid != 0 || r.Flag == "" || len(m.posts) != 0 {
		t.Fatalf("invoice refunded before matching earned credit: %+v", r)
	}
	m.mu.Lock()
	m.refunded = false
	m.mu.Unlock()
	prior, ended := m.f.start.AddDate(0, -2, 0), m.f.start.AddDate(0, -1, 0)
	m.exec(`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, m.f.c.TeamID, prior)
	m.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, m.f.c.TeamID, ended, m.f.start)
	waiting := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(waiting); r.State != "pending" || r.Paid != 70000 {
		t.Fatalf("match not recorded behind the close fence: %+v", r)
	}
	m.mu.Lock()
	m.refunded = true
	m.mu.Unlock()
	m.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),'{}','{}')`, m.f.c.TeamID, ended, m.f.start, "in_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
	for i := 0; i < 2; i++ {
		if err := m.tick(); err != nil {
			t.Fatal(err)
		}
	}
	if r := m.row(waiting); r.State != "pending" || r.Flag == "" || len(m.posts) != 0 {
		t.Fatalf("grant sent for a payment reversed while the match waited: %+v", r)
	}
	if _, err := m.f.h.Pool.Exec(t.Context(), `UPDATE billing_matching_credit SET state='uncertain',first_attempt_at=clock_timestamp() WHERE invoice_id=$1`, waiting); err == nil {
		t.Fatal("database allowed a flagged match to be dispatched")
	}
	var id uuid.UUID
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_matching_credit WHERE invoice_id=$1`, waiting).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "won dispute", ""); err == nil {
		t.Fatal("held match acknowledged without a resolution")
	}
	if _, state, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "dispute was won", "issue"); err != nil || state != "pending" {
		t.Fatal("staff could not release a held match", state, err)
	}
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(waiting); r.State != "issued" || len(m.posts) != 1 {
		t.Fatalf("released match was not issued: %+v", r)
	}
}

func TestMatchingCreditWithheldMatchKeepsCapReserved(t *testing.T) {
	m := newMatchingFixture(t, 10000, 70000, 0)
	prior, ended := m.f.start.AddDate(0, -2, 0), m.f.start.AddDate(0, -1, 0)
	m.exec(`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, m.f.c.TeamID, prior)
	m.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, m.f.c.TeamID, ended, m.f.start)
	held := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.refunded = true
	m.mu.Unlock()
	m.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),'{}','{}')`, m.f.c.TeamID, ended, m.f.start, "in_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_matching_credit WHERE invoice_id=$1 AND flagged_at IS NOT NULL`, held).Scan(&id); err != nil {
		t.Fatal("reversal did not hold the match", err)
	}
	if _, state, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "refunded", "withhold"); err != nil || state != "withheld" {
		t.Fatal("staff could not withhold a held match", state, err)
	}
	m.mu.Lock()
	m.refunded = false
	m.mu.Unlock()
	next := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(next); r.Paid != 0 || r.State != "skipped" || len(m.posts) != 0 {
		t.Fatalf("withholding released cap that earlier skips could not reclaim: %+v", r)
	}
	if r := m.row(held); r.State != "withheld" {
		t.Fatalf("withheld match changed: %+v", r)
	}
}

func TestMatchingCreditRetiresMalformedPlansDurably(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	var malformed []string
	for _, prices := range []any{[]any{nil, "price_cpu"}, []any{1, "price_cpu"}, []any{[]any{"price_cpu"}, "price_cpu"}} {
		m.prices = prices
		malformed = append(malformed, m.paidInvoice("paid", usageLine("price_cpu", 100)))
	}
	m.prices = map[string]any{"unexpected": true}
	for i := 0; i < 21; i++ {
		malformed = append(malformed, m.paidInvoice("paid", usageLine("price_cpu", 100)))
	}
	m.prices = nil
	valid := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	for i := 0; i < 2; i++ {
		if err := m.tick(); err != nil {
			t.Fatal(err)
		}
	}
	for _, invoice := range malformed {
		if r := m.row(invoice); r.State != "skipped" || r.Skip == "" || r.Flag == "" {
			t.Fatalf("malformed plan not retired for staff: %+v", r)
		}
	}
	if r := m.row(valid); r.State != "issued" {
		t.Fatalf("malformed plans starved a valid invoice: %+v", r)
	}
}

func TestMatchingCreditReviewWindowStartsAtIssuance(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	conn, err := m.f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, sql := range []string{`SET session_replication_role=replica`, `UPDATE billing_matching_credit SET created_at=created_at-interval '200 days',review_checked_at=NULL WHERE invoice_id=$1`, `SET session_replication_role=origin`} {
		var args []any
		if strings.Contains(sql, "$1") {
			args = append(args, invoice)
		}
		if _, err = conn.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	m.refunded = true
	m.mu.Unlock()
	if err = m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(invoice); r.Flag == "" {
		t.Fatalf("refund after a late issuance escaped review: %+v", r)
	}
}

func TestMatchingCreditIgnoresReplacementSubscriptions(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	m.planSub = "sub_" + uuid.NewString()
	replacement := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_matching_credit WHERE invoice_id=$1`, replacement).Scan(&rows); err != nil || rows != 0 || len(m.posts) != 0 {
		t.Fatal("an invoice from another subscription was matched under this contract", rows, err)
	}
	if _, err := m.f.h.Pool.Exec(t.Context(), `INSERT INTO billing_matching_credit(team_id,contract_id,invoice_id,customer_id,period_start,period_end,usage_cents,credit_applied_cents,discount_cents,unpaid_cents,matchable_cents,amount_cents,invoice_evidence,state,idempotency_key)
 SELECT team_id,$2,invoice_id,$3,period_start,period_end,1,0,0,0,0,0,'{}','skipped','' FROM billing_invoice_close WHERE invoice_id=$1`, replacement, m.f.c.ID, m.f.c.CustomerID); err == nil {
		t.Fatal("ledger accepted an invoice from another subscription")
	}
	m.planSub = ""
	own := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if r := m.row(own); r.State != "issued" {
		t.Fatalf("the contract's own subscription was not matched: %+v", r)
	}
}

func TestMatchingCreditYieldsToSuccessorContract(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	before := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	successorStart := m.periodEnd
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	conn, err := m.f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, sql := range []string{
		`SET session_replication_role=replica`,
		`INSERT INTO billing_commercial_contract(team_id,offer_key,status,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor)
 SELECT team_id,offer_key,'ended',$2,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,$2 FROM billing_commercial_contract WHERE id=$1`,
		`SET session_replication_role=origin`,
	} {
		var args []any
		if strings.Contains(sql, "$1") {
			args = []any{m.f.c.ID, successorStart}
		}
		if _, err = conn.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = m.tick(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err = m.f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("a contract kept matching after a successor started on its subscription", rows, err)
	}
	if r := m.row(before); r.State != "issued" {
		t.Fatalf("usage before the successor started was not matched: %+v", r)
	}
}

func TestMatchingCreditPaymentDiscrepanciesDoNotStarveQueue(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	var unpaid []string
	for i := 0; i < 21; i++ {
		invoice := m.paidInvoice("paid", usageLine("price_cpu", 100))
		m.unpaid[invoice] = true
		unpaid = append(unpaid, invoice)
	}
	valid := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	for i := 0; i < 2; i++ {
		if err := m.tick(); err != nil {
			t.Fatal(err)
		}
	}
	for _, invoice := range unpaid {
		if r := m.row(invoice); r.State != "skipped" || r.Flag == "" || r.Paid != 0 {
			t.Fatalf("payment discrepancy not retired for staff: %+v", r)
		}
	}
	if r := m.row(valid); r.State != "issued" {
		t.Fatalf("payment discrepancies starved a valid invoice: %+v", r)
	}
}

func TestMatchingCreditFinalReviewChecksReversals(t *testing.T) {
	for _, refunded := range []bool{false, true} {
		t.Run(fmt.Sprint(refunded), func(t *testing.T) {
			m := newMatchingFixture(t, 10000, 8_000_000, 0)
			invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			conn, err := m.f.h.Pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, sql := range []string{`SET session_replication_role=replica`, `UPDATE billing_matching_credit SET issued_at=now()-interval '120 days 1 hour',review_checked_at=now()-interval '25 hours' WHERE invoice_id=$1`, `SET session_replication_role=origin`} {
				var args []any
				if strings.Contains(sql, "$1") {
					args = append(args, invoice)
				}
				if _, err = conn.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			conn.Release()
			m.mu.Lock()
			m.refunded = refunded
			m.mu.Unlock()
			if err = m.tick(); err != nil {
				t.Fatal(err)
			}
			if r := m.row(invoice); (r.Flag != "") != refunded {
				t.Fatalf("final review missed reversal: %+v", r)
			}
			var retired bool
			if err = m.f.h.Pool.QueryRow(t.Context(), `SELECT review_checked_at='infinity'::timestamptz FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&retired); err != nil || retired == refunded {
				t.Fatal("final review retirement", retired, err)
			}
		})
	}
}

func TestMatchingCreditInspectionFailuresDoNotStarveQueue(t *testing.T) {
	for _, stage := range []string{"invoice", "reversal"} {
		t.Run(stage, func(t *testing.T) {
			m := newMatchingFixture(t, 10000, 8_000_000, 0)
			bad := map[string]bool{}
			for i := 0; i < 20; i++ {
				bad[m.paidInvoice("paid", usageLine("price_cpu", 100))] = true
			}
			valid := m.paidInvoice("paid", usageLine("price_cpu", 70000))
			var recovered atomic.Bool
			var failedRequests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoice := strings.TrimPrefix(r.URL.Path, "/v1/invoices/")
				if stage == "reversal" {
					invoice = r.URL.Query().Get("invoice")
				}
				if bad[invoice] && !recovered.Load() {
					var durable bool
					if err := m.f.h.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM billing_matching_invoice_inspection WHERE invoice_id=$1 AND next_attempt_at>clock_timestamp())`, invoice).Scan(&durable); err != nil || !durable {
						t.Errorf("provider inspection preceded durable retry claim: %v %v", durable, err)
					}
					failedRequests.Add(1)
					if stage == "invoice" {
						http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
					} else {
						fmt.Fprint(w, `{"data":{}}`)
					}
					return
				}
				m.serve(w, r)
			}))
			defer srv.Close()
			m.client.baseURL = srv.URL
			if err := m.tick(); err == nil {
				t.Fatal("provider failures were not reported")
			}
			if got := failedRequests.Load(); got != 20 {
				t.Fatalf("failed provider requests = %d", got)
			}
			var deferred int
			if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_matching_invoice_inspection i JOIN billing_invoice_close j USING(invoice_id) WHERE j.team_id=$1 AND i.next_attempt_at>clock_timestamp() AND i.last_error IS NOT NULL`, m.f.c.TeamID).Scan(&deferred); err != nil || deferred != 20 {
				t.Fatal("failed candidates lack durable backoff", deferred, err)
			}
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			if r := m.row(valid); r.State != "issued" || failedRequests.Load() != 20 {
				t.Fatalf("failed inspections starved or retried ahead of a valid invoice: %+v requests=%d", r, failedRequests.Load())
			}
			recovered.Store(true)
			m.exec(`UPDATE billing_matching_invoice_inspection SET next_attempt_at=clock_timestamp() WHERE invoice_id=ANY($1)`, func() []string {
				var ids []string
				for id := range bad {
					ids = append(ids, id)
				}
				return ids
			}())
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			for invoice := range bad {
				if r := m.row(invoice); r.State != "issued" {
					t.Fatalf("recovered inspection never issued: %+v", r)
				}
			}
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			if len(m.posts) != 21 {
				t.Fatalf("recovery duplicated grants: %d", len(m.posts))
			}
		})
	}
}

func TestMatchingCreditUnsupportedPaidEvidenceCannotAuthorizeOrRetire(t *testing.T) {
	for _, field := range []string{"invoice", "type", "intent", "retrieved intent", "missing payments", "empty payments", "partial payments", "duplicate payments"} {
		for _, stage := range []string{"inspection", "issuance", "final review"} {
			t.Run(field+"/"+stage, func(t *testing.T) {
				m := newMatchingFixture(t, 10000, 8_000_000, 0)
				invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
				switch stage {
				case "issuance":
					if err := m.f.h.recordPaidMatchingInvoices(t.Context(), m.client); err != nil {
						t.Fatal(err)
					}
				case "final review":
					if err := m.tick(); err != nil {
						t.Fatal(err)
					}
					conn, err := m.f.h.Pool.Acquire(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					for _, sql := range []string{`SET session_replication_role=replica`, `UPDATE billing_matching_credit SET issued_at=now()-interval '120 days 1 hour',review_checked_at=now()-interval '25 hours' WHERE invoice_id=$1`, `SET session_replication_role=origin`} {
						var args []any
						if strings.Contains(sql, "$1") {
							args = append(args, invoice)
						}
						if _, err = conn.Exec(t.Context(), sql, args...); err != nil {
							t.Fatal(err)
						}
					}
					conn.Release()
				}
				var recovered atomic.Bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !recovered.Load() {
						if field == "retrieved intent" && r.URL.Path == "/v1/payment_intents/pi_match" {
							fmt.Fprint(w, `{"id":"pi_other","latest_charge":"ch_match"}`)
							return
						}
						if field != "retrieved intent" && r.URL.Path == "/v1/invoice_payments" {
							if field == "missing payments" {
								fmt.Fprint(w, `{}`)
								return
							}
							if field == "empty payments" {
								fmt.Fprint(w, `{"data":[]}`)
								return
							}
							if field == "duplicate payments" {
								payment := map[string]any{"invoice": invoice, "amount_paid": 35000, "payment": map[string]string{"type": "payment_intent", "payment_intent": "pi_match"}}
								json.NewEncoder(w).Encode(map[string]any{"data": []any{payment, payment}})
								return
							}
							inv, kind, intent := invoice, "payment_intent", "pi_match"
							switch field {
							case "invoice":
								inv = "in_other"
							case "type":
								kind = "payment_record"
							case "intent":
								intent = ""
							}
							json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"invoice": inv, "amount_paid": 100, "payment": map[string]any{"type": kind, "payment_intent": intent}}}})
							return
						}
					}
					m.serve(w, r)
				}))
				defer srv.Close()
				m.client.baseURL = srv.URL
				if err := m.tick(); err == nil {
					t.Fatal("unsupported payment evidence was accepted as clean")
				}
				switch stage {
				case "inspection":
					var deferred bool
					if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT next_attempt_at>clock_timestamp() AND last_error IS NOT NULL FROM billing_matching_invoice_inspection WHERE invoice_id=$1`, invoice).Scan(&deferred); err != nil || !deferred {
						t.Fatal("inspection lacks durable evidence retry", deferred, err)
					}
				case "issuance":
					if row := m.row(invoice); row.State != "pending" || row.Grant != "" {
						t.Fatal("unsupported evidence dispatched a grant", row)
					}
				case "final review":
					var retired bool
					if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT review_checked_at='infinity'::timestamptz FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&retired); err != nil || retired {
						t.Fatal("unsupported evidence retired final review", retired, err)
					}
				}
				if stage != "final review" && len(m.posts) != 0 {
					t.Fatal("unsupported evidence issued credit", len(m.posts))
				}
				recovered.Store(true)
				m.exec(`UPDATE billing_matching_invoice_inspection SET next_attempt_at=clock_timestamp() WHERE invoice_id=$1`, invoice)
				m.exec(`UPDATE billing_matching_credit SET review_checked_at=clock_timestamp()-interval '25 hours' WHERE invoice_id=$1`, invoice)
				if err := m.tick(); err != nil {
					t.Fatal("valid evidence recovery failed", err)
				}
				if row := m.row(invoice); row.State != "issued" || len(m.posts) != 1 {
					t.Fatal("recovery lost or duplicated credit", row, len(m.posts))
				}
			})
		}
	}
}

func TestMatchingCreditBacklogBudgetPreservesIssuanceAndReversalReview(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	issued := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	pending := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	if err := m.f.h.recordPaidMatchingInvoices(t.Context(), m.client); err != nil {
		t.Fatal(err)
	}
	backlog := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	m.exec(`UPDATE billing_matching_credit SET review_checked_at=clock_timestamp()-interval '25 hours' WHERE invoice_id=$1`, issued)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/invoices/"+backlog:
			<-r.Context().Done()
		case r.URL.Path == "/v1/invoice_payments" && r.URL.Query().Get("invoice") == issued:
			fmt.Fprintf(w, `{"data":[{"invoice":%q,"amount_paid":100,"payment":{"type":"payment_intent","payment_intent":"pi_review"}}]}`, issued)
		case r.URL.Path == "/v1/payment_intents/pi_review":
			fmt.Fprint(w, `{"id":"pi_review","latest_charge":"ch_review"}`)
		case r.URL.Path == "/v1/charges/ch_review":
			fmt.Fprintf(w, `{"id":"ch_review","customer":%q,"payment_intent":"pi_review","currency":"usd","paid":true,"captured":true,"amount_captured":100,"amount_refunded":100}`, m.f.c.CustomerID)
		default:
			m.serve(w, r)
		}
	}))
	defer srv.Close()
	m.client.baseURL = srv.URL
	err := runBillingPhases(t.Context(), time.Second,
		func(ctx context.Context) error { return m.f.h.recordPaidMatchingInvoices(ctx, m.client) },
		func(ctx context.Context) error { return m.f.h.issueDueMatchingCredits(ctx, m.client) },
		func(ctx context.Context) error { return m.f.h.reviewMatchedInvoices(ctx, m.client) },
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("backlog timeout was not reported", err)
	}
	if row := m.row(pending); row.State != "issued" {
		t.Fatal("candidate timeout starved a pending grant", row)
	}
	if row := m.row(issued); row.Flag == "" {
		t.Fatal("candidate timeout starved reversal review", row)
	}
}
