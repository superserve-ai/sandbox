//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type prepaidFixture struct {
	t                   *testing.T
	h                   *Handlers
	client              *stripeHTTPClient
	team                uuid.UUID
	customer, sub       string
	mu                  sync.Mutex
	intents             map[string]prepaidPaymentIntent
	intentByKey         map[string]string
	sessions            map[string]map[string]any
	sessionByKey        map[string]string
	invoices            map[string]StripeInvoiceAmounts
	products            map[string]map[string]string
	grants              map[string]entitlementGrant
	grantByKey          map[string]string
	balances            map[string]int64
	intentPosts         []url.Values
	intentKeys          []string
	grantPosts          []url.Values
	decline, loseIntent bool
	aggregateReads      int
	assigned            []uuid.UUID
}

func newPrepaidFixture(t *testing.T) *prepaidFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("DATABASE_URL must name a migrated disposable test database", err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool, DB: db.New(pool), Config: &config.Config{}}
	installPrepaidPublicStateFixture(t, h)
	setPricingVersion(t, h, "v2")
	team, err := h.DB.CreateTeam(t.Context(), "prepaid-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	terms, err := h.planTerms(t.Context(), "starter")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = assignInTx(t, h, planAssignment{Team: team.ID, Terms: terms, Source: planSourceCreditPurchase, Reason: "fixture prepaid team"}); err != nil {
		t.Fatal(err)
	}
	f := &prepaidFixture{t: t, h: h, team: team.ID, customer: "cus_" + uuid.NewString(), sub: "sub_" + uuid.NewString(),
		intents: map[string]prepaidPaymentIntent{}, intentByKey: map[string]string{}, sessions: map[string]map[string]any{}, sessionByKey: map[string]string{},
		invoices: map[string]StripeInvoiceAmounts{}, products: map[string]map[string]string{}, grants: map[string]entitlementGrant{}, grantByKey: map[string]string{}, balances: map[string]int64{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.client = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	h.Stripe = f.client
	f.exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status) VALUES($1,$2,$3,'active')`, f.team, f.customer, f.sub)
	f.exec(`INSERT INTO billing_funding_account(team_id,observe) VALUES($1,true) ON CONFLICT(team_id) DO UPDATE SET observe=true`, f.team)
	f.observe(1000, true)
	assign := assignStarterAfterPurchase
	assignStarterAfterPurchase = func(_ context.Context, _ *Handlers, _ uuid.UUID, purchase uuid.UUID) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.assigned = append(f.assigned, purchase)
		return nil
	}
	t.Cleanup(func() {
		assignStarterAfterPurchase = assign
		_, _ = pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false,prepaid=false WHERE team_id=$1`, f.team)
		_, _ = pool.Exec(context.Background(), `UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
		_, _ = pool.Exec(context.Background(), `UPDATE billing_prepaid_purchase SET next_attempt_at='9999-01-01',credit_balance_checked_at='9999-01-01' WHERE team_id=$1`, f.team)
	})
	return f
}

func (f *prepaidFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.h.Pool.Exec(f.t.Context(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

// observe publishes a fresh funding observation, as the funding worker would.
func (f *prepaidFixture) observe(creditCents int64, card bool) {
	f.t.Helper()
	f.exec(`UPDATE billing_funding_account SET observed_generation=generation,customer_id=$2,subscription_id=$3,credit_usd=$4::numeric/100,
 credit_valid_until=clock_timestamp()+interval '1 minute',credit_checked_at=clock_timestamp(),payment_method_ready=$5,payment_method_id=CASE WHEN $5 THEN 'pm_saved' END WHERE team_id=$1`,
		f.team, f.customer, f.sub, creditCents, card)
}

func (f *prepaidFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = r.ParseForm()
	key := r.Header.Get("Idempotency-Key")
	path := r.URL.Path
	switch {
	case path == "/v1/payment_intents" && r.Method == http.MethodPost:
		f.intentPosts = append(f.intentPosts, r.PostForm)
		f.intentKeys = append(f.intentKeys, key)
		if f.decline {
			w.WriteHeader(http.StatusPaymentRequired)
			fmt.Fprint(w, `{"error":{"type":"card_error","code":"card_declined"}}`)
			return
		}
		id, ok := f.intentByKey[key]
		if !ok {
			amount, _ := strconv.ParseInt(r.PostForm.Get("amount"), 10, 64)
			id = "pi_" + uuid.NewString()
			f.intents[id] = prepaidPaymentIntent{ID: id, Status: "succeeded", Amount: amount, AmountReceived: amount, Currency: "usd", Customer: r.PostForm.Get("customer"), PaymentMethod: r.PostForm.Get("payment_method"), Created: time.Now().Unix(), Metadata: map[string]string{"prepaid_purchase_id": r.PostForm.Get("metadata[prepaid_purchase_id]")}}
			f.intentByKey[key] = id
		}
		if f.loseIntent {
			f.loseIntent = false
			http.Error(w, "lost", 503)
			return
		}
		json.NewEncoder(w).Encode(f.intents[id])
	case strings.HasPrefix(path, "/v1/payment_intents/"):
		json.NewEncoder(w).Encode(f.intents[strings.TrimPrefix(path, "/v1/payment_intents/")])
	case path == "/v1/payment_intents":
		data := []prepaidPaymentIntent{}
		for _, pi := range f.intents {
			data = append(data, pi)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	case path == "/v1/checkout/sessions" && r.Method == http.MethodPost:
		var frozen bool
		if err := f.h.Pool.QueryRow(r.Context(), `SELECT plan_snapshot IS NOT NULL FROM billing_prepaid_purchase WHERE id=$1`, r.PostForm.Get("metadata[prepaid_purchase_id]")).Scan(&frozen); err != nil || !frozen {
			f.t.Error("checkout dispatched before durable plan authority", frozen, err)
		}
		id, ok := f.sessionByKey[key]
		if !ok {
			id = "cs_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			f.sessions[id] = map[string]any{"id": id, "url": "https://checkout.example.com/" + id, "mode": r.PostForm.Get("mode"), "status": "open", "customer": r.PostForm.Get("customer"),
				"metadata": map[string]string{"prepaid_purchase_id": r.PostForm.Get("metadata[prepaid_purchase_id]")}, "amount": r.PostForm.Get("line_items[0][price_data][unit_amount]")}
			f.sessionByKey[key] = id
		}
		json.NewEncoder(w).Encode(f.sessions[id])
	case path == "/v1/checkout/sessions" && r.Method == http.MethodGet:
		sessions := []map[string]any{}
		for _, session := range f.sessions {
			sessions = append(sessions, session)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": sessions, "has_more": false})
	case strings.HasPrefix(path, "/v1/checkout/sessions/"):
		json.NewEncoder(w).Encode(f.sessions[strings.TrimPrefix(path, "/v1/checkout/sessions/")])
	case strings.HasPrefix(path, "/v1/invoices/"):
		json.NewEncoder(w).Encode(f.invoices[strings.TrimPrefix(path, "/v1/invoices/")])
	case strings.HasPrefix(path, "/v1/products/"):
		id := strings.TrimPrefix(path, "/v1/products/")
		json.NewEncoder(w).Encode(map[string]any{"id": id, "metadata": f.products[id]})
	case path == "/v1/billing/credit_grants" && r.Method == http.MethodPost:
		f.grantPosts = append(f.grantPosts, r.PostForm)
		id, ok := f.grantByKey[key]
		if !ok {
			var g entitlementGrant
			g.ID, g.Customer, g.Category, g.Priority = "credgr_"+uuid.NewString(), r.PostForm.Get("customer"), r.PostForm.Get("category"), 50
			g.Created, g.EffectiveAt = time.Now().Unix(), time.Now().Unix()
			g.Amount.Type, g.Amount.Monetary.Currency = "monetary", "usd"
			g.Amount.Monetary.Value, _ = strconv.ParseInt(r.PostForm.Get("amount[monetary][value]"), 10, 64)
			g.Applicability.Scope.PriceType = r.PostForm.Get("applicability_config[scope][price_type]")
			g.Metadata = map[string]string{"prepaid_purchase_id": r.PostForm.Get("metadata[prepaid_purchase_id]"), "source": r.PostForm.Get("metadata[source]")}
			f.grants[g.ID] = g
			f.balances[g.ID] = g.Amount.Monetary.Value
			f.grantByKey[key] = g.ID
			id = g.ID
		}
		json.NewEncoder(w).Encode(f.grants[id])
	case path == "/v1/billing/credit_grants":
		data := []entitlementGrant{}
		for _, g := range f.grants {
			data = append(data, g)
		}
		sort.Slice(data, func(i, j int) bool { return data[i].ID > data[j].ID })
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	case strings.HasSuffix(path, "/void"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/billing/credit_grants/"), "/void")
		g := f.grants[id]
		g.VoidedAt = time.Now().Unix()
		f.grants[id] = g
		json.NewEncoder(w).Encode(g)
	case strings.HasPrefix(path, "/v1/billing/credit_grants/"):
		json.NewEncoder(w).Encode(f.grants[strings.TrimPrefix(path, "/v1/billing/credit_grants/")])
	case path == "/v1/invoices":
		fmt.Fprint(w, `{"data":[]}`)
	case path == "/v1/billing/credit_balance_summary" && r.URL.Query().Get("filter[type]") == "applicability_scope":
		f.aggregateReads++
		total := int64(0)
		for id, g := range f.grants {
			if g.VoidedAt == 0 {
				total += f.balances[id]
			}
		}
		fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}},"available_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, total, total)
	case path == "/v1/billing/credit_balance_summary":
		id := r.URL.Query().Get("filter[credit_grant]")
		fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}},"available_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, f.balances[id], f.balances[id])
	default:
		f.t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", 500)
	}
}

func (f *prepaidFixture) tick() error {
	f.exec(`UPDATE billing_prepaid_purchase SET next_attempt_at=clock_timestamp() WHERE team_id=$1`, f.team)
	return f.h.prepaidTick(f.t.Context(), f.client)
}

type prepaidRow struct {
	Source, Payment, Credit, Grant, Failure string
	Amount                                  int64
}

func (f *prepaidFixture) rows() []prepaidRow {
	f.t.Helper()
	rows, err := f.h.Pool.Query(f.t.Context(), `SELECT source,payment_state,credit_state,COALESCE(stripe_credit_grant_id,''),COALESCE(failure_reason,''),amount_cents FROM billing_prepaid_purchase WHERE team_id=$1 ORDER BY created_at`, f.team)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []prepaidRow
	for rows.Next() {
		var r prepaidRow
		if err = rows.Scan(&r.Source, &r.Payment, &r.Credit, &r.Grant, &r.Failure, &r.Amount); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (f *prepaidFixture) enableAutoRecharge(threshold, amount int64) {
	f.exec(`INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,threshold_cents,amount_cents) VALUES($1,true,$2,$3)
 ON CONFLICT(team_id) DO UPDATE SET enabled=true,threshold_cents=$2,amount_cents=$3,disabled_reason=NULL,disabled_at=NULL`, f.team, threshold, amount)
}

func TestPrepaidAutoRechargeChargesOnceAndIssuesPaidCredit(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(1500, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	rows := f.rows()
	if len(rows) != 1 || rows[0].Source != "auto_recharge" || rows[0].Payment != "succeeded" || rows[0].Credit != "issued" || rows[0].Amount != 5000 {
		t.Fatalf("auto-recharge did not settle: %+v", rows)
	}
	pi := f.intentPosts[0]
	for k, want := range map[string]string{"amount": "5000", "currency": "usd", "customer": f.customer, "payment_method": "pm_saved", "off_session": "true", "confirm": "true"} {
		if pi.Get(k) != want {
			t.Fatalf("payment %s = %q, want %q", k, pi.Get(k), want)
		}
	}
	grant := f.grantPosts[0]
	for k, want := range map[string]string{"category": "paid", "amount[monetary][value]": "5000", "applicability_config[scope][price_type]": "metered", "priority": "50"} {
		if grant.Get(k) != want {
			t.Fatalf("grant %s = %q, want %q", k, grant.Get(k), want)
		}
	}
	if grant.Has("expires_at") {
		t.Fatal("purchased credit must not expire")
	}
	for i := 0; i < 3; i++ {
		if err := f.tick(); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.intentPosts) != 1 {
		t.Fatalf("a stale balance observation charged again: %d charges", len(f.intentPosts))
	}
	g := f.grants[f.rows()[0].Grant]
	if err := f.h.verifyOwnedEntitlementGrant(t.Context(), g); err != nil {
		t.Fatal("issued purchase grant rejected by the invoice credit ownership check", err)
	}
	kept, err := f.h.withoutLedgerOwnedGrants(t.Context(), nil)
	if err != nil || len(kept) != 0 {
		t.Fatal(kept, err)
	}
}

func TestPrepaidAutoRechargeReplaysLostChargeWithSameKey(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	f.loseIntent = true
	if err := f.tick(); err == nil {
		t.Fatal("expected a lost provider response")
	}
	if r := f.rows(); len(r) != 1 || r[0].Payment != "uncertain" {
		t.Fatalf("lost charge not durable: %+v", r)
	}
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if len(f.intents) != 1 || len(f.intentKeys) != 2 || f.intentKeys[0] != f.intentKeys[1] || f.intentPosts[0].Encode() != f.intentPosts[1].Encode() {
		t.Fatalf("replay changed the charge: intents=%d keys=%v", len(f.intents), f.intentKeys)
	}
	if r := f.rows(); len(r) != 1 || r[0].Credit != "issued" {
		t.Fatalf("replayed charge not credited once: %+v", r)
	}
}

func TestPrepaidAutoRechargeDeclineDisablesAndRecordsWhy(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	f.decline = true
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); len(r) != 1 || r[0].Payment != "failed" || r[0].Credit != "none" || r[0].Failure == "" {
		t.Fatalf("decline not recorded: %+v", r)
	}
	var enabled bool
	var reason *string
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT enabled,disabled_reason FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled, &reason); err != nil || enabled || reason == nil {
		t.Fatalf("decline did not disable auto-recharge: %v %v %v", enabled, reason, err)
	}
	f.decline = false
	if err := f.tick(); err != nil || len(f.intentPosts) != 1 {
		t.Fatal("disabled auto-recharge charged again", err)
	}
}

func TestPrepaidAutoRechargeSafetyCaps(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 500)
	f.exec(`INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key,next_attempt_at)
 SELECT $1,$2,'checkout',500,gen_random_uuid(),'','','9999-01-01' FROM generate_series(1,$3)`, f.team, f.customer, prepaidLiveGrantLimit)
	f.observe(0, true)
	if err := f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var auto int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1 AND source='auto_recharge'`, f.team).Scan(&auto); err != nil || auto != 0 {
		t.Fatal("unspent purchases were not bounded", auto, err)
	}
	f.exec(`UPDATE billing_prepaid_purchase SET payment_state='failed',failure_reason='fixture' WHERE team_id=$1`, f.team)
	for i := 0; i <= prepaidAutoRechargeDailyCap; i++ {
		f.observe(0, true)
		if err := f.tick(); err != nil {
			t.Fatal(err)
		}
		f.exec(`UPDATE billing_prepaid_purchase SET credit_voided_at=clock_timestamp() WHERE team_id=$1 AND credit_state='issued' AND credit_voided_at IS NULL`, f.team)
	}
	var enabled bool
	var reason string
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT enabled,COALESCE(disabled_reason,'') FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled, &reason); err != nil {
		t.Fatal(err)
	}
	if enabled || !strings.Contains(reason, "24 hours") || len(f.intentPosts) != prepaidAutoRechargeDailyCap {
		t.Fatalf("daily cap not enforced: enabled=%v reason=%q charges=%d", enabled, reason, len(f.intentPosts))
	}
}

func TestPrepaidSwitchOffKeepsExistingAutoRecharge(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	setPricingVersion(t, f.h, "legacy")
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); len(r) != 1 || r[0].Credit != "issued" {
		t.Fatalf("switch-off stranded a team that enabled auto-recharge: %+v", r)
	}
}

func TestPrepaidPaymentCheckoutCreditsOnlyAfterVerifiedPayment(t *testing.T) {
	f := newPrepaidFixture(t)
	s, err := f.h.startPrepaidPaymentCheckout(t.Context(), f.client, f.team, uuid.New(), f.customer, 2500, "https://console.example.com/ok", "https://console.example.com/cancel")
	if err != nil || s.URL == "" {
		t.Fatal(s, err)
	}
	if err = f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); r[0].Payment != "processing" || len(f.grantPosts) != 0 {
		t.Fatalf("open checkout was credited: %+v", r)
	}
	var id uuid.UUID
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	pi := prepaidPaymentIntent{ID: "pi_" + uuid.NewString(), Status: "succeeded", Amount: 2500, AmountReceived: 2500, Currency: "usd", Customer: f.customer, Metadata: map[string]string{"prepaid_purchase_id": id.String()}}
	f.intents[pi.ID] = pi
	f.sessions[s.ID]["status"], f.sessions[s.ID]["payment_intent"] = "complete", pi.ID
	f.mu.Unlock()
	for i := 0; i < 2; i++ {
		if err = f.tick(); err != nil {
			t.Fatal(err)
		}
	}
	if r := f.rows(); r[0].Payment != "succeeded" || r[0].Credit != "issued" || len(f.grantPosts) != 1 {
		t.Fatalf("verified payment not credited exactly once: %+v posts=%d", r, len(f.grantPosts))
	}
	if len(f.assigned) == 0 || f.assigned[0] != id {
		t.Fatal("a verified checkout purchase did not move the team to Starter")
	}
}

func TestPrepaidFirstPurchaseUsesSubscriptionInvoice(t *testing.T) {
	f, predecessor := prepaidPlanFixture(t)
	assertPlan := prepaidPlanReader(t, f, f.team)
	assertPlan(predecessor)
	lease := time.Now().UTC()
	id := prepaidCheckoutPurchaseID(f.team, lease, 1000)
	if id != prepaidCheckoutPurchaseID(f.team, lease, 1000) {
		t.Fatal("replayed lease must map to the same purchase")
	}
	session := "cs_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	actor := uuid.New()
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 1000, session); err != nil {
		t.Fatal(err)
	}
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 1000, session); err != nil {
		t.Fatal("replayed record failed", err)
	}
	if err := f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 1000, "cs_other"); err == nil {
		t.Fatal("a purchase was rebound to another session")
	}
	invoice := "in_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	zero := int64(0)
	inv := StripeInvoiceAmounts{ID: invoice, Customer: f.customer, Status: "paid", AmountRemaining: &zero, Currency: "usd"}
	inv.Lines.Data = []StripeInvoiceAmountLine{usageLine("price_cpu", 0), usageLine("price_credit", 1000)}
	inv.Lines.Data[0].Parent.SubscriptionItemDetails = &struct {
		Subscription     string `json:"subscription"`
		SubscriptionItem string `json:"subscription_item"`
		Proration        bool   `json:"proration"`
	}{Subscription: f.sub}
	inv.Lines.Data[0].Pricing.PriceDetails.Product = "prod_cpu"
	inv.Lines.Data[1].Pricing.PriceDetails.Product = "prod_credit"
	f.mu.Lock()
	f.invoices[invoice] = inv
	f.products["prod_credit"] = map[string]string{"prepaid_purchase_id": id.String()}
	f.sessions[session] = map[string]any{"id": session, "mode": "subscription", "status": "complete", "customer": f.customer, "invoice": invoice, "subscription": f.sub}
	f.mu.Unlock()
	var frozen []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT plan_snapshot FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&frozen); err != nil {
		t.Fatal(err)
	}
	var snapshot prepaidPurchasePlan
	if err := json.Unmarshal(frozen, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Predecessor == nil || *snapshot.Predecessor != predecessor.ID {
		t.Fatal("purchase did not freeze its Free predecessor", snapshot)
	}
	limitsMatch := func(want planLimits) bool {
		t.Helper()
		var match bool
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT max_sandboxes IS NOT DISTINCT FROM $2::integer
   AND max_template_vcpu IS NOT DISTINCT FROM $3::integer AND max_template_memory_mib IS NOT DISTINCT FROM $4::integer
   AND max_template_disk_mib IS NOT DISTINCT FROM $5::integer FROM team WHERE id=$1`, f.team, want.MaxConcurrent, want.MaxVCPU, want.MaxMemoryMiB, want.MaxDiskMiB).Scan(&match); err != nil {
			t.Fatal(err)
		}
		return match
	}
	fault := "zz_prepaid_assignment_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.exec(`CREATE FUNCTION ` + fault + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected assignment commit failure'; END $$`)
	f.exec(`CREATE CONSTRAINT TRIGGER ` + fault + ` AFTER INSERT ON team_plan_assignment DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN(NEW.team_id='` + f.team.String() + `'::uuid AND NEW.source='credit_purchase') EXECUTE FUNCTION ` + fault + `()`)
	t.Cleanup(func() {
		if _, err := f.h.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON team_plan_assignment; DROP FUNCTION IF EXISTS `+fault+`() `); err != nil {
			t.Error(err)
		}
	})
	if err := f.tick(); err == nil {
		t.Fatal("assignment commit failure was not reported")
	}
	if row := f.rows()[0]; row.Payment != "succeeded" || row.Credit != "none" || len(f.grantPosts) != 0 {
		t.Fatal("failed assignment lost payment or issued credit", row)
	}
	current, ok, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || !ok || current.ID != predecessor.ID || !limitsMatch(predecessor.Limits) {
		t.Fatal("failed assignment partially replaced Free authority", current, err)
	}
	assertPlan(current)
	f.exec(`DROP TRIGGER ` + fault + ` ON team_plan_assignment; DROP FUNCTION ` + fault + `() `)
	setPricingVersion(t, f.h, "legacy")
	if err := f.tick(); err != nil {
		t.Fatal("accepted checkout recovery while OFF", err)
	}
	current, ok, err = currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || !ok || current.Kind != planKindPrepaid || current.Source != planSourceCreditPurchase || !reflect.DeepEqual(current.Terms, freezePlanTerms(snapshot.Terms)) || !limitsMatch(snapshot.Terms.Limits) {
		t.Fatal("paid checkout retained Free assignment or limits", current, err)
	}
	assertPlan(current)
	if err := f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
		t.Fatal("settlement replay", err)
	}
	replay, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || replay.ID != current.ID || len(f.grantPosts) != 1 {
		t.Fatal("settlement replay replaced assignment or duplicated credit", replay, err)
	}
	assertPlan(replay)
	if r := f.rows(); len(r) != 1 || r[0].Payment != "succeeded" || r[0].Credit != "issued" || r[0].Amount != 1000 {
		t.Fatalf("first purchase not credited from its paid invoice: %+v", r)
	}
}

func TestPrepaidExpiredCheckoutIsNeverCredited(t *testing.T) {
	f := newPrepaidFixture(t)
	s, err := f.h.startPrepaidPaymentCheckout(t.Context(), f.client, f.team, uuid.New(), f.customer, 500, "https://console.example.com/ok", "https://console.example.com/cancel")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.sessions[s.ID]["status"] = "expired"
	f.mu.Unlock()
	if err = f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); r[0].Payment != "failed" || len(f.grantPosts) != 0 {
		t.Fatalf("expired checkout credited: %+v", r)
	}
}

func TestPrepaidEnforcementPausesAtZeroRegardlessOfCard(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(500, 1000)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
	f.observe(1000, true)
	if err := f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	eligible := func() bool {
		var ok bool
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT team_sandbox_billing_eligible($1)`, f.team).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	var prepaid bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || !prepaid {
		t.Fatal("observed purchase did not start prepaid enforcement", err)
	}
	if !eligible() {
		t.Fatal("team with observed credit is not eligible")
	}
	f.exec(`UPDATE billing_funding_account SET collection_ready=true,provider_valid_until=clock_timestamp()+interval '1 hour' WHERE team_id=$1`, f.team)
	f.observe(0, true)
	if eligible() {
		t.Fatal("a saved card kept a prepaid team running at $0")
	}
}

func TestPrepaidEnforcementWaitsForObservedCredit(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(500, 1000)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if err := f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	var prepaid bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || prepaid {
		t.Fatal("enforcement began before the purchased credit was observed", err)
	}
}

func TestPrepaidSpentGrantIsVoidedOnlyOutsideClose(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(500, 1000)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	grant := f.rows()[0].Grant
	f.mu.Lock()
	f.balances[grant] = 0
	f.mu.Unlock()
	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	f.exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, f.team, f.customer, f.sub, start.Add(-time.Hour))
	f.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, f.team, start, start.Add(24*time.Hour))
	f.exec(`UPDATE billing_prepaid_purchase SET credit_balance_checked_at=NULL WHERE team_id=$1`, f.team)
	if err := f.h.voidSpentPrepaidGrants(t.Context(), f.client); err != nil {
		t.Fatal(err)
	}
	if f.grants[grant].VoidedAt != 0 {
		t.Fatal("grant voided while an ended period awaits its close")
	}
	f.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),'{}','{}')`, f.team, start, start.Add(24*time.Hour), "in_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
	f.exec(`UPDATE billing_prepaid_purchase SET credit_balance_checked_at=NULL WHERE team_id=$1`, f.team)
	if err := f.h.voidSpentPrepaidGrants(t.Context(), f.client); err != nil {
		t.Fatal(err)
	}
	if f.grants[grant].VoidedAt == 0 {
		t.Fatal("spent grant was not voided")
	}
	if n, _ := prepaidUnspentPurchases(t.Context(), f.h.Pool, f.team); n != 0 {
		t.Fatal("voided purchase still counts as unspent", n)
	}
}

func TestPrepaidReenrolmentAtCapacity(t *testing.T) {
	f := newPrepaidFixture(t)
	var budget int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT max_observed_teams FROM billing_funding_policy`).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=$1`, budget)
	})
	f.exec(`UPDATE billing_funding_policy SET max_observed_teams=(SELECT count(*) FROM billing_funding_account WHERE observe)`)
	if err := f.h.enrolPrepaidObservation(t.Context(), f.team); err != nil {
		t.Fatal("an already observed team was refused at capacity", err)
	}
	if ok, err := f.h.prepaidCapacityAvailable(t.Context(), f.team); err != nil || !ok {
		t.Fatal("an observed team cannot buy credit at capacity", ok, err)
	}
	other, err := f.h.DB.CreateTeam(t.Context(), "prepaid-full-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := f.h.prepaidCapacityAvailable(t.Context(), other.ID); err != nil || ok {
		t.Fatal("a new team was offered a purchase with no observation slot", ok, err)
	}
}

func TestPrepaidDisableNeverFailsAnInFlightCharge(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	f.loseIntent = true
	if err := f.tick(); err == nil {
		t.Fatal("expected a lost provider response")
	}
	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); len(r) != 1 || r[0].Payment != "succeeded" || r[0].Credit != "issued" {
		t.Fatalf("a charge that may have reached Stripe was failed by a later disable: %+v", r)
	}
}

func TestPrepaidOpenCheckoutDoesNotBlockAutoRecharge(t *testing.T) {
	f := newPrepaidFixture(t)
	if _, err := f.h.startPrepaidPaymentCheckout(t.Context(), f.client, f.team, uuid.New(), f.customer, 500, "https://console.example.com/ok", "https://console.example.com/cancel"); err != nil {
		t.Fatal(err)
	}
	f.enableAutoRecharge(2000, 5000)
	f.observe(0, true)
	if err := f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1 AND source='auto_recharge'`, f.team).Scan(&n); err != nil || n != 1 {
		t.Fatal("an open manual checkout suppressed auto-recharge", n, err)
	}
}

func TestPrepaidObservationScalesPastEightGrants(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var seed entitlementGrant
	for _, g := range f.grants {
		seed = g
	}
	for i := 0; i < 11; i++ {
		g := seed
		g.ID = "credgr_" + uuid.NewString()
		f.grants[g.ID] = g
		f.balances[g.ID] = 500
	}
	f.mu.Unlock()
	if len(f.grants) < 9 {
		t.Fatalf("fixture needs more than eight live grants, has %d", len(f.grants))
	}
	total, _, _, _, verify, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil {
		t.Fatal("a prepaid team with many purchases could not be observed", err)
	}
	if total != int64(len(f.grants))*500 || f.aggregateReads == 0 {
		t.Fatalf("aggregate balance %d for %d grants (aggregate reads %d)", total, len(f.grants), f.aggregateReads)
	}
	if verify == nil || verify(nil) != nil {
		t.Fatal("aggregate observation is not stable", verify == nil)
	}
	f.mu.Lock()
	for id, g := range f.grants {
		g.Applicability.Scope.PriceType = ""
		f.grants[id] = g
		break
	}
	f.mu.Unlock()
	if _, _, _, _, _, err = f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now()); err == nil {
		t.Fatal("a price-scoped grant did not fall back to the bounded per-grant observation")
	}
}

func TestPrepaidSummaryFlagsLowBalanceOnlyWithoutAutoRecharge(t *testing.T) {
	f := newPrepaidFixture(t)
	low := func() bool {
		raw, err := f.h.prepaidSummary(t.Context(), f.team, 0)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Low bool `json:"low_balance"`
		}
		if err = json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s.Low
	}
	f.observe(400, true)
	if !low() {
		t.Fatal("a $4 balance without auto-recharge is not low")
	}
	f.enableAutoRecharge(1000, 2500)
	if low() {
		t.Fatal("a balance auto-recharge will refill was flagged low")
	}
	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
	f.observe(2500, true)
	if low() {
		t.Fatal("a $25 balance was flagged low")
	}
}

func TestPrepaidObservationIgnoresSpentHistoryBeforeTheLastClose(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var old entitlementGrant
	for _, g := range f.grants {
		old = g
	}
	old.ID = "credgr_" + uuid.NewString()
	old.Category = "promotional"
	old.Created = time.Now().Add(-500 * 24 * time.Hour).Unix()
	old.EffectiveAt = old.Created
	f.grants[old.ID] = old
	f.balances[old.ID] = 0
	f.mu.Unlock()
	closed := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	f.exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, f.team, f.customer, f.sub, closed.Add(-72*time.Hour))
	f.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, f.team, closed.Add(-24*time.Hour), closed)
	f.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),'{}','{}')`, f.team, closed.Add(-24*time.Hour), closed, "in_"+strings.ReplaceAll(uuid.NewString(), "-", ""))
	_, start, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if start.Before(closed) {
		t.Fatalf("reconciliation window reaches back to %s, before the last close %s", start, closed)
	}
}

func TestPrepaidObservationWithEveryGrantVoided(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for id, g := range f.grants {
		g.VoidedAt = time.Now().Unix()
		f.grants[id] = g
	}
	f.mu.Unlock()
	reads := f.aggregateReads
	total, _, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil || total != 0 || f.aggregateReads != reads {
		t.Fatal("a prepaid team with only voided grants could not be observed as $0", total, err)
	}
}

func TestPrepaidEnrolmentIsRetriedAfterPayment(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_funding_account SET observe=false WHERE team_id=$1`, f.team)
	var budget int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT max_observed_teams FROM billing_funding_policy`).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=$1`, budget)
	})
	filler, err := f.h.DB.CreateTeam(t.Context(), "prepaid-filler-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false WHERE team_id=$1`, filler.ID)
	})
	f.exec(`UPDATE billing_funding_policy SET max_observed_teams=(SELECT count(*) FROM billing_funding_account WHERE observe)+1`)
	f.exec(`INSERT INTO billing_funding_account(team_id,observe) VALUES($1,true) ON CONFLICT(team_id) DO UPDATE SET observe=true`, filler.ID)
	if err := f.h.enrolPrepaidObservation(t.Context(), f.team); err != errPrepaidCapacity {
		t.Fatal("expected the cohort to be full", err)
	}
	f.exec(`UPDATE billing_funding_policy SET max_observed_teams=(SELECT count(*) FROM billing_funding_account WHERE observe)+1`)
	if err := f.h.retryPrepaidEnrolment(t.Context()); err != nil {
		t.Fatal(err)
	}
	var observed bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT observe FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&observed); err != nil || !observed {
		t.Fatal("a paid team that lost its observation slot was not enrolled again", err)
	}
}

func TestFundingObservationUnchangedForTeamsWithoutPrepaidCredit(t *testing.T) {
	f := newPrepaidFixture(t)
	f.mu.Lock()
	for i := 0; i < 3; i++ {
		var g entitlementGrant
		g.ID, g.Customer, g.Category, g.Priority = "credgr_"+uuid.NewString(), f.customer, "promotional", 50
		g.Created, g.EffectiveAt = time.Now().Add(-time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
		g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 1000
		g.Applicability.Scope.PriceType = "metered"
		f.grants[g.ID] = g
		f.balances[g.ID] = 1000
	}
	f.mu.Unlock()
	total, _, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil || total != 3000 {
		t.Fatal(total, err)
	}
	if f.aggregateReads != 0 {
		t.Fatal("a team without prepaid credit was observed through the aggregate balance")
	}
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err = f.tick(); err != nil {
		t.Fatal(err)
	}
	if total, _, _, _, _, err = f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now()); err != nil || total != 3500 || f.aggregateReads == 0 {
		t.Fatal("issued prepaid credit did not switch the team to the aggregate balance", total, err, f.aggregateReads)
	}
}

func TestPrepaidObservationFallsBackForExpiringGrants(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var promo entitlementGrant
	for _, g := range f.grants {
		promo = g
	}
	promo.ID = "credgr_" + uuid.NewString()
	promo.Category = "promotional"
	promo.Amount.Monetary.Value = 1000
	promo.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Unix()
	f.grants[promo.ID] = promo
	f.balances[promo.ID] = 1000
	f.mu.Unlock()
	reads := f.aggregateReads
	total, _, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil || total != 1500 || f.aggregateReads != reads {
		t.Fatal("an expiring grant was not observed exactly once through the per-grant path", total, err, f.aggregateReads-reads)
	}
}

func TestPrepaidObservationFloorStopsAtTheFirstUnreleasedPeriod(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for id, g := range f.grants {
		g.Created = time.Now().Add(-10 * 24 * time.Hour).Unix()
		g.EffectiveAt = g.Created
		f.grants[id] = g
	}
	f.mu.Unlock()
	day := 24 * time.Hour
	base := time.Now().UTC().Add(-6 * day).Truncate(time.Second)
	f.exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, f.team, f.customer, f.sub, base.Add(-time.Hour))
	period := func(start time.Time, released bool) {
		f.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, f.team, start, start.Add(day))
		state := "verified"
		if released {
			state = "released"
		}
		f.exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,$5,clock_timestamp(),'{}','{}')`, f.team, start, start.Add(day), "in_"+strings.ReplaceAll(uuid.NewString(), "-", ""), state)
	}
	period(base, true)
	period(base.Add(day), false)
	period(base.Add(2*day), true)
	_, start, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(base.Add(day)) {
		t.Fatalf("window starts at %s, want the end of the unbroken released run %s", start, base.Add(day))
	}
}

func TestPrepaidObservationFloorIgnoresPeriodsBeforeEnrolment(t *testing.T) {
	f := newPrepaidFixture(t)
	f.enableAutoRecharge(5000, 500)
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	enrolled := time.Now().UTC().Add(-3 * day).Truncate(time.Second)
	f.mu.Lock()
	for id, g := range f.grants {
		g.Created = enrolled.Add(-30 * day).Unix()
		g.EffectiveAt = g.Created
		f.grants[id] = g
	}
	f.mu.Unlock()
	f.exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, f.team, f.customer, f.sub, enrolled)
	f.exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, f.team, enrolled.Add(-10*day), enrolled.Add(-9*day))
	_, start, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if start.Before(enrolled) {
		t.Fatalf("window starts at %s, before invoice enrolment at %s", start, enrolled)
	}
}

func TestPrepaidWorkerRetriesEnrolmentBeforeIssuingCredit(t *testing.T) {
	f := newPrepaidFixture(t)
	f.exec(`UPDATE billing_funding_account SET observe=false WHERE team_id=$1`, f.team)
	id := uuid.New()
	f.exec(`INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key) VALUES($1,$2,$3,'checkout',500,$4,'','')`, id, f.team, f.customer, uuid.New())
	f.exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',500,'customer',$2::text) WHERE id=$1`, id, f.customer)
	constraint := "reject_prepaid_enrolment_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.exec(`ALTER TABLE billing_funding_account ADD CONSTRAINT ` + constraint + ` CHECK(team_id<>'` + f.team.String() + `'::uuid) NOT VALID`)
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `ALTER TABLE billing_funding_account DROP CONSTRAINT IF EXISTS `+constraint)
	})
	if err := f.h.settleDuePrepaidPurchases(t.Context(), f.client); err == nil {
		t.Fatal("expected enrolment failure before its retry marker could be written")
	}
	if r := f.rows(); len(r) != 1 || r[0].Payment != "succeeded" || r[0].Credit != "none" || len(f.grantPosts) != 0 {
		t.Fatalf("purchase stopped retrying after enrolment failure: %+v", r)
	}
	f.exec(`ALTER TABLE billing_funding_account DROP CONSTRAINT ` + constraint)
	f.exec(`UPDATE billing_prepaid_purchase SET next_attempt_at=clock_timestamp() WHERE id=$1`, id)
	if err := f.h.settleDuePrepaidPurchases(t.Context(), f.client); err != nil {
		t.Fatal(err)
	}
	var observed bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT observe FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&observed); err != nil || !observed {
		t.Fatal("worker did not retry enrolment", observed, err)
	}
	if r := f.rows(); r[0].Credit != "issued" || len(f.grantPosts) != 1 {
		t.Fatalf("retry did not issue the paid credit exactly once: %+v", r)
	}
}
