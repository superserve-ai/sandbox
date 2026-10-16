//go:build integration

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type entitlementFixture struct {
	noDispatch         atomic.Bool
	paymentFail        atomic.Bool
	paymentUnavailable atomic.Bool
	paymentRefunded    atomic.Bool
	paymentDisputed    atomic.Bool
	keys               []string
	h                  *Handlers
	c                  db.BillingCommercialContract
	start, end         time.Time
	grants             atomic.Int32
	lost               atomic.Bool
	debt               atomic.Bool
	mu                 sync.Mutex
	grant              *entitlementGrant
	requests           []string
}

func newEntitlementFixture(t *testing.T, annual ...bool) *entitlementFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL must name a migrated disposable test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires a test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool, DB: db.New(pool), Config: &config.Config{BillingUsageEntitlementsEnabled: true}}
	team, err := h.DB.CreateTeam(t.Context(), "entitlement-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	_, end, _ := billing.AnniversaryPeriod(start, now)
	anchor, coverageEnd, amount, months, offer, interval := start, end, int64(120000), int32(1), "pro_monthly", "month"
	if len(annual) > 0 && annual[0] {
		anchor = start.AddDate(0, -1, 0)
		coverageEnd = anchor.AddDate(1, 0, 0)
		amount = 1200000
		months = 12
		offer = "pro_annual"
		interval = "year"
	}
	customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team.ID, customer, subscription, anchor)
	yc := len(annual) > 1 && annual[1]
	var ycID, ycContract uuid.UUID
	if yc {
		ensureYCTestAuthority(t, pool)
		h.PromotionAuthPool = pool
		ycID, ycContract = uuid.New(), uuid.New()
		offer = "yc_2026"
		fixtureTerms := []StripeCheckoutResourceTerms{}
		for _, r := range []string{"cpu", "memory", "storage"} {
			fixtureTerms = append(fixtureTerms, StripeCheckoutResourceTerms{ResourceKey: r, PriceID: "price_" + r, UnitAmountDecimal: "1", MeterID: "mtr_price_" + r, EventName: r})
		}
		fixturePayload, _ := json.Marshal(StripeCreateCheckoutSessionParams{ResourceTerms: fixtureTerms})
		request, _ := json.Marshal(ycApproval{CompanyIdentity: "https://www.ycombinator.com/companies/fixture-" + team.ID.String(), Region: "test", Live: new(bool)})
		exec(`INSERT INTO billing_yc_operation(id,team_id,contract_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,starts_at,ends_at,state,payment_method_ready,payment_method_checked_at) VALUES($1,$2,$3,'operator','fixture',$4,$9,$5,$6,$7,$8,'enrolling',true,clock_timestamp())`, ycID, team.ID, ycContract, request, customer, subscription, anchor, coverageEnd, fixturePayload)
		exec(`INSERT INTO public.yc_company_activation_authority(company_identity,approval_id,team_id,home_region,approved_by,evidence_reference) VALUES($1,$2,$3,'test',$4,'fixture')`, "https://www.ycombinator.com/companies/fixture-"+team.ID.String(), ycID, team.ID, uuid.New())
	}
	var c db.BillingCommercialContract
	if yc {
		exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'yc_2026',$3,$4,$5,$6,'price_base',1200000,12,'metered_usage',100000,'scheduled',$3)`, ycContract, team.ID, anchor, coverageEnd, customer, subscription)
		exec(`INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,CASE WHEN m<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) m`, team.ID, ycContract)
		exec(`INSERT INTO billing_contract_waiver(id,team_id,contract_id,offer_key,offer_version,customer_id,subscription_id,starts_at,ends_at,collectible_base_cents) VALUES($1,$2,$3,'yc_2026',1,$4,$5,$6,$7,0)`, ycID, team.ID, ycContract, customer, subscription, anchor, coverageEnd)
		c, err = h.DB.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: team.ID, ContractID: ycContract, ExpectedRevision: 0})
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE billing_yc_operation SET state='active' WHERE id=$1`, ycID)
	} else {
		c, err = h.DB.CreateCommercialContract(t.Context(), db.CreateCommercialContractParams{TeamID: team.ID, OfferKey: offer, StartsAt: anchor, CustomerID: customer, SubscriptionID: subscription, BasePriceID: "price_base", ChargeAmountCents: amount, ChargeIntervalMonths: months, EntitlementKind: "metered_usage", EntitlementAmountCents: 100000, EntitlementCadence: "monthly", EntitlementAnchor: anchor})
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.DB.RecordCommercialBasePayment(t.Context(), db.RecordCommercialBasePaymentParams{TeamID: team.ID, ContractID: c.ID, InvoiceID: "in_paid_" + team.ID.String(), PaymentReference: "pay_" + uuid.NewString(), CustomerID: customer, SubscriptionID: &subscription, BasePriceID: "price_base", ServicePeriodStart: anchor, ServicePeriodEnd: coverageEnd, BaseAmountPaidCents: amount, InvoiceAmountPaidCents: amount, Currency: "usd", PaidAt: start, VerifiedAt: now, Evidence: []byte(`{"paid":true}`)})
		if err != nil {
			t.Fatal(err)
		}
		c, err = h.DB.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: team.ID, ContractID: c.ID, ExpectedRevision: c.Revision})
		if err != nil {
			t.Fatal(err)
		}

	}
	terms := []StripeCheckoutResourceTerms{}
	items := []any{map[string]any{"id": "si_base", "quantity": 1, "price": map[string]any{"id": "price_base", "currency": "usd", "unit_amount_decimal": fmt.Sprint(amount), "billing_scheme": "per_unit", "recurring": map[string]any{"usage_type": "licensed", "interval": interval, "interval_count": 1}}}}
	price := func(id, usage string) map[string]any {
		return map[string]any{"id": id, "active": true, "currency": "usd", "unit_amount_decimal": "1", "billing_scheme": "per_unit", "recurring": map[string]any{"usage_type": usage, "interval": "month", "interval_count": 1, "meter": "mtr_" + id}}
	}
	for _, r := range []string{"cpu", "memory", "storage"} {
		id := "price_" + r
		terms = append(terms, StripeCheckoutResourceTerms{ResourceKey: r, PriceID: id, UnitAmountDecimal: "1", MeterID: "mtr_" + id, EventName: r})
		items = append(items, map[string]any{"id": "si_" + r, "price": price(id, "metered"), "current_period_start": start.Unix(), "current_period_end": end.Unix()})
	}
	items = append(items, map[string]any{"id": "si_round", "price": price("price_round", "metered"), "current_period_start": start.Unix(), "current_period_end": end.Unix()})
	payload, _ := json.Marshal(StripeCreateCheckoutSessionParams{ResourceTerms: terms})
	if !yc {
		exec(`UPDATE billing_signup_choice SET offer_key=$6,state='committed',generation=$2,actor_id=$3,base_price_id='price_base',request_payload=$4,subscription_id=$5 WHERE team_id=$1`, team.ID, start, uuid.New(), payload, subscription, offer)
	}
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_price_round',$4)`, team.ID, customer, subscription, start)
	sub := map[string]any{"id": subscription, "customer": customer, "status": "active", "billing_mode": map[string]any{"type": "flexible"}, "billing_cycle_anchor": anchor.Unix(), "pause_collection": map[string]any{"behavior": "keep_as_draft"}, "items": map[string]any{"data": items}}
	f := &entitlementFixture{h: h, c: c, start: start, end: end}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/invoices/in_paid_" + team.ID.String():
			if f.paymentUnavailable.Load() {
				http.Error(w, "temporary outage", 503)
				return
			}
			if f.paymentFail.Load() {
				fmt.Fprint(w, `{"id":"ambiguous"}`)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","total":%d,"amount_due":%d,"starting_balance":0,"ending_balance":0,"amount_paid":%d,"amount_remaining":0,"status_transitions":{"paid_at":%d},"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"quantity":1,"amount":%d,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":"price_base"}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, "in_paid_"+team.ID.String(), customer, amount, amount, amount, anchor.Unix(), subscription, amount, anchor.Unix(), coverageEnd.Unix(), subscription)
		case "/v1/invoices/in_prior_" + team.ID.String():
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","amount_remaining":0,"total":0,"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[]}}`, "in_prior_"+team.ID.String(), customer, subscription)
		case "/v1/invoice_payments":
			fmt.Fprintf(w, `{"data":[{"id":"inpay_example","invoice":%q,"status":"paid","currency":"usd","amount_paid":%d,"payment":{"type":"payment_intent","payment_intent":"pi_example"}}]}`, "in_paid_"+team.ID.String(), amount)
		case "/v1/payment_intents/pi_example":
			fmt.Fprintf(w, `{"id":"pi_example","status":"succeeded","customer":%q,"currency":"usd","amount_received":%d,"latest_charge":"ch_example"}`, customer, amount)
		case "/v1/charges/ch_example":
			refunded := int64(0)
			if f.paymentRefunded.Load() {
				refunded = amount
			}
			fmt.Fprintf(w, `{"id":"ch_example","customer":%q,"payment_intent":"pi_example","currency":"usd","paid":true,"captured":true,"amount_captured":%d,"amount_refunded":%d,"disputed":%t}`, customer, amount, refunded, f.paymentDisputed.Load())
		case "/v1/invoices":
			if r.URL.Query().Get("customer") != "" && r.URL.Query().Get("customer") != customer {
				http.Error(w, "unavailable customer", 503)
				return
			}
			if f.debt.Load() && r.URL.Query().Get("status") == "open" {
				json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "in_unpaid", "customer": customer, "status": "open"}}})
			} else {
				fmt.Fprint(w, `{"data":[]}`)
			}
		case "/v1/prices/price_round":
			json.NewEncoder(w).Encode(price("price_round", "metered"))
		case "/v1/billing/meters":
			fmt.Fprint(w, `{"data":[{"id":"mtr_price_round","event_name":"round","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}}]}`)
		case "/v1/subscriptions/" + subscription:
			json.NewEncoder(w).Encode(sub)
		case "/v1/subscriptions":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{sub}})
		case "/v1/billing/credit_grants":
			f.mu.Lock()
			defer f.mu.Unlock()
			if r.Method == http.MethodGet {
				data := []any{}
				if f.grant != nil {
					data = append(data, *f.grant)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": data})
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			f.requests = append(f.requests, r.Form.Encode())
			f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
			f.grants.Add(1)
			if f.noDispatch.Swap(false) {
				http.Error(w, `{"error":{"message":"before dispatch"}}`, 503)
				return
			}
			if r.Form.Has("effective_at") {
				t.Error("request backdates activation")
			}
			g := testEntitlementGrant()
			g.ID = "credgr_" + team.ID.String()
			g.Customer = customer
			g.Amount.Monetary.Value, _ = strconv.ParseInt(r.Form.Get("amount[monetary][value]"), 10, 64)
			g.Created = time.Now().Unix()
			g.EffectiveAt = g.Created
			g.ExpiresAt = end.Unix() + 1
			g.Metadata = map[string]string{"entitlement_id": r.Form.Get("metadata[entitlement_id]")}
			for i := range g.Applicability.Scope.Prices {
				g.Applicability.Scope.Prices[i].ID = r.Form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i))
			}
			f.grant = &g
			if f.lost.Swap(false) {
				http.Error(w, `{"error":{"message":"response lost"}}`, 503)
				return
			}
			json.NewEncoder(w).Encode(g)
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/credgr_") {
				f.mu.Lock()
				defer f.mu.Unlock()
				json.NewEncoder(w).Encode(f.grant)
			} else {
				t.Errorf("unexpected provider request %s", r.URL)
				http.Error(w, "unexpected", 500)
			}
		}
	}))
	t.Cleanup(srv.Close)
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	return f
}
func TestEntitlementWorkerIntegration(t *testing.T) {
	f := newEntitlementFixture(t)
	f.debt.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if f.grants.Load() != 0 {
		t.Fatal("issued despite finalized debt")
	}
	f.debt.Store(false)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("expected unknown provider result")
	} else {
		t.Logf("provider result: %v", err)
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: f.c.EntitlementKind})
	if err != nil || e.State != "uncertain" {
		t.Fatalf("missing durable request: %+v %v", e, err)
	}
	if _, err = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	e, err = f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: f.c.EntitlementKind})
	if err != nil || e.State != "issued" {
		t.Fatalf("failed to recover grant: %s %v", e.State, err)
	}
	if f.grants.Load() != 1 {
		t.Fatal("recovery dispatched a second grant")
	}
	f.debt.Store(true)
	if _, err = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if f.grants.Load() != 1 {
		t.Fatal("later debt duplicated issued grant")
	}
}
func TestEntitlementInventoryResumesBeyondFirstPage(t *testing.T) {
	f := newEntitlementFixture(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := calls.Add(1)
		data := []entitlementGrant{}
		for i := 0; i < 50; i++ {
			g := testEntitlementGrant()
			g.Customer = f.c.CustomerID
			g.ID = fmt.Sprintf("credgr_%d_%d", page, i)
			g.Metadata = nil
			data = append(data, g)
		}
		if page > 1 && r.URL.Query().Get("starting_after") != fmt.Sprintf("credgr_%d_49", page-1) {
			t.Error("cursor not resumed")
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": page < 3})
	}))
	defer srv.Close()
	c := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	for i := 0; i < 3; i++ {
		err := f.h.syncCreditInventory(t.Context(), f.c.ID, f.c.CustomerID, c)
		if i < 2 && !errors.Is(err, errCreditInventoryPending) {
			t.Fatal(err)
		}
		if i == 2 && err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_provider_credit WHERE customer_id=$1`, f.c.CustomerID).Scan(&count); err != nil || count != 150 {
		t.Fatal("incomplete inventory", count, err)
	}
}

func TestEntitlementRecoveryRejectsVoidedGrant(t *testing.T) {
	f := newEntitlementFixture(t)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("expected lost provider response")
	}
	f.mu.Lock()
	f.grant.VoidedAt = time.Now().Unix()
	voided := *f.grant
	f.mu.Unlock()
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("accepted voided grant during recovery")
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: f.c.EntitlementKind})
	if err != nil || e.State != "uncertain" || f.grants.Load() != 1 {
		t.Fatalf("voided recovery concealed or replaced the failed allowance: state=%s posts=%d err=%v", e.State, f.grants.Load(), err)
	}
	raw, _ := json.Marshal(voided)
	if _, err = f.h.DB.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: f.c.TeamID, EntitlementID: e.ID, GrantID: &voided.ID, Evidence: raw}); err == nil {
		t.Fatal("database accepted voided confirmation evidence")
	}
}

func TestEntitlementCrashBeforeDispatchAndConcurrentRecovery(t *testing.T) {
	f := newEntitlementFixture(t)
	f.noDispatch.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("expected dispatch failure")
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 2 || f.requests[0] != f.requests[1] {
		t.Fatal("recovery changed the saved request")
	}
	if len(f.keys) != 2 || f.keys[0] == "" || f.keys[0] != f.keys[1] {
		t.Fatal("recovery changed idempotency identity", f.keys)
	}
	saved, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: f.c.EntitlementKind})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range f.keys {
		if key != saved.IdempotencyKey {
			t.Fatal("wire key differs from durable identity")
		}
	}
	form, err := url.ParseQuery(f.requests[0])
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"amount[type]": "monetary", "amount[monetary][currency]": "usd", "amount[monetary][value]": "100000", "category": "promotional", "priority": "50", "expires_at": fmt.Sprint(f.end.Unix() + 1), "customer": f.c.CustomerID} {
		if form.Get(key) != want {
			t.Fatalf("wire %s = %q, want %q", key, form.Get(key), want)
		}
	}
	if form.Has("effective_at") || form.Get("metadata[entitlement_id]") == "" {
		t.Fatal("invalid activation identity")
	}
	for i, price := range []string{"price_cpu", "price_memory", "price_round", "price_storage"} {
		if form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i)) != price {
			t.Fatal("wire scope changed")
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.grants.Load() != 2 {
		t.Fatal("duplicate dispatch after confirmed grant")
	}
}

func TestEntitlementAnnualMonthlyRefresh(t *testing.T) {
	f := newEntitlementFixture(t, true)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	prior := f.c.EntitlementAnchor
	exec(`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, f.c.TeamID, prior)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil || f.grants.Load() != 0 {
		t.Fatal("missing prior close did not block rollover", err)
	}
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, f.c.TeamID, prior, f.start)
	exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),jsonb_build_object('customer',$5::text,'subscription',$6::text,'expected_cents',0,'credit_before_cents',0,'resources',jsonb_build_array(jsonb_build_object('resource','cpu','expected_cents',0,'snapshot',billing_meter_accounting_snapshot($1,$2,$3,'cpu')))), '{"credit_applied_cents":0,"credit_remaining_cents":0,"net_cents":0}')`, f.c.TeamID, prior, f.start, "in_prior_"+f.c.TeamID.String(), f.c.CustomerID, f.c.SubscriptionID)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: f.c.EntitlementKind})
	if err != nil || e.State != "issued" || !e.PeriodStart.Equal(f.start) || !e.PeriodEnd.Equal(f.end) || e.AmountCents != 100000 || e.PeriodStart.Equal(f.c.EntitlementAnchor) {
		t.Fatalf("annual paid receipt did not fund second monthly period: %+v %v", e, err)
	}
}
func TestEntitlementAmbiguousFreshPaymentBlocksGrant(t *testing.T) {
	f := newEntitlementFixture(t)
	f.paymentFail.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("ambiguous payment authorized")
	}
	if f.grants.Load() != 0 {
		t.Fatal("grant issued without fresh payment proof")
	}
}
func TestEntitlementPriorCloseGate(t *testing.T) {
	for _, state := range []string{"missing", "draft", "unreconciled", "unpaid", "zero_paid"} {
		t.Run(state, func(t *testing.T) {
			f := newEntitlementFixture(t)
			prior := f.start.AddDate(0, -1, 0)
			c := f.c
			c.EntitlementAnchor = prior
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := f.h.Pool.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, c.TeamID, prior)
			invoice := "in_prior_" + c.TeamID.String()
			if state != "missing" {
				exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, c.TeamID, prior, f.start)
				closeState := "released"
				if state == "unreconciled" {
					closeState = "prepared"
				}
				exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,$5,clock_timestamp(),jsonb_build_object('customer',$6::text,'subscription',$7::text,'expected_cents',0,'credit_before_cents',0,'resources',jsonb_build_array(jsonb_build_object('resource','cpu','expected_cents',0,'snapshot',billing_meter_accounting_snapshot($1,$2,$3,'cpu')))), '{"credit_applied_cents":0,"credit_remaining_cents":0,"net_cents":0}')`, c.TeamID, prior, f.start, invoice, closeState, c.CustomerID, c.SubscriptionID)
			}
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				status, remaining := "paid", 0
				if state == "draft" {
					status = "draft"
				}
				if state == "unpaid" {
					status = "open"
					remaining = 200
				}
				fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":%q,"amount_remaining":%d,"amount_due":0,"total":0,"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[]}}`, invoice, c.CustomerID, status, remaining, c.SubscriptionID)
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			err := f.h.entitlementClosingInvoice(t.Context(), c, f.start, client)
			if (err == nil) != (state == "zero_paid") {
				t.Fatalf("state %s: %v", state, err)
			}
			if state == "zero_paid" && calls != 1 {
				t.Fatal("settlement was not freshly verified")
			}
		})
	}
}
func TestEntitlementRetainsOlderDebtEvidence(t *testing.T) {
	f := newEntitlementFixture(t)
	p := billing.ExportPeriod{TeamID: f.c.TeamID, Start: f.start, End: f.end}
	for _, id := range []string{"in_older", "in_newer"} {
		if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,$3)`, f.c.ID, f.start, id); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "in_older"
		finalized := f.start.Unix() - 1
		if strings.HasSuffix(r.URL.Path, "in_newer") {
			id = "in_newer"
			finalized = f.start.Add(time.Hour).Unix()
		}
		fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","status_transitions":{"finalized_at":%d,"paid_at":%d},"lines":{"data":[]}}`, id, f.c.CustomerID, finalized, f.end.Unix()+1)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	if err := f.h.verifyEntitlementForfeiture(t.Context(), f.c.ID, p, invoiceAccount{Customer: f.c.CustomerID, Subscription: f.c.SubscriptionID}, client); err != nil {
		t.Fatal(err)
	}
}

func TestEntitlementSchedulerLeasesRetryAndEscalation(t *testing.T) {
	f := newEntitlementFixture(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Keep other fixture jobs out of this scheduler test's due set.
	exec(`UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()+interval '1 day' WHERE contract_id<>$1`, f.c.ID)
	exec(`UPDATE billing_entitlement_work SET lease_token=$2,lease_until=clock_timestamp()+interval '1 minute' WHERE contract_id=$1`, f.c.ID, uuid.New())
	if count, err := f.h.usageEntitlementBatch(t.Context(), false, 2); err != nil || count != 0 {
		t.Fatal("stole live lease", count, err)
	}
	f.paymentUnavailable.Store(true)
	exec(`UPDATE billing_entitlement_work SET lease_until=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp()-interval '1 second',problem_since=clock_timestamp()-interval '6 minutes' WHERE contract_id=$1`, f.c.ID)
	if count, err := f.h.usageEntitlementBatch(t.Context(), false, 2); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var failures int
	var alerted time.Time
	var released, backoff, incident bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT failures,alerted_at,lease_token IS NULL AND lease_until IS NULL,next_check_at>clock_timestamp(),EXISTS(SELECT 1 FROM billing_entitlement_withheld WHERE contract_id=$1 AND platform_failure_at IS NOT NULL) FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID).Scan(&failures, &alerted, &released, &backoff, &incident); err != nil || failures != 1 || !released || !backoff || !incident {
		t.Fatal("failure was not saved/escalated", failures, released, backoff, incident, err)
	}
	exec(`UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()-interval '1 second' WHERE contract_id=$1`, f.c.ID)
	if count, err := f.h.usageEntitlementBatch(t.Context(), false, 2); err != nil || count != 0 {
		t.Fatal("retry consumed fresh lane", count, err)
	}
	if count, err := f.h.usageEntitlementBatch(t.Context(), true, 2); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var again time.Time
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT alerted_at FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID).Scan(&again); err != nil || !again.Equal(alerted) {
		t.Fatal("repeated alert within one hour", again, alerted, err)
	}
	f.paymentUnavailable.Store(false)
	exec(`UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()-interval '1 second' WHERE contract_id=$1`, f.c.ID)
	if count, err := f.h.usageEntitlementBatch(t.Context(), true, 2); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if f.grants.Load() != 1 {
		t.Fatal("retry did not restore issuance")
	}
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT failures,lease_token IS NULL FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID).Scan(&failures, &released); err != nil || failures != 0 || !released {
		t.Fatal("successful retry was not acknowledged", failures, released, err)
	}
}

func TestInvoiceCreditPlanJSONBRoundTrip(t *testing.T) {
	f := newEntitlementFixture(t)
	g := testEntitlementGrant()
	raw, _ := json.Marshal(g)
	plan := billing.InvoiceClosePlan{CreditVersion: 1, CreditGrants: []billing.InvoiceCreditGrant{{ID: g.ID, Before: 100000, ExpiresAt: g.ExpiresAt, Evidence: raw}}}
	encoded, _ := json.Marshal(plan)
	var stored []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT $1::jsonb`, encoded).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var decoded billing.InvoiceClosePlan
	if err := json.Unmarshal(stored, &decoded); err != nil {
		t.Fatal(err)
	}
	if !sameInvoiceCreditGrants(plan.CreditGrants, decoded.CreditGrants) {
		t.Fatal("JSONB encoding changed credit identity")
	}
	decoded.CreditGrants[0].Before--
	if sameInvoiceCreditGrants(plan.CreditGrants, decoded.CreditGrants) {
		t.Fatal("balance drift accepted")
	}
}
func TestEntitlementSchedulerCustomerIsolation(t *testing.T) {
	healthy := newEntitlementFixture(t)
	failed := newEntitlementFixture(t)
	if _, err := healthy.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()+interval '1 day' WHERE contract_id<>$1 AND contract_id<>$2`, healthy.c.ID, failed.c.ID); err != nil {
		t.Fatal(err)
	}
	if count, err := healthy.h.usageEntitlementBatch(t.Context(), false, 2); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if healthy.grants.Load() != 1 {
		t.Fatal("failed customer suppressed healthy grant")
	}
	var failures int
	if err := healthy.h.Pool.QueryRow(t.Context(), `SELECT failures FROM billing_entitlement_work WHERE contract_id=$1`, failed.c.ID).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("failed customer lost retry", failures, err)
	}
}

func TestInvoiceCreditScanSkipsDepletedHistory(t *testing.T) {
	f := newEntitlementFixture(t)
	seedCreditScanHead(t, f, "credgr_205")
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at) SELECT $1,'credgr_'||lpad(i::text,3,'0'),'{}'::jsonb,0,0 FROM generate_series(1,205) i`, f.c.CustomerID); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/billing/credit_grants" {
			fmt.Fprint(w, `{"data":[{"id":"credgr_205"}]}`)
			return
		}
		if r.URL.Path == "/v1/billing/credit_balance_transactions" {
			fmt.Fprint(w, `{"data":[{"id":"cbtxn_original"}]}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/") {
			g := testEntitlementGrant()
			g.ID = strings.TrimPrefix(r.URL.Path, "/v1/billing/credit_grants/")
			g.Customer = f.c.CustomerID
			g.Metadata = nil
			g.EffectiveAt = 1
			g.ExpiresAt = 0
			json.NewEncoder(w).Encode(g)
			return
		}
		if r.URL.Path == "/v1/billing/credit_balance_summary" {
			balance := 0
			if r.URL.Query().Get("filter[credit_grant]") == "credgr_205" {
				balance = 100000
			}
			fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, balance)
			return
		}
		t.Error("unexpected path", r.URL.Path)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	prices := []string{"cpu", "memory", "round", "storage"}
	for page := 0; page < 5; page++ {
		grants, err := f.h.eligibleInvoiceCredits(t.Context(), f.c.CustomerID, f.end.Unix(), prices, client)
		if page < 4 {
			if !errors.Is(err, errCreditInventoryPending) {
				t.Fatal("scan did not save progress", page, err)
			}
		} else if err != nil || len(grants) != 1 || grants[0].ID != "credgr_205" {
			t.Fatal("depleted history blocked current credit", grants, err)
		}
	}
}
func TestInvoiceDiscoveryResumesAndIncludesDelayedCreation(t *testing.T) {
	f := newEntitlementFixture(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/invoices" {
			calls++
			if r.URL.Query().Has("created[lte]") {
				t.Error("delayed creation excluded")
			}
			if calls == 1 {
				fmt.Fprintf(w, `{"data":[{"id":"in_cursor","customer":%q}],"has_more":true}`, f.c.CustomerID)
				return
			}
			if calls == 2 && r.URL.Query().Get("starting_after") != "in_cursor" {
				t.Error("cursor not resumed")
			}
			id := "in_delayed"
			if calls > 2 {
				id = "in_replacement"
			}
			fmt.Fprintf(w, `{"data":[{"id":%q,"customer":%q,"billing_reason":"subscription_cycle","period_start":%d,"period_end":%d}]}`, id, f.c.CustomerID, f.start.Unix(), f.end.Unix())
			return
		}
		fmt.Fprintf(w, `{"id":%q,"customer":%q,"currency":"usd","status":"draft","billing_reason":"subscription_cycle","created":%d,"period_start":%d,"period_end":%d,"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[]}}`, strings.TrimPrefix(r.URL.Path, "/v1/invoices/"), f.c.CustomerID, f.end.AddDate(0, 1, 0).Unix(), f.start.Unix(), f.end.Unix(), f.c.SubscriptionID)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	a := invoiceAccount{Customer: f.c.CustomerID, Subscription: f.c.SubscriptionID}
	if _, err := f.h.billingCycleInvoice(t.Context(), a, f.start.Unix(), f.end.Unix(), client); err == nil {
		t.Fatal("incomplete discovery accepted")
	}
	if inv, err := f.h.billingCycleInvoice(t.Context(), a, f.start.Unix(), f.end.Unix(), client); err != nil || inv.ID != "in_delayed" {
		t.Fatal(inv.ID, err)
	}
	if inv, err := f.h.billingCycleInvoice(t.Context(), a, f.start.Unix(), f.end.Unix(), client); err != nil || inv.ID != "in_replacement" {
		t.Fatal("completed scan retained obsolete match", inv.ID, err)
	}
}

func TestInvoiceCreditScanRefreshesEarlierPages(t *testing.T) {
	for _, change := range []string{"consumed", "voided"} {
		t.Run(change, func(t *testing.T) {
			f := newEntitlementFixture(t)
			seedCreditScanHead(t, f, "credgr_051")
			if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at) SELECT $1,'credgr_'||lpad(i::text,3,'0'),'{}'::jsonb,0,0 FROM generate_series(1,51) i`, f.c.CustomerID); err != nil {
				t.Fatal(err)
			}
			var changed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/billing/credit_grants" {
					fmt.Fprint(w, `{"data":[{"id":"credgr_051"}]}`)
					return
				}
				if r.URL.Path == "/v1/billing/credit_balance_transactions" {
					fmt.Fprint(w, `{"data":[{"id":"cbtxn_original"}]}`)
					return
				}
				if strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/") {
					g := testEntitlementGrant()
					g.ID = strings.TrimPrefix(r.URL.Path, "/v1/billing/credit_grants/")
					g.Customer = f.c.CustomerID
					g.Metadata = nil
					g.EffectiveAt = 1
					g.ExpiresAt = 0
					if g.ID == "credgr_001" && changed.Load() && change == "voided" {
						g.VoidedAt = 2
					}
					json.NewEncoder(w).Encode(g)
					return
				}
				balance := 0
				if r.URL.Query().Get("filter[credit_grant]") == "credgr_001" {
					balance = 100000
					if changed.Load() {
						balance = 20000
					}
				}
				fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, balance)
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			prices := []string{"cpu", "memory", "round", "storage"}
			if _, err := f.h.eligibleInvoiceCredits(t.Context(), f.c.CustomerID, f.end.Unix(), prices, client); !errors.Is(err, errCreditInventoryPending) {
				t.Fatal(err)
			}
			changed.Store(true)
			grants, err := f.h.eligibleInvoiceCredits(t.Context(), f.c.CustomerID, f.end.Unix(), prices, client)
			if err != nil {
				t.Fatal(err)
			}
			if change == "voided" {
				if len(grants) != 0 {
					t.Fatal("voided earlier-page grant accepted", grants)
				}
			} else if len(grants) != 1 || grants[0].Before != 20000 {
				t.Fatal("stale earlier-page balance accepted", grants)
			}
		})
	}
}
func TestEntitlementForfeitureDiscoversOmittedOlderDebt(t *testing.T) {
	f := newEntitlementFixture(t)
	p := billing.ExportPeriod{TeamID: f.c.TeamID, Start: f.start, End: f.end}
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence) VALUES($1,$2,$3,'{}')`, f.c.ID, f.start, f.end); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,'in_newer')`, f.c.ID, f.start); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/invoices" {
			if r.URL.Query().Get("status") != "" {
				t.Error("discovery excludes settled/uncollectible history")
			}
			if r.URL.Query().Get("starting_after") == "" {
				fmt.Fprintf(w, `{"data":[{"id":"in_newer","customer":%q}],"has_more":true}`, f.c.CustomerID)
			} else {
				if r.URL.Query().Get("starting_after") != "in_newer" {
					t.Error("cursor not resumed")
				}
				fmt.Fprintf(w, `{"data":[{"id":"in_older","customer":%q}]}`, f.c.CustomerID)
			}
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/invoices/")
		finalized := f.start.Unix() + 3600
		if id == "in_older" {
			finalized = f.start.Unix() - 3600
		}
		fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","status_transitions":{"finalized_at":%d,"paid_at":%d},"lines":{"data":[]}}`, id, f.c.CustomerID, finalized, f.end.Unix()+1)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	a := invoiceAccount{Customer: f.c.CustomerID, Subscription: f.c.SubscriptionID}
	if err := f.h.verifyEntitlementForfeiture(t.Context(), f.c.ID, p, a, client); !errors.Is(err, errCreditInventoryPending) {
		t.Fatal("historical scan did not persist cursor", err)
	}
	if err := f.h.verifyEntitlementForfeiture(t.Context(), f.c.ID, p, a, client); err != nil {
		t.Fatal("omitted older debt not recovered", err)
	}
	var saved bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_entitlement_debt WHERE contract_id=$1 AND invoice_id='in_older')`, f.c.ID).Scan(&saved); err != nil || !saved {
		t.Fatal("forfeiture proof not retained", saved, err)
	}
}

func seedCreditScanHead(t *testing.T, f *entitlementFixture, head string) {
	t.Helper()
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_work SET inventory_head=$2,inventory_checked_at=clock_timestamp(),inventory_cursor=NULL WHERE contract_id=$1`, f.c.ID, head); err != nil {
		t.Fatal(err)
	}
}
func TestInvoiceCreditScanRestartsForReinstatedZeroBalance(t *testing.T) {
	f := newEntitlementFixture(t)
	seedCreditScanHead(t, f, "credgr_051")
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at) SELECT $1,'credgr_'||lpad(i::text,3,'0'),'{}'::jsonb,0,0 FROM generate_series(1,51) i`, f.c.CustomerID); err != nil {
		t.Fatal(err)
	}
	var reinstated atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/billing/credit_grants" {
			fmt.Fprint(w, `{"data":[{"id":"credgr_051"}]}`)
			return
		}
		if r.URL.Path == "/v1/billing/credit_balance_transactions" {
			id := "cbtxn_original"
			if reinstated.Load() {
				id = "cbtxn_reinstated"
			}
			fmt.Fprintf(w, `{"data":[{"id":%q}]}`, id)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/") {
			g := testEntitlementGrant()
			g.ID = strings.TrimPrefix(r.URL.Path, "/v1/billing/credit_grants/")
			g.Customer = f.c.CustomerID
			g.Metadata = nil
			g.EffectiveAt = 1
			g.ExpiresAt = 0
			json.NewEncoder(w).Encode(g)
			return
		}
		balance := 0
		if r.URL.Query().Get("filter[credit_grant]") == "credgr_001" && reinstated.Load() {
			balance = 100000
		}
		fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, balance)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	prices := []string{"cpu", "memory", "round", "storage"}
	scan := func() ([]billing.InvoiceCreditGrant, error) {
		return f.h.eligibleInvoiceCredits(t.Context(), f.c.CustomerID, f.end.Unix(), prices, client)
	}
	if _, err := scan(); !errors.Is(err, errCreditInventoryPending) {
		t.Fatal(err)
	}
	reinstated.Store(true)
	if _, err := scan(); !errors.Is(err, errCreditInventoryPending) {
		t.Fatal("ledger change did not restart scan", err)
	}
	if _, err := scan(); !errors.Is(err, errCreditInventoryPending) {
		t.Fatal("restarted scan did not read first page", err)
	}
	grants, err := scan()
	if err != nil || len(grants) != 1 || grants[0].ID != "credgr_001" || grants[0].Before != 100000 {
		t.Fatal("reinstated credit omitted", grants, err)
	}
}

func TestEntitlementCoverageAuditWithoutScheduledWork(t *testing.T) {
	f := newEntitlementFixture(t)
	read := func() entitlementCoverageSample {
		t.Helper()
		var after uuid.UUID
		for {
			rows, err := f.h.entitlementCoveragePage(t.Context(), after, time.Now(), 7)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Contract == f.c.ID {
					return row
				}
				after = row.Contract
			}
			if len(rows) < 7 {
				t.Fatal("audit omitted active contract")
			}
		}
	}
	if _, err := f.h.Pool.Exec(t.Context(), `DELETE FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID); err != nil {
		t.Fatal(err)
	}
	if row := read(); row.Age <= 15*60 || !row.Unknown {
		t.Fatalf("missing work and absent fresh collection evidence concealed paid period: %+v", row)
	}
	f.debt.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if row := read(); row.Age != 0 {
		t.Fatalf("fresh verified debt was not excluded: %+v", row)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_withheld SET observed_at=clock_timestamp()-interval '2 minutes' WHERE contract_id=$1`, f.c.ID); err != nil {
		t.Fatal(err)
	}
	if row := read(); row.Age <= 15*60 || !row.Unknown {
		t.Fatalf("stale debt concealed missing paid allowance: %+v", row)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_work(contract_id,next_check_at) VALUES($1,clock_timestamp()+interval '1 year')`, f.c.ID); err != nil {
		t.Fatal(err)
	}
	if row := read(); row.Age <= 15*60 {
		t.Fatalf("deferred work concealed missing paid allowance: %+v", row)
	}
	f.debt.Store(false)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if row := read(); row.Age != 0 {
		t.Fatalf("confirmed issuance did not clear audit: %+v", row)
	}
}
