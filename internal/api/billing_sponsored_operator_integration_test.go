//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestSponsoredOperatorOnboardingAndRetry(t *testing.T) {
	for _, scenario := range []string{"new", "existing_anniversary", "revoke_creation", "catalog_rotation", "checkout_race", "revoke_canceled", "historical_terms", "capacity_existing", "capacity_new", "capacity_race"} {
		t.Run(scenario, func(t *testing.T) { sponsoredOperatorScenario(t, scenario) })
	}
}
func sponsoredOperatorScenario(t *testing.T, scenario string) {
	h, team := fundingTransitionFixture(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
	exec(`UPDATE billing_funding_policy SET max_observed_teams=100 WHERE singleton`)
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, team)
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=4 WHERE singleton`)
	})
	h.Config = &config.Config{TeamCreationRegion: "use", BillingUsageEntitlementsEnabled: true}
	now := time.Now().UTC()
	anchor := now.Add(-5 * time.Second).Truncate(time.Second)
	_, end, _ := billing.AnniversaryPeriod(anchor, now)
	prices := map[string]storagePrice{}
	rates, err := h.DB.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: team, EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"vcpu", "memory_gib", "storage_gib"} {
		id := "price_" + key
		h.Config.BillingResources = append(h.Config.BillingResources, config.BillingResourceConfig{ResourceKey: key, UsageUnit: "second", StripePriceID: id, StripeEventName: key, Tracked: true, Billable: true, CheckoutEnabled: true})
		var amount string
		for _, rate := range rates {
			if rate.Resource == key && rate.Unit == "second" {
				v, _ := rate.PriceUsd.Value()
				r, ok := new(big.Rat).SetString(fmt.Sprint(v))
				if !ok {
					t.Fatal("rate")
				}
				amount = new(big.Rat).Mul(r, big.NewRat(360000, 1)).FloatString(12)
			}
		}
		if amount == "" {
			t.Fatal("missing rate", key)
		}
		p := storagePrice{ID: id, Product: "prod_" + key, Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: amount}
		p.Recurring.UsageType = "metered"
		p.Recurring.Interval = "month"
		p.Recurring.IntervalCount = 1
		p.Recurring.Meter = "mtr_" + key
		prices[id] = p
	}
	round := storagePrice{ID: "price_round", Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1"}
	round.Recurring.UsageType = "metered"
	round.Recurring.Interval = "month"
	round.Recurring.IntervalCount = 1
	round.Recurring.Meter = "mtr_round"
	prices[round.ID] = round
	var mu sync.Mutex
	customer := "cus_" + team.String()
	sub := invoiceSubscription{ID: "sub_" + team.String(), Customer: customer, Status: "active", StartDate: anchor.Unix(), BillingCycleAnchor: anchor.Unix(), CollectionMethod: "charge_automatically"}
	sub.BillingMode.Type = "flexible"
	var customerWrites, subWrites, grantWrites, writes int
	var created bool
	firstCustomer := make(chan struct{})
	releaseCustomer := make(chan struct{})
	customerResult := make(chan error, 1)
	var first sync.Once
	var customerKey, customerName string
	var grant *entitlementGrant
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if scenario == "checkout_race" && r.URL.Path == "/v1/customers" {
			hold := false
			first.Do(func() { hold = true; close(firstCustomer) })
			if hold {
				<-releaseCustomer
			}
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		output := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.Method != http.MethodGet {
			writes++
		}
		switch {
		case r.URL.Path == "/v1/customers":
			customerWrites++
			if customerKey != "" && (customerKey != r.Header.Get("Idempotency-Key") || customerName != r.Form.Get("name")) {
				t.Error("customer creators use different identities or payloads")
			}
			customerKey, customerName = r.Header.Get("Idempotency-Key"), r.Form.Get("name")
			output(map[string]any{"id": customer})
		case r.URL.Path == "/v1/subscriptions" && r.Method == http.MethodPost:
			if r.Form.Has("pause_collection[behavior]") || r.Form.Has("default_payment_method") || r.Form.Has("discounts[0][coupon]") {
				t.Error("unsupported create parameter or payment requirement")
			}
			subWrites++
			created = true
			sub.Metadata = map[string]string{"sponsored_operation": r.Form.Get("metadata[sponsored_operation]")}
			for i := 0; i < 3; i++ {
				id := r.Form.Get(fmt.Sprintf("items[%d][price]", i))
				sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{ID: "si_" + id, Price: prices[id], Start: anchor.Unix(), End: end.Unix()})
			}
			if scenario == "revoke_creation" && subWrites == 1 {
				_, e := h.Pool.Exec(ctx, `UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE id=$1`, sub.Metadata["sponsored_operation"], uuid.New())
				if e != nil {
					t.Error(e)
				}
				http.Error(w, "lost create response", 503)
				return
			}
			output(sub)
		case r.URL.Path == "/v1/subscriptions":
			if created {
				output(map[string]any{"data": []invoiceSubscription{sub}})
			} else {
				output(map[string]any{"data": []any{}})
			}
		case r.URL.Path == "/v1/subscriptions/"+sub.ID:
			if r.Method == http.MethodPost && r.Form.Has("pause_collection[behavior]") {
				sub.PauseCollection = &struct {
					Behavior  string `json:"behavior"`
					ResumesAt int64  `json:"resumes_at"`
				}{Behavior: "keep_as_draft"}
			}
			output(sub)
		case r.URL.Path == "/v1/subscription_items":
			item := invoiceSubscriptionItem{ID: "si_round", Price: round, Start: anchor.Unix(), End: end.Unix()}
			sub.Items.Data = append(sub.Items.Data, item)
			output(item)
		case r.URL.Path == "/v1/prices":
			output(map[string]any{"data": []storagePrice{round}})
		case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
			output(prices[strings.TrimPrefix(r.URL.Path, "/v1/prices/")])
		case r.URL.Path == "/v1/billing/meters":
			meters := []any{}
			for _, key := range []string{"vcpu", "memory_gib", "storage_gib", "round"} {
				event := key
				if key == "round" {
					event = invoiceRoundingEvent
				}
				meters = append(meters, map[string]any{"id": "mtr_" + key, "event_name": event, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
			}
			output(map[string]any{"data": meters})
		case r.URL.Path == "/v1/invoices":
			output(map[string]any{"data": []any{}})
		case r.URL.Path == "/v1/billing/credit_grants":
			if r.Method == http.MethodGet {
				data := []any{}
				if grant != nil {
					data = append(data, *grant)
				}
				output(map[string]any{"data": data})
				return
			}
			grantWrites++
			g := testEntitlementGrant()
			g.ID = "credgr_" + team.String()
			g.Customer = customer
			g.Amount.Monetary.Value = 3000000
			g.Created = time.Now().Unix()
			g.EffectiveAt = g.Created
			g.ExpiresAt = end.Unix() + 1
			g.Metadata = map[string]string{"entitlement_id": r.Form.Get("metadata[entitlement_id]")}
			for i := range g.Applicability.Scope.Prices {
				g.Applicability.Scope.Prices[i].ID = r.Form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i))
			}
			grant = &g
			output(g)
		case r.URL.Path == "/v1/billing/credit_balance_summary":
			output(map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": 0}}}}})
		default:
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", 500)
		}
	}))
	defer srv.Close()
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, httpClient: srv.Client(), apiVersion: "2026-07-29.dahlia"}
	request := sponsoredRequest{Key: "onboarding", Schedule: []sponsoredPhase{{3, 3000000}, {9, 100000}}, Start: "now", Reason: "pilot", Reference: "approval"}
	if scenario == "historical_terms" {
		prior, _ := json.Marshal(StripeCreateCheckoutSessionParams{ResourceTerms: []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "price_obsolete", MeterID: "mtr_obsolete", EventName: "obsolete", UnitAmountDecimal: "1"}}})
		exec(`INSERT INTO billing_sponsored_operation(team_id,idempotency_key,request,resource_terms,approved_by,approved_at,reason,reference,customer_id,subscription_id,state,revoked_at,revoked_by) VALUES($1,'old','{}',$2,$3,clock_timestamp()-interval '1 day','fixture','fixture',$4,$5,'revoked',clock_timestamp(),$3)`, team, prior, uuid.New(), customer, sub.ID)
	}
	actor := uuid.New()
	callForTeam := func(target uuid.UUID, apply bool, r sponsoredRequest) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(r)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "team_id", Value: target.String()}}
		c.Set("actor_id", actor)
		h.sponsoredApply(c, apply)
		return w
	}
	call := func(apply bool, r sponsoredRequest) *httptest.ResponseRecorder {
		return callForTeam(team, apply, r)
	}
	if strings.HasPrefix(scenario, "capacity_") {
		exec(`UPDATE billing_funding_policy SET max_observed_teams=4 WHERE singleton`)
		var occupants []uuid.UUID
		t.Cleanup(func() {
			_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=ANY($1::uuid[])`, occupants)
		})
		if scenario == "capacity_existing" {
			exec(`UPDATE billing_funding_account SET observe=true WHERE team_id=$1`, team)
			occupants = append(occupants, team)
		}
		seats := 4
		if scenario == "capacity_race" {
			seats = 3
		}
		for len(occupants) < seats {
			_, id := fundingTransitionFixture(t)
			occupants = append(occupants, id)
			exec(`UPDATE billing_funding_account SET observe=true WHERE team_id=$1`, id)
		}
		preflight := func(target uuid.UUID, wantAvailable, wantObserved bool) {
			t.Helper()
			w := callForTeam(target, false, request)
			var result struct {
				Eligible  bool     `json:"eligible"`
				Conflicts []string `json:"conflicts"`
				Capacity  struct {
					Max       int  `json:"max_observed_teams"`
					Count     int  `json:"observed_teams"`
					Observed  bool `json:"target_already_observed"`
					Available bool `json:"available"`
				} `json:"funding_capacity"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
				t.Fatalf("capacity preflight: %d %s %v", w.Code, w.Body.String(), err)
			}
			if result.Eligible != wantAvailable || result.Capacity.Available != wantAvailable || result.Capacity.Observed != wantObserved || result.Capacity.Max != 4 || result.Capacity.Count != seats {
				t.Fatalf("unexpected capacity preview: %+v", result)
			}
			if !wantAvailable && !strings.Contains(strings.Join(result.Conflicts, " "), "cohort is at capacity") {
				t.Fatal("missing capacity conflict", result)
			}
			var operations int
			if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_sponsored_operation WHERE team_id=$1`, target).Scan(&operations); err != nil || operations != 0 || writes != 0 {
				t.Fatal("preflight mutated state", operations, writes, err)
			}
		}
		preflight(team, scenario != "capacity_new", scenario == "capacity_existing")
		if scenario == "capacity_new" {
			w := call(true, request)
			var operations, contracts, accounts int
			var observed bool
			err := h.Pool.QueryRow(ctx, `SELECT
              (SELECT count(*) FROM billing_sponsored_operation WHERE team_id=$1),
              (SELECT count(*) FROM billing_commercial_contract WHERE team_id=$1),
              (SELECT count(*) FROM team_billing_account WHERE team_id=$1),
              (SELECT observe FROM billing_funding_account WHERE team_id=$1)`, team).Scan(&operations, &contracts, &accounts, &observed)
			if w.Code != 409 || err != nil || operations != 0 || contracts != 0 || accounts != 0 || observed || writes != 0 {
				t.Fatal("capacity rejection was not atomic", w.Code, w.Body.String(), operations, contracts, accounts, observed, writes, err)
			}
			return
		}
		if scenario == "capacity_race" {
			_, other := fundingTransitionFixture(t)
			exec(`UPDATE team SET home_region='use' WHERE id=$1`, other)
			// Cover both missing and existing unobserved funding rows.
			exec(`DELETE FROM billing_funding_account WHERE team_id=$1`, other)
			preflight(other, true, false)
			occupants = append(occupants, team, other)
			lock, err := h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(context.Background())
			if _, err = lock.Exec(ctx, `SELECT singleton FROM billing_funding_policy WHERE singleton FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			results := make(chan *httptest.ResponseRecorder, 2)
			for _, target := range []uuid.UUID{team, other} {
				go func() { results <- callForTeam(target, true, request) }()
			}
			// Both approvals must reach enrollment before releasing the last slot.
			deadline := time.Now().Add(5 * time.Second)
			for {
				var waiting int
				err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
                  AND cardinality(pg_blocking_pids(pid))>0 AND query LIKE 'UPDATE billing_funding_account SET observe=true%'`).Scan(&waiting)
				if err != nil || time.Now().After(deadline) {
					t.Fatalf("enrollments did not contend for capacity: waiting=%d error=%v", waiting, err)
				}
				if waiting == 2 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = lock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			codes := map[int]int{}
			for range 2 {
				w := <-results
				codes[w.Code]++
				if w.Code != 200 && (w.Code != 409 || !strings.Contains(w.Body.String(), "capacity budget")) {
					t.Fatal("unexpected race result", w.Code, w.Body.String())
				}
			}
			var count, operations, contracts int
			var optedIn bool
			err = h.Pool.QueryRow(ctx, `SELECT
              (SELECT count(*) FROM billing_funding_account WHERE observe),
              (SELECT count(*) FROM billing_sponsored_operation WHERE team_id=ANY($1::uuid[])),
              (SELECT count(*) FROM billing_commercial_contract WHERE team_id=ANY($1::uuid[])),
              (SELECT bool_and(f.observe AND f.enforce) FROM billing_sponsored_operation o JOIN billing_funding_account f USING(team_id) WHERE o.team_id=ANY($1::uuid[]))`, []uuid.UUID{team, other}).Scan(&count, &operations, &contracts, &optedIn)
			if err != nil || codes[200] != 1 || codes[409] != 1 || count != 4 || operations != 1 || contracts != 0 || !optedIn || writes != 0 {
				t.Fatal("last slot was not exclusive/atomic", codes, count, operations, contracts, optedIn, writes, err)
			}
			return
		}
	}
	if scenario == "existing_anniversary" {
		exec(`INSERT INTO team_billing_account(team_id,commercial_billing_anchor) VALUES($1,$2) ON CONFLICT(team_id) DO UPDATE SET commercial_billing_anchor=$2`, team, anchor.Add(-time.Hour))
		w := call(false, request)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "existing anniversary has no aligned") {
			t.Fatal("preflight omitted calendar conflict", w.Code, w.Body.String())
		}
		if w = call(true, request); w.Code != 409 || writes != 0 {
			t.Fatal("conflicting calendar created provider objects", w.Code, writes)
		}
		return
	}
	if w := call(false, request); w.Code != 200 {
		t.Fatal("preflight", w.Code, w.Body.String())
	}
	var rows int
	if err = h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_sponsored_operation WHERE team_id=$1 AND idempotency_key='onboarding'`, team).Scan(&rows); err != nil || rows != 0 || writes != 0 {
		t.Fatal("preflight wrote state", rows, writes, err)
	}
	if w := call(true, request); w.Code != 200 {
		t.Fatal("apply", w.Code, w.Body.String())
	}
	var id uuid.UUID
	if err = h.Pool.QueryRow(ctx, `SELECT id FROM billing_sponsored_operation WHERE team_id=$1 AND idempotency_key='onboarding'`, team).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if w := call(true, request); w.Code != 200 {
		t.Fatal("replay", w.Code, w.Body.String())
	}
	changed := request
	changed.Reason = "different"
	if w := call(true, changed); w.Code != 409 {
		t.Fatal("changed replay accepted", w.Code)
	}
	if scenario == "checkout_race" {
		go func() { _, e := h.ensureStripeCustomer(ctx, team); customerResult <- e }()
		<-firstCustomer
	}
	err = h.reconcileSponsored(ctx, id)
	if scenario == "checkout_race" {
		close(releaseCustomer)
		if e := <-customerResult; e != nil {
			t.Fatal(e)
		}
	}
	if scenario == "revoke_creation" {
		if err == nil {
			t.Fatal("lost response not reported")
		}
	} else if err != nil {
		t.Fatal("onboarding", err)
	}
	if err = h.reconcileSponsored(ctx, id); err != nil {
		t.Fatal("onboarding replay", err)
	}
	o, err := h.sponsoredOperation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if scenario == "revoke_creation" {
		if o.State != "revoked" || grantWrites != 0 || subWrites != 1 {
			t.Fatal("revoked bootstrap", o.State, grantWrites, subWrites)
		}
		a, e := h.DB.GetTeamBillingAccount(ctx, team)
		if e != nil || derefString(a.StripeSubscriptionID) != sub.ID {
			t.Fatal("revocation orphaned subscription", a, e)
		}
		if _, enrolled, e := h.invoiceAccount(ctx, team); e != nil || !enrolled {
			t.Fatal("recovered subscription unenrolled", enrolled, e)
		}
		return
	}
	if o.State != "active" {
		t.Fatal("operation", o.State)
	}
	if scenario == "catalog_rotation" {
		for i := range h.Config.BillingResources {
			h.Config.BillingResources[i].StripePriceID += "_new"
		}
		a, enrolled, e := h.invoiceAccount(ctx, team)
		if e != nil || !enrolled {
			t.Fatal(e)
		}
		if e = h.validateInvoiceEnrollmentSubscription(ctx, team, a, h.Stripe.(*stripeHTTPClient), sub, h.Pool); e != nil {
			t.Fatal("rotated catalog broke existing collection", e)
		}
	}
	if scenario == "historical_terms" {
		states, e := h.billingSubscriptionResourceStates(ctx, team, sub.ID, false)
		if e != nil || len(states) != 3 {
			t.Fatal("stale resource authority", states, e)
		}
		scope, e := h.fundingCreditResourcePrices(ctx, team, customer)
		if e != nil {
			t.Fatal("stale credit authority", scope, e)
		}
		for _, price := range scope {
			if price == "price_obsolete" {
				t.Fatal("historical price selected")
			}
		}
	}
	if scenario == "revoke_canceled" {
		sub.Status = "canceled"
		exec(`UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE id=$1`, id, actor)
		if e := h.reconcileSponsored(ctx, id); e != nil {
			t.Fatal("terminal subscription blocked revocation", e)
		}
		o, e := h.sponsoredOperation(ctx, id)
		if e != nil || o.State != "revoked" || grantWrites != 0 {
			t.Fatal("revocation", o.State, e)
		}
		return
	}
	if _, err = h.reconcileUsageEntitlement(ctx, o.Contract); err != nil {
		t.Fatal("grant", err)
	}
	expectedCustomers := 1
	if scenario == "checkout_race" {
		expectedCustomers = 2
	}
	if customerWrites != expectedCustomers || subWrites != 1 || grantWrites != 1 {
		t.Fatal("duplicate/missing external writes", customerWrites, subWrites, grantWrites)
	}
	var choice string
	if err = h.Pool.QueryRow(ctx, `SELECT state FROM billing_signup_choice WHERE team_id=$1`, team).Scan(&choice); err != nil || choice != "selecting" {
		t.Fatal("signup state changed", choice, err)
	}
}
