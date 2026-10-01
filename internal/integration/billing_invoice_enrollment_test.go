//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_InvoiceAutomaticEnrollment(t *testing.T) {
	correctionExec(t, `UPDATE billing_invoice_enrollment SET completed_at=now()`)
	team, _, start, _ := seedBillingPeriodForStripe(t, true, true)
	// Exercise the migration's actual backfill statement with a pre-existing row.
	correctionExec(t, `DELETE FROM billing_invoice_enrollment WHERE team_id=$1`, team)
	migration, err := os.ReadFile(filepath.Join("..", "..", "supabase", "migrations", "20261001212145_automatic_invoice_enrollment.sql"))
	if err != nil {
		t.Fatal(err)
	}
	seed := string(migration)[strings.LastIndex(string(migration), "INSERT INTO billing_invoice_enrollment(team_id,"):]
	// Other tests already have queue rows; only this test's missing row needs seeding.
	seed = strings.TrimSuffix(strings.TrimSpace(seed), ";") + " ON CONFLICT(team_id) DO NOTHING"
	correctionExec(t, seed)
	addPricing := func(id string) {
		key := "enrollment-" + id
		insertPricingPlanForTest(t, t.Context(), key, true)
		correctionExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.00001,$2)`, key, start)
		correctionExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, id, key, start)
		correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, id, start)
	}
	addPricing(team.String())
	type providerSub struct {
		held, item                bool
		holds, adds               int
		customer, status          string
		wrongMeter, inactivePrice bool
		change                    string
		reads                     int
	}
	var mu sync.Mutex
	subs := map[string]*providerSub{"sub_" + team.String(): {}}
	unprotectedEnd := int64(0)
	loseAdd := true
	price := func(id, meter, amount string) map[string]any {
		return map[string]any{"id": id, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": amount, "recurring": map[string]any{"usage_type": "metered", "meter": meter, "interval": "month", "interval_count": 1}}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = r.ParseForm()
		var out any
		switch {
		case r.URL.Path == "/v1/prices":
			out = map[string]any{"data": []any{price("price_round", "mtr_round", "1")}, "has_more": false}
		case r.URL.Path == "/v1/prices/price_round":
			out = price("price_round", "mtr_round", "1")
		case r.URL.Path == "/v1/billing/meters":
			data := []any{}
			for id, event := range map[string]string{"mtr_round": "invoice_rounding_cents_v1", "mtr_cpu": "cpu_hours"} {
				data = append(data, map[string]any{"id": id, "event_name": event, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
			}
			out = map[string]any{"data": data, "has_more": false}
		case r.URL.Path == "/v1/billing/credit_grants":
			out = map[string]any{"data": []any{}, "has_more": false}
		case r.URL.Path == "/v1/invoices":
			if sub := subs[r.Form.Get("subscription")]; sub != nil && sub.change == "before commit" {
				sub.wrongMeter = true
			}
			data := []any{}
			if unprotectedEnd != 0 && r.Form.Get("subscription") == "sub_"+team.String() {
				data = append(data, map[string]any{"id": "in_pre_hold", "billing_reason": "subscription_cycle", "period_end": unprotectedEnd})
			}
			out = map[string]any{"data": data, "has_more": false}
		case r.URL.Path == "/v1/invoices/in_pre_hold":
			if r.Method != http.MethodGet {
				t.Error("already finalized invoice was modified")
			}
			out = map[string]any{"id": "in_pre_hold", "customer": "cus_" + team.String(), "billing_reason": "subscription_cycle", "period_end": unprotectedEnd, "status": "paid", "auto_advance": false, "parent": map[string]any{"subscription_details": map[string]any{"subscription": "sub_" + team.String()}}, "lines": map[string]any{"data": []any{}, "has_more": false}}
		case r.URL.Path == "/v1/subscriptions":
			data := []any{}
			for id, sub := range subs {
				customer, status := sub.customer, sub.status
				if customer == "" {
					customer = "cus_" + strings.TrimPrefix(id, "sub_")
				}
				if status == "" {
					status = "active"
				}
				if customer == r.Form.Get("customer") {
					data = append(data, map[string]any{"id": id, "status": status})
				}
			}
			out = map[string]any{"data": data, "has_more": false}
		case strings.HasPrefix(r.URL.Path, "/v1/subscriptions/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
			sub := subs[id]
			if sub == nil {
				http.Error(w, "unknown subscription", 404)
				return
			}
			if r.Method == http.MethodGet {
				sub.reads++
				if sub.change == "before writes" && sub.reads >= 2 {
					sub.wrongMeter = true
				}
			}
			if r.Method == http.MethodPost {
				if r.Form.Get("pause_collection[behavior]") != "keep_as_draft" {
					t.Error("invalid hold")
				}
				sub.held = true
				sub.holds++
			}
			meter := "mtr_cpu"
			if sub.wrongMeter {
				meter = "mtr_other"
			}
			cpu := price("price_cpu", meter, "3.6")
			if sub.inactivePrice {
				cpu["active"] = false
			}
			items := []any{map[string]any{"id": "si_cpu", "price": cpu}}
			if sub.item {
				items = append(items, map[string]any{"id": "si_round", "price": price("price_round", "mtr_round", "1")})
			}
			customer, status := sub.customer, sub.status
			if customer == "" {
				customer = "cus_" + strings.TrimPrefix(id, "sub_")
			}
			if status == "" {
				status = "active"
			}
			out = map[string]any{"id": id, "customer": customer, "status": status, "items": map[string]any{"data": items, "has_more": false}}
			if sub.held {
				out.(map[string]any)["pause_collection"] = map[string]any{"behavior": "keep_as_draft"}
			}
		case r.URL.Path == "/v1/subscription_items":
			sub := subs[r.Form.Get("subscription")]
			if sub == nil {
				t.Error("unexpected subscription")
				http.Error(w, "bad", 400)
				return
			}
			if r.Form.Get("price") != "price_round" || r.Form.Get("proration_behavior") != "none" || r.Header.Get("Idempotency-Key") == "" {
				t.Error("unsafe rounding item request")
			}
			sub.item = true
			sub.adds++
			if sub.change == "after item" {
				sub.wrongMeter = true
			}
			if loseAdd {
				loseAdd = false
				http.Error(w, `{"error":{"message":"response lost"}}`, 500)
				return
			}
			out = map[string]any{"id": "si_round"}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	cfg := &config.Config{StripeSecretKey: "sk_test_example", StripeAPIVersion: "2026-05-27.dahlia", StripeAPIBaseURL: server.URL, BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_cpu", StripeEventName: "cpu_hours", Billable: true, CheckoutEnabled: true}}}
	handler := func() *api.Handlers {
		h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
		h.Pool = testPool
		h.Stripe = api.NewStripeBillingClient(cfg)
		return h
	}
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err == nil {
		t.Fatalf("lost response worked=%v err=%v", worked, err)
	}
	var pending bool
	if err = testPool.QueryRow(t.Context(), `SELECT completed_at IS NULL AND last_error IS NOT NULL AND attempt_count=1 AND next_attempt_at>now() FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&pending); err != nil || !pending {
		t.Fatalf("durable retry missing %v %v", pending, err)
	}
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); worked || err != nil {
		t.Fatalf("backoff ignored: %v %v", worked, err)
	}
	// Simulate a renewal finalized while the initial attempt had not reached the
	// hold. The committed enrollment boundary must exclude that invoice.
	mu.Lock()
	unprotectedEnd = time.Now().Add(-time.Hour).Unix()
	cutover := unprotectedEnd
	mu.Unlock()
	correctionExec(t, `UPDATE billing_invoice_enrollment SET started_at=$2 WHERE team_id=$1`, team, time.Unix(cutover-3600, 0))
	// A later activation is enrolled while the failed account is backing off.
	next, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	addPricing(next.String())
	mu.Lock()
	subs["sub_"+next.String()] = &providerSub{}
	mu.Unlock()
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err != nil {
		t.Fatalf("new activation: %v %v", worked, err)
	}
	correctionExec(t, `UPDATE billing_invoice_enrollment SET next_attempt_at=now()-interval '1 second' WHERE team_id=$1`, team)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := handler().InvoiceEnrollmentTickForTest(t.Context()); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var actualBoundary time.Time
	if err = testPool.QueryRow(t.Context(), `SELECT enrolled_at FROM billing_invoice_account WHERE team_id=$1`, team).Scan(&actualBoundary); err != nil || actualBoundary.Unix() != cutover {
		t.Fatalf("unprotected renewal remained enrolled: %s %v", actualBoundary, err)
	}
	for _, id := range []string{team.String(), next.String()} {
		var ready bool
		if err = testPool.QueryRow(t.Context(), `SELECT w.completed_at IS NOT NULL AND a.subscription_id=$2 AND a.enrolled_at=w.started_at FROM billing_invoice_enrollment w JOIN billing_invoice_account a USING(team_id) WHERE team_id=$1`, id, "sub_"+id).Scan(&ready); err != nil || !ready {
			t.Fatalf("enrollment missing: %v %v", ready, err)
		}
		mu.Lock()
		s := *subs["sub_"+id]
		mu.Unlock()
		if s.holds != 1 || s.adds != 1 {
			t.Fatalf("duplicate side effects: %+v", s)
		}
	}
	shadow, _, _, _ := seedBillingPeriodForStripe(t, true, false)
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); worked || err != nil {
		t.Fatalf("shadow enrollment: %v %v", worked, err)
	}
	var count int
	if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_invoice_account WHERE team_id=$1`, shadow).Scan(&count); err != nil || count != 0 {
		t.Fatal("shadow account enrolled", count, err)
	}
	// An ended subscription with no outstanding enrolled periods can transition.
	// Unsettled history must instead keep its association and hold the replacement.
	for _, replacement := range []struct {
		id      string
		pending bool
	}{{next.String(), false}, {team.String(), true}} {
		id := replacement.id
		if replacement.pending {
			correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, id, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		}
		oldID, newID := "sub_"+id, "sub_replacement_"+id
		mu.Lock()
		subs[oldID].status = "canceled"
		subs[newID] = &providerSub{customer: "cus_" + id}
		mu.Unlock()
		correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='canceled' WHERE team_id=$1`, id)
		correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, id, newID)
		correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, id)
		if !replacement.pending {
			// A newly opened replacement period is not unsettled old history.
			correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end) SELECT $1,requested_at-interval '1 second',requested_at+interval '1 month' FROM billing_invoice_enrollment WHERE team_id=$1`, id)
		}
		var reset bool
		if err = testPool.QueryRow(t.Context(), `SELECT started_at IS NULL AND completed_at IS NULL FROM billing_invoice_enrollment WHERE team_id=$1`, id).Scan(&reset); err != nil || !reset {
			t.Fatalf("replacement retained old cutover: %v %v", reset, err)
		}
		worked, e := handler().InvoiceEnrollmentTickForTest(t.Context())
		if !worked || (e != nil) != replacement.pending {
			t.Fatalf("replacement pending=%v: %v %v", replacement.pending, worked, e)
		}
		var saved string
		if err = testPool.QueryRow(t.Context(), `SELECT subscription_id FROM billing_invoice_account WHERE team_id=$1`, id).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		want := newID
		if replacement.pending {
			want = oldID
		}
		if saved != want {
			t.Fatalf("association=%s want=%s", saved, want)
		}
		mu.Lock()
		s := *subs[newID]
		mu.Unlock()
		if !s.held || !s.item || s.holds != 1 || s.adds != 1 {
			t.Fatalf("replacement not protected: %+v", s)
		}
	}
	// Cancellation recovery never permits enrolling a canceled subscription.
	inactive, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	addPricing(inactive.String())
	mu.Lock()
	subs["sub_"+inactive.String()] = &providerSub{status: "canceled"}
	mu.Unlock()
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err == nil {
		t.Fatalf("canceled enrollment accepted: %v %v", worked, err)
	}
	mu.Lock()
	s := *subs["sub_"+inactive.String()]
	mu.Unlock()
	if s.held || s.item {
		t.Fatal("canceled subscription was mutated")
	}
	for _, bad := range []string{"meter", "inactive price"} {
		invalid, _, _, _ := seedBillingPeriodForStripe(t, true, true)
		addPricing(invalid.String())
		mu.Lock()
		subs["sub_"+invalid.String()] = &providerSub{wrongMeter: bad == "meter", inactivePrice: bad == "inactive price"}
		mu.Unlock()
		if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err == nil {
			t.Fatalf("invalid %s enrolled: %v %v", bad, worked, err)
		}
		mu.Lock()
		s := *subs["sub_"+invalid.String()]
		mu.Unlock()
		if s.held || s.item || s.holds != 0 || s.adds != 0 {
			t.Fatalf("invalid %s changed provider: %+v", bad, s)
		}
	}
	legacy, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err == nil || !strings.Contains(err.Error(), "commercial billing anchor") {
		t.Fatalf("unanchored legacy account enrolled: %v %v", worked, err)
	}
	var untouched bool
	if err = testPool.QueryRow(t.Context(), `SELECT started_at IS NULL AND completed_at IS NULL AND last_error IS NOT NULL FROM billing_invoice_enrollment WHERE team_id=$1`, legacy).Scan(&untouched); err != nil || !untouched {
		t.Fatalf("unanchored account established a cutover: %v %v", untouched, err)
	}
	for _, change := range []string{"before writes", "after item", "before commit"} {
		changing, _, _, _ := seedBillingPeriodForStripe(t, true, true)
		addPricing(changing.String())
		id := "sub_" + changing.String()
		mu.Lock()
		subs[id] = &providerSub{change: change}
		mu.Unlock()
		if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err == nil {
			t.Fatalf("changed mapping %s accepted: %v %v", change, worked, err)
		}
		var saved int
		if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_invoice_account WHERE team_id=$1`, changing).Scan(&saved); err != nil || saved != 0 {
			t.Fatalf("changed mapping committed: %d %v", saved, err)
		}
		mu.Lock()
		s := *subs[id]
		subs[id].change = ""
		subs[id].wrongMeter = false
		mu.Unlock()
		if s.item != (change != "before writes") || s.held != (change == "before commit") {
			t.Fatalf("unsafe mutation order for %s: %+v", change, s)
		}
		correctionExec(t, `UPDATE billing_invoice_enrollment SET next_attempt_at=now()-interval '1 second' WHERE team_id=$1`, changing)
		if worked, err := handler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err != nil {
			t.Fatalf("restored mapping %s did not recover: %v %v", change, worked, err)
		}
		mu.Lock()
		s = *subs[id]
		mu.Unlock()
		if !s.held || !s.item || s.holds != 1 || s.adds != 1 {
			t.Fatalf("restored mapping duplicated mutation: %+v", s)
		}
	}
}

func TestIntegration_InvoiceEnrollmentQueueDoesNotBlockTeamCleanup(t *testing.T) {
	team, err := testQueries.CreateTeam(t.Context(), "example-enrollment-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status) VALUES($1,$2,$3,'active')`, team.ID, "cus_"+team.ID.String(), "sub_"+team.ID.String())
	correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id) VALUES($1,$2,$3,'price_round','round','mtr_round')`, team.ID, "cus_"+team.ID.String(), "sub_"+team.ID.String())
	correctionExec(t, `DELETE FROM team WHERE id=$1`, team.ID)
	var count int
	if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_invoice_enrollment WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("queue survived cleanup: %d %v", count, err)
	}
	if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_invoice_account WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("enrollment survived cleanup: %d %v", count, err)
	}
}
