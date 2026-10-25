//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// testCatalogOffer is a self-serve plan the migrations don't ship. Plans
// can't be deleted, so it stays, unavailable, for the rest of the run.
const testCatalogOffer = "example_monthly"

func ensureTestCatalogPlan(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO plan_limits
		SELECT $1, max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib FROM plan_limits WHERE offer_key='free'
		ON CONFLICT DO NOTHING`, testCatalogOffer); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_plan VALUES ($1,'example','Example',1,10000,10000,false,10)
		ON CONFLICT DO NOTHING`, testCatalogOffer); err != nil {
		t.Fatal(err)
	}
}

func setCatalogPlan(t *testing.T, offer string, amount, credit int64, available bool) {
	t.Helper()
	if offer == testCatalogOffer {
		ensureTestCatalogPlan(t)
	}
	var oldAmount, oldCredit int64
	var oldAvailable bool
	if err := testPool.QueryRow(t.Context(), `SELECT charge_amount_cents,monthly_credit_cents,available FROM billing_plan WHERE offer_key=$1`, offer).Scan(&oldAmount, &oldCredit, &oldAvailable); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_plan SET charge_amount_cents=$2,monthly_credit_cents=$3,available=$4 WHERE offer_key=$1`, offer, amount, credit, available); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `UPDATE billing_plan SET charge_amount_cents=$2,monthly_credit_cents=$3,available=$4 WHERE offer_key=$1`, offer, oldAmount, oldCredit, oldAvailable); err != nil {
			t.Error(err)
		}
	})
}

func TestIntegration_PlanCatalogRejectsUnavailablePlan(t *testing.T) {
	setCatalogPlan(t, testCatalogOffer, 10000, 5000, false)
	_, r, key := newProFixture(t, testCatalogOffer)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(testCatalogOffer), 400, "invalid_offer")
}

func TestIntegration_PlanCatalogPurchaseKeepsCheckoutTerms(t *testing.T) {
	setCatalogPlan(t, testCatalogOffer, 10000, 5000, true)
	f, r, key := newProFixture(t, testCatalogOffer)
	f.amount = 10000
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	// A catalog edit after checkout must not change the purchase in flight.
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_plan SET monthly_credit_cents=7500,available=false WHERE offer_key=$1`, testCatalogOffer); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var amount, credit int64
	var sandboxes int32
	if err := testPool.QueryRow(t.Context(), `SELECT c.charge_amount_cents,c.entitlement_amount_cents,t.max_sandboxes FROM billing_commercial_contract c JOIN team t ON t.id=c.team_id
		WHERE c.team_id=$1 AND c.offer_key=$2 AND c.status='active'`, f.team, testCatalogOffer).Scan(&amount, &credit, &sandboxes); err != nil {
		t.Fatal(err)
	}
	if amount != 10000 || credit != 5000 || sandboxes != 20 {
		t.Fatalf("contract amount=%d credit=%d max_sandboxes=%d", amount, credit, sandboxes)
	}
}

func TestIntegration_PlanCatalogCompletesPurchaseStartedBeforeCatalog(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_signup_choice SET request_payload=request_payload-'PlanTerms' WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var credit int64
	if err := testPool.QueryRow(t.Context(), `SELECT entitlement_amount_cents FROM billing_commercial_contract WHERE team_id=$1 AND status='active'`, f.team).Scan(&credit); err != nil || credit != 100000 {
		t.Fatalf("legacy purchase credit=%d err=%v", credit, err)
	}
}

func TestIntegration_PlanCatalogResumeUsesCheckoutTerms(t *testing.T) {
	setCatalogPlan(t, testCatalogOffer, 10000, 5000, true)
	f, r, key := newProFixture(t, testCatalogOffer)
	f.amount = 10000
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	// Returning to the checkout replays the purchase as started, even after the
	// plan's price changes and it stops accepting new checkouts.
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_plan SET charge_amount_cents=20000,available=false WHERE offer_key=$1`, testCatalogOffer); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
}

func TestIntegration_PublicBillingPlansListTodaysPurchasablePlans(t *testing.T) {
	ensureTestCatalogPlan(t)
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	cfg := &config.Config{
		Port:                    "0",
		VMDAddress:              "localhost:0",
		SystemTeamID:            testSystemTeamID.String(),
		StripePlanPriceIDs:      map[string]string{testCatalogOffer: "price_example_monthly"},
		StripeProMonthlyPriceID: "price_pro_monthly",
		StripeProAnnualPriceID:  "price_pro_annual",
	}
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
	h.Pool = testPool
	w := do(api.SetupRouter(t.Context(), h, testPool), "GET", "/billing/plans/public", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("plans: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Plans []struct {
			Key                string `json:"key"`
			IntervalMonths     int32  `json:"interval_months"`
			PriceCents         int64  `json:"price_cents"`
			MonthlyCreditCents int64  `json:"monthly_credit_cents"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// An unavailable plan stays unlisted even where a price is configured, so
	// only the Pro offers checkout already sells are listed, at today's terms.
	var catalog []string
	if err := testPool.QueryRow(t.Context(), `SELECT array_agg(offer_key ORDER BY offer_key) FROM billing_plan WHERE offer_key <> $1`, testCatalogOffer).Scan(&catalog); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(catalog) != "[pro_annual pro_monthly]" {
		t.Fatalf("migrated catalog = %v, want only the Pro offers", catalog)
	}
	got := fmt.Sprint(body.Plans)
	want := "[{pro_monthly 1 120000 100000} {pro_annual 12 1200000 100000}]"
	if got != want {
		t.Fatalf("plans = %s, want %s", got, want)
	}
}
