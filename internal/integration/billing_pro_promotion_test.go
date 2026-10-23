//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func setPricingVersion(t *testing.T, version string) {
	t.Helper()
	r := newInternalRouter(t)
	admin := seedPlatformAdminProfile(t).String()
	if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, fmt.Sprintf(`{"pricing_version":%q,"reason":"pricing v2 test"}`, version)); w.Code != http.StatusOK {
		t.Fatalf("switch to %s = %d %s", version, w.Code, w.Body)
	}
}

func withPricingV2(t *testing.T) {
	t.Helper()
	setPricingVersion(t, "v2")
	t.Cleanup(func() { setPricingVersion(t, "legacy") })
}

func sellProWithPricingV2(t *testing.T, f *proProviderFixture, r *gin.Engine, key string) {
	t.Helper()
	withPricingV2(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.promotionCodes || f.amount != 25000 {
		t.Fatalf("pricing v2 checkout: promotion codes=%v fee=%d", f.promotionCodes, f.amount)
	}
}

func proPaymentDiscount(t *testing.T, f *proProviderFixture, newest bool) (paid, discounted int64) {
	t.Helper()
	order := "ASC"
	if newest {
		order = "DESC"
	}
	if err := testPool.QueryRow(t.Context(), `SELECT p.invoice_amount_paid_cents,COALESCE(d.discounted_cents,0) FROM billing_contract_payment p LEFT JOIN billing_contract_promotion d ON d.contract_id=p.contract_id AND d.checkout_invoice_id=p.invoice_id WHERE p.team_id=$1 ORDER BY p.service_period_start `+order+` LIMIT 1`, f.team).Scan(&paid, &discounted); err != nil {
		t.Fatal(err)
	}
	return paid, discounted
}

func TestIntegration_ProPromotionCodeDiscountsTheCheckoutInvoice(t *testing.T) {
	for name, discount := range map[string]int64{"partial": 5000, "full": 25000} {
		t.Run(name, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			sellProWithPricingV2(t, f, r, key)
			f.mu.Lock()
			f.status, f.paid, f.discount, f.subDiscount = "complete", true, discount, true
			f.mu.Unlock()
			for range 2 {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			}
			var assignments, concurrency int
			var family, pricing, name string
			var grant, allowance int64
			if err := testPool.QueryRow(t.Context(), `SELECT count(*),max((limits->>'max_concurrent')::integer),max(terms->>'family'),max(terms->>'pricing_version'),max(terms->>'display_name'),max((terms#>>'{grants,0,amount_cents}')::bigint),max((terms#>>'{allowance,amount_cents}')::bigint) FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND contract_id IS NOT NULL`, f.team).Scan(&assignments, &concurrency, &family, &pricing, &name, &grant, &allowance); err != nil || grant != 25000 || allowance != 25000 || assignments != 1 || concurrency != 1000 || family != "pro" || pricing != "v2" || name != "Pro" {
				t.Fatalf("paid plan assignment: count=%d concurrency=%d family=%q pricing=%q name=%q err=%v", assignments, concurrency, family, pricing, name, err)
			}
			if paid, discounted := proPaymentDiscount(t, f, false); paid != 25000-discount || discounted != discount {
				t.Fatalf("checkout receipt paid=%d discount=%d", paid, discounted)
			}
			var code, coupon string
			var fee, credit int64
			if err := testPool.QueryRow(t.Context(), `SELECT p.promotion_code,p.coupon_id,c.charge_amount_cents,c.entitlement_amount_cents FROM billing_contract_promotion p JOIN billing_commercial_contract c ON c.id=p.contract_id WHERE p.team_id=$1`, f.team).Scan(&code, &coupon, &fee, &credit); err != nil || code != "promo_example" || coupon != "coupon_example" || fee != 25000 || credit != 25000 {
				t.Fatalf("contract promotion code=%q coupon=%q fee=%d credit=%d err=%v", code, coupon, fee, credit, err)
			}
			f.mu.Lock()
			cleared, still := f.discountCleared, f.subDiscount
			f.mu.Unlock()
			if cleared != 1 || still {
				t.Fatalf("promotion kept on the subscription: cleared=%d remaining=%v", cleared, still)
			}
			f.mu.Lock()
			f.baseStart = f.baseEnd
			f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
			f.mu.Unlock()
			assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			if paid, discounted := proPaymentDiscount(t, f, true); paid != 25000 || discounted != 0 {
				t.Fatalf("renewal paid=%d discount=%d", paid, discounted)
			}
		})
	}
}

func TestIntegration_ProWithoutPricingV2RejectsDiscountedInvoices(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	f.status, f.paid, f.discount = "complete", true, 25000
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	var receipts, promotions int
	if err := testPool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_contract_payment WHERE team_id=$1),(SELECT count(*) FROM billing_contract_promotion WHERE team_id=$1)`, f.team).Scan(&receipts, &promotions); err != nil || receipts != 0 || promotions != 0 {
		t.Fatalf("legacy purchase accepted a discount: receipts=%d promotions=%d err=%v", receipts, promotions, err)
	}
}

func TestIntegration_ProPromotionRenewalRejectsDiscounts(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	sellProWithPricingV2(t, f, r, key)
	f.mu.Lock()
	f.status, f.paid, f.discount, f.subDiscount = "complete", true, 5000, true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	f.mu.Lock()
	f.renewalDiscount = 5000
	f.baseStart = f.baseEnd
	f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	var receipts int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("discounted renewal was recorded: receipts=%d err=%v", receipts, err)
	}
}

func TestIntegration_ProPricingV2RefusesAnnualAndUnimplementedUpgrades(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	withPricingV2(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_annual"), 400, "invalid_offer")
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_signup_choice SET state='committed',offer_key='free' WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET trial_ended_at=now() WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 409, "plan_conflict")
}

func TestIntegration_ProPricingV2RejectsExistingCalendarBeforePayment(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	withPricingV2(t)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,commercial_billing_anchor) VALUES($1,$2,now()-interval '10 days') ON CONFLICT(team_id) DO UPDATE SET commercial_billing_anchor=EXCLUDED.commercial_billing_anchor`, f.team, f.customer); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 409, "plan_conflict")
}

func TestIntegration_ProLegacyCheckoutOffersNoPromotionCodes(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.promotionCodes || f.amount != 120000 {
		t.Fatalf("legacy checkout: promotion codes=%v fee=%d", f.promotionCodes, f.amount)
	}
}

// Turning pricing v2 off stops new v2 sales but keeps serving existing ones.
func TestIntegration_ProPricingV2PurchaseSurvivesSwitchOff(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	sellProWithPricingV2(t, f, r, key)
	f.mu.Lock()
	f.status, f.paid, f.discount, f.subDiscount = "complete", true, 25000, true
	f.mu.Unlock()
	setPricingVersion(t, "legacy")
	for range 2 {
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	}
	f.mu.Lock()
	f.baseStart = f.baseEnd
	f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var fee, credit, receipts, promotions int64
	if err := testPool.QueryRow(t.Context(), `SELECT c.charge_amount_cents,c.entitlement_amount_cents,(SELECT count(*) FROM billing_contract_payment WHERE contract_id=c.id),(SELECT count(*) FROM billing_contract_promotion WHERE contract_id=c.id) FROM billing_commercial_contract c WHERE c.team_id=$1 AND c.status='active'`, f.team).Scan(&fee, &credit, &receipts, &promotions); err != nil || fee != 25000 || credit != 25000 || receipts != 2 || promotions != 1 {
		t.Fatalf("v2 contract after switch-off fee=%d credit=%d receipts=%d promotions=%d err=%v", fee, credit, receipts, promotions, err)
	}
	if paid, discounted := proPaymentDiscount(t, f, true); paid != 25000 || discounted != 0 {
		t.Fatalf("renewal after switch-off paid=%d discount=%d", paid, discounted)
	}
	next, nr, nkey := newProFixture(t, "pro_monthly")
	assertProResponse(t, nr, nkey, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, next.session)
	next.mu.Lock()
	defer next.mu.Unlock()
	if next.promotionCodes || next.amount != 120000 {
		t.Fatalf("new checkout after switch-off: promotion codes=%v fee=%d", next.promotionCodes, next.amount)
	}
}

func TestIntegration_ProRejectsNewLegacyCheckoutForAssignedTeam(t *testing.T) {
	withPricingV2(t)
	f, r, key := newProFixture(t, "pro_monthly")
	var assigned bool
	if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND kind='free')`, f.team).Scan(&assigned); err != nil || !assigned {
		t.Fatalf("new v2 team has no Free assignment: %v %v", assigned, err)
	}
	setPricingVersion(t, "legacy")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 409, "plan_conflict")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 0 {
		t.Fatalf("created %d legacy checkouts for an assigned team", f.creates)
	}
}
