//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func setProFixturePricingState(t *testing.T, version string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version=$1 WHERE singleton`, version); err != nil {
		t.Fatal(err)
	}
	if version != "v2" {
		return
	}
	var epoch string
	if err := testPool.QueryRow(t.Context(), `SELECT epoch::text FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{"epoch": epoch, "region": "usw", "system_team_id": testSystemTeamID.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "disposable-fixture", "worker_reference": "disposable-fixture"})
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2 WHERE singleton`, testSystemTeamID, evidence); err != nil {
		t.Fatal(err)
	}
}

func withReleasedProPricing(t *testing.T) {
	t.Helper()
	setProFixturePricingState(t, "v2")
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	})
}

func sellProWithPricingV2(t *testing.T, f *proProviderFixture, r *gin.Engine, key string) {
	t.Helper()
	f.upgrade = &proUpgradeProviderFixture{t: t}
	now := time.Now().UTC().Truncate(time.Second)
	f.handlers.Now = func() time.Time { return now }
	withReleasedProPricing(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	start, end := billing.CurrentBillingPeriod(now)
	expected := (int64(25000)*(end.Unix()-now.Unix()) + (end.Unix()-start.Unix())/2) / (end.Unix() - start.Unix())
	if f.upgrade.quoted != expected || f.anchor != start.Unix() || f.upgrade.recurringStart != end.Unix() {
		t.Fatalf("proration/calendar differs: amount=%d expected=%d anchor=%d expectedAnchor=%d next=%d expectedNext=%d", f.upgrade.quoted, expected, f.anchor, start.Unix(), f.upgrade.recurringStart, end.Unix())
	}
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
	for name, fraction := range map[string]int64{"partial": 2, "full": 1} {
		t.Run(name, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			sellProWithPricingV2(t, f, r, key)
			f.mu.Lock()
			discount := f.upgrade.quoted / fraction
			f.status, f.paid, f.discount = "complete", true, discount
			f.mu.Unlock()
			if fraction == 1 {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "payment_method_required")
				f.mu.Lock()
				f.upgrade.setupComplete = true
				f.mu.Unlock()
			}
			for range 2 {
				assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
			}
			var assignments, concurrency int
			var family, pricing, name string
			var grant, allowance int64
			if err := testPool.QueryRow(t.Context(), `SELECT count(*),max((limits->>'max_concurrent')::integer),max(terms->>'family'),max(terms->>'pricing_version'),max(terms->>'display_name'),max((terms#>>'{grants,0,amount_cents}')::bigint),max((terms#>>'{allowance,amount_cents}')::bigint) FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND contract_id IS NOT NULL`, f.team).Scan(&assignments, &concurrency, &family, &pricing, &name, &grant, &allowance); err != nil || grant != 25000 || allowance != 25000 || assignments != 1 || concurrency != 1000 || family != "pro" || pricing != "v2" || name != "Pro" {
				t.Fatalf("paid plan assignment: count=%d concurrency=%d family=%q pricing=%q name=%q err=%v", assignments, concurrency, family, pricing, name, err)
			}

			var quote, paid, fee, credit int64
			var expires int64
			var starts, next time.Time
			if err := testPool.QueryRow(t.Context(), `SELECT u.amount_cents,(u.payment_evidence->'Session'->>'amount_total')::bigint,c.charge_amount_cents,c.entitlement_amount_cents,p.expires_at,c.starts_at,u.period_end FROM billing_pro_upgrade u JOIN billing_commercial_contract c ON c.id=u.contract_id JOIN billing_provider_credit p ON p.grant_id=u.grant_id WHERE u.team_id=$1`, f.team).Scan(&quote, &paid, &fee, &credit, &expires, &starts, &next); err != nil || paid != quote-discount || fee != 25000 || credit != 25000 || expires != 0 || !starts.Equal(next) {
				t.Fatalf("upgrade economics: quote=%d paid=%d fee=%d credit=%d expires=%d starts=%s next=%s err=%v", quote, paid, fee, credit, expires, starts, next, err)
			}
			f.mu.Lock()
			grants, subDiscount := f.upgrade.grantCreates, f.subDiscount
			f.mu.Unlock()
			if grants != 1 || subDiscount {
				t.Fatalf("duplicate grant or recurring promotion: grants=%d discount=%v", grants, subDiscount)
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
	f.status, f.paid, f.discount = "complete", true, f.upgrade.quoted/2
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	f.mu.Lock()
	f.renewalDiscount = 5000
	f.baseStart = f.baseEnd
	f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 202, "payment_confirmation_pending")
	var receipts int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE team_id=$1`, f.team).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("discounted renewal was recorded: receipts=%d err=%v", receipts, err)
	}
}

func TestIntegration_ProPricingV2RefusesAnnualAndAcceptsCommittedFreeUpgrade(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.upgrade = &proUpgradeProviderFixture{t: t}
	withReleasedProPricing(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_annual"), 400, "invalid_offer")
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_signup_choice SET state='committed',offer_key='free' WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET trial_ended_at=now() WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
}

func TestIntegration_ProPricingV2PreservesExistingCalendarBeforePayment(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.upgrade = &proUpgradeProviderFixture{t: t}
	now := time.Now().UTC().Truncate(time.Second)
	anchor := now.AddDate(0, 0, -10)
	f.handlers.Now = func() time.Time { return now }
	withReleasedProPricing(t)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,commercial_billing_anchor) VALUES($1,$2,$3) ON CONFLICT(team_id) DO UPDATE SET commercial_billing_anchor=EXCLUDED.commercial_billing_anchor`, f.team, f.customer, anchor); err != nil {
		t.Fatal(err)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	start, end, ok := billing.AnniversaryPeriod(anchor, now)
	if !ok {
		t.Fatal("invalid calendar fixture")
	}
	expected := (int64(25000)*(end.Unix()-now.Unix()) + (end.Unix()-start.Unix())/2) / (end.Unix() - start.Unix())
	var preserved bool
	if err := testPool.QueryRow(t.Context(), `SELECT u.anchor=$2 AND a.commercial_billing_anchor=$2 AND u.period_start=$3 AND u.period_end=$4 AND u.amount_cents=$5 AND u.payment_evidence IS NULL AND u.contract_id IS NULL FROM billing_pro_upgrade u JOIN team_billing_account a USING(team_id) WHERE u.team_id=$1`, f.team, anchor, start, end, expected).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("existing anchor/proration changed before payment: %v %v", preserved, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.anchor != anchor.Unix() || f.baseEnd != end.Unix() {
		t.Fatal("provider request reset the original calendar")
	}
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
	f.status, f.paid, f.discount = "complete", true, f.upgrade.quoted/2
	f.mu.Unlock()
	setProFixturePricingState(t, "legacy")
	for range 2 {
		assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	}
	var kind, plan string
	if err := testPool.QueryRow(t.Context(), `SELECT kind,plan_key FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, f.team).Scan(&kind, &plan); err != nil || kind != "subscription" || plan != "pro_monthly" {
		t.Fatalf("purchase paid after switch-off was not assigned Pro: kind=%q plan=%q err=%v", kind, plan, err)
	}
	f.mu.Lock()
	f.baseStart = f.baseEnd
	f.baseEnd = time.Unix(f.baseStart, 0).UTC().AddDate(0, 1, 0).Unix()
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var fee, credit, receipts, promotions int64
	if err := testPool.QueryRow(t.Context(), `SELECT c.charge_amount_cents,c.entitlement_amount_cents,(SELECT count(*) FROM billing_contract_payment WHERE contract_id=c.id),(SELECT count(*) FROM billing_contract_promotion WHERE contract_id=c.id) FROM billing_commercial_contract c WHERE c.team_id=$1 AND c.status='pending'`, f.team).Scan(&fee, &credit, &receipts, &promotions); err != nil || fee != 25000 || credit != 25000 || receipts != 1 || promotions != 0 {
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
	withReleasedProPricing(t)
	f, r, key := newProFixture(t, "pro_monthly")
	var assigned bool
	if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND kind='free')`, f.team).Scan(&assigned); err != nil || !assigned {
		t.Fatalf("new v2 team has no Free assignment: %v %v", assigned, err)
	}
	setProFixturePricingState(t, "legacy")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 409, "plan_conflict")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 0 {
		t.Fatalf("created %d legacy checkouts for an assigned team", f.creates)
	}
}

func TestIntegration_ProUpgradeHoldPrecedesCheckoutAndRecoversLostResponse(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.upgrade = &proUpgradeProviderFixture{t: t, loseHoldResponse: true}
	withReleasedProPricing(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 202, "payment_confirmation_pending")
	f.mu.Lock()
	creates, held, writes := f.creates, f.held, f.upgrade.holdWrites
	f.mu.Unlock()
	if creates != 0 || !held || writes != 1 {
		t.Fatalf("checkout preceded verified hold: sessions=%d held=%v writes=%d", creates, held, writes)
	}
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 1 || f.upgrade.holdWrites != 1 {
		t.Fatalf("lost hold response duplicated operation: sessions=%d holdWrites=%d", f.creates, f.upgrade.holdWrites)
	}
}

func TestIntegration_ProRejectsIncompatibleExistingSubscriptionWithoutHoldingCollection(t *testing.T) {
	for _, failure := range []string{"calendar", "resource"} {
		t.Run(failure, func(t *testing.T) {
			f, r, key := newProFixture(t, "pro_monthly")
			now := time.Now().UTC().Truncate(time.Second)
			start, end := billing.CurrentBillingPeriod(now)
			f.handlers.Now = func() time.Time { return now }
			f.anchor, f.baseStart, f.baseEnd = start.Unix(), start.Unix(), end.Unix()
			f.upgrade = &proUpgradeProviderFixture{t: t, id: "existing", subscription: true, invalidCalendar: failure == "calendar", invalidResource: failure == "resource"}
			if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4) ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id=$2,stripe_subscription_id=$3,stripe_subscription_status='active',commercial_billing_anchor=$4`, f.team, f.customer, f.sub, start); err != nil {
				t.Fatal(err)
			}
			withReleasedProPricing(t)
			assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 202, "payment_confirmation_pending")
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.held || f.creates != 0 || f.upgrade.holdWrites != 0 || f.upgrade.base {
				t.Fatalf("unsupported subscription was modified before refusal: held=%v sessions=%d holdWrites=%d base=%v", f.held, f.creates, f.upgrade.holdWrites, f.upgrade.base)
			}
		})
	}
}

func TestIntegration_ProUpgradeLostCheckoutResponseRecoversFrozenPurchaseOff(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.upgrade = &proUpgradeProviderFixture{t: t}
	f.failCreate = true
	withReleasedProPricing(t)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 202, "payment_confirmation_pending")
	f.mu.Lock()
	initialPrices, quote := len(f.priceCreates), f.upgrade.quoted
	f.mu.Unlock()
	setProFixturePricingState(t, "legacy")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 1 || len(f.priceCreates) != initialPrices || f.upgrade.quoted != quote {
		t.Fatalf("response loss repriced/recreated accepted operation: creates=%d prices=%d/%d quote=%d/%d", f.creates, len(f.priceCreates), initialPrices, f.upgrade.quoted, quote)
	}
}
