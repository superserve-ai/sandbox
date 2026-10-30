//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fundedSubscriptionFixture moves a prepaid fixture team onto a published
// prepaid-funded subscription backed by a contract. All values are arbitrary
// fixtures, not catalog values.
func fundedSubscriptionFixture(t *testing.T, topoff *planTopoff) (*prepaidFixture, uuid.UUID) {
	t.Helper()
	f := newPrepaidFixture(t)
	terms := f.publishFundedPlan(topoff, false)
	contract := f.fundedContract(terms.OfferKey)
	if _, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: terms, Source: planSourceCheckout, Reason: "funded subscription fixture", ContractID: &contract}); err != nil {
		t.Fatal(err)
	}
	return f, contract
}

// publishFundedPlan publishes a prepaid-funded subscription, sold at checkout
// when sellable, and returns its monthly terms.
func (f *prepaidFixture) publishFundedPlan(topoff *planTopoff, sellable bool) planTerms {
	f.t.Helper()
	family := "funded" + uuid.NewString()[:8]
	var version uuid.UUID
	var amount, threshold *int64
	var preselect *bool
	if topoff != nil {
		amount, threshold, preselect = &topoff.AmountCents, &topoff.ThresholdCents, &topoff.DefaultEnabled
	}
	if err := f.h.Pool.QueryRow(f.t.Context(), `INSERT INTO billing_plan_version(family,version,pricing_version,kind,display_name,monthly_fee_cents,credit_schedule,max_sandboxes,
  public,self_serve,funding_policy,topoff_amount_cents,topoff_threshold_cents,topoff_default_enabled)
 VALUES($1,1,'v2','subscription','Funded fixture',700,'[{"start_months":0,"every_months":1,"amount_cents":700,"expires_after_months":1}]',3,$5,$5,'prepaid',$2,$3,$4) RETURNING id`,
		family, amount, threshold, preselect, sellable).Scan(&version); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE billing_plan_version SET state='published',published_at=clock_timestamp() WHERE id=$1`, version)
	f.t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_plan_version SET state='retired',retired_at=clock_timestamp() WHERE id=$1`, version)
	})
	terms, err := f.h.planTermsVersion(f.t.Context(), version, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return terms
}

func (f *prepaidFixture) fundedContract(offerKey string) uuid.UUID {
	f.t.Helper()
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	f.exec(`UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, f.team, start)
	var contract uuid.UUID
	if err := f.h.Pool.QueryRow(f.t.Context(), `INSERT INTO billing_commercial_contract(team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor)
 VALUES($1,$2,$3,$4,$5,'price_fixture',700,1,700,$3) RETURNING id`, f.team, offerKey, start, f.customer, f.sub).Scan(&contract); err != nil {
		f.t.Fatal(err)
	}
	return contract
}

// issueIncludedGrant records the period's included grant as issued, as the
// entitlement worker would after Stripe confirms it.
func (f *prepaidFixture) issueIncludedGrant(contract uuid.UUID) {
	f.t.Helper()
	conn, err := f.h.Pool.Acquire(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Release()
	// The payment row is outside what this test exercises.
	if _, err = conn.Exec(f.t.Context(), `SET session_replication_role=replica`); err != nil {
		f.t.Fatal(err)
	}
	defer conn.Exec(context.WithoutCancel(f.t.Context()), `RESET session_replication_role`)
	if _, err = conn.Exec(f.t.Context(), `INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency,state,
  first_attempt_at,request_payload,provider_invoice_start,provider_invoice_end,stripe_credit_grant_id,issuance_evidence,issued_at)
 VALUES($1,$2,gen_random_uuid(),'metered_usage',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '29 days',700,'usd','issued',
  clock_timestamp(),'{}',clock_timestamp()-interval '1 hour',clock_timestamp(),$3,'{"fixture":true}',clock_timestamp())`,
		f.team, contract, "cg_"+uuid.NewString()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *prepaidFixture) eligible() bool {
	f.t.Helper()
	var ok bool
	if err := f.h.Pool.QueryRow(f.t.Context(), `SELECT team_sandbox_billing_eligible($1)`, f.team).Scan(&ok); err != nil {
		f.t.Fatal(err)
	}
	return ok
}

func (f *prepaidFixture) applyTopoff(session string, enabled bool) error {
	f.t.Helper()
	tx, err := f.h.Pool.Begin(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(f.t.Context()))
	if err = applyCheckoutTopoff(f.t.Context(), tx, f.team, session, enabled, pricingPublicState{Version: "v2", EntryOpen: true}); err != nil {
		return err
	}
	return tx.Commit(f.t.Context())
}

func TestPrepaidFundedSubscriptionPausesAtZeroWithTopoffOff(t *testing.T) {
	f, contract := fundedSubscriptionFixture(t, &planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true})
	f.exec(`UPDATE billing_funding_account SET observe=false WHERE team_id=$1`, f.team)
	if err := f.applyTopoff("cs_off", false); err != nil {
		t.Fatal(err)
	}
	if err := f.h.retryPrepaidEnrolment(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.observe(500, true)
	if err := f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	var prepaid bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT observe AND prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || prepaid {
		t.Fatal("enforcement began before the included grant was issued and observed", prepaid, err)
	}
	f.issueIncludedGrant(contract)
	f.observe(500, true)
	if err := f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT observe AND prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || !prepaid {
		t.Fatal("observed included grant did not start enforcement", prepaid, err)
	}
	if !f.eligible() {
		t.Fatal("funded team with credit is not eligible")
	}
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if f.eligible() || len(f.intentPosts) != 0 {
		t.Fatal("team with Auto Topoff off kept running or was charged at $0", len(f.intentPosts))
	}
}

func TestPrepaidFundedSubscriptionTopsUpAndPausesAfterDecline(t *testing.T) {
	f, _ := fundedSubscriptionFixture(t, &planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true})
	if err := f.applyTopoff("cs_on", true); err != nil {
		t.Fatal(err)
	}
	f.observe(500, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(); len(r) != 1 || r[0].Source != "auto_recharge" || r[0].Amount != 1500 || r[0].Credit != "issued" {
		t.Fatalf("top-off did not use the frozen amount: %+v", r)
	}
	f.exec(`UPDATE billing_prepaid_purchase SET credit_voided_at=clock_timestamp() WHERE team_id=$1`, f.team)
	f.exec(`UPDATE billing_funding_account SET enforce=true,prepaid=true WHERE team_id=$1`, f.team)
	f.decline = true
	f.observe(0, true)
	if err := f.tick(); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT enabled FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled); err != nil || enabled {
		t.Fatal("declined top-off left Auto Topoff on", enabled, err)
	}
	if f.eligible() {
		t.Fatal("team kept running after a declined top-off at $0")
	}
}

func TestPrepaidFundedSubscriptionTopoffChoiceReplaysPerSession(t *testing.T) {
	f, _ := fundedSubscriptionFixture(t, &planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true})
	state := func() (enabled bool, amount int64) {
		t.Helper()
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT enabled,amount_cents FROM billing_prepaid_auto_recharge WHERE team_id=$1`, f.team).Scan(&enabled, &amount); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := f.applyTopoff("cs_first", true); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, f.team)
	if err := f.applyTopoff("cs_first", true); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := state(); enabled {
		t.Fatal("a replayed settlement overrode the customer's later choice")
	}
	if err := f.applyTopoff("cs_second", true); err != nil {
		t.Fatal(err)
	}
	if enabled, amount := state(); !enabled || amount != 1500 {
		t.Fatal("a new checkout's choice was not applied", enabled, amount)
	}
	if err := f.applyTopoff("cs_third", false); err != nil {
		t.Fatal(err)
	}
	if err := f.applyTopoff("cs_second", true); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := state(); enabled {
		t.Fatal("an older checkout retried out of order overrode a newer choice")
	}
}

func TestPrepaidFundedSubscriptionTopoffNeedsAnOffer(t *testing.T) {
	f, _ := fundedSubscriptionFixture(t, nil)
	if err := f.applyTopoff("cs_none", true); !errors.Is(err, errTopoffNotOffered) {
		t.Fatal("enabled a top-off the plan does not offer", err)
	}
	if err := f.applyTopoff("cs_none", false); err != nil {
		t.Fatal("declining an unoffered top-off must still record the checkout", err)
	}
}

func TestInvoiceCashFundedSubscriptionCollectsDespiteSettledTopoff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  string
		settled bool
		want    string
	}{
		{"funded settled", fundingPolicyPrepaid, true, "residual_allowed"},
		{"funded unsettled", fundingPolicyPrepaid, false, "prepaid_hold"},
		{"postpaid settled", "", true, "prepaid_hold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvoiceCashFixture(t, "", "")
			f.quiescePrepaidPurchases(t)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := f.h.Pool.Exec(t.Context(), q, args...); err != nil {
					t.Fatal(err)
				}
			}
			var contract uuid.UUID
			if err := f.h.Pool.QueryRow(t.Context(), `INSERT INTO billing_commercial_contract(team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor)
 VALUES($1,'funded_monthly',$2,$3,$4,'price_base',700,1,700,$2) RETURNING id`, f.team, f.start, f.invoice.Customer, "sub_"+f.team.String()).Scan(&contract); err != nil {
				t.Fatal(err)
			}
			exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason,contract_id)
 VALUES($1,'funded_monthly','subscription',jsonb_strip_nulls(jsonb_build_object('kind','subscription','pricing_version','v2','funding_policy',NULLIF($2,''))),'{"max_concurrent":1}',$3,'staff','funded fixture',$4)`,
				f.team, tc.policy, f.start.Add(-time.Hour), contract)
			id := uuid.New()
			exec(`INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,payment_idempotency_key,credit_idempotency_key,payment_request,created_at)
 VALUES($1,$2,$3,'auto_recharge',500,'','','{}',$4)`, id, f.team, f.invoice.Customer, f.start.Add(time.Hour))
			exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',amount_cents,'customer',customer_id) WHERE id=$1`, id)
			if tc.settled {
				request, err := prepaidCreditRequest(id, f.invoice.Customer, 500, "auto_recharge")
				if err != nil {
					t.Fatal(err)
				}
				exec(`UPDATE billing_prepaid_purchase SET credit_state='pending',credit_request=$2 WHERE id=$1`, id, request)
				exec(`UPDATE billing_prepaid_purchase SET credit_state='uncertain',credit_first_attempt_at=clock_timestamp() WHERE id=$1`, id)
				exec(`UPDATE billing_prepaid_purchase SET credit_state='issued',stripe_credit_grant_id=$2,credit_evidence=credit_request || jsonb_build_object('id',$2::text),credited_at=clock_timestamp() WHERE id=$1`, id, "cg_"+id.String())
			}
			var policy string
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT policy FROM resolve_invoice_cash_authority($1)`, f.invoice.ID).Scan(&policy); err != nil || policy != tc.want {
				t.Fatalf("cash authority = %q, want %q (%v)", policy, tc.want, err)
			}
		})
	}
}

func TestPrepaidFundedSubscriptionCheckoutFreezesFunding(t *testing.T) {
	f := newPrepaidFixture(t)
	topoff := &planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true}
	terms := f.publishFundedPlan(topoff, true)
	offer, err := f.h.proOfferForPricingVersion(t.Context(), terms.OfferKey, "v2")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(StripeCreateCheckoutSessionParams{AllowPromotionCodes: true, PlanTerms: checkoutPlanTerms(offer, true)})
	if err != nil {
		t.Fatal(err)
	}
	choice := proChoice{Team: f.team, Offer: terms.OfferKey, Actor: uuid.New(), Payload: payload}
	frozen, err := choice.frozenOffer()
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil {
		t.Fatal(err)
	}
	frozen.PredecessorKnown, frozen.InitialAssignment = true, &current.ID
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if err = assignCheckoutPlan(t.Context(), tx, choice, frozen, f.fundedContract(terms.OfferKey)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	plan, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || !plan.prepaidFunded() || plan.Terms.Topoff == nil || *plan.Terms.Topoff != *topoff {
		t.Fatalf("checkout lost the plan's funding terms: %+v %v", plan.Terms, err)
	}
	if err = f.applyTopoff("cs_checkout", true); err != nil {
		t.Fatal(err)
	}
}

func TestPrepaidFundedSubscriptionUpgradeGrantStartsEnforcement(t *testing.T) {
	f, _ := fundedSubscriptionFixture(t, nil)
	f.observe(500, true)
	conn, err := f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	// Only the credited upgrade and its grant matter here, not how they got there.
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	grant := "cg_" + uuid.NewString()
	if _, err = conn.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence,grant_id)
 VALUES(gen_random_uuid(),$1,gen_random_uuid(),$2,'funded_monthly','{}',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '29 days',clock_timestamp()-interval '1 hour',700,'credited','{}',$3)`,
		f.team, f.customer, grant); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at) VALUES($1,$2,'{}',0,0)`, f.customer, grant); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(t.Context(), `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE billing_pro_upgrade SET next_check_at='9999-01-01' WHERE team_id=$1`, f.team)
	f.observe(500, true)
	if err = f.h.startPrepaidEnforcement(t.Context()); err != nil {
		t.Fatal(err)
	}
	var prepaid bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT prepaid FROM billing_funding_account WHERE team_id=$1`, f.team).Scan(&prepaid); err != nil || !prepaid {
		t.Fatal("an observed first-cycle upgrade grant did not start enforcement", prepaid, err)
	}
}

func TestProInvoiceCashFundedUpgradeCollectsDespiteSettledTopoff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		funded bool
		source string
		retain bool
		valid  bool
	}{
		{"funded top-off", true, "auto_recharge", false, true},
		{"funded checkout purchase", true, "checkout", false, false},
		{"funded retained credit purchase", true, "checkout", true, true},
		{"postpaid top-off", false, "auto_recharge", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newProCashFixtureMode(t, planKindPrepaid, 2, 30000, 25000, true)
			f.quiescePrepaidPurchases(t)
			if tc.funded {
				conn, err := f.h.Pool.Acquire(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				// Assignments are immutable; the fixture's paid plan just needs the funded policy.
				if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				_, err = conn.Exec(t.Context(), `UPDATE team_plan_assignment SET terms=terms||'{"funding_policy":"prepaid"}' WHERE team_id=$1 AND kind='subscription'`, f.team)
				_, _ = conn.Exec(context.WithoutCancel(t.Context()), `RESET session_replication_role`)
				conn.Release()
				if err != nil {
					t.Fatal(err)
				}
			}
			if allowed, err := f.h.freezeProInvoiceCash(t.Context(), f.invoice); err != nil || !allowed {
				t.Fatal("component proof unavailable", allowed, err)
			}
			id := insertProCashFundingPurchase(t, f.h, f.team, f.invoice.Customer, tc.source, "succeeded", f.start.Add(time.Hour), tc.retain)
			request, err := prepaidCreditRequest(id, f.invoice.Customer, 500, tc.source)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{
				`UPDATE billing_prepaid_purchase SET credit_state='pending',credit_request=$2 WHERE id=$1`,
				`UPDATE billing_prepaid_purchase SET credit_state='uncertain',credit_first_attempt_at=clock_timestamp() WHERE id=$1 AND $2::jsonb IS NOT NULL`,
				`UPDATE billing_prepaid_purchase SET credit_state='issued',stripe_credit_grant_id='cg_'||id::text,credit_evidence=credit_request||jsonb_build_object('id','cg_'||id::text),credited_at=clock_timestamp() WHERE id=$1 AND $2::jsonb IS NOT NULL`,
			} {
				if _, err = f.h.Pool.Exec(t.Context(), q, id, request); err != nil {
					t.Fatal(err)
				}
			}
			var valid bool
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT pro_invoice_cash_source_valid($1,$2)`, f.invoice.ID, invoiceSettlementHash(f.invoice)).Scan(&valid); err != nil || valid != tc.valid {
				t.Fatalf("component proof valid=%v, want %v (%v)", valid, tc.valid, err)
			}
		})
	}
}

func TestPrepaidFundedSubscriptionBuysCreditAndKeepsPlan(t *testing.T) {
	f, contract := fundedSubscriptionFixture(t, nil)
	assignStarterAfterPurchase = settlePrepaidPlan
	f.issueIncludedGrant(contract)
	before, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil {
		t.Fatal(err)
	}
	balance := func() int64 {
		t.Helper()
		total, _, _, _, _, err := f.h.observeProviderFundingGrants(t.Context(), f.client, f.team, f.customer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return total
	}
	start := balance()
	id, actor := uuid.New(), uuid.New()
	// A second click with the same operation records nothing new.
	for range 2 {
		if err = f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 500, ""); err != nil {
			t.Fatal(err)
		}
	}
	f.exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',amount_cents,'customer',customer_id) WHERE id=$1`, id)
	for range 2 {
		if err = f.h.settlePrepaidPurchase(t.Context(), f.client, id); err != nil {
			t.Fatal(err)
		}
	}
	if r := f.rows(); len(r) != 1 || r[0].Source != "checkout" || r[0].Amount != 500 || r[0].Credit != "issued" || len(f.grantPosts) != 1 {
		t.Fatalf("one purchase was not credited exactly once: %+v posts=%d", r, len(f.grantPosts))
	}
	if got := balance(); got != start+500 {
		t.Fatal("purchased credit not observed", start, got)
	}
	after, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || after.ID != before.ID || !after.prepaidFunded() {
		t.Fatal("credit purchase replaced the funded subscription", after, err)
	}
	var starter bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND idempotency_key=$2)`, f.team, "prepaid-plan:v1:"+id.String()).Scan(&starter); err != nil || starter {
		t.Fatal("credit purchase assigned Starter", starter, err)
	}
}

func TestPrepaidPostpaidSubscriptionCannotBuyCredit(t *testing.T) {
	f := newPrepaidFixture(t)
	if _, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("pro", planKindSubscription, 1, nil), Source: planSourceStaff, Reason: "postpaid fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.recordCheckoutPurchase(t.Context(), uuid.New(), f.team, f.customer, uuid.New(), 500, ""); !errors.Is(err, errPlanCannotBuyCredit) {
		t.Fatal("postpaid subscription was allowed to buy credit", err)
	}
}
