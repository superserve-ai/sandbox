//go:build integration

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

// newPrepaidRollFixture is a Developer team on a prepaid-funded subscription
// whose previous period ended rolledAgo ago. That period's monthly grant was
// issued, the next one is not, and its funding is observed with no credit.
// It reuses the sponsored roll helpers; only the funding source differs.
func newPrepaidRollFixture(t *testing.T, rolledAgo time.Duration) *sponsoredRollFixture {
	t.Helper()
	at := time.Now().UTC().Add(-rolledAgo).Truncate(time.Second)
	f := &sponsoredRollFixture{entitlementFixture: newEntitlementFixtureAt(t, at), t: t}
	ctx := t.Context()
	anchor := priorAnniversaryAnchor(f.start)
	f.prior, _, _ = billing.AnniversaryPeriod(anchor, f.start.Add(-time.Second))
	withoutTriggers(t, f.h, func(conn db.DBTX) {
		grant := "credgr_prior_" + f.c.ID.String()
		invoice := "in_prior_fee_" + f.c.TeamID.String()
		for _, step := range []struct {
			q    string
			args []any
		}{
			{`UPDATE billing_commercial_contract SET starts_at=$2,entitlement_anchor=$2 WHERE id=$1`, []any{f.c.ID, anchor}},
			{`UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, []any{f.c.TeamID, anchor}},
			{`UPDATE billing_invoice_account SET enrolled_at=$2 WHERE team_id=$1`, []any{f.c.TeamID, f.prior}},
			{`INSERT INTO billing_contract_payment(team_id,contract_id,invoice_id,payment_reference,customer_id,subscription_id,base_price_id,service_period_start,service_period_end,base_amount_paid_cents,invoice_amount_paid_cents,invoice_amount_remaining_cents,currency,paid_at,verified_at,evidence)
 VALUES($1,$2,$3,$3,$4,$5,'price_base',$6,$7,$8,$8,0,'usd',$6,$6,'{"paid":true}')`, []any{f.c.TeamID, f.c.ID, invoice, f.c.CustomerID, f.c.SubscriptionID, f.prior, f.start, f.c.ChargeAmountCents}},
			{`INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency,state,first_attempt_at,request_payload,provider_invoice_start,provider_invoice_end,stripe_credit_grant_id,issuance_evidence,issued_at)
 SELECT $1,$2,id,'metered_usage',$4,$5,100000,'usd','issued',$4,'{}',$4,$5,$6,'{"fixture":true}',$4 FROM billing_contract_payment WHERE contract_id=$2 AND invoice_id=$3`, []any{f.c.TeamID, f.c.ID, invoice, f.prior, f.start, grant}},
			{`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',$3,0,0,0)`, []any{f.c.TeamID, f.prior, f.start}},
			{`INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$2,$3,$6)`, []any{f.c.TeamID, f.prior, f.start, f.c.CustomerID, f.c.SubscriptionID, anchor.Unix()}},
		} {
			if _, err := conn.Exec(ctx, step.q, step.args...); err != nil {
				t.Fatal(err)
			}
		}
	})
	terms := (&prepaidFixture{t: t, h: f.h}).publishFundedPlan(&planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true}, false)
	if _, err := assignInTx(t, f.h, planAssignment{Team: f.c.TeamID, Terms: terms, Source: planSourceCheckout, Reason: "prepaid roll fixture", ContractID: &f.c.ID}); err != nil {
		t.Fatal(err)
	}
	enforcePrepaidFunding(t, f.entitlementFixture)
	observePrepaidCredit(t, f.entitlementFixture, 0)
	return f
}

// withoutTriggers runs fixture writes for history that predates this test's clock.
func withoutTriggers(t *testing.T, h *Handlers, write func(db.DBTX)) {
	t.Helper()
	conn, err := h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(context.WithoutCancel(t.Context()), `RESET session_replication_role`)
	write(conn)
}

func enforcePrepaidFunding(t *testing.T, f *entitlementFixture) {
	t.Helper()
	var budget int32
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT max_observed_teams FROM billing_funding_policy WHERE singleton`).Scan(&budget); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_funding_policy SET max_observed_teams=greatest(max_observed_teams,100) WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false,prepaid=false WHERE team_id=$1`, f.c.TeamID)
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=$1 WHERE singleton`, budget)
	})
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_funding_account SET observe=true,enforce=true,prepaid=true WHERE team_id=$1`, f.c.TeamID); err != nil {
		t.Fatal(err)
	}
}

// observePrepaidCredit publishes a successful credit read, as the funding worker would.
func observePrepaidCredit(t *testing.T, f *entitlementFixture, creditUSD int) {
	t.Helper()
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_funding_account SET observed_generation=generation,customer_id=$2,subscription_id=$3,credit_usd=$4,credit_valid_until=now()+interval '1 minute',credit_checked_at=clock_timestamp(),payment_method_ready=true,collection_ready=true,provider_valid_until=now()+interval '1 minute' WHERE team_id=$1`, f.c.TeamID, f.c.CustomerID, f.c.SubscriptionID, creditUSD); err != nil {
		t.Fatal(err)
	}
}

func TestPrepaidRenewalRollStaysEligible(t *testing.T) {
	cases := []struct {
		name      string
		rolledAgo time.Duration
		change    func(f *sponsoredRollFixture)
		credit    int
		eligible  bool
	}{
		{"observed credit keeps it", 7 * time.Hour, func(*sponsoredRollFixture) {}, 10, true},
		{"two hours after the roll keeps it", 2 * time.Hour, func(*sponsoredRollFixture) {}, 0, true},
		{"platform failure keeps it", 2 * time.Hour, func(f *sponsoredRollFixture) {
			f.exec(`INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence,platform_failure_at) VALUES($1,$2,$3,'{}',clock_timestamp())`, f.c.ID, f.start, f.end)
		}, 0, true},
		{"unpaid invoice ends it", 2 * time.Hour, func(f *sponsoredRollFixture) {
			f.exec(`INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence) VALUES($1,$2,$3,'{"unpaid_invoice":"in_unpaid"}')`, f.c.ID, f.start, f.end)
		}, 0, false},
		{"debt ends it", 2 * time.Hour, func(f *sponsoredRollFixture) {
			f.exec(`INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,'in_unpaid')`, f.c.ID, f.start)
		}, 0, false},
		{"contract ending at the roll ends it", 2 * time.Hour, func(f *sponsoredRollFixture) {
			withoutTriggers(f.t, f.h, func(conn db.DBTX) {
				if _, err := conn.Exec(f.t.Context(), `UPDATE billing_commercial_contract SET ends_at=$2 WHERE id=$1`, f.c.ID, f.start); err != nil {
					f.t.Fatal(err)
				}
			})
		}, 0, false},
		{"six hours ends it", 7 * time.Hour, func(*sponsoredRollFixture) {}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrepaidRollFixture(t, tc.rolledAgo)
			tc.change(f)
			observePrepaidCredit(t, f.entitlementFixture, tc.credit)
			if got := f.eligible(); got != tc.eligible {
				t.Fatalf("eligible = %v, want %v", got, tc.eligible)
			}
		})
	}
}

func (f *sponsoredRollFixture) issueNextGrant() {
	f.t.Helper()
	f.releasePriorClose()
	if _, err := f.h.reconcileUsageEntitlement(f.t.Context(), f.c.ID); err != nil || f.grants.Load() != 1 {
		f.t.Fatal("next grant not issued", err, f.grants.Load())
	}
}

func (f *sponsoredRollFixture) publishCredit(credit *fundingCreditObservation, workErr error) {
	f.t.Helper()
	j, s := claimFundingTestJob(f.t, f.h, f.c.TeamID)
	if err := f.h.publishFundingObservation(f.t.Context(), j, s, credit, nil, workErr); err != nil {
		f.t.Fatal(err)
	}
}

func TestPrepaidRenewalRollGraceLastsUntilIssuedGrantIsRead(t *testing.T) {
	f := newPrepaidRollFixture(t, 2*time.Hour)
	f.issueNextGrant()
	if !f.eligible() {
		t.Fatal("team paused before the issued grant was observed")
	}
	f.publishCredit(nil, errors.New("provider temporarily unavailable"))
	if !f.eligible() {
		t.Fatal("failed credit read ended the grace")
	}
}

func TestPrepaidRenewalRollEndsOnSuccessfulCreditRead(t *testing.T) {
	f := newPrepaidRollFixture(t, 2*time.Hour)
	f.issueNextGrant()
	f.publishCredit(&fundingCreditObservation{SpendableUSD: "1000", ValidUntil: time.Now().Add(time.Minute), Evidence: []byte(`{"fixture":"credit"}`)}, nil)
	if !f.eligible() {
		t.Fatal("observed next grant left the team paused")
	}
	f.publishCredit(&fundingCreditObservation{SpendableUSD: "0", ValidUntil: time.Now().Add(time.Minute), Evidence: []byte(`{"fixture":"credit"}`)}, nil)
	if f.eligible() {
		t.Fatal("grace outlived a successful read showing no credit")
	}
}

// firstRenewalFixture is a new-cohort Developer team whose first paid month
// came from a first-cycle upgrade that ended rolledAgo ago. Its bridge grant
// expired with that month and its recurring contract, which starts at the
// month's end, still waits for the held renewal invoice to be paid.
type firstRenewalFixture struct {
	*prepaidFixture
	contract db.BillingCommercialContract
	upgrade  uuid.UUID
	anchor   time.Time
	start    time.Time
	end      time.Time
}

func newFirstRenewalFixture(t *testing.T, rolledAgo time.Duration) *firstRenewalFixture {
	t.Helper()
	p := newPrepaidFixture(t)
	f := &firstRenewalFixture{prepaidFixture: p, upgrade: uuid.New(), end: time.Now().UTC().Add(-rolledAgo).Truncate(time.Second)}
	f.anchor = priorAnniversaryAnchor(f.end)
	f.start, _, _ = billing.AnniversaryPeriod(f.anchor, f.end.Add(-time.Second))
	ctx := t.Context()
	terms := p.publishFundedPlan(&planTopoff{AmountCents: 1500, ThresholdCents: 1000, DefaultEnabled: true}, false)
	p.exec(`UPDATE team_billing_account SET commercial_billing_anchor=$2,trial_ended_at=$3 WHERE team_id=$1`, p.team, f.anchor, f.start)
	var err error
	f.contract, err = p.h.DB.CreateCommercialContract(ctx, db.CreateCommercialContractParams{TeamID: p.team, OfferKey: terms.OfferKey, StartsAt: f.end, CustomerID: p.customer, SubscriptionID: p.sub, BasePriceID: "price_developer", ChargeAmountCents: terms.FeeCents, ChargeIntervalMonths: 1, EntitlementKind: "metered_usage", EntitlementAmountCents: terms.MonthlyCreditCents, EntitlementCadence: "monthly", EntitlementAnchor: f.anchor})
	if err != nil {
		t.Fatal(err)
	}
	grant := "credgr_bridge_" + f.upgrade.String()
	p.exec(`INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,bridge_credit_cents,state,session_id,payment_evidence,payment_method_id,grant_id,grant_attempted_at,contract_id)
 VALUES($1,$2,$3,$4,$5,$6,jsonb_build_object('FirstPaidProCycle',true,'BasePriceID','price_developer'),$14,$7,$8,$7,$9,$10,'active',$11,'{"fixture":true}','pm_saved',$12,$7,$13)`,
		f.upgrade, p.team, uuid.New(), p.customer, p.sub, terms.OfferKey, f.start, f.end, terms.FeeCents, terms.MonthlyCreditCents, "cs_"+f.upgrade.String(), grant, f.contract.ID, f.anchor)
	p.exec(`INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at,observed_at) VALUES($1,$2,'{"fixture":true}',$3,$4,$5)`, p.customer, grant, f.start.Unix(), f.end.Unix()+1, f.start)
	if _, err = assignInTx(t, p.h, planAssignment{Team: p.team, Terms: terms, Source: planSourceCheckout, Reason: "first-cycle Developer fixture", ContractID: &f.contract.ID}); err != nil {
		t.Fatal(err)
	}
	p.exec(`UPDATE billing_funding_account SET enforce=true,prepaid=true WHERE team_id=$1`, p.team)
	p.observe(0, true)
	return f
}

func TestPrepaidFirstRenewalRollStaysEligible(t *testing.T) {
	cases := []struct {
		name      string
		rolledAgo time.Duration
		change    func(f *firstRenewalFixture)
		credit    int64
		eligible  bool
	}{
		{"observed credit keeps it", 7 * time.Hour, func(*firstRenewalFixture) {}, 1000, true},
		{"two hours after the first roll keeps it", 2 * time.Hour, func(*firstRenewalFixture) {}, 0, true},
		{"six hours ends it", 7 * time.Hour, func(*firstRenewalFixture) {}, 0, false},
		{"ended upgrade ends it", 2 * time.Hour, func(f *firstRenewalFixture) {
			f.exec(`UPDATE billing_pro_upgrade SET state='ended' WHERE id=$1`, f.upgrade)
		}, 0, false},
		{"ended contract ends it", 2 * time.Hour, func(f *firstRenewalFixture) {
			f.exec(`UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1`, f.contract.ID)
		}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFirstRenewalFixture(t, tc.rolledAgo)
			tc.change(f)
			f.observe(tc.credit, true)
			if got := f.eligible(); got != tc.eligible {
				t.Fatalf("eligible = %v, want %v", got, tc.eligible)
			}
		})
	}
}

func TestPrepaidFirstRenewalRollEndsOnSuccessfulCreditRead(t *testing.T) {
	f := newFirstRenewalFixture(t, 2*time.Hour)
	ctx := t.Context()
	_, next, _ := billing.AnniversaryPeriod(f.anchor, f.end)
	payment, err := f.h.DB.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: f.team, ContractID: f.contract.ID, InvoiceID: "in_renewal_" + f.team.String(), PaymentReference: "pay_" + uuid.NewString(), CustomerID: f.customer, SubscriptionID: &f.sub, BasePriceID: "price_developer", ServicePeriodStart: f.end, ServicePeriodEnd: next, BaseAmountPaidCents: f.contract.ChargeAmountCents, InvoiceAmountPaidCents: f.contract.ChargeAmountCents, Currency: "usd", PaidAt: time.Now(), Evidence: []byte(`{"paid":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.DB.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: f.team, ContractID: f.contract.ID, ExpectedRevision: f.contract.Revision}); err != nil {
		t.Fatal(err)
	}
	withoutTriggers(t, f.h, func(conn db.DBTX) {
		if _, err := conn.Exec(ctx, `INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency,state,first_attempt_at,request_payload,provider_invoice_start,provider_invoice_end,stripe_credit_grant_id,issuance_evidence,issued_at)
 VALUES($1,$2,$3,'metered_usage',$4,$5,$6,'usd','issued',clock_timestamp(),'{}',$4,$5,$7,'{"fixture":true}',clock_timestamp())`, f.team, f.contract.ID, payment.ID, f.end, next, f.contract.EntitlementAmountCents, "credgr_next_"+f.contract.ID.String()); err != nil {
			t.Fatal(err)
		}
	})
	f.exec(`UPDATE billing_funding_account SET generation=generation+1 WHERE team_id=$1`, f.team)
	f.observe(f.contract.EntitlementAmountCents, true)
	if !f.eligible() {
		t.Fatal("observed first monthly grant left the team paused")
	}
	f.observe(0, true)
	if f.eligible() {
		t.Fatal("grace outlived a successful read showing no credit")
	}
}

func TestPrepaidRenewalRollGraceHoldsAutoRecharge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rolledAgo time.Duration
		want      int
	}{
		{"in the grace", 2 * time.Hour, 0},
		{"after the grace", 7 * time.Hour, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrepaidRollFixture(t, tc.rolledAgo)
			f.exec(`INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,threshold_cents,amount_cents) VALUES($1,true,1000,1500)`, f.c.TeamID)
			f.exec(`UPDATE billing_funding_account SET payment_method_id='pm_saved' WHERE team_id=$1`, f.c.TeamID)
			observePrepaidCredit(t, f.entitlementFixture, 0)
			if err := f.h.recordAutoRecharges(t.Context()); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1 AND source='auto_recharge'`, f.c.TeamID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != tc.want {
				t.Fatalf("automatic recharges = %d, want %d", n, tc.want)
			}
		})
	}
}
