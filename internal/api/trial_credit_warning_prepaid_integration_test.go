//go:build integration

package api

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

type countingCreditWarningSender struct {
	mu        sync.Mutex
	remaining []float64
}

func (s *countingCreditWarningSender) SendTrialCreditWarning(_ context.Context, _ uuid.UUID, remaining float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remaining = append(s.remaining, remaining)
	return nil
}

func (s *countingCreditWarningSender) sent() []float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.remaining)
}

// lowCreditFixture is a prepaid-funded subscription with a configured
// low-credit level above its top-off threshold, so tests see which one
// messaging uses. Fixture values are arbitrary.
func lowCreditFixture(t *testing.T) (*prepaidFixture, uuid.UUID) {
	t.Helper()
	f, contract := fundedSubscriptionFixture(t, &planTopoff{AmountCents: 1500, ThresholdCents: 500, DefaultEnabled: true})
	f.exec(`UPDATE billing_funding_policy SET low_credit_warning_cents=1000 WHERE singleton`)
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET low_credit_warning_cents=DEFAULT WHERE singleton`)
	})
	return f, contract
}

func TestPrepaidLowCreditWarningOnlyWithAutoTopoffOff(t *testing.T) {
	f, contract := lowCreditFixture(t)
	sender := &countingCreditWarningSender{}
	f.h.TrialWarningSender = sender
	discovered := func() bool {
		t.Helper()
		teams, err := f.h.DB.ListTrialCreditWarningTeams(t.Context(), db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(teams, f.team)
	}
	process := func() {
		t.Helper()
		for range 2 {
			f.h.processTrialCreditWarning(t.Context(), f.team)
		}
	}

	f.observe(500, true)
	process()
	if discovered() || len(sender.sent()) != 0 {
		t.Fatal("warned before the period's included grant was issued")
	}
	f.issueIncludedGrant(contract)
	process()
	if discovered() || len(sender.sent()) != 0 {
		t.Fatal("warned on a reading taken before the included grant was issued")
	}

	if err := f.applyTopoff("cs_"+uuid.NewString(), true); err != nil {
		t.Fatal(err)
	}
	f.observe(500, true)
	process()
	if discovered() || len(sender.sent()) != 0 {
		t.Fatal("warned a team whose Auto Topoff is on")
	}
	b, err := f.h.DB.GetTeamTrialBalance(t.Context(), f.team)
	if err != nil || b.Kind != creditWarningPrepaid || b.State != "auto_topoff" || b.Eligible {
		t.Fatalf("balance with Auto Topoff on = %+v, %v", b, err)
	}

	f.exec(`UPDATE billing_prepaid_auto_recharge SET enabled=false,disabled_reason='card declined',disabled_at=clock_timestamp() WHERE team_id=$1`, f.team)
	f.observe(1000, true)
	process()
	if discovered() || len(sender.sent()) != 0 {
		t.Fatal("warned at the low-credit level")
	}
	f.observe(999, true)
	if !discovered() {
		t.Fatal("low balance with Auto Topoff off was not discovered")
	}
	process()
	if got := sender.sent(); len(got) != 1 || got[0] != 9.99 {
		t.Fatalf("low-credit warnings = %v, want one quoting the balance", got)
	}
	if discovered() {
		t.Fatal("a warned balance stays in discovery")
	}

	f.rawExec(`INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,payment_state,payment_idempotency_key,payment_first_attempt_at,
  paid_at,payment_evidence,credit_state,credit_idempotency_key,credit_request,credit_first_attempt_at,stripe_credit_grant_id,credit_evidence,credited_at)
 VALUES($1,$2,'auto_recharge',1500,'succeeded',gen_random_uuid()::text,clock_timestamp(),clock_timestamp(),'{}','issued',gen_random_uuid()::text,'{}',clock_timestamp(),
  'cg_'||gen_random_uuid(),'{}',clock_timestamp())`, f.team, f.customer)
	process()
	if got := sender.sent(); len(got) != 1 {
		t.Fatalf("warned again on a reading taken before the top-off: %v", got)
	}
	f.observe(800, true)
	process()
	if got := sender.sent(); len(got) != 2 || got[1] != 8 {
		t.Fatalf("warnings after a top-off = %v, want the warning re-armed once", got)
	}

	f.rawExec(`UPDATE billing_usage_entitlement SET period_end=clock_timestamp() WHERE team_id=$1`, f.team)
	f.rawExec(`INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency,state,
  first_attempt_at,request_payload,provider_invoice_start,provider_invoice_end,stripe_credit_grant_id,issuance_evidence,issued_at)
 SELECT team_id,contract_id,gen_random_uuid(),kind,period_end,period_end+interval '30 days',amount_cents,currency,'issued',
  clock_timestamp(),'{}',period_end,period_end+interval '1 hour','cg_'||gen_random_uuid(),'{"fixture":true}',clock_timestamp()
 FROM billing_usage_entitlement WHERE team_id=$1`, f.team)
	f.observe(700, true)
	process()
	if got := sender.sent(); len(got) != 3 || got[2] != 7 {
		t.Fatalf("warnings after a new period's grant = %v, want the warning re-armed once", got)
	}
}

func (f *prepaidFixture) lowCreditWarnings(sender *countingCreditWarningSender) (discovered bool, sent int) {
	f.t.Helper()
	teams, err := f.h.DB.ListTrialCreditWarningTeams(f.t.Context(), db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
	if err != nil {
		f.t.Fatal(err)
	}
	f.h.processTrialCreditWarning(f.t.Context(), f.team)
	return slices.Contains(teams, f.team), len(sender.sent())
}

func TestPrepaidLowCreditWarningUsesFirstCycleUpgradeGrant(t *testing.T) {
	f, contract := lowCreditFixture(t)
	sender := &countingCreditWarningSender{}
	f.h.TrialWarningSender = sender
	grant := "cg_" + uuid.NewString()
	f.rawExec(`INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence,grant_id,contract_id)
 VALUES(gen_random_uuid(),$1,gen_random_uuid(),$2,'funded_monthly','{}',now(),now()-interval '1 hour',now()+interval '29 days',now(),700,'credited','{}',$3,$4)`, f.team, f.customer, grant, contract)
	f.rawExec(`INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at,observed_at)
 VALUES($1,$2,'{}',extract(epoch FROM now())::bigint,extract(epoch FROM now()+interval '29 days')::bigint,clock_timestamp())`, f.customer, grant)
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); !discovered || sent != 1 {
		t.Fatalf("month-one balance below the low-credit level: discovered=%v warnings=%d", discovered, sent)
	}
}

func TestPrepaidLowCreditWarningStopsWaitingForAMissingGrant(t *testing.T) {
	f, _ := lowCreditFixture(t)
	sender := &countingCreditWarningSender{}
	f.h.TrialWarningSender = sender
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); discovered || sent != 0 {
		t.Fatal("warned within the grace for the period's grant")
	}
	f.exec(`UPDATE billing_funding_policy SET low_credit_grant_grace=interval '1 millisecond' WHERE singleton`)
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET low_credit_grant_grace=DEFAULT WHERE singleton`)
	})
	f.rawExec(`INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,payment_state,payment_idempotency_key,payment_first_attempt_at,
  paid_at,payment_evidence,credit_state,credit_idempotency_key,credit_request)
 VALUES($1,$2,'auto_recharge',1500,'succeeded',gen_random_uuid()::text,clock_timestamp(),clock_timestamp(),'{}','pending',gen_random_uuid()::text,'{}')`, f.team, f.customer)
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); discovered || sent != 0 {
		t.Fatal("warned while a paid top-off was still being credited")
	}
	f.rawExec(`UPDATE billing_prepaid_purchase SET payment_state='failed',paid_at=NULL,payment_evidence=NULL,failure_reason='fixture',credit_state='none',credit_request=NULL WHERE team_id=$1`, f.team)
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); !discovered || sent != 1 {
		t.Fatalf("a period whose grant never landed stayed silent: discovered=%v warnings=%d", discovered, sent)
	}
}

func TestPrepaidLowCreditWarningWaitsForRenewalCollection(t *testing.T) {
	f, contract := lowCreditFixture(t)
	sender := &countingCreditWarningSender{}
	f.h.TrialWarningSender = sender
	invoice := "in_" + uuid.NewString()
	f.rawExec(`UPDATE team_plan_assignment SET effective_from=now()-interval '31 days' WHERE team_id=$1 AND effective_to IS NULL`, f.team)
	f.rawExec(`INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency,state,
  first_attempt_at,request_payload,provider_invoice_start,provider_invoice_end,stripe_credit_grant_id,issuance_evidence,issued_at)
 VALUES($1,$2,gen_random_uuid(),'metered_usage',date_trunc('second',now())-interval '31 days',date_trunc('second',now())-interval '2 hours',700,'usd','issued',
  now()-interval '31 days','{}',now()-interval '31 days',now()-interval '30 days','cg_'||gen_random_uuid(),'{"fixture":true}',now()-interval '31 days')`, f.team, contract)
	f.rawExec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state)
 SELECT team_id,period_start,period_end,$2,'{}','released' FROM billing_usage_entitlement WHERE team_id=$1`, f.team, invoice)
	f.rawExec(`INSERT INTO billing_invoice_collection(invoice_id,customer_id,subscription_id,livemode,settlement_hash,idempotency_key,payment_authorized,state)
 VALUES($1,$2,$3,false,'fixture',$1,true,'processing')`, invoice, f.customer, f.sub)
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); discovered || sent != 0 {
		t.Fatal("warned while the renewal invoice was still being collected")
	}
	f.rawExec(`UPDATE billing_invoice_collection SET state='requires_payment_method' WHERE invoice_id=$1`, invoice)
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); !discovered || sent != 1 {
		t.Fatalf("a failed renewal stayed silent: discovered=%v warnings=%d", discovered, sent)
	}
}

func TestPrepaidLowCreditWarningRearmsWhenAnOlderTopoffSettlesLater(t *testing.T) {
	f, contract := lowCreditFixture(t)
	f.issueIncludedGrant(contract)
	sender := &countingCreditWarningSender{}
	f.h.TrialWarningSender = sender
	issued := func(createdAgo string) {
		t.Helper()
		f.rawExec(`INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,payment_state,payment_idempotency_key,payment_first_attempt_at,
  paid_at,payment_evidence,credit_state,credit_idempotency_key,credit_request,credit_first_attempt_at,stripe_credit_grant_id,credit_evidence,credited_at,created_at)
 VALUES($1,$2,'auto_recharge',1500,'succeeded',gen_random_uuid()::text,clock_timestamp(),clock_timestamp(),'{}','issued',gen_random_uuid()::text,'{}',clock_timestamp(),
  'cg_'||gen_random_uuid(),'{}',clock_timestamp(),clock_timestamp()-$3::interval)`, f.team, f.customer, createdAgo)
	}
	issued("0 seconds")
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); !discovered || sent != 1 {
		t.Fatalf("low balance after the first top-off: discovered=%v warnings=%d", discovered, sent)
	}
	issued("1 hour")
	f.observe(500, true)
	if discovered, sent := f.lowCreditWarnings(sender); !discovered || sent != 2 {
		t.Fatalf("an older top-off that settled later did not re-arm the warning: discovered=%v warnings=%d", discovered, sent)
	}
}

// rawExec writes payment, credit and grant history directly; how they are
// settled is outside what these tests exercise.
func (f *prepaidFixture) rawExec(sql string, args ...any) {
	f.t.Helper()
	conn, err := f.h.Pool.Acquire(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(f.t.Context(), `SET session_replication_role=replica`); err != nil {
		f.t.Fatal(err)
	}
	defer conn.Exec(context.WithoutCancel(f.t.Context()), `RESET session_replication_role`)
	if _, err = conn.Exec(f.t.Context(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func TestPrepaidSummaryUnobservedBalanceIsNotLow(t *testing.T) {
	f := newPrepaidFixture(t)
	summary := func() (observed, low bool) {
		t.Helper()
		raw, err := f.h.prepaidSummary(t.Context(), f.team, 0)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Observed bool `json:"balance_observed"`
			Low      bool `json:"low_balance"`
		}
		if err = json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s.Observed, s.Low
	}
	f.observe(100, true)
	if observed, low := summary(); !observed || !low {
		t.Fatal("a fresh low balance is not reported as observed and low")
	}
	f.exec(`UPDATE billing_funding_account SET credit_valid_until=clock_timestamp()-interval '1 second' WHERE team_id=$1`, f.team)
	if observed, low := summary(); observed || low {
		t.Fatal("a stale balance is reported as observed or low")
	}
}

func TestPrepaidSummaryLowBalanceUsesConfiguredLevel(t *testing.T) {
	f, contract := lowCreditFixture(t)
	f.issueIncludedGrant(contract)
	low := func() bool {
		t.Helper()
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
	f.observe(999, true)
	if !low() {
		t.Fatal("a balance below the configured level is not low")
	}
	f.observe(1000, true)
	if low() {
		t.Fatal("a balance at the configured level is low")
	}
}
