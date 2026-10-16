//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func commercialTime(at time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: at, Valid: true}
}

func commercialNow(t *testing.T) time.Time {
	t.Helper()
	var now time.Time
	if err := testPool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

func commercialFixture(t *testing.T, annual bool) db.BillingCommercialContract {
	t.Helper()
	team, err := testQueries.CreateTeam(t.Context(), "commercial-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
	now := commercialNow(t)
	anchor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	interval, price, offer := int32(1), int64(120000), "pro_monthly"
	if annual {
		anchor = anchor.AddDate(0, -3, 0)
		interval, price, offer = 12, 1200000, "pro_annual"
	}
	correctionExec(t, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team.ID, customer, subscription, anchor)
	c, err := testQueries.CreateCommercialContract(t.Context(), db.CreateCommercialContractParams{
		TeamID: team.ID, OfferKey: offer, StartsAt: anchor, CustomerID: customer, SubscriptionID: subscription,
		BasePriceID: "price_base", ChargeAmountCents: price, ChargeIntervalMonths: interval,
		EntitlementKind: "metered_usage", EntitlementAmountCents: 100000, EntitlementCadence: "monthly", EntitlementAnchor: anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func commercialPayment(t *testing.T, c db.BillingCommercialContract) db.RecordCommercialBasePaymentParams {
	return db.RecordCommercialBasePaymentParams{
		TeamID: c.TeamID, ContractID: c.ID, InvoiceID: "in_" + uuid.NewString(), PaymentReference: "pay_" + uuid.NewString(),
		CustomerID: c.CustomerID, SubscriptionID: &c.SubscriptionID, BasePriceID: c.BasePriceID,
		ServicePeriodStart: c.StartsAt, ServicePeriodEnd: c.StartsAt.UTC().AddDate(0, int(c.ChargeIntervalMonths), 0),
		BaseAmountPaidCents: c.ChargeAmountCents, InvoiceAmountPaidCents: c.ChargeAmountCents,
		Currency: "usd", PaidAt: c.StartsAt, VerifiedAt: commercialNow(t), Evidence: []byte(`{"verified_payment":"example"}`),
	}
}

func commercialActivate(t *testing.T, c db.BillingCommercialContract) db.BillingCommercialContract {
	t.Helper()
	if _, err := testQueries.RecordCommercialBasePayment(t.Context(), commercialPayment(t, c)); err != nil {
		t.Fatal(err)
	}
	c, err := testQueries.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{
		TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func commercialObserve(t *testing.T, c db.BillingCommercialContract, overdue bool) db.BillingCommercialContract {
	t.Helper()
	now := commercialNow(t)
	start, end, _ := billing.AnniversaryPeriod(c.EntitlementAnchor, now)
	evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": start, "period_end": end})
	correctionExec(t, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) SELECT invoice_id,false,'{"verified":true}' FROM billing_contract_payment WHERE contract_id=$1 ON CONFLICT(invoice_id) DO UPDATE SET observed_at=clock_timestamp()`, c.ID)
	c, err := testQueries.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{
		TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision, HasOverdueBalance: &overdue,
		CheckedAt: commercialTime(now), ValidUntil: commercialTime(now.Add(4 * time.Minute)), Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func commercialClaim(t *testing.T, c db.BillingCommercialContract) db.BillingUsageEntitlement {
	t.Helper()
	e, err := testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func commercialBegin(t *testing.T, c db.BillingCommercialContract, e db.BillingUsageEntitlement) db.BillingUsageEntitlement {
	t.Helper()
	commercialMap(t, c, e)
	e, err := testQueries.BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{
		TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID,
		InvoiceStart: commercialTime(e.PeriodStart), InvoiceEnd: commercialTime(e.PeriodEnd),
		Prices: []byte(`[{"id":"price_cpu"},{"id":"price_memory"},{"id":"price_storage"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func commercialMap(t *testing.T, c db.BillingCommercialContract, e db.BillingUsageEntitlement) {
	t.Helper()
	correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, c.TeamID, e.PeriodStart, e.PeriodEnd)
	correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, c.TeamID, c.CustomerID, c.SubscriptionID, c.StartsAt)
	correctionExec(t, `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$2,$3,$6)`, c.TeamID, e.PeriodStart, e.PeriodEnd, c.CustomerID, c.SubscriptionID, c.EntitlementAnchor.Unix())
}

func TestIntegration_CommercialAnniversaryBoundaries(t *testing.T) {
	for _, year := range []int{2026, 2027} {
		anchor := time.Date(year, 10, 30, 17, 23, 42, 0, time.UTC)
		for _, at := range []time.Time{anchor.Add(-time.Second), anchor, time.Date(year+1, 2, 28, 17, 23, 42, 0, time.UTC), time.Date(year+1, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(year+1, 3, 30, 17, 23, 42, 0, time.UTC)} {
			start, end, ok := billing.AnniversaryPeriod(anchor, at)
			var gotStart, gotEnd time.Time
			err := testPool.QueryRow(t.Context(), `SELECT * FROM billing_entitlement_period($1,$2)`, anchor, at).Scan(&gotStart, &gotEnd)
			if !ok {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("before anchor: %v", err)
				}
				continue
			}
			if err != nil || !start.Equal(gotStart) || !end.Equal(gotEnd) {
				t.Fatalf("at %s: got [%s,%s), want [%s,%s): %v", at, gotStart, gotEnd, start, end, err)
			}
		}
	}
	for _, at := range []string{"2026-03-10", "2026-04-07"} {
		var start, end time.Time
		if err := testPool.QueryRow(t.Context(), `SELECT * FROM billing_entitlement_period('2026-01-01Z',$1::timestamptz)`, at).Scan(&start, &end); err != nil {
			t.Fatal(err)
		}
		if start.UTC().Day() != 1 || end.UTC().Day() != 1 || end.UTC().Month() != start.UTC().Month()+1 {
			t.Fatalf("late settlement moved anniversary: %s %s", start, end)
		}
	}
}

func TestIntegration_CommercialPaymentAuthority(t *testing.T) {
	c := commercialFixture(t, true)
	if _, err := testQueries.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID}); err == nil {
		t.Fatal("activated without base payment")
	}
	for _, change := range []struct {
		name   string
		mutate func(*db.RecordCommercialBasePaymentParams)
	}{
		{"zero invoice", func(p *db.RecordCommercialBasePaymentParams) { p.BaseAmountPaidCents = 0; p.InvoiceAmountPaidCents = 0 }},
		{"overage invoice", func(p *db.RecordCommercialBasePaymentParams) { p.BaseAmountPaidCents = 10000 }},
		{"wrong customer", func(p *db.RecordCommercialBasePaymentParams) { p.CustomerID = "cus_other" }},
		{"wrong subscription", func(p *db.RecordCommercialBasePaymentParams) { v := "sub_other"; p.SubscriptionID = &v }},
		{"wrong price", func(p *db.RecordCommercialBasePaymentParams) { p.BasePriceID = "price_cpu" }},
		{"unpaid remainder", func(p *db.RecordCommercialBasePaymentParams) { p.InvoiceAmountRemainingCents = 1 }},
		{"monthly coverage for annual", func(p *db.RecordCommercialBasePaymentParams) {
			p.ServicePeriodEnd = p.ServicePeriodStart.AddDate(0, 1, 0)
		}},
		{"other team", func(p *db.RecordCommercialBasePaymentParams) { p.TeamID = uuid.New() }},
	} {
		t.Run(change.name, func(t *testing.T) {
			p := commercialPayment(t, c)
			change.mutate(&p)
			if _, err := testQueries.RecordCommercialBasePayment(t.Context(), p); err == nil {
				t.Fatal("accepted invalid payment evidence")
			}
		})
	}
	c = commercialActivate(t, c)
	if _, err := testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown collection status authorized grant: %v", err)
	}
	c = commercialObserve(t, c, false)
	e := commercialClaim(t, c)
	if e.AmountCents != 100000 || !e.PeriodEnd.Before(c.StartsAt.UTC().AddDate(1, 0, 0)) {
		t.Fatalf("annual payment did not fund monthly allowance: %+v", e)
	}
	if _, err := testQueries.GetUsageEntitlement(t.Context(), db.GetUsageEntitlementParams{TeamID: uuid.New(), EntitlementID: e.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-team entitlement read: %v", err)
	}
	if _, err := testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: uuid.New(), ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-team claim: %v", err)
	}
}

func TestIntegration_CommercialConcurrentClaims(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("claims won=%d", winners)
	}
	e, err := testQueries.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: c.TeamID, Kind: "metered_usage"})
	if err != nil {
		t.Fatal(err)
	}
	for _, shift := range []time.Duration{-time.Minute, time.Minute} {
		_, err = testPool.Exec(t.Context(), `INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, e.TeamID, e.ContractID, e.PaymentID, e.Kind, e.PeriodStart.Add(shift), e.PeriodEnd, e.AmountCents, e.Currency)
		if err == nil {
			t.Fatal("accepted shifted overlapping entitlement")
		}
	}
}

func TestIntegration_CommercialOverdueRestoration(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, true)), true)
	stale := c
	if _, err := testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("overdue claim: %v", err)
	}
	c = commercialObserve(t, c, false)
	clear := false
	if _, err := testQueries.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: stale.Revision, HasOverdueBalance: &clear, CheckedAt: commercialTime(time.Now()), ValidUntil: commercialTime(time.Now().Add(time.Minute)), Evidence: []byte(`{"stale":true}`)}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale observation overwrote state: %v", err)
	}
	e := commercialClaim(t, c)
	wantStart, wantEnd, _ := billing.AnniversaryPeriod(c.EntitlementAnchor, time.Now())
	if e.AmountCents != 100000 || !e.PeriodStart.Equal(wantStart) || !e.PeriodEnd.Equal(wantEnd) {
		t.Fatalf("incorrect restoration: %+v", e)
	}
	_, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_entitlement(team_id,contract_id,payment_id,kind,period_start,period_end,amount_cents,currency) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, e.TeamID, e.ContractID, e.PaymentID, e.Kind, e.PeriodStart.AddDate(0, -1, 0), e.PeriodStart, e.AmountCents, e.Currency)
	if err == nil {
		t.Fatal("restored a forfeited period")
	}
	if _, err = testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("restoration duplicated allowance: %v", err)
	}
	current, err := testQueries.GetCommercialContract(t.Context(), db.GetCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID})
	if err != nil || !current.StartsAt.Equal(c.StartsAt) || current.EndsAt.Valid {
		t.Fatalf("restoration changed annual term: %+v %v", current, err)
	}
	c = commercialObserve(t, c, true)
	if _, err = testQueries.BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID, InvoiceStart: commercialTime(e.PeriodStart), InvoiceEnd: commercialTime(e.PeriodEnd), Prices: []byte(`[{"id":"price_cpu"}]`)}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("overdue pending issuance: %v", err)
	}
}

func TestIntegration_CommercialIssuanceRecovery(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
	e := commercialClaim(t, c)
	e = commercialBegin(t, c, e)
	if e.State != "uncertain" || e.StripeCreditGrantID != nil || !e.FirstAttemptAt.Valid {
		t.Fatalf("missing durable uncertainty: %+v", e)
	}
	replayed, err := testQueries.GetReplayableUsageEntitlement(t.Context(), db.GetReplayableUsageEntitlementParams{TeamID: c.TeamID, EntitlementID: e.ID})
	if err != nil || replayed.IdempotencyKey != e.IdempotencyKey || string(replayed.RequestPayload) != string(e.RequestPayload) {
		t.Fatalf("replay changed identity/payload: %v", err)
	}
	for _, statement := range []string{
		`UPDATE billing_usage_entitlement SET state='pending',first_attempt_at=NULL,request_payload=NULL,provider_invoice_start=NULL,provider_invoice_end=NULL WHERE id=$1`,
		`UPDATE billing_usage_entitlement SET idempotency_key='replacement' WHERE id=$1`,
		`UPDATE billing_usage_entitlement SET request_payload=jsonb_set(request_payload,'{amount,monetary,value}','200000') WHERE id=$1`,
		`DELETE FROM billing_usage_entitlement WHERE id=$1`,
	} {
		if _, err := testPool.Exec(t.Context(), statement, e.ID); err == nil {
			t.Fatalf("allowed loss of possible Stripe success: %s", statement)
		}
	}
	var evidence map[string]any
	if err = json.Unmarshal(e.RequestPayload, &evidence); err != nil {
		t.Fatal(err)
	}
	grant := "credgr_" + uuid.NewString()
	evidence["id"] = grant
	evidence["customer"] = "cus_other"
	wrong, _ := json.Marshal(evidence)
	if _, err = testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: wrong}); err == nil {
		t.Fatal("accepted other customer's grant")
	}
	evidence["customer"] = c.CustomerID
	correct, _ := json.Marshal(evidence)
	confirmed, err := testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: correct})
	if err != nil || confirmed.State != "issued" {
		t.Fatalf("confirm issued: %v", err)
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE billing_usage_entitlement SET state='uncertain',stripe_credit_grant_id=NULL,issuance_evidence=NULL,issued_at=NULL WHERE id=$1`, e.ID); err == nil {
		t.Fatal("reopened issued allowance")
	}
	if _, err = testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("duplicate issued claim: %v", err)
	}
}

func TestIntegration_CommercialExpiredReplayWindow(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
	e := commercialBegin(t, c, commercialClaim(t, c))
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	// Age the stored attempt without waiting a day; all production guards are
	// enabled again before exercising recovery, and the fixture rolls back.
	if _, err = tx.Exec(t.Context(), `ALTER TABLE billing_usage_entitlement DISABLE TRIGGER billing_usage_entitlement_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE billing_usage_entitlement SET first_attempt_at=now()-interval '24 hours' WHERE id=$1`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `ALTER TABLE billing_usage_entitlement ENABLE TRIGGER billing_usage_entitlement_guard`); err != nil {
		t.Fatal(err)
	}
	q := testQueries.WithTx(tx)
	if _, err = q.GetReplayableUsageEntitlement(t.Context(), db.GetReplayableUsageEntitlementParams{TeamID: c.TeamID, EntitlementID: e.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("allowed unsafe replay: %v", err)
	}
	if _, err = q.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("reclaimed ambiguous grant: %v", err)
	}
	var evidence map[string]any
	json.Unmarshal(e.RequestPayload, &evidence)
	grant := "credgr_" + uuid.NewString()
	evidence["id"] = grant
	payload, _ := json.Marshal(evidence)
	if _, err = q.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: payload}); err != nil {
		t.Fatalf("could not reconcile existing provider grant: %v", err)
	}
}

func TestIntegration_CommercialPrivilegesAndFree(t *testing.T) {
	team, err := testQueries.CreateTeam(t.Context(), "payg-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = testQueries.GetCurrentCommercialContract(t.Context(), team.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("PAYG team received a fabricated commercial contract: %v", err)
	}
	correctionExec(t, `DO $$ DECLARE r text; BEGIN
        FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
            IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN',r); END IF;
        END LOOP;
    END $$`)
	pool := promotionIsolatedDatabase(t, true)
	for _, role := range []string{"anon", "authenticated"} {
		for _, table := range []string{"billing_commercial_contract", "billing_contract_payment", "billing_usage_entitlement"} {
			var exists bool
			if err = pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Fatalf("privilege fixture requires role %s before migrations", role)
			}
			var access, rls bool
			if err = pool.QueryRow(t.Context(), `SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),relrowsecurity FROM pg_class WHERE oid=$2::regclass`, role, table).Scan(&access, &rls); err != nil || access || !rls {
				t.Fatalf("%s access=%v rls=%v to %s: %v", role, access, rls, table, err)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(t.Context(), "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(t.Context(), fmt.Sprintf("INSERT INTO %s DEFAULT VALUES", pgx.Identifier{table}.Sanitize())); err == nil {
				t.Fatal("browser wrote billing state")
			}
			tx.Rollback(t.Context())
		}
	}
}

func TestIntegration_CommercialPreservesExistingAnniversaryAndHistory(t *testing.T) {
	c := commercialFixture(t, false)
	// Replace the unactivated contract on the same subscription. The paid
	// contract begins on a clipped February anniversary of the original 30th.
	_, err := testQueries.EndCommercialContract(t.Context(), db.EndCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	anchor := time.Date(2024, 10, 30, 12, 0, 0, 0, time.UTC)
	start := time.Date(2025, 2, 28, 12, 0, 0, 0, time.UTC)
	// The fixture's anchor has no exported usage and can be corrected for this scenario.
	correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, c.TeamID, anchor)
	create := db.CreateCommercialContractParams{TeamID: c.TeamID, OfferKey: "pro_monthly", StartsAt: start,
		CustomerID: c.CustomerID, SubscriptionID: c.SubscriptionID, BasePriceID: c.BasePriceID,
		ChargeAmountCents: 120000, ChargeIntervalMonths: 1, EntitlementKind: "metered_usage", EntitlementAmountCents: 100000,
		EntitlementCadence: "monthly", EntitlementAnchor: anchor}
	replacement, err := testQueries.CreateCommercialContract(t.Context(), create)
	if err != nil {
		t.Fatalf("replacement on existing anniversary/subscription: %v", err)
	}
	p := commercialPayment(t, replacement)
	p.ServicePeriodEnd = time.Date(2025, 3, 30, 12, 0, 0, 0, time.UTC)
	if _, err = testQueries.RecordCommercialBasePayment(t.Context(), p); err != nil {
		t.Fatalf("clipped-month paid coverage rejected: %v", err)
	}
	old, err := testQueries.GetCommercialContract(t.Context(), db.GetCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID})
	if err != nil || old.Status != "ended" || !old.StartsAt.Equal(c.StartsAt) {
		t.Fatalf("old terms lost: %+v %v", old, err)
	}
	if _, err = testQueries.CreateCommercialContract(t.Context(), create); err == nil {
		t.Fatal("two current contracts on one subscription")
	}
}

func TestIntegration_CommercialRejectsWrongInvoiceCalendar(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, true)), false)
	e := commercialClaim(t, c)
	commercialMap(t, c, e)
	for _, end := range []time.Time{e.PeriodEnd.AddDate(0, 1, 0), c.StartsAt.UTC().AddDate(1, 0, 0)} {
		if _, err := testQueries.BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{
			TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID, InvoiceStart: commercialTime(e.PeriodStart), InvoiceEnd: commercialTime(end), Prices: []byte(`[{"id":"price_cpu"}]`),
		}); err == nil {
			t.Fatal("froze a grant against a different invoice period")
		}
	}
	stored, err := testQueries.GetUsageEntitlement(t.Context(), db.GetUsageEntitlementParams{TeamID: c.TeamID, EntitlementID: e.ID})
	if err != nil || stored.State != "pending" || stored.FirstAttemptAt.Valid {
		t.Fatalf("failed preparation consumed issuance: %+v %v", stored, err)
	}
}

func TestIntegration_CommercialRechecksDeadlineAfterLock(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
	e := commercialClaim(t, c)
	commercialMap(t, c, e)
	checked := commercialNow(t)
	clear := false
	_, err := testQueries.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision,
		HasOverdueBalance: &clear, CheckedAt: commercialTime(checked), ValidUntil: commercialTime(checked.Add(time.Second)), Evidence: []byte(`{"deadline":"imminent"}`)})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(t.Context())
	if _, err = lock.Exec(t.Context(), `SELECT 1 FROM billing_commercial_contract WHERE id=$1 FOR UPDATE`, c.ID); err != nil {
		t.Fatal(err)
	}
	conn, err := testPool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	result := make(chan error, 1)
	go func() {
		_, err := db.New(conn).BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID, InvoiceStart: commercialTime(e.PeriodStart), InvoiceEnd: commercialTime(e.PeriodEnd), Prices: []byte(`[{"id":"price_cpu"}]`)})
		result <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = lock.QueryRow(t.Context(), `SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1`, conn.Conn().PgConn().PID()).Scan(&waiting); err == nil && waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("issuance never waited on contract lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = lock.Exec(t.Context(), `SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	if err = lock.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deadline passed during lock wait but issuance proceeded: %v", err)
	}
	stored, err := testQueries.GetUsageEntitlement(t.Context(), db.GetUsageEntitlementParams{TeamID: c.TeamID, EntitlementID: e.ID})
	if err != nil || stored.State != "pending" {
		t.Fatalf("expired observation dispatched a request: %+v %v", stored, err)
	}
}

// A standalone cash invoice must not be attributed to the continuing usage
// subscription, and the lower allowance must start on the fourth anniversary.
func TestIntegration_CommercialUpfrontScheduleAndAdoption(t *testing.T) {
	team, err := testQueries.CreateTeam(t.Context(), "scheduled-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	now := commercialNow(t)
	anchor := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, -3, -7)
	var termEnd time.Time
	if err := testPool.QueryRow(t.Context(), `SELECT billing_anniversary_boundary($1,12)`, anchor).Scan(&termEnd); err != nil {
		t.Fatal(err)
	}
	customer, subscription := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
	correctionExec(t, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team.ID, customer, subscription, anchor)
	c, err := testQueries.CreateUpfrontCommercialContract(t.Context(), db.CreateUpfrontCommercialContractParams{
		ContractID: uuid.New(), TeamID: team.ID, OfferKey: "example_prepaid", StartsAt: anchor, EndsAt: commercialTime(termEnd),
		CustomerID: customer, SubscriptionID: subscription, BasePriceID: "price_upfront", ChargeAmountCents: 10000000, ChargeIntervalMonths: 12,
		EntitlementKind: "metered_usage", EntitlementAmountCents: 3000000, EntitlementAnchor: anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := commercialPayment(t, c)
	p.ServicePeriodEnd = c.EndsAt.Time
	p.Evidence = []byte(`{"parent":null,"verified_payment":"example"}`)
	if _, err = testQueries.RecordCommercialBasePayment(t.Context(), p); err == nil {
		t.Fatal("standalone receipt accepted with subscription parent")
	}
	p.SubscriptionID = nil
	if _, err = testQueries.RecordCommercialBasePayment(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	for n, i := range []int32{0, 1, 2, 9, 10, 11, 3, 4, 5, 6, 7, 8} {
		if n == 11 {
			if _, err = testQueries.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID}); err == nil {
				t.Fatal("activated incomplete schedule")
			}
		}
		if n == 6 {
			tx, err := testPool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(t.Context(), `UPDATE billing_commercial_contract SET ends_at=billing_anniversary_boundary(entitlement_anchor,6),revision=revision+1 WHERE id=$1`, c.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = testQueries.WithTx(tx).ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: 1}); err == nil {
				t.Fatal("activated sparse schedule after term shortening")
			}
			tx.Rollback(t.Context())
		}
		amount := int64(100000)
		if i < 3 {
			amount = 3000000
		}
		if _, err = testQueries.AddCommercialEntitlementPeriod(t.Context(), db.AddCommercialEntitlementPeriodParams{TeamID: c.TeamID, ContractID: c.ID, MonthOffset: i, AmountCents: amount}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = testQueries.AddCommercialEntitlementPeriod(t.Context(), db.AddCommercialEntitlementPeriodParams{TeamID: c.TeamID, ContractID: c.ID, MonthOffset: 12, AmountCents: 100000}); err == nil {
		t.Fatal("accepted thirteenth grant")
	}
	for i := 0; i < 13; i++ {
		var amount int64
		err = testPool.QueryRow(t.Context(), `SELECT amount_cents FROM billing_contract_entitlement((SELECT c FROM billing_commercial_contract c WHERE id=$1),billing_anniversary_boundary($2,$3))`, c.ID, anchor, i).Scan(&amount)
		if i == 12 {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("offer continued past end: %v", err)
			}
			continue
		}
		want := int64(100000)
		if i < 3 {
			want = 3000000
		}
		if err != nil || amount != want {
			t.Fatalf("month %d amount %d, want %d: %v", i+1, amount, want, err)
		}
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE billing_contract_entitlement_schedule SET amount_cents=3000000 WHERE contract_id=$1 AND month_offset=3`, c.ID); err == nil {
		t.Fatal("rewrote historical schedule")
	}
	c = commercialObserve(t, c, true)
	if _, err = testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("pending adoption exposed issuance: %v", err)
	}
	e := db.BillingUsageEntitlement{TeamID: c.TeamID, ContractID: c.ID}
	if err = testPool.QueryRow(t.Context(), `SELECT period_start,period_end,amount_cents FROM billing_contract_entitlement((SELECT c FROM billing_commercial_contract c WHERE id=$1),clock_timestamp())`, c.ID).Scan(&e.PeriodStart, &e.PeriodEnd, &e.AmountCents); err != nil {
		t.Fatal(err)
	}
	if e.AmountCents != 100000 {
		t.Fatalf("fourth month received %d", e.AmountCents)
	}
	commercialMap(t, c, e)
	grant := "credgr_" + uuid.NewString()
	created := now.Add(-time.Hour).Truncate(time.Second)
	balance := int64(43210)
	evidence := map[string]any{
		"id": grant, "customer": c.CustomerID, "created": created.Unix(), "category": "promotional",
		"amount":       map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": e.AmountCents}},
		"effective_at": created.Unix(), "expires_at": e.PeriodEnd.Unix() + 1, "available_balance_cents": balance,
		"applicability_config": map[string]any{"scope": map[string]any{"prices": []map[string]string{{"id": "price_cpu"}, {"id": "price_memory"}, {"id": "price_storage"}}}},
		"metadata": map[string]string{"superserve_team_id": c.TeamID.String(), "superserve_contract_id": c.ID.String(), "superserve_offer": c.OfferKey, "superserve_contract_version": "1", "superserve_object_role": "monthly_usage_entitlement",
			"superserve_entitlement": fmt.Sprintf("%s:usage:%d:%d", c.ID, e.PeriodStart.Unix(), e.PeriodEnd.Unix()), "superserve_period_start": fmt.Sprint(e.PeriodStart.Unix()), "superserve_period_end": fmt.Sprint(e.PeriodEnd.Unix())},
	}
	payload, _ := json.Marshal(evidence)
	params := db.AdoptUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID, GrantID: &grant, Evidence: payload, ProviderCreatedAt: created, AvailableBalanceCents: balance, InvoiceStart: e.PeriodStart, InvoiceEnd: e.PeriodEnd}
	for _, field := range []string{"customer", "expires_at", "available_balance_cents", "metadata"} {
		bad := map[string]any{}
		for k, v := range evidence {
			bad[k] = v
		}
		delete(bad, field)
		params.Evidence, _ = json.Marshal(bad)
		if _, err = testQueries.AdoptUsageEntitlement(t.Context(), params); err == nil {
			t.Fatalf("adopted grant without %s", field)
		}
	}
	params.Evidence = payload
	adopted, err := testQueries.AdoptUsageEntitlement(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.IssuanceSource != "adopted" || adopted.FirstAttemptAt.Valid || len(adopted.RequestPayload) != 0 || !adopted.IssuedAt.Time.Equal(created) || *adopted.AdoptedAvailableBalanceCents != balance {
		t.Fatalf("adoption lost original state: %+v", adopted)
	}
	if _, err = testQueries.AdoptUsageEntitlement(t.Context(), params); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("adoption retry changed grant: %v", err)
	}
	c, err = testQueries.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	c = commercialObserve(t, c, false)
	e.ID = adopted.ID
	if _, err = testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("adopted allowance duplicated: %v", err)
	}
	if _, err = testQueries.BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("adopted grant entered create path: %v", err)
	}
}

func TestIntegration_CommercialImmediateIssuanceRecovery(t *testing.T) {
	c := commercialObserve(t, commercialActivate(t, commercialFixture(t, false)), false)
	e := commercialClaim(t, c)
	commercialMap(t, c, e)
	e, err := testQueries.BeginImmediateUsageEntitlementIssuance(t.Context(), db.BeginImmediateUsageEntitlementIssuanceParams{TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID, InvoiceStart: commercialTime(e.PeriodStart), InvoiceEnd: commercialTime(e.PeriodEnd), Prices: []byte(`[{"id":"price_cpu"},{"id":"price_memory"},{"id":"price_storage"},{"id":"price_round"}]`)})
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err = json.Unmarshal(e.RequestPayload, &evidence); err != nil {
		t.Fatal(err)
	}
	if _, ok := evidence["effective_at"]; ok {
		t.Fatal("immediate grant froze a timestamp that can become backdated")
	}
	// A crash before dispatch retains the request; provider confirmation may be later.
	replay, err := testQueries.GetReplayableUsageEntitlement(t.Context(), db.GetReplayableUsageEntitlementParams{TeamID: c.TeamID, EntitlementID: e.ID})
	if err != nil || replay.IdempotencyKey != e.IdempotencyKey || string(replay.RequestPayload) != string(e.RequestPayload) {
		t.Fatal("request identity changed", err)
	}
	grant := "credgr_" + uuid.NewString()
	evidence["id"] = grant
	evidence["effective_at"] = e.PeriodStart.Unix()
	raw, _ := json.Marshal(evidence)
	if _, err = testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: raw}); err == nil {
		t.Fatal("accepted credit overlapping previous invoice")
	}
	evidence["effective_at"] = commercialNow(t).Unix()
	evidence["priority"] = 0
	raw, _ = json.Marshal(evidence)
	if _, err = testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: raw}); err == nil {
		t.Fatal("accepted wrong priority")
	}
	evidence["priority"] = 50
	raw, _ = json.Marshal(evidence)
	issued, err := testQueries.ConfirmUsageEntitlementIssued(t.Context(), db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant, Evidence: raw})
	if err != nil || issued.State != "issued" {
		t.Fatal("confirmation lost provider time", err)
	}
}
func TestIntegration_CommercialLegacyDebtObservationCannotAuthorize(t *testing.T) {
	c := commercialActivate(t, commercialFixture(t, false))
	noDebt := false
	now := commercialNow(t)
	_, err := testQueries.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision, HasOverdueBalance: &noDebt, CheckedAt: commercialTime(now), ValidUntil: commercialTime(now.Add(time.Minute)), Evidence: []byte(`{"overdue":false}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = testQueries.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("legacy overdue policy authorized Pro allowance", err)
	}
}
