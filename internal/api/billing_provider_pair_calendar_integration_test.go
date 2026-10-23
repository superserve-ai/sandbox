//go:build integration

package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func monthlyPairMappingFixture(t *testing.T, anchor time.Time) (pgx.Tx, ContractProviderBinding, *pairFixture, *Handlers) {
	return paidPairMappingFixture(t, anchor, true)
}

func paidPairMappingFixture(t *testing.T, anchor time.Time, monthly bool) (pgx.Tx, ContractProviderBinding, *pairFixture, *Handlers) {
	h, team := fundingTransitionFixture(t)
	f := newPairFixture(t)
	f.p.Identity.TeamID = team
	movePairFixture(f, anchor)
	verified, err := f.client(t).verifyInitialProviderPair(t.Context(), f.p)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(t.Context()) })
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true)`, team)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor)
	exec(`INSERT INTO billing_commercial_offer_assignment(id,team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,resource_rates,request,assigned_by,reason,reference)
 VALUES($1,$2,$3,'example-company','use','yc_2026',1,'initial','payg',$4,clock_timestamp(),'[]','{}',$5,'fixture','fixture')`, f.p.Identity.AssignmentID, team, uuid.New(), []uuid.UUID{uuid.New()}, uuid.New())
	contract := uuid.New()
	end := annualBoundary(f.p.Anchor, 12)
	exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
 VALUES($1,$2,'yc_2026',$3,$4,$5,$6,$7,1200000,12,'metered_usage',100000,'scheduled',$3)`, contract, team, f.p.Anchor, end, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Terms.FeePriceID)
	previous, err := ConfirmContractProviderBinding(t.Context(), tx, contract, verified)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1`, contract)
	next := successorPairFixture(f, previous, monthly)
	start, finish, _ := billing.AnniversaryPeriod(next.FeeAnchor, time.Now())
	if !monthly {
		m := (start.Year()-next.FeeAnchor.Year())*12 + int(start.Month()-next.FeeAnchor.Month())
		m -= m % 12
		start, finish = annualBoundary(next.FeeAnchor, m), annualBoundary(next.FeeAnchor, m+12)
	}
	f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = start.Unix(), finish.Unix()
	start, finish, _ = billing.AnniversaryPeriod(next.Anchor, time.Now())
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = start.Unix(), finish.Unix()
	}
	proof, err := f.client(t).verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID)
	if err != nil {
		t.Fatal(err)
	}
	offer := "pro_annual"
	if monthly {
		offer = "pro_monthly"
	}
	exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
 VALUES($1,$2,$8,$3,$4,$5,$6,$9,$10,'metered_usage',100000,'monthly',$7)`, next.ContractID, team, next.StartsAt, next.CustomerID, next.UsageSubscriptionID, next.Terms.FeePriceID, next.Anchor, offer, next.Terms.FeeAmount, next.Terms.FeeMonths)
	if _, err = ConfirmSuccessorProviderPair(t.Context(), tx, proof); err != nil {
		t.Fatal(err)
	}
	return tx, next, f, h
}

func recordMonthlyPairCash(t *testing.T, tx pgx.Tx, b ContractProviderBinding, f *pairFixture, offset int) db.BillingContractPayment {
	t.Helper()
	start, end := annualBoundary(b.FeeAnchor, offset), annualBoundary(b.FeeAnchor, offset+1)
	f.invoice.ID = "in_monthly_" + uuid.NewString()
	f.p.WaiverInvoiceID = f.invoice.ID
	f.invoice.Lines.Data[0].Period.Start, f.invoice.Lines.Data[0].Period.End = start.Unix(), end.Unix()
	f.invoice.Status, f.invoice.AmountPaid, f.invoice.AmountRemaining = "paid", 120000, 0
	f.invoice.StatusTransitions.PaidAt = start.Add(time.Second).Unix()
	cash, err := f.client(t).verifyProviderPairPayment(t.Context(), b, f.invoice.ID)
	if err != nil {
		t.Fatal(err)
	}
	var verifiedAt time.Time
	if err = tx.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&verifiedAt); err != nil {
		t.Fatal(err)
	}
	payment, err := db.New(tx).RecordCommercialBasePayment(t.Context(), db.RecordCommercialBasePaymentParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID, InvoiceID: cash.Invoice.ID, PaymentReference: cash.Reference, CustomerID: b.CustomerID, SubscriptionID: &b.FeeSubscriptionID, BasePriceID: b.Terms.FeePriceID, ServicePeriodStart: time.Unix(cash.Start, 0), ServicePeriodEnd: time.Unix(cash.End, 0), BaseAmountPaidCents: 120000, InvoiceAmountPaidCents: 120000, Currency: "usd", PaidAt: time.Unix(cash.Invoice.StatusTransitions.PaidAt, 0), VerifiedAt: verifiedAt, Evidence: cash.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if err = observeProPaymentReviewTx(t.Context(), tx, b.Identity.TeamID, payment.InvoiceID, cash, nil); err != nil {
		t.Fatal(err)
	}
	return payment
}

func TestProviderPairMonthlyPaymentCalendarMapping(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		anchor                       string
		offset                       int
		feeEnd, grantStart, grantEnd string
	}{
		{"leap", "2024-02-29", 0, "2025-03-28", "2025-02-28", "2025-03-29"},
		{"non_leap_february", "2023-01-31", 13, "2025-03-31", "2025-02-28", "2025-03-31"},
		{"thirty_day_month", "2024-03-31", 1, "2025-05-31", "2025-04-30", "2025-05-31"},
		{"normal", "2024-01-15", 0, "2025-02-15", "2025-01-15", "2025-02-15"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor, _ := time.Parse("2006-01-02", tc.anchor)
			tx, b, f, _ := monthlyPairMappingFixture(t, anchor)
			p := recordMonthlyPairCash(t, tx, b, f, tc.offset)
			m, err := ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, b.Identity, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if m.FeePeriodEnd.UTC().Format("2006-01-02") != tc.feeEnd || m.PeriodStart.UTC().Format("2006-01-02") != tc.grantStart || m.PeriodEnd.UTC().Format("2006-01-02") != tc.grantEnd || m.AmountCents != 100000 {
				t.Fatalf("wrong mapping: %+v", m)
			}
			again, err := ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, b.Identity, p.ID)
			if err != nil || again != m {
				t.Fatalf("replay changed mapping: %+v %v", again, err)
			}
			var actualEnd time.Time
			if err = tx.QueryRow(t.Context(), `SELECT service_period_end FROM billing_contract_payment WHERE id=$1`, p.ID).Scan(&actualEnd); err != nil || !actualEnd.Equal(m.FeePeriodEnd) {
				t.Fatal("receipt dates changed", err)
			}
			var authorized bool
			if err = tx.QueryRow(t.Context(), `SELECT billing_payment_authorizes_entitlement(c,p,$2,$3) FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE p.id=$1`, p.ID, m.PeriodStart, m.PeriodEnd).Scan(&authorized); err != nil || !authorized {
				t.Fatal("mapped period not authorized", err)
			}
			if err = tx.QueryRow(t.Context(), `SELECT billing_payment_authorizes_entitlement(c,p,$2,$3) FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE p.id=$1`, p.ID, m.PeriodEnd, annualBoundary(b.Anchor, 13+tc.offset+1)).Scan(&authorized); err != nil || authorized {
				t.Fatal("payment reused for another month", err)
			}
			bad := b.Identity
			bad.TeamID = uuid.New()
			sp, _ := tx.Begin(t.Context())
			_, err = ConfirmProviderPairMonthlyPayment(t.Context(), sp, b.ContractID, bad, p.ID)
			_ = sp.Rollback(t.Context())
			if err == nil {
				t.Fatal("cross-team authority accepted")
			}
			bad = b.Identity
			bad.OperationID = uuid.New()
			if _, err = ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, bad, p.ID); err == nil {
				t.Fatal("wrong choice operation accepted")
			}
			for _, query := range []string{
				`UPDATE billing_provider_pair_monthly_payment SET period_end=period_end+interval '1 day' WHERE payment_id=$1`,
				`DELETE FROM billing_provider_pair_monthly_payment WHERE payment_id=$1`,
				`INSERT INTO billing_provider_pair_monthly_payment SELECT payment_id,team_id,contract_id,invoice_id,fee_item_id,fee_period_start,fee_period_end,period_end,period_end+interval '1 month',amount_cents,created_at FROM billing_provider_pair_monthly_payment WHERE payment_id=$1`,
				`INSERT INTO billing_contract_payment SELECT gen_random_uuid(),team_id,contract_id,invoice_id||'_duplicate',payment_reference,customer_id,subscription_id,base_price_id,service_period_start,service_period_end,base_amount_paid_cents,invoice_amount_paid_cents,invoice_amount_remaining_cents,currency,paid_at,verified_at,evidence FROM billing_contract_payment WHERE id=$1`,
			} {
				sp, _ := tx.Begin(t.Context())
				_, err = sp.Exec(t.Context(), query, p.ID)
				_ = sp.Rollback(t.Context())
				if err == nil {
					t.Fatal("immutable or overlapping payment authority accepted")
				}
			}
		})
	}
}

func TestProviderPairMonthlyPaymentClaimGates(t *testing.T) {
	tx, b, f, _ := monthlyPairMappingFixture(t, time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC))
	start, end, _ := billing.AnniversaryPeriod(b.Anchor, time.Now())
	offset := (start.Year()-b.FeeAnchor.Year())*12 + int(start.Month()-b.FeeAnchor.Month())
	p := recordMonthlyPairCash(t, tx, b, f, offset)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Literal coverage must not bypass mandatory one-to-one authority, including
	// calendar months where fee and allowance happen to coincide.
	var authorized bool
	if err := tx.QueryRow(t.Context(), `SELECT billing_payment_authorizes_entitlement(c,p,$2,$3) FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE p.id=$1`, p.ID, start, end).Scan(&authorized); err != nil || authorized {
		t.Fatal("unmapped receipt authorized allowance", err)
	}
	sp, err := tx.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = sp.Exec(t.Context(), `UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, b.ContractID)
	_ = sp.Rollback(t.Context())
	if err == nil {
		t.Fatal("unmapped monthly payment activated contract")
	}
	if _, err := ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, b.Identity, p.ID); err != nil {
		t.Fatal(err)
	}
	// Model a review aging out without waiting a minute in the test.
	sp, err = tx.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`ALTER TABLE billing_pro_payment_verification DISABLE TRIGGER billing_pro_payment_verification_guard`, `UPDATE billing_pro_payment_verification SET observed_at=clock_timestamp()-interval '2 minutes'`, `ALTER TABLE billing_pro_payment_verification ENABLE TRIGGER billing_pro_payment_verification_guard`} {
		if _, err = sp.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	_, err = sp.Exec(t.Context(), `UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, b.ContractID)
	_ = sp.Rollback(t.Context())
	if err == nil {
		t.Fatal("stale monthly review activated contract")
	}
	exec(`UPDATE billing_pro_payment_verification SET review_required=true WHERE invoice_id=$1`, p.InvoiceID)
	sp, err = tx.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = sp.Exec(t.Context(), `UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, b.ContractID)
	_ = sp.Rollback(t.Context())
	if err == nil {
		t.Fatal("questioned monthly review activated contract")
	}
	exec(`UPDATE billing_pro_payment_verification SET review_required=false WHERE invoice_id=$1`, p.InvoiceID)
	exec(`UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, b.ContractID)
	exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),collection_valid_until=clock_timestamp()+interval '1 minute',collection_evidence=jsonb_build_object('gate','finalized_invoice_gate_v1','period_start',$2::timestamptz,'period_end',$3::timestamptz),revision=revision+1 WHERE id=$1`, b.ContractID, start, end)
	eligible := func(want bool) {
		t.Helper()
		var got bool
		if err := tx.QueryRow(t.Context(), `SELECT billing_contract_eligible(c,$2,$3) FROM billing_commercial_contract c WHERE id=$1`, b.ContractID, start, end).Scan(&got); err != nil || got != want {
			t.Fatalf("eligibility=%v want %v: %v", got, want, err)
		}
	}
	eligible(true)
	exec(`UPDATE billing_pro_payment_verification SET review_required=true WHERE invoice_id=$1`, p.InvoiceID)
	eligible(false)
	exec(`UPDATE billing_pro_payment_verification SET review_required=false WHERE invoice_id=$1`, p.InvoiceID)
	exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=true,collection_checked_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, b.ContractID)
	eligible(false)
	exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, b.ContractID)
	claim := db.ClaimCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID}
	e, err := db.New(tx).ClaimCurrentUsageEntitlement(t.Context(), claim)
	if err != nil || !e.PeriodStart.Equal(start) || !e.PeriodEnd.Equal(end) || e.AmountCents != 100000 {
		t.Fatalf("mapped claim: %+v %v", e, err)
	}
	if _, err = db.New(tx).ClaimCurrentUsageEntitlement(t.Context(), claim); err != pgx.ErrNoRows {
		t.Fatalf("duplicate claim: %v", err)
	}
	// Keep provider invoice calendar and expiry based on usage, never fee dates.
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_price_round',$4)`, b.Identity.TeamID, b.CustomerID, b.UsageSubscriptionID, b.Anchor)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, b.Identity.TeamID, start, end)
	exec(`INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$2,$3,$6)`, b.Identity.TeamID, start, end, b.CustomerID, b.UsageSubscriptionID, b.Anchor.Unix())
	issued, err := db.New(tx).BeginUsageEntitlementIssuance(t.Context(), db.BeginUsageEntitlementIssuanceParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID, EntitlementID: e.ID, InvoiceStart: pgtype.Timestamptz{Time: start, Valid: true}, InvoiceEnd: pgtype.Timestamptz{Time: end, Valid: true}, Prices: []byte(`[{"id":"price_cpu"}]`)})
	if err != nil || issued.State != "uncertain" {
		t.Fatalf("mapped issuance: %v", err)
	}
	var expires int64
	if err = tx.QueryRow(t.Context(), `SELECT (request_payload->>'expires_at')::bigint FROM billing_usage_entitlement WHERE id=$1`, e.ID).Scan(&expires); err != nil || expires != end.Unix()+1 {
		t.Fatalf("grant expiry moved off usage calendar: %d %v", expires, err)
	}
	if err = RevokeProviderPairAuthority(t.Context(), tx, b.ContractID, b.Identity); err != nil {
		t.Fatal(err)
	}
	eligible(false)
	if _, err = ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, b.Identity, p.ID); err == nil {
		t.Fatal("revoked mapping replay authorized")
	}
}
