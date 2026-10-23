//go:build integration

package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestProviderPairInitialActivation(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("DATABASE_URL must name a migrated disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_card_waiver", true: "materializer_rollback"}[mismatch], func(t *testing.T) {
			f := newPairFixture(t)
			f.p.Anchor = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			f.fee.StartDate, f.fee.BillingCycleAnchor = f.p.Anchor.Unix(), f.p.Anchor.Unix()
			f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 12).Unix()
			f.usage.StartDate, f.usage.BillingCycleAnchor = f.p.Anchor.Unix(), f.p.Anchor.Unix()
			for i := range f.usage.Items.Data {
				f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 1).Unix()
				if i < 3 {
					f.usage.Items.Data[i].Price.UnitAmountDecimal = "3.6"
					f.p.Terms.Resources[i].UnitAmountDecimal = "3.6"
				}
			}
			f.invoice.Lines.Data[0].Period.Start, f.invoice.Lines.Data[0].Period.End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 12).Unix()
			f.p.Identity.ProviderTermsDigest, _ = f.p.Terms.Digest()
			verified, err := f.client(t).verifyInitialProviderPair(t.Context(), f.p)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO team(id,name,home_region) VALUES($1,$2,'use')`, f.p.Identity.TeamID, "pair-"+uuid.NewString())
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true)`, f.p.Identity.TeamID)
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, f.p.Identity.TeamID, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor)
			rates := []map[string]string{}
			price := "0.00001"
			if mismatch {
				price = "0.00002"
			}
			for _, resource := range f.p.Terms.Resources {
				rates = append(rates, map[string]string{"resource": resource.ResourceKey, "plan_key": "payg", "currency": "USD", "unit": "second", "price_usd": price})
			}
			raw, _ := json.Marshal(rates)
			exec(`INSERT INTO billing_commercial_offer_assignment(id,team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,resource_rates,request,assigned_by,reason,reference)
 VALUES($1,$2,$3,'example-company','use','yc_2026',1,'initial','payg',$4,clock_timestamp(),$5,'{}',$6,'fixture','fixture')`, f.p.Identity.AssignmentID, f.p.Identity.TeamID, uuid.New(), []uuid.UUID{uuid.New()}, raw, uuid.New())
			contract := uuid.New()
			attempt, err := tx.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			b, err := ActivateInitialProviderPair(t.Context(), attempt, contract, verified)
			if mismatch {
				if err == nil || !strings.Contains(err.Error(), "execution resource terms differ") {
					t.Fatalf("mismatched assignment materialized: %v", err)
				}
				_ = attempt.Rollback(t.Context())
				var count int
				if err = tx.QueryRow(t.Context(), `SELECT count(*) FROM billing_commercial_contract WHERE id=$1`, contract).Scan(&count); err != nil || count != 0 {
					t.Fatalf("failed materialization leaked activation: %d %v", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = attempt.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err = ActivateInitialProviderPair(t.Context(), tx, contract, verified); err != nil {
				t.Fatalf("activation replay: %v", err)
			}
			var periods, receipts, waivers int
			if err = tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_commercial_offer_period WHERE assignment_id=(SELECT assignment_id FROM billing_commercial_offer_activation WHERE contract_id=$1)), (SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1), (SELECT count(*) FROM billing_provider_pair_waiver WHERE contract_id=$1)`, contract).Scan(&periods, &receipts, &waivers); err != nil || periods != 12 || receipts != 0 || waivers != 1 {
				t.Fatalf("authority/materialization: periods=%d cash=%d waivers=%d err=%v", periods, receipts, waivers, err)
			}
			var eligible bool
			check := func(want bool) {
				t.Helper()
				if err = tx.QueryRow(t.Context(), `SELECT billing_contract_eligible(c,$2,$3) FROM billing_commercial_contract c WHERE id=$1`, contract, b.StartsAt, annualBoundary(b.Anchor, 1)).Scan(&eligible); err != nil || eligible != want {
					t.Fatalf("eligibility=%v want=%v err=%v", eligible, want, err)
				}
			}
			check(false) // A waiver never substitutes for the customer-wide debt check.
			exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),collection_valid_until=clock_timestamp()+interval '1 minute',collection_evidence=jsonb_build_object('gate','finalized_invoice_gate_v1','period_start',$2::timestamptz,'period_end',$3::timestamptz),revision=revision+1 WHERE id=$1`, contract, b.StartsAt, annualBoundary(b.Anchor, 1))
			check(true)
			e, err := db.New(tx).ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: f.p.Identity.TeamID, ContractID: contract})
			if err != nil || !e.PairedWaiverID.Valid || e.PaymentID.Valid || e.WaiverID.Valid || e.SponsorshipID.Valid || e.AmountCents != 3000000 {
				t.Fatalf("first period authority or allowance: %#v %v", e, err)
			}
			exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=true,collection_checked_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, contract)
			check(false)
			exec(`UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),revision=revision+1 WHERE id=$1`, contract)
			wrong := b.Identity
			wrong.OperationID = uuid.New()
			if err = RevokeProviderPairAuthority(t.Context(), tx, contract, wrong); err == nil {
				t.Fatal("different operation revoked finalized authority")
			}
			check(true)
			for range 2 {
				if err = RevokeProviderPairAuthority(t.Context(), tx, contract, b.Identity); err != nil {
					t.Fatalf("revocation replay: %v", err)
				}
			}
			check(false)
			if _, err = ActivateInitialProviderPair(t.Context(), tx, contract, verified); err == nil {
				t.Fatal("late finalizer revived revoked authority")
			}
			attempt, err = tx.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = attempt.Exec(t.Context(), `UPDATE billing_usage_entitlement SET state='uncertain',first_attempt_at=clock_timestamp() WHERE id=$1`, e.ID)
			_ = attempt.Rollback(t.Context())
			if err == nil || !strings.Contains(err.Error(), "not eligible for issuance") {
				t.Fatalf("pending grant crossed acknowledged revocation: %v", err)
			}
		})
	}
}
