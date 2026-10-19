//go:build integration

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestSponsoredIssuanceDebtRecoveryAndPlan(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	f.paymentUnavailable.Store(true)
	f.debt.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if f.grants.Load() != 0 {
		t.Fatal("debt authorized sponsored credit")
	}
	f.debt.Store(false)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("lost response should be uncertain")
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: "metered_usage"})
	if err != nil || e.State != "issued" || e.AmountCents != 3000000 || e.PaymentID.Valid || e.WaiverID.Valid || !e.SponsorshipID.Valid || f.grants.Load() != 1 {
		t.Fatalf("wrong sponsored authority or retry: %+v %v", e, err)
	}
	if _, err = f.h.DB.GetCurrentCommercialPlan(t.Context(), f.c.TeamID); err != pgx.ErrNoRows {
		t.Fatal("sponsorship changed plan", err)
	}
	var payments int
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1`, f.c.ID).Scan(&payments); err != nil || payments != 0 {
		t.Fatal("sponsorship created paid evidence", payments, err)
	}
	var later int64
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT p.amount_cents FROM billing_commercial_contract c CROSS JOIN LATERAL billing_contract_entitlement(c,billing_anniversary_boundary(c.entitlement_anchor,3)) p WHERE c.id=$1`, f.c.ID).Scan(&later); err != nil || later != 100000 {
		t.Fatal("phase transition", later, err)
	}
}
func TestSponsoredRevocationPreservesUnknownGrant(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
		t.Fatal("expected lost response")
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE contract_id=$1`, f.c.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: "metered_usage"})
	if err != nil || e.State != "issued" || !e.PeriodEnd.Equal(f.end) || f.grants.Load() != 1 {
		t.Fatal("revocation lost or duplicated grant", e, err)
	}
	var allowed bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT billing_contract_eligible(c,$2,$3) FROM billing_commercial_contract c WHERE id=$1`, f.c.ID, f.start, f.end).Scan(&allowed); err != nil || allowed {
		t.Fatal("revocation authorized new issuance", allowed, err)
	}
}
func TestSponsoredRevocationBeforeDispatch(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE contract_id=$1`, f.c.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if f.grants.Load() != 0 {
		t.Fatal("revoked sponsorship dispatched")
	}
}
func TestSponsoredEligibilityConfirmedExpiryAndConflicts(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.h.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE billing_funding_policy SET max_observed_teams=100 WHERE singleton`)
	t.Cleanup(func() {
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, f.c.TeamID)
		_, _ = f.h.Pool.Exec(context.Background(), `UPDATE billing_funding_policy SET max_observed_teams=4 WHERE singleton`)
	})
	exec(`UPDATE billing_funding_account SET observe=true,enforce=true WHERE team_id=$1`, f.c.TeamID)
	refresh := func(amount int) {
		exec(`UPDATE billing_funding_account SET observed_generation=generation,customer_id=$2,subscription_id=$3,credit_usd=$4,credit_valid_until=now()+interval '1 minute' WHERE team_id=$1`, f.c.TeamID, f.c.CustomerID, f.c.SubscriptionID, amount)
	}
	eligible := func(want bool) {
		t.Helper()
		got, err := f.h.DB.IsTeamSandboxBillingEligible(ctx, f.c.TeamID)
		if err != nil || got != want {
			t.Fatal("eligibility", got, want, err)
		}
	}
	refresh(100)
	eligible(false)
	if _, err := f.h.reconcileUsageEntitlement(ctx, f.c.ID); err != nil {
		t.Fatal(err)
	}
	refresh(100)
	eligible(true)
	refresh(0)
	eligible(false)
	refresh(100)
	exec(`UPDATE billing_funding_account SET credit_valid_until=$2 WHERE team_id=$1`, f.c.TeamID, time.Now().Add(-time.Minute))
	eligible(false)
	if _, err := f.h.Pool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=clock_timestamp() WHERE team_id=$1`, f.c.TeamID); err == nil {
		t.Fatal("checkout bypassed sponsorship fence")
	}
	if _, err := f.h.Pool.Exec(ctx, `UPDATE billing_sponsored_operation SET reason='rewritten' WHERE contract_id=$1`, f.c.ID); err == nil {
		t.Fatal("audit terms were mutable")
	}
}

func TestSponsoredCanceledPendingDoesNotPoisonInvoice(t *testing.T) {
	at := time.Now().UTC().Add(5*time.Minute).AddDate(-4, 0, 0).Truncate(time.Second)
	f := newEntitlementFixtureAt(t, at, false, false, false, false, true)
	ctx := t.Context()
	if f.end.Sub(time.Now()) > 10*time.Minute {
		t.Fatal("fixture must approach its closing boundary")
	}
	_, err := f.h.Pool.Exec(ctx, `UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),collection_valid_until=clock_timestamp()+interval '1 minute',collection_evidence=jsonb_build_object('gate','finalized_invoice_gate_v1','period_start',$2::timestamptz,'period_end',$3::timestamptz),revision=revision+1 WHERE id=$1`, f.c.ID, f.start, f.end)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.DB.ClaimCurrentUsageEntitlement(ctx, db.ClaimCurrentUsageEntitlementParams{TeamID: f.c.TeamID, ContractID: f.c.ID}); err != nil {
		t.Fatal(err)
	}
	token := uuid.New()
	if _, err = f.h.Pool.Exec(ctx, `UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE contract_id=$1`, f.c.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(ctx, `UPDATE billing_entitlement_work SET lease_token=$2,lease_until=clock_timestamp()+interval '1 minute' WHERE contract_id=$1`, f.c.ID, token); err != nil {
		t.Fatal(err)
	}
	if err = f.h.processEntitlementJob(ctx, entitlementJob{Contract: f.c.ID, Token: token}); err != nil {
		t.Fatal(err)
	}
	var poisoned bool
	if err = f.h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_entitlement_withheld WHERE contract_id=$1 AND platform_failure_at IS NOT NULL) OR EXISTS(SELECT 1 FROM billing_entitlement_work WHERE contract_id=$1 AND alerted_at IS NOT NULL)`, f.c.ID).Scan(&poisoned); err != nil || poisoned || f.grants.Load() != 0 {
		t.Fatal("canceled grant poisoned closing invoice", poisoned, err)
	}
}

func TestSponsoredExpirationReleasesContract(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	h.Config = &config.Config{TeamCreationRegion: "use"}
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := h.Pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	op, contract := uuid.New(), uuid.New()
	customer, sub := "cus_"+team.String(), "sub_"+team.String()
	now := time.Now().UTC()
	start := time.Date(now.Year()-2, now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(1, 0, 0)
	exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, team, customer, sub, start)
	exec(`INSERT INTO billing_sponsored_operation(id,team_id,contract_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id,anchor,starts_at,ends_at) VALUES($1,$2,$3,'past','{}','{}',$4,'fixture','fixture',$5,$6,$7,$7,$8)`, op, team, contract, uuid.New(), customer, sub, start, end)
	exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_kind,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'sponsored_usage',$3,$4,$5,$6,'','sponsored_entitlement',0,1,'metered_usage',100,'scheduled',$3)`, contract, team, start, end, customer, sub)
	exec(`INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,100 FROM generate_series(0,11) m`, team, contract)
	exec(`UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, contract)
	exec(`UPDATE billing_sponsored_operation SET state='active' WHERE id=$1`, op)
	if e := h.reconcileSponsored(ctx, op); e != nil {
		t.Fatal(e)
	}
	var closed bool
	if e := h.Pool.QueryRow(ctx, `SELECT c.status='ended' AND o.state='expired' AND c.ends_at=$2 AND o.ends_at=$2 FROM billing_commercial_contract c JOIN billing_sponsored_operation o ON o.contract_id=c.id WHERE c.id=$1`, contract, end).Scan(&closed); e != nil || !closed {
		t.Fatal("expiry did not retain history and release authority", closed, e)
	}
	if e := h.sponsoredLocalPreflight(ctx, h.Pool, team); e != nil {
		t.Fatal("expired sponsorship blocks successor", e)
	}
}

func TestSponsoredSuccessorCannotRewriteIssuedCreditScope(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	ctx := t.Context()
	if _, err := f.h.reconcileUsageEntitlement(ctx, f.c.ID); err != nil {
		t.Fatal(err)
	}
	var prior uuid.UUID
	if err := f.h.Pool.QueryRow(ctx, `SELECT id FROM billing_sponsored_operation WHERE contract_id=$1`, f.c.ID).Scan(&prior); err != nil {
		t.Fatal(err)
	}
	f.h.Config.TeamCreationRegion = "use"
	if _, err := f.h.Pool.Exec(ctx, `UPDATE team SET home_region='use' WHERE id=$1`, f.c.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Pool.Exec(ctx, `UPDATE billing_sponsored_operation SET revoked_at=clock_timestamp(),revoked_by=$2,state='revoking' WHERE id=$1`, prior, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := f.h.reconcileSponsored(ctx, prior); err != nil {
		t.Fatal(err)
	}
	// The issued grant still covers a period whose invoice has not closed.
	var outstanding bool
	if err := f.h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE contract_id=$1 AND state='issued' AND NOT EXISTS(SELECT 1 FROM billing_invoice_close i WHERE i.team_id=e.team_id AND i.period_start=e.period_start AND i.period_end=e.period_end AND i.state='released'))`, f.c.ID).Scan(&outstanding); err != nil || !outstanding {
		t.Fatal("missing historical obligation", outstanding, err)
	}
	_, err := f.h.Pool.Exec(ctx, `INSERT INTO billing_sponsored_operation(team_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id) SELECT team_id,'replacement','{}',jsonb_set(resource_terms,'{ResourceTerms,0,PriceID}','"price_changed"'),approved_by,'fixture','fixture',customer_id,subscription_id FROM billing_sponsored_operation WHERE id=$1`, prior)
	if err == nil || !strings.Contains(err.Error(), "resource terms conflict with historical sponsorship") {
		t.Fatal("successor reinterpreted predecessor credit/invoice", err)
	}
}

func TestSponsoredExpirationWaitsForDatabaseBoundary(t *testing.T) {
	f := newEntitlementFixture(t, false, false, false, false, true)
	var id uuid.UUID
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_sponsored_operation WHERE contract_id=$1`, f.c.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	o, err := f.h.sponsoredOperation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the expiration path as an ahead-of-database API clock would.
	if err = f.h.expireSponsorship(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	var active bool
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT o.state='active' AND c.status='active' FROM billing_sponsored_operation o JOIN billing_commercial_contract c ON c.id=o.contract_id WHERE o.id=$1`, id).Scan(&active); err != nil || !active {
		t.Fatal("premature terminal transition", active, err)
	}
}
