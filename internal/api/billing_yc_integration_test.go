//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestYCRenewedUsageRequiresUnquestionedCurrentReceipt(t *testing.T) {
	for _, failure := range []string{"refund", "dispute"} {
		t.Run(failure, func(t *testing.T) {
			f := newEntitlementFixture(t, true)
			ctx := t.Context()
			if _, err := f.h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, f.c.TeamID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.h.Pool.Exec(ctx, `INSERT INTO billing_yc_operation(team_id,renewal_contract_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,state,payment_method_ready,payment_method_checked_at) VALUES($1,$2,'operator','fixture',jsonb_build_object('company_identity',$1::uuid::text),'{}',$3,$4,'renewed',true,clock_timestamp())`, f.c.TeamID, f.c.ID, f.c.CustomerID, f.c.SubscriptionID); err != nil {
				t.Fatal(err)
			}
			assertEligible := func(want bool) {
				t.Helper()
				got, err := f.h.DB.IsTeamSandboxBillingEligible(ctx, f.c.TeamID)
				if err != nil || got != want {
					t.Fatalf("renewed usage eligible=%v want=%v: %v", got, want, err)
				}
			}
			assertEligible(false)
			client := f.h.Stripe.(*stripeHTTPClient)
			invoice := "in_paid_" + f.c.TeamID.String()
			offer := proOffer{Key: "pro_annual", Price: "price_base", Amount: 1200000, Months: 12}
			receipt, paid, err := client.verifyProInvoice(ctx, invoice, offer, f.c.CustomerID, f.c.SubscriptionID)
			if err != nil || !paid {
				t.Fatal("valid renewal receipt rejected", err)
			}
			if err = f.h.observeProPaymentReview(ctx, f.c.TeamID, invoice, receipt, nil); err != nil {
				t.Fatal(err)
			}
			assertEligible(true)
			f.paymentRefunded.Store(failure == "refund")
			f.paymentDisputed.Store(failure == "dispute")
			receipt, _, err = client.verifyProInvoice(ctx, invoice, offer, f.c.CustomerID, f.c.SubscriptionID)
			if err == nil {
				t.Fatal("questioned renewal receipt accepted")
			}
			if err = f.h.observeProPaymentReview(ctx, f.c.TeamID, invoice, receipt, err); err != nil {
				t.Fatal(err)
			}
			assertEligible(false)
		})
	}
}

func TestYCWaiverActivationAndMonthlyAuthority(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := db.New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, offset := range []int{0, 2, 3, 11} {
		t.Run(time.Month(offset+1).String(), func(t *testing.T) {
			team, err := q.CreateTeam(t.Context(), "yc-fixture-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			anchor := time.Date(time.Now().UTC().Year(), time.Now().UTC().Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -offset, 0)
			end := anchor.AddDate(1, 0, 0)
			customer, sub := "cus_"+uuid.NewString(), "sub_"+uuid.NewString()
			op, contract := uuid.New(), uuid.New()
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team.ID, customer, sub, anchor)
			exec(`INSERT INTO billing_yc_operation(id,team_id,contract_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,starts_at,ends_at,state) VALUES($1,$2,$3,'operator','manual-review',jsonb_build_object('company_identity',$1::uuid::text),'{}',$4,$5,$6,$7,'enrolling')`, op, team.ID, contract, customer, sub, anchor, end)
			exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'yc_2026',$3,$4,$5,$6,'price_annual',1200000,12,'metered_usage',100000,'scheduled',$3)`, contract, team.ID, anchor, end, customer, sub)
			exec(`INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,CASE WHEN m<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) m`, team.ID, contract)
			exec(`INSERT INTO billing_contract_waiver(id,team_id,contract_id,offer_key,offer_version,customer_id,subscription_id,starts_at,ends_at,collectible_base_cents) VALUES($1,$2,$3,'yc_2026',1,$4,$5,$6,$7,0)`, op, team.ID, contract, customer, sub, anchor, end)
			_, err = q.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: team.ID, ContractID: contract, ExpectedRevision: 0})
			if err == nil {
				t.Fatal("activated without payment method")
			}
			eligible, err := q.IsTeamSandboxBillingEligible(t.Context(), team.ID)
			if err != nil || eligible {
				t.Fatalf("usage before card: %v %v", eligible, err)
			}
			exec(`UPDATE billing_yc_operation SET payment_method_ready=true,payment_method_checked_at=clock_timestamp() WHERE id=$1`, op)
			c, err := q.ActivateCommercialContract(t.Context(), db.ActivateCommercialContractParams{TeamID: team.ID, ContractID: contract, ExpectedRevision: 0})
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE billing_yc_operation SET state='active' WHERE id=$1`, op)
			eligible, err = q.IsTeamSandboxBillingEligible(t.Context(), team.ID)
			if err != nil || !eligible {
				t.Fatalf("usage after card: %v %v", eligible, err)
			}
			var receipts int
			if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1`, contract).Scan(&receipts); err != nil || receipts != 0 {
				t.Fatalf("fabricated receipts: %d %v", receipts, err)
			}
			start := anchor.AddDate(0, offset, 0)
			periodEnd := start.AddDate(0, 1, 0)
			evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": start, "period_end": periodEnd})
			var observed time.Time
			if err = pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			c, err = q.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{TeamID: team.ID, ContractID: contract, ExpectedRevision: c.Revision, HasOverdueBalance: new(bool), CheckedAt: pgtype.Timestamptz{Time: observed, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: observed.Add(30 * time.Second), Valid: true}, Evidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			e, err := q.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: team.ID, ContractID: contract})
			if err != nil {
				t.Fatal(err)
			}
			want := int64(100000)
			if offset < 3 {
				want = 3000000
			}
			if e.AmountCents != want || (!e.WaiverID.Valid || uuid.UUID(e.WaiverID.Bytes) != op) {
				t.Fatalf("wrong entitlement authority or amount: %+v", e)
			}
			if _, err = q.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: team.ID, ContractID: contract}); err == nil {
				t.Fatal("duplicate entitlement")
			}
			exec(`UPDATE billing_yc_operation SET revoked_at=clock_timestamp(),revoked_by='operator' WHERE id=$1`, op)
			var canIssue bool
			if err = pool.QueryRow(t.Context(), `SELECT billing_contract_eligible(c,$2,$3) FROM billing_commercial_contract c WHERE id=$1`, contract, start, periodEnd).Scan(&canIssue); err != nil || canIssue {
				t.Fatalf("new grant after revocation: %v %v", canIssue, err)
			}
			var count int
			if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_usage_entitlement WHERE id=$1 AND amount_cents=$2`, e.ID, want).Scan(&count); err != nil || count != 1 {
				t.Fatal("revocation erased entitlement history", err)
			}
			var limits int
			if err = pool.QueryRow(t.Context(), `SELECT max_sandboxes FROM team WHERE id=$1`, team.ID).Scan(&limits); err != nil || limits != 1000 {
				t.Fatal("YC product limits unavailable", limits, err)
			}
		})
	}
}

// The isolated regional test database also hosts the shared-auth fixture.
// Production uses a separate pool and an RPC-only connection role.
func ensureYCTestAuthority(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF; IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF; END $$`); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('public.yc_company_activation_authority') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		return
	}
	if _, err := pool.Exec(t.Context(), `DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy') THEN CREATE ROLE promotion_evidence_proxy; END IF; END $$; GRANT USAGE ON SCHEMA public TO promotion_evidence_proxy`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../supabase/shared-auth-migrations/20261016070000_yc_company_activation_authority.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated`); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(t.Context(), `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM anon,authenticated`)
	if _, err = pool.Exec(t.Context(), string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestYCSharedIssuerRecovery(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	f.lost.Store(true)
	_, _ = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID)
	f.h.PromotionAuthPool = nil // A confirmed provider success can recover during shared Auth outage.
	for i := 0; i < 4; i++ {
		_, _ = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID)
	}
	e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: "metered_usage"})
	if err != nil || e.State != "issued" || e.AmountCents != 3000000 || !e.WaiverID.Valid || e.PaymentID.Valid {
		t.Fatalf("YC recovery: %+v %v", e, err)
	}
	if f.grants.Load() != 1 {
		t.Fatalf("duplicate grants: %d", f.grants.Load())
	}
}

func TestYCGlobalRevocationPreventsProviderDispatch(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	_, err := f.h.PromotionAuthPool.Exec(t.Context(), `SELECT public.revoke_yc_activation_authority(id,team_id,$2) FROM billing_yc_operation WHERE team_id=$1`, f.c.TeamID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID)
	}
	if f.grants.Load() != 0 {
		t.Fatal("provider grant after global revocation")
	}
}

func TestYCGlobalReservationRPCOnly(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL ROLE promotion_evidence_proxy`); err != nil {
		t.Fatal(err)
	}
	company := "https://www.ycombinator.com/companies/test-" + uuid.NewString()
	team, actor := uuid.New(), uuid.New()
	var id, again uuid.UUID
	query := `SELECT approval_id FROM public.reserve_yc_activation_authority($1,$2,'test',$3,'operator','manual',NULL)`
	if err = tx.QueryRow(t.Context(), query, company, team, actor).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(t.Context(), query, company, team, actor).Scan(&again); err != nil || id != again {
		t.Fatal("reservation retry differs", err)
	}
	if _, err = tx.Exec(t.Context(), `SELECT * FROM public.yc_company_activation_authority`); err == nil {
		t.Fatal("proxy has direct authority table access")
	}
}

func TestYCGlobalRevocationFencesDispatch(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	o, err := f.h.ycOperation(t.Context(), f.c.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	release, err := f.h.lockYCAuthority(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	_, err = f.h.PromotionAuthPool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, o.ID, o.Team, uuid.New())
	cancel()
	release()
	if err == nil {
		t.Fatal("revocation crossed dispatch lock")
	}
	if _, err = f.h.PromotionAuthPool.Exec(t.Context(), `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, o.ID, o.Team, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if release, err = f.h.lockYCAuthority(t.Context(), o); err == nil {
		release()
		t.Fatal("dispatch allowed after revocation")
	}
}

func TestYCSharedAuthorityProductionPoolCapacity(t *testing.T) {
	fixtures := []*entitlementFixture{}
	for i := 0; i < 4; i++ {
		fixtures = append(fixtures, newEntitlementFixture(t, true, true))
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 4)
	for _, f := range fixtures {
		f.h.PromotionAuthPool = pool
		go func() { _, err := f.h.reconcileUsageEntitlement(ctx, f.c.ID); done <- err }()
	}
	for range fixtures {
		if err := <-done; err != nil {
			t.Fatal("production-sized authority pool stalled", err)
		}
	}
	for _, f := range fixtures {
		if f.grants.Load() != 1 {
			t.Fatal("missing dispatch")
		}
	}
}

func TestYCSharedAuthorityRejectsPublicRoles(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	for _, role := range []string{"anon", "authenticated"} {
		for _, signature := range []string{"read_yc_activation_authority(text,uuid)", "reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid)", "revoke_yc_activation_authority(uuid,uuid,uuid)", "lock_yc_activation_authority(uuid,uuid,text)"} {
			var allowed bool
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT has_function_privilege($1,$2,'EXECUTE')`, role, "public."+signature).Scan(&allowed); err != nil || allowed {
				t.Fatalf("public authority RPC %s %s: %v %v", role, signature, allowed, err)
			}
		}
	}
}

func TestYCCancellationIntentRecovery(t *testing.T) {
	f := newEntitlementFixture(t, true, true)
	o, err := f.h.ycOperation(t.Context(), f.c.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	sub, _, _ := ycTestSubscription()
	sub.ID = o.Subscription
	sub.Customer = o.Customer
	sub.StartDate = o.Start.Time.Unix()
	sub.BillingCycleAnchor = sub.StartDate
	sub.CancelAtPeriodEnd = true
	sub.CanceledAt = time.Now().Unix()
	keys := []string{}
	lose := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			_ = r.ParseForm()
			if r.Form.Get("cancel_at") != fmt.Sprint(o.End.Time.Unix()) || r.Form.Get("proration_behavior") != "none" {
				t.Error("wrong cancellation boundary")
			}
			sub.CancelAtPeriodEnd = false
			sub.CancelAt = o.End.Time.Unix()
			if lose {
				lose = false
				http.Error(w, "response lost", 503)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(sub)
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	if _, err = f.h.normalizeYCCancellation(t.Context(), o, sub, client); err != nil {
		t.Fatal(err)
	}
	// A separate cancel action after resuming must not reuse the earlier key.
	sub.CancelAt = 0
	sub.CancelAtPeriodEnd = true
	sub.CanceledAt++
	lose = true
	if _, err = f.h.normalizeYCCancellation(t.Context(), o, sub, client); err == nil {
		t.Fatal("expected lost response")
	}
	if _, err = f.h.normalizeYCCancellation(t.Context(), o, sub, client); err != nil {
		t.Fatal("lost response recovery", err)
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatal("cancellation generations reused", keys)
	}
}
