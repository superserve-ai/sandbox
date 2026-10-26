//go:build integration

package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOfferProviderInitialEnrollmentAndFrozenFunding(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || cfg.ConnConfig.Database != "offer_composition_test" && cfg.ConnConfig.Database != "sandbox_test" {
		t.Fatal("requires local disposable composition database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	f := newPairFixture(t)
	verified, err := f.client(t).verifyInitialProviderPair(t.Context(), f.p)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	contract := uuid.New()
	exec(`INSERT INTO team(id,name,home_region) VALUES($1,$2,'use')`, f.p.Identity.TeamID, "offer-"+uuid.NewString())
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true),($1,'billing_export_enabled',true)`, f.p.Identity.TeamID)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, f.p.Identity.TeamID, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor)
	exec(`INSERT INTO billing_commercial_offer_assignment(id,team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,resource_rates,request,assigned_by,reason,reference)
 VALUES($1,$2,$3,'example-company','use','yc_2026',1,'initial','payg',$4,clock_timestamp(),'[]','{}',$5,'fixture','fixture')`, f.p.Identity.AssignmentID, f.p.Identity.TeamID, uuid.New(), []uuid.UUID{uuid.New()}, uuid.New())
	exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
 VALUES($1,$2,'yc_2026',$3,$4,$5,$6,$7,1200000,12,'metered_usage',100000,'scheduled',$3)`, contract, f.p.Identity.TeamID, f.p.Anchor, annualBoundary(f.p.Anchor, 12), f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Terms.FeePriceID)
	if _, err = ConfirmContractProviderBinding(t.Context(), tx, contract, verified); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = enrollInitialProviderPair(t.Context(), tx, contract, verified); err != nil {
			t.Fatal(err)
		}
	}
	var subscription, price string
	var complete bool
	if err = tx.QueryRow(t.Context(), `SELECT a.subscription_id,a.adjustment_price_id,e.completed_at IS NOT NULL AND a.enrolled_at=e.started_at FROM billing_invoice_account a JOIN billing_invoice_enrollment e USING(team_id) WHERE team_id=$1`, f.p.Identity.TeamID).Scan(&subscription, &price, &complete); err != nil || !complete || subscription != f.p.UsageSubscriptionID || price != f.p.Terms.Rounding.PriceID {
		t.Fatalf("wrong invoice enrollment: %s %s %v %v", subscription, price, complete, err)
	}
	prices, paired, err := fundingPairCreditResourcePrices(t.Context(), tx, f.p.Identity.TeamID, f.p.CustomerID)
	if err != nil || !paired || strings.Join(prices, ",") != "price_vcpu,price_memory_gib,price_rounding" {
		t.Fatalf("frozen scope lost: %v %v %v", prices, paired, err)
	}
	if _, paired, err = fundingPairCreditResourcePrices(t.Context(), tx, uuid.New(), f.p.CustomerID); err != nil || paired {
		t.Fatalf("cross-team binding used: %v %v", paired, err)
	}
	// Serialization cannot recreate a verifier's private seal.
	raw, _ := json.Marshal(verified)
	var unsealed VerifiedProviderPair
	_ = json.Unmarshal(raw, &unsealed)
	if err = enrollInitialProviderPair(t.Context(), tx, contract, unsealed); err == nil {
		t.Fatal("serialized proof enrolled an account")
	}
	// An existing enrollment cannot be moved to a later attempt's clock.
	exec(`UPDATE billing_invoice_enrollment SET started_at=started_at+interval '1 second' WHERE team_id=$1`, f.p.Identity.TeamID)
	if err = enrollInitialProviderPair(t.Context(), tx, contract, verified); err == nil {
		t.Fatal("changed original boundary accepted")
	}
}
