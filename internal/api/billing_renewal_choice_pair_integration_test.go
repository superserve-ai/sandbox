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
)

// This exercises the real activation/binding schema and read-only renewal
// inspector. It does not stand in for shared financial-authority finalization.
func newRenewalActivatedPairFixture(t *testing.T, anchor time.Time) (*pgxpool.Pool, *pairFixture, *stripeHTTPClient, renewalChoiceKey, renewalChoiceOperation) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("DATABASE_URL must name a migrated disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f := newPairFixture(t)
	f.p.Anchor = anchor
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
	client := f.client(t)
	verified, err := client.verifyInitialProviderPair(t.Context(), f.p)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO team(id,name,home_region) VALUES($1,$2,'use')`, f.p.Identity.TeamID, "renewal-"+uuid.NewString())
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true)`, f.p.Identity.TeamID)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,$2,$3,$4)`, f.p.Identity.TeamID, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor)
	rates := []map[string]string{}
	for _, r := range f.p.Terms.Resources {
		rates = append(rates, map[string]string{"resource": r.ResourceKey, "plan_key": "payg", "currency": "USD", "unit": "second", "price_usd": "0.00001"})
	}
	raw, _ := json.Marshal(rates)
	exec(`INSERT INTO billing_commercial_offer_assignment(id,team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,resource_rates,request,assigned_by,reason,reference)
 VALUES($1,$2,$3,'example-company','use','yc_2026',1,'initial','payg',$4,clock_timestamp(),$5,'{}',$6,'fixture','fixture')`, f.p.Identity.AssignmentID, f.p.Identity.TeamID, uuid.New(), []uuid.UUID{uuid.New()}, raw, uuid.New())
	b, err := ActivateInitialProviderPair(t.Context(), tx, uuid.New(), verified)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	k, loaded, err := loadRenewalChoicePair(t.Context(), pool, b.Identity.TeamID, b.Identity.AssignmentID)
	if err != nil || loaded.ContractID != b.ContractID || !k.Boundary.Equal(annualBoundary(f.p.Anchor, 12)) {
		t.Fatal("original activation did not bind renewal", loaded, err)
	}
	terms, err := loadRenewalChoiceTerms(t.Context(), pool, "annual", 1, b.Terms)
	if err != nil {
		t.Fatal(err)
	}
	op := renewalChoiceOperation{ID: uuid.New(), Binding: renewalChoiceBindingFromPair(b), Terms: terms, Request: renewalChoiceRequest{Choice: "annual"}}
	store := postgresRenewalChoiceStore{Pool: pool}
	if err = store.Transact(t.Context(), k, func(tx renewalChoiceTransaction) error { return tx.Save("inspector_fixture") }); err != nil {
		t.Fatal(err)
	}
	return pool, f, client, k, op
}

func TestRenewalChoiceInspectorUsesActivatedPair(t *testing.T) {
	pool, f, client, k, op := newRenewalActivatedPairFixture(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	verifier := &stripeRenewalScheduleVerifier{Pool: pool, Client: client}
	proof, err := verifier.ObserveChoice(t.Context(), k, op)
	if err != nil || proof.Outcome != "confirmed" || proof.Timing != "future_configuration" {
		t.Fatal("verified original annual pair unavailable", proof, err)
	}
	f.fee.Discounts = []string{"di_waiver"}
	if _, err = verifier.Inspect(t.Context(), k, op); err != nil {
		t.Fatal("original once waiver rejected", err)
	}
	f.fee.Discounts = []string{"di_foreign_recurring"}
	if _, err = verifier.ObserveChoice(t.Context(), k, op); err == nil {
		t.Fatal("foreign recurring discount confirmed Annual")
	}
	f.fee.Discounts = nil
	f.fee.Schedule = "sub_sched_foreign"
	if _, err = verifier.Inspect(t.Context(), k, op); err == nil {
		t.Fatal("foreign schedule treated as owned")
	}
	f.fee.Schedule = ""
	f.truncated = true
	if _, err = verifier.Inspect(t.Context(), k, op); err == nil {
		t.Fatal("truncated inventory confirmed Annual")
	}
	f.truncated = false
	foreign := k
	foreign.Team = uuid.New()
	if _, err = verifier.Inspect(t.Context(), foreign, op); err == nil {
		t.Fatal("pair crossed customer isolation")
	}
}

func TestRenewalChoicePublishedCatalogMapping(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("migrated composition database not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires loopback migrated test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	mapping := newPairFixture(t).p.Terms
	annual, err := loadRenewalChoiceTerms(t.Context(), pool, "annual", 1, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if annual.Offer != "pro_annual" || annual.Amount != 1200000 || len(annual.Allowances) != 12 {
		t.Fatal(annual)
	}
	mapping.FeeAmount = 120000
	mapping.FeeMonths = 1
	mapping.FeePriceID = "price_monthly_fixture"
	monthly, err := loadRenewalChoiceTerms(t.Context(), pool, "monthly", 1, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if monthly.Amount != 120000 || len(monthly.Allowances) != 1 || monthly.Allowances[0] != 100000 || monthly.Price != mapping.FeePriceID {
		t.Fatal(monthly)
	}
	mapping.FeeAmount++
	if _, err = loadRenewalChoiceTerms(t.Context(), pool, "monthly", 1, mapping); err == nil {
		t.Fatal("provider price economics differed from published version")
	}
	mapping.FeeAmount--
	if _, err = loadRenewalChoiceTerms(t.Context(), pool, "monthly", 2, mapping); err == nil {
		t.Fatal("unpublished version resolved")
	}
}
