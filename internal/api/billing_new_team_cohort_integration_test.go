//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/integrationdb"
)

type newTeamCohortFixture struct {
	h                       *Handlers
	team, old, actor, epoch uuid.UUID
}

func newTeamCohortTestFixture(t *testing.T) newTeamCohortFixture {
	t.Helper()
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "cohort_api_" + uuid.NewString()[:8] + "_test"
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	system, err := integrationdb.Reset(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	f := newTeamCohortFixture{h: &Handlers{Pool: pool, DB: db.New(pool), Config: &config.Config{TeamCreationRegion: "use", SystemTeamID: system.String()}}, actor: uuid.New()}
	exec := func(s string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, s, args...); e != nil {
			t.Fatal(e)
		}
	}
	old, err := f.h.DB.CreateTeam(ctx, "old-cohort-control")
	if err != nil {
		t.Fatal(err)
	}
	f.old = old.ID
	exec(`INSERT INTO profile(id,email) VALUES($1,'cohort-api@example.invalid')`, f.actor)
	// Production runs the zero-template Free step on the catalog's Free.
	var free uuid.UUID
	if err = pool.QueryRow(ctx, `INSERT INTO billing_plan_version SELECT (jsonb_populate_record(NULL::billing_plan_version,to_jsonb(v)||jsonb_build_object(
  'id',gen_random_uuid(),'version',(SELECT max(version)+1 FROM billing_plan_version WHERE family='free'),'state','draft','max_templates',0,
  'created_by',NULL,'published_by',NULL,'published_at',NULL,'retired_by',NULL,'retired_at',NULL))).*
 FROM billing_plan_version v WHERE v.family='free' AND v.pricing_version='v2' AND v.state='published' RETURNING id`).Scan(&free); err != nil {
		t.Fatal(err)
	}
	exec(`SELECT publish_billing_plan_version($1,NULL)`, free)
	var developer uuid.UUID
	err = pool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,pricing_version,kind,public,self_serve,display_name,monthly_fee_cents,credit_schedule,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)
 VALUES('developer',1,'v2','subscription',true,true,'Developer',3100,jsonb_build_array(jsonb_build_object('start_months',0,'repeat',NULL,'every_months',1,'amount_cents',3100,'expires_after_months',1)),7,3,3072,9216,4) RETURNING id`).Scan(&developer)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT publish_billing_plan_version($1,NULL)`, developer)
	exec(`UPDATE billing_trial_policy SET credit_usd=0.07,max_sandboxes=2,max_vcpu=3,max_memory_mib=5120,max_disk_mib=9216 WHERE singleton`)
	if err = pool.QueryRow(ctx, `SELECT billing_prepare_new_team_gate('use',$1,'test','new-team API test')`, system).Scan(&f.epoch); err != nil {
		t.Fatal(err)
	}
	sha := "1111111111111111111111111111111111111111"
	var writers []map[string]any
	for _, role := range []string{"api", "workers", "console"} {
		writers = append(writers, map[string]any{"role": role, "cohort_contract": 1, "verified": true, "source_sha": sha, "reference": "local-disposable-fixture", "digest": "local-disposable-fixture"})
	}
	evidence, _ := json.Marshal(map[string]any{"region": "use", "system_team_id": system, "epoch": f.epoch, "cohort_contract": 1, "assembled_sha": sha, "schema_sha": sha, "writers": writers})
	exec(`SELECT billing_release_new_team_gate('use',$1,$2,'test','local verified test writers',$3)`, system, f.epoch, evidence)
	if err = pool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial('new-cohort-control',$1,'use','first_team')`, f.actor).Scan(&f.team); err != nil {
		t.Fatal(err)
	}
	for _, team := range []uuid.UUID{f.team, f.old} {
		exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, f.actor)
		exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, f.actor, team)
	}
	f.h.Stripe = &stripeHTTPClient{}
	return f
}

// onFree puts the trial team on Free, as teams enrolled before paid-first
// signup still are.
func (f newTeamCohortFixture) onFree(t *testing.T) {
	t.Helper()
	terms, err := f.h.planTermsForPricingVersion(t.Context(), "free", "v2")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = assignTeamPlan(t.Context(), tx, planAssignment{Team: f.team, Terms: terms, Source: planSourceStaff, Actor: &f.actor, Reason: "enrolled before paid-first signup"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (f newTeamCohortFixture) entryState(t *testing.T, team uuid.UUID) (string, bool) {
	t.Helper()
	r := gin.New()
	r.GET("/plan", func(c *gin.Context) {
		c.Set("team_id", team.String())
		c.Set("actor_id", f.actor)
		f.h.GetBillingPlan(c)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plan", nil))
	var v struct {
		Plan       *customerPlan       `json:"plan"`
		EntryState string              `json:"entry_state"`
		Checkout   customerProCheckout `json:"pro_checkout"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("billing plan response: %d %s", rec.Code, rec.Body.String())
	}
	if v.EntryState != entryActive && v.Plan != nil {
		t.Fatalf("entry state %s disagrees with plan %+v", v.EntryState, v.Plan)
	}
	return v.EntryState, v.Checkout.FirstPaidProCycle
}

func (f newTeamCohortFixture) close(t *testing.T) {
	t.Helper()
	if _, err := f.h.Pool.Exec(t.Context(), `SELECT billing_close_new_team_gate($1,'test','close new acceptance only')`, f.epoch); err != nil {
		t.Fatal(err)
	}
}

func TestNewTeamCohortCapabilitiesAreTeamScopedAndKeepClosedDisplay(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	get := func(team uuid.UUID) map[string]any {
		t.Helper()
		r := gin.New()
		r.GET("/cap", func(c *gin.Context) {
			c.Set("team_id", team.String())
			c.Set("actor_id", f.actor)
			f.h.GetBillingCapabilities(c)
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cap", nil))
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("capability response: %d %s", rec.Code, rec.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	old, newState := get(f.old), get(f.team)
	if old["pricing_version"] != "legacy" || old["fresh_entry"].(map[string]any)["pro"] != false {
		t.Fatalf("public new signup repriced old team: %+v", old)
	}
	if newState["pricing_version"] != "v2" || newState["fresh_entry"].(map[string]any)["pro"] != true {
		t.Fatal("new team missing v2 admission")
	}
	for _, v := range []map[string]any{old, newState} {
		if v["catalog"].(map[string]any)["pricing_version"] != v["pricing_version"] {
			t.Fatal("catalog/model mismatch")
		}
	}
	public, err := f.h.signupPricingState(t.Context())
	if err != nil || public.Version != "v2" || !public.EntryOpen {
		t.Fatalf("new signup catalog=%+v %v", public, err)
	}
	f.close(t)
	closed := get(f.team)
	if closed["pricing_version"] != "v2" || closed["entry_open"] != false || closed["enrollment_epoch"] != newState["enrollment_epoch"] || closed["epoch"] == newState["epoch"] {
		t.Fatal("gate closure lost immutable enrolled display")
	}
	if closed["fresh_entry"].(map[string]any)["starter"] != false || closed["actions"].(map[string]any)["recover_payment"] != true || closed["actions"].(map[string]any)["disable_auto_recharge"] != true {
		t.Fatal("closure confused fresh and retained actions")
	}
	// A query parameter cannot switch the authenticated capability to another team.
}

func TestNewTeamCohortStarterFreezesAndReplaysAcrossGateClosure(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	f.onFree(t)
	customer := "cus_local_cohort"
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, f.team, customer); err != nil {
		t.Fatal(err)
	}
	purchase := uuid.New()
	prepare := func(id uuid.UUID) error {
		tx, err := f.h.Pool.Begin(t.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(t.Context())
		if err = f.h.preparePrepaidPurchase(t.Context(), tx, id, f.team, customer, f.actor, 500); err != nil {
			return err
		}
		return tx.Commit(t.Context())
	}
	if err := prepare(purchase); err != nil {
		t.Fatal(err)
	}
	var source string
	var epoch uuid.UUID
	var snapshot []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT admission_source,admission_epoch,plan_snapshot FROM billing_prepaid_purchase WHERE id=$1`, purchase).Scan(&source, &epoch, &snapshot); err != nil {
		t.Fatal(err)
	}
	var p prepaidPurchasePlan
	if err := json.Unmarshal(snapshot, &p); err != nil {
		t.Fatal(err)
	}
	if source != "new_team" || epoch != f.epoch || p.Terms.PricingVersion != "v2" || p.Terms.Kind != "prepaid" || p.Predecessor == nil {
		t.Fatalf("unfrozen Starter admission: %s/%s/%s", source, epoch, snapshot)
	}
	f.close(t)
	if err := prepare(purchase); err != nil {
		t.Fatalf("gate close stranded accepted money: %v", err)
	}
	if err := prepare(uuid.New()); !errors.Is(err, errPricingV2Off) {
		t.Fatalf("new purchase bypassed closed gate: %v", err)
	}
	var after []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT plan_snapshot FROM billing_prepaid_purchase WHERE id=$1`, purchase).Scan(&after); err != nil || string(after) != string(snapshot) {
		t.Fatal("replay changed frozen Starter terms")
	}
}

func TestNewTeamCohortFirstProUsesFullMonthAndRetainsAcceptedQuote(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.h.Now = func() time.Time { return now }
	customer := "cus_local_pro"
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, f.team, customer); err != nil {
		t.Fatal(err)
	}
	terms, err := f.h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_local_pro", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Pricing: "v2", PricingV2: true, Limits: &terms.Limits, Grants: terms.Grants}
	params := StripeCreateCheckoutSessionParams{CustomerID: customer, OperationID: uuid.New(), ClientReferenceID: f.team.String(), BasePriceID: offer.Price, OneOffProduct: "prod_local_pro", AllowPromotionCodes: true, PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "test unavailable", 503) }))
	t.Cleanup(provider.Close)
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
	admission, err := f.h.teamPricingState(t.Context(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	quote := func() {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/quote", nil)
		f.h.createProUpgrade(c, f.team, f.actor, offer, params, admission)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("cohort quote %d %s", rec.Code, rec.Body.String())
		}
	}
	if state, first := f.entryState(t, f.team); state != entryTrial || !first {
		t.Fatalf("new team before checkout: %s first=%v", state, first)
	}
	if state, _ := f.entryState(t, f.old); state != entryActive {
		t.Fatalf("existing team entry state %s", state)
	}
	quote()
	accepted, err := f.h.proUpgrade(t.Context(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryTrial {
		t.Fatalf("open checkout entry state %s", state)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade_setup(id,upgrade_id,request_payload,created_at) VALUES(gen_random_uuid(),$1,'{}',now())`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryTrial {
		t.Fatalf("checkout needing a card ended a trial with credit left: %s", state)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE team_trial_eligibility_cache SET eligible=false WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryPaymentFailed {
		t.Fatalf("used-up trial with a checkout needing a card: %s", state)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade_setup SET state='expired' WHERE upgrade_id=$1`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	settled := accepted
	settled.Start, settled.End = accepted.Anchor, accepted.End
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(t.Context(), `UPDATE billing_pro_upgrade SET state='credited',payment_evidence='{}',grant_id='credgr_local' WHERE id=$1`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	if err = retireFirstProCycleReportingPeriods(t.Context(), tx, settled); err != nil {
		t.Fatalf("paid first month of a trial team cannot settle: %v", err)
	}
	contract := uuid.New()
	if _, err = tx.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id='sub_local',stripe_subscription_status='active',commercial_billing_anchor=$2 WHERE team_id=$1`, f.team, accepted.Anchor); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_monthly',$3,$4,'sub_local','price_local_pro',25000,1,25000,'monthly',$3)`, contract, f.team, accepted.Anchor, customer); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE billing_pro_upgrade SET contract_id=$2 WHERE id=$1`, accepted.ID, contract); err != nil {
		t.Fatal(err)
	}
	if _, err = assignTeamPlan(t.Context(), tx, planAssignment{Team: f.team, Terms: terms, Source: planSourceCheckout, Actor: &f.actor, Reason: "paid checkout", ContractID: &contract, Key: "checkout:" + contract.String()}); err != nil {
		t.Fatal(err)
	}
	if err = retireFirstProCycleReportingPeriods(t.Context(), tx, settled); err != nil {
		t.Fatalf("settlement retry after the paid plan was assigned failed: %v", err)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, end, valid := billing.AnniversaryPeriod(now, now)
	var frozen StripeCreateCheckoutSessionParams
	_ = json.Unmarshal(accepted.Payload, &frozen)
	if !valid || accepted.Amount != 25000 || accepted.bridgeCreditAmount() != 25000 || !accepted.Anchor.Equal(now) || !accepted.End.Equal(end) || !frozen.FirstPaidProCycle {
		t.Fatalf("new-team Pro was prorated or repriced: %+v", accepted)
	}
	f.close(t)
	f.h.Now = func() time.Time { return now.Add(48 * time.Hour) }
	quote()
	replay, err := f.h.proUpgrade(t.Context(), f.team)
	if err != nil || replay.ID != accepted.ID || string(replay.Payload) != string(accepted.Payload) {
		t.Fatalf("accepted quote changed after close: %+v %v", replay, err)
	}
}

func TestNewTeamCohortPaidFirstCheckoutActivatesWithoutPicker(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.h.Now = func() time.Time { return now }
	customer := "cus_local_activating"
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, f.team, customer); err != nil {
		t.Fatal(err)
	}
	terms, err := f.h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
	if err != nil {
		t.Fatal(err)
	}
	offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_local_pro", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Pricing: "v2", PricingV2: true, Limits: &terms.Limits, Grants: terms.Grants}
	params := StripeCreateCheckoutSessionParams{CustomerID: customer, OperationID: uuid.New(), ClientReferenceID: f.team.String(), BasePriceID: offer.Price, OneOffProduct: "prod_local_pro", PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants}}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "test unavailable", 503) }))
	t.Cleanup(provider.Close)
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
	admission, err := f.h.teamPricingState(t.Context(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/quote", nil)
	f.h.createProUpgrade(c, f.team, f.actor, offer, params, admission)
	accepted, err := f.h.proUpgrade(t.Context(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE team_trial_eligibility_cache SET eligible=false WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryTrialEnded {
		t.Fatalf("unpaid checkout after the trial: %s", state)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade SET state='credited',payment_evidence='{}',grant_id='credgr_local' WHERE id=$1`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO billing_pro_upgrade_setup(id,upgrade_id,request_payload,created_at) VALUES(gen_random_uuid(),$1,'{}',now())`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryPaymentFailed {
		t.Fatalf("paid checkout still needing a card hid its card setup: %s", state)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade_setup SET state='expired' WHERE upgrade_id=$1`, accepted.ID); err != nil {
		t.Fatal(err)
	}
	if state, _ := f.entryState(t, f.team); state != entryActivating {
		t.Fatalf("paid checkout awaiting its plan sent back to the picker: %s", state)
	}

	holder := uuid.New()
	if _, err = f.h.DB.ClaimStripeWebhookProcessingLease(t.Context(), db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customer, Token: holder}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.recoverProCheckoutWithin(t.Context(), f.team, false, time.Second); err == nil {
		t.Fatal("recovery behind a busy worker reported an outcome before activation")
	}
	activated := make(chan error, 1)
	go func() {
		time.Sleep(700 * time.Millisecond)
		contract := uuid.New()
		if _, e := f.h.Pool.Exec(context.Background(), `UPDATE team_billing_account SET stripe_subscription_id='sub_local',stripe_subscription_status='active',commercial_billing_anchor=$2 WHERE team_id=$1`, f.team, accepted.Anchor); e != nil {
			activated <- e
			return
		}
		_, e := f.h.Pool.Exec(context.Background(), `WITH c AS (INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_monthly',$3,$4,'sub_local','price_local_pro',25000,1,25000,'monthly',$3) RETURNING id) UPDATE billing_pro_upgrade SET state='active',contract_id=(SELECT id FROM c) WHERE id=$5`, contract, f.team, accepted.Anchor, customer, accepted.ID)
		activated <- e
	}()
	outcome, err := f.h.recoverProCheckoutWithin(t.Context(), f.team, false, 5*time.Second)
	if e := <-activated; e != nil {
		t.Fatal(e)
	}
	if err != nil || outcome != "active" {
		t.Fatalf("recovery behind a busy worker did not wait for its activation: %q %v", outcome, err)
	}
}

func TestNewTeamCohortStarterLeaseRetainsIdentityAfterClose(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_cohort_lease')`, f.team); err != nil {
		t.Fatal(err)
	}
	if err := f.h.DB.PrepareStripeCheckoutIdentity(t.Context(), db.PrepareStripeCheckoutIdentityParams{TeamID: f.team, UserID: f.actor}); err != nil {
		t.Fatal(err)
	}
	req := billingCheckoutSessionRequest{SuccessURL: "https://console.example.invalid/return", CancelURL: "https://console.example.invalid/cancel"}
	first, err := f.h.beginCohortPrepaidCheckout(t.Context(), f.team, f.actor, req, "cohort-accepted-key", uuid.New(), false)
	if err != nil || !first.CheckoutInitializingAt.Valid {
		t.Fatalf("ordinary Starter admission: %+v %v", first, err)
	}
	f.close(t)
	second, err := f.h.beginCohortPrepaidCheckout(t.Context(), f.team, f.actor, req, "cohort-accepted-key", uuid.New(), false)
	if err != nil || !second.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || derefString(second.CheckoutRequestKey) != derefString(first.CheckoutRequestKey) || derefString(second.StripeCustomerID) != derefString(first.StripeCustomerID) {
		t.Fatalf("accepted Starter lease changed after close: %+v %v", second, err)
	}
	_, err = f.h.beginCohortPrepaidCheckout(t.Context(), f.team, f.actor, req, "different-request", uuid.New(), false)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a different request stole the accepted Starter generation: %v", err)
	}
}

// The scheduler consumes an existing saved authorization. Closing signup and
// fresh settings admission must not invent a new consent or strand that one.
func TestNewTeamCohortRechargeSchedulerKeepsAcceptedConsentAfterClose(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	terms, err := f.h.planTermsForPricingVersion(t.Context(), "starter", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = assignInTx(t, f.h, planAssignment{Team: f.team, Terms: terms, Source: planSourceCreditPurchase, Reason: "local previously funded Starter fixture"}); err != nil {
		t.Fatal(err)
	}
	exec := func(s string, args ...any) {
		t.Helper()
		if _, e := f.h.Pool.Exec(t.Context(), s, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_saved_consent')`, f.team)
	exec(`INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,threshold_cents,amount_cents,updated_by,admission_source,admission_epoch) VALUES($1,true,500,500,$2,'new_team',$3)`, f.team, f.actor, f.epoch)
	if err = f.h.enrolPrepaidObservation(t.Context(), f.team); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE billing_funding_account SET observe=true,customer_id='cus_saved_consent',payment_method_ready=true,payment_method_id='pm_saved',credit_usd=0,credit_checked_at=clock_timestamp(),credit_valid_until=clock_timestamp()+interval '1 minute',observed_generation=generation WHERE team_id=$1`, f.team)
	f.close(t)
	if err = f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatalf("closed gate stranded existing recharge consent: %v", err)
	}
	if err = f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	var epoch uuid.UUID
	var source string
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*),max(admission_source),(array_agg(admission_epoch))[1] FROM billing_prepaid_purchase WHERE team_id=$1 AND source='auto_recharge'`, f.team).Scan(&count, &source, &epoch); err != nil {
		t.Fatal(err)
	}
	if count != 1 || source != "new_team" || epoch != f.epoch {
		t.Fatalf("saved consent duplicated or re-admitted: %d/%s/%s", count, source, epoch)
	}
}

func TestNewTeamCohortImplicitPrepaidHTTPReplayAfterClose(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	f.onFree(t)
	f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	for _, sql := range []string{`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_implicit')`, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`} {
		if _, err := f.h.Pool.Exec(t.Context(), sql, f.team); err != nil {
			t.Fatal(err)
		}
	}
	var calls int
	var firstKey, firstExpiry string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/checkout/sessions" {
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		calls++
		if calls == 1 {
			firstKey = r.Header.Get("Idempotency-Key")
			firstExpiry = r.Form.Get("expires_at")
			http.Error(w, "lost response", 503)
			return
		}
		if r.Header.Get("Idempotency-Key") != firstKey || r.Form.Get("expires_at") != firstExpiry {
			t.Error("recovery changed provider identity or expiration")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cs_implicit","url":"https://checkout.stripe.com/implicit"}`))
	}))
	t.Cleanup(provider.Close)
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
	actor := f.actor
	r := gin.New()
	r.POST("/billing/prepaid/checkout", func(c *gin.Context) {
		c.Set("team_id", f.team.String())
		c.Set("actor_id", actor)
		f.h.CreatePrepaidCheckout(c)
	})
	req := prepaidCheckoutBody{AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	if rec := prepaidOperationPost(r, req); rec.Code != 502 {
		t.Fatalf("initial lost reply %d %s", rec.Code, rec.Body)
	}
	var before []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('id',id,'actor',actor_id,'amount',amount_cents,'snapshot',plan_snapshot,'epoch',admission_epoch,'payment_key',payment_idempotency_key,'credit_key',credit_idempotency_key) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var evidence []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT evidence FROM billing_new_team_gate WHERE singleton`).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	f.close(t)
	for _, change := range []func(*prepaidCheckoutBody){func(p *prepaidCheckoutBody) { p.AmountCents = 1000 }, func(p *prepaidCheckoutBody) { p.SuccessURL += "?other=1" }, func(p *prepaidCheckoutBody) { p.CancelURL += "?other=1" }, func(p *prepaidCheckoutBody) { p.OperationID = uuid.New() }} {
		bad := req
		change(&bad)
		want := http.StatusConflict
		if bad.OperationID == uuid.Nil && bad.AmountCents == req.AmountCents {
			want = http.StatusAccepted // Existing purchase status only; never dispatch.
		}
		if rec := prepaidOperationPost(r, bad); rec.Code != want {
			t.Fatalf("different request response %d %s", rec.Code, rec.Body)
		}
	}
	otherActor := uuid.New()
	for _, sql := range []string{`INSERT INTO profile(id,email) VALUES($1,'other-cohort@example.invalid')`, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($2,$1,'active')`, `INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`} {
		var err error
		if strings.Contains(sql, "$2") {
			_, err = f.h.Pool.Exec(t.Context(), sql, otherActor, f.team)
		} else {
			_, err = f.h.Pool.Exec(t.Context(), sql, otherActor)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	actor = otherActor
	if rec := prepaidOperationPost(r, req); rec.Code != 409 {
		t.Fatalf("different authorized actor bypassed closed gate %d %s", rec.Code, rec.Body)
	}
	actor = f.actor
	if calls != 1 {
		t.Fatal("different request contacted provider")
	}
	// Retained acceptance survives removed and temporarily unavailable redirect
	// policy; only the original canonical URLs may recover its frozen lease.
	for _, origins := range [][]string{{"https://new-console.example.com"}, nil} {
		f.h.Config.AppAllowedOrigins = origins
		altered := req
		altered.SuccessURL += "?changed=1"
		if rec := prepaidOperationPost(r, altered); rec.Code != http.StatusAccepted {
			t.Fatalf("policy change did not preserve status-only altered redirects: %d %s", rec.Code, rec.Body)
		}
		replay := req
		replay.SuccessURL = "  " + replay.SuccessURL + "  "
		rec := prepaidOperationPost(r, replay)
		var got billingSessionResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ID != "cs_implicit" {
			t.Fatalf("implicit replay %d %s", rec.Code, rec.Body)
		}
	}
	var after []byte
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('id',id,'actor',actor_id,'amount',amount_cents,'snapshot',plan_snapshot,'epoch',admission_epoch,'payment_key',payment_idempotency_key,'credit_key',credit_idempotency_key) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&after); err != nil || string(before) != string(after) {
		t.Fatalf("recovery changed frozen purchase: %v", err)
	}
	if calls != 3 || firstKey == "" || firstExpiry == "" {
		t.Fatalf("provider replay evidence %d/%s/%s", calls, firstKey, firstExpiry)
	}
	// Subscription completion can become visible while its original lease is
	// still retained. Recover that purchase, never start a payment-only top-up.
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id='sub_completed',stripe_subscription_status='active' WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	rec := prepaidOperationPost(r, req)
	var pending prepaidOperationResponse
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &pending) != nil || pending.PurchaseID == uuid.Nil || calls != 3 {
		t.Fatalf("completed subscription became fresh payment: %d %s", rec.Code, rec.Body)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	// Reopen admission, then let ordinary checkout completion clear the lease
	// between read-only recovery proof and locked admission. The stale proof must
	// not be reused for a fresh generation even when fresh entry is open again.
	var epoch uuid.UUID
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT billing_prepare_new_team_gate('use',$1,'test','reopen for stale-proof regression')`, uuid.MustParse(f.h.Config.SystemTeamID)).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	var released map[string]any
	if err := json.Unmarshal(evidence, &released); err != nil {
		t.Fatal(err)
	}
	released["epoch"] = epoch
	evidence, _ = json.Marshal(released)
	if _, err := f.h.Pool.Exec(t.Context(), `SELECT billing_release_new_team_gate('use',$1,$2,'test','same verified disposable writers',$3)`, uuid.MustParse(f.h.Config.SystemTeamID), epoch, evidence); err != nil {
		t.Fatal(err)
	}
	fresh := req
	fresh.OperationID = uuid.New()
	if rec := prepaidOperationPost(r, fresh); rec.Code != http.StatusBadRequest || calls != 3 {
		t.Fatalf("fresh operation bypassed unavailable redirect policy: %d %s", rec.Code, rec.Body)
	}
	var freshOperations int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_checkout_operation WHERE id=$1`, fresh.OperationID).Scan(&freshOperations); err != nil || freshOperations != 0 {
		t.Fatalf("rejected fresh operation persisted: %d/%v", freshOperations, err)
	}
	proof, err := f.h.acceptedImplicitPrepaidLease(t.Context(), f.team, f.actor, req)
	if err != nil || proof == nil {
		t.Fatalf("accepted proof missing: %v", err)
	}
	if err = f.h.DB.FinishTeamBillingCheckout(t.Context(), f.team); err != nil {
		t.Fatal(err)
	}
	_, err = f.h.beginCohortPrepaidCheckout(t.Context(), f.team, f.actor, billingCheckoutSessionRequest{SuccessURL: req.SuccessURL, CancelURL: req.CancelURL}, proof.RequestKey, uuid.New(), false, proof)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale proof created a new generation: %v", err)
	}
	account, err := f.h.DB.GetTeamBillingCheckoutForRecovery(t.Context(), f.team)
	if err != nil || account.CheckoutInitializingAt.Valid || calls != 3 {
		t.Fatalf("stale proof produced effects: %+v/%d/%v", account.CheckoutInitializingAt, calls, err)
	}
}

func TestNewTeamCohortImplicitRedirectDelimiterCannotBypassPolicy(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	f.onFree(t)
	f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	original := prepaidCheckoutBody{AmountCents: 500, SuccessURL: "https://console.example.com/ok?x=a", CancelURL: "https://console.example.com/cancel?x=b|https://evil.example/out"}
	altered := original
	altered.SuccessURL += "|https://console.example.com/cancel?x=b"
	altered.CancelURL = "https://evil.example/out"
	prices, err := billingCheckoutPriceIDs(f.h.billingResourceStates(false))
	if err != nil {
		t.Fatal(err)
	}
	prices = append(prices, "prepaid:500")
	key := checkoutSessionIdempotencyKey(f.team, "cus_delimiter", original.SuccessURL, original.CancelURL, prices)
	if key != checkoutSessionIdempotencyKey(f.team, "cus_delimiter", altered.SuccessURL, altered.CancelURL, prices) {
		t.Fatal("fixture must reproduce the legacy delimiter collision")
	}
	if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,checkout_initializing_at,stripe_checkout_actor_id,checkout_request_key) VALUES($1,'cus_delimiter',clock_timestamp(),$2,$3)`, f.team, f.actor, key); err != nil {
		t.Fatal(err)
	}
	account, err := f.h.DB.GetTeamBillingCheckoutForRecovery(t.Context(), f.team)
	if err != nil {
		t.Fatal(err)
	}
	purchase := prepaidCheckoutPurchaseID(f.team, account.CheckoutInitializingAt.Time, original.AmountCents)
	if err = f.h.recordCheckoutPurchase(t.Context(), purchase, f.team, "cus_delimiter", f.actor, original.AmountCents, ""); err != nil {
		t.Fatal(err)
	}
	if proof, err := f.h.acceptedImplicitPrepaidLease(t.Context(), f.team, f.actor, original); err != nil || proof == nil {
		t.Fatalf("original allowed lease must be accepted: %+v/%v", proof, err)
	}
	f.close(t)
	for _, origins := range [][]string{{"https://console.example.com"}, nil} {
		f.h.Config.AppAllowedOrigins = origins
		if proof, err := f.h.acceptedImplicitPrepaidLease(t.Context(), f.team, f.actor, altered); err != nil || proof != nil {
			t.Fatalf("colliding URLs bypassed redirect admission: %+v/%v", proof, err)
		}
	}
}

func TestNewTeamCohortImplicitRecoverySurvivesFreshPolicyChanges(t *testing.T) {
	for _, policy := range []string{"capacity", "pro_pending", "export", "managed"} {
		t.Run(policy, func(t *testing.T) {
			f := newTeamCohortTestFixture(t)
			f.onFree(t)
			f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
			f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := f.h.Pool.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_policy')`, f.team)
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, f.team)
			calls := 0
			var key, expiry string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/checkout/sessions" {
					t.Errorf("unexpected provider request %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected", 500)
					return
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				calls++
				if calls == 1 {
					key, expiry = r.Header.Get("Idempotency-Key"), r.Form.Get("expires_at")
					http.Error(w, "lost response", 500)
					return
				}
				if key != r.Header.Get("Idempotency-Key") || expiry != r.Form.Get("expires_at") {
					t.Error("recovery changed provider identity")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"cs_policy","url":"https://checkout.stripe.com/policy"}`))
			}))
			t.Cleanup(provider.Close)
			f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
			r := gin.New()
			r.POST("/billing/prepaid/checkout", func(c *gin.Context) {
				c.Set("team_id", f.team.String())
				c.Set("actor_id", f.actor)
				f.h.CreatePrepaidCheckout(c)
			})
			req := prepaidCheckoutBody{AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
			if rec := prepaidOperationPost(r, req); rec.Code != http.StatusBadGateway {
				t.Fatalf("initial ambiguous response: %d %s", rec.Code, rec.Body)
			}
			var frozen []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('id',id,'amount',amount_cents,'snapshot',plan_snapshot,'epoch',admission_epoch,'payment_key',payment_idempotency_key,'credit_key',credit_idempotency_key) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&frozen); err != nil {
				t.Fatal(err)
			}
			var accountBefore []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1`, f.team).Scan(&accountBefore); err != nil {
				t.Fatal(err)
			}
			freshStatus := http.StatusForbidden
			switch policy {
			case "capacity":
				exec(`INSERT INTO billing_funding_account(team_id,observe) VALUES($1,true) ON CONFLICT(team_id) DO UPDATE SET observe=true`, f.old)
				exec(`UPDATE billing_funding_policy SET max_observed_teams=1`)
				if available, err := f.h.prepaidCapacityAvailable(t.Context(), f.team); err != nil || available {
					t.Fatalf("capacity fixture not exhausted: %v/%v", available, err)
				}
				freshStatus = http.StatusServiceUnavailable
			case "pro_pending":
				exec(`UPDATE billing_signup_choice SET offer_key='pro_monthly',state='pending',generation=clock_timestamp(),actor_id=$2,base_price_id='price_pro',request_payload='{"PlanTerms":{"PricingV2":true}}',admission_source='new_team',admission_epoch=$3 WHERE team_id=$1`, f.team, f.actor, f.epoch)
				freshStatus = http.StatusConflict
			case "export":
				exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, f.team)
			case "managed":
				authority, org := uuid.New(), uuid.New()
				exec(`INSERT INTO qm_team_service_authority(namespace,authority_id,home_region) VALUES('policy-test',$1,'use')`, authority)
				exec(`INSERT INTO qm_organization_teams(namespace,qm_org_id,idempotency_key,authority_id,team_id,home_region) VALUES('policy-test',$1::uuid,'qm-org:v1:'||$1::text,$2,$3,'use')`, org, authority, f.team)
			}
			fresh := req
			fresh.OperationID = uuid.New()
			if rec := prepaidOperationPost(r, fresh); rec.Code != freshStatus || calls != 1 {
				t.Fatalf("fresh %s policy bypass: %d %s calls=%d", policy, rec.Code, rec.Body, calls)
			}
			f.close(t)
			rec := prepaidOperationPost(r, req)
			want, callsWant := http.StatusOK, 2
			if policy == "managed" || policy == "pro_pending" {
				want, callsWant = http.StatusAccepted, 1
			}
			if rec.Code != want || calls != callsWant {
				t.Fatalf("retained %s recovery: %d %s calls=%d", policy, rec.Code, rec.Body, calls)
			}
			var after []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('id',id,'amount',amount_cents,'snapshot',plan_snapshot,'epoch',admission_epoch,'payment_key',payment_idempotency_key,'credit_key',credit_idempotency_key) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&after); err != nil || string(after) != string(frozen) {
				t.Fatalf("retained purchase changed: %v", err)
			}
			if policy == "managed" || policy == "pro_pending" {
				var accountAfter []byte
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1`, f.team).Scan(&accountAfter); err != nil || string(accountBefore) != string(accountAfter) {
					t.Fatalf("conflicting authority mutated the accepted account: %v", err)
				}
				var got prepaidOperationResponse
				if json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.PurchaseID == uuid.Nil || got.State != "pending" {
					t.Fatalf("managed takeover lost accepted status: %s", rec.Body)
				}
			}
		})
	}
}

func TestNewTeamCohortImplicitPriceDriftReturnsStatusWithoutReplay(t *testing.T) {
	for _, drift := range []string{"prices", "resources", "missing_prices"} {
		t.Run(drift, func(t *testing.T) {
			f := newTeamCohortTestFixture(t)
			f.onFree(t)
			f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
			f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
			for _, sql := range []string{`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_drift')`, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`} {
				if _, err := f.h.Pool.Exec(t.Context(), sql, f.team); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "lost response", 500) }))
			t.Cleanup(provider.Close)
			f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
			r := gin.New()
			r.POST("/billing/prepaid/checkout", func(c *gin.Context) {
				c.Set("team_id", f.team.String())
				c.Set("actor_id", f.actor)
				f.h.CreatePrepaidCheckout(c)
			})
			req := prepaidCheckoutBody{AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
			if rec := prepaidOperationPost(r, req); rec.Code != http.StatusBadGateway || calls != 1 {
				t.Fatalf("initial ambiguous checkout: %d %s/%d", rec.Code, rec.Body, calls)
			}
			var purchase uuid.UUID
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&purchase); err != nil {
				t.Fatal(err)
			}
			snapshot := func() []byte {
				t.Helper()
				var raw []byte
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('account',(SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1),'purchase',(SELECT to_jsonb(p) FROM billing_prepaid_purchase p WHERE id=$2),'operations',(SELECT count(*) FROM billing_prepaid_checkout_operation WHERE team_id=$1))`, f.team, purchase).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			switch drift {
			case "prices":
				f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu_v2", "price_memory_v2"}
			case "resources":
				f.h.Config.BillingResources = defaultBillingResourcesFromPriceIDs(f.h.Config.StripeCheckoutPriceIDs)
				f.h.Config.BillingResources[1].CheckoutEnabled = false
			case "missing_prices":
				f.h.Config.StripeCheckoutPriceIDs = nil
			}
			f.close(t)
			before := snapshot()
			for _, alterURL := range []bool{false, true} {
				statusReq := req
				if alterURL {
					statusReq.CancelURL = "https://unapproved.example/out"
				}
				rec := prepaidOperationPost(r, statusReq)
				var got prepaidOperationResponse
				if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.PurchaseID != purchase || got.State != "pending" || got.URL != "" || got.ID != "" {
					t.Fatalf("drift status: %d %s", rec.Code, rec.Body)
				}
				if calls != 1 || string(snapshot()) != string(before) {
					t.Fatal("status fallback mutated account/purchase/operation or called provider")
				}
			}
			for _, change := range []func(*prepaidCheckoutBody){func(p *prepaidCheckoutBody) { p.AmountCents = 1000 }, func(p *prepaidCheckoutBody) { p.OperationID = uuid.New() }} {
				bad := req
				change(&bad)
				if rec := prepaidOperationPost(r, bad); rec.Code != http.StatusConflict || calls != 1 {
					t.Fatalf("different purchase got status authority: %d %s", rec.Code, rec.Body)
				}
			}
			if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id='cus_other' WHERE team_id=$1`, f.team); err != nil {
				t.Fatal(err)
			}
			if rec := prepaidOperationPost(r, req); rec.Code != http.StatusConflict || calls != 1 {
				t.Fatalf("changed customer got status authority: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestNewTeamCohortFirstCheckoutClosureRaceIsConflict(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	for _, sql := range []string{`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_closed_race')`, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`} {
		if _, err := f.h.Pool.Exec(t.Context(), sql, f.team); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "must not dispatch", 500) }))
	t.Cleanup(provider.Close)
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client()}
	r := gin.New()
	r.POST("/checkout", func(c *gin.Context) {
		state, err := f.h.teamPricingState(c.Request.Context(), f.team)
		if err != nil || !state.EntryOpen {
			t.Fatalf("descriptive admission unavailable: %+v/%v", state, err)
		}
		f.close(t)
		f.h.createPAYGCheckout(c, f.team, f.actor, billingCheckoutSessionRequest{SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}, false, &prepaidCheckoutLine{AmountCents: 500})
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/checkout", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("closure race should be conflict: %d %s", rec.Code, rec.Body)
	}
	var clean bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT checkout_initializing_at IS NULL AND cardinality(checkout_pending_attempt_ids)=0 AND NOT EXISTS(SELECT 1 FROM billing_prepaid_purchase WHERE team_id=$1) FROM team_billing_account WHERE team_id=$1`, f.team).Scan(&clean); err != nil || !clean || calls != 0 {
		t.Fatalf("closed admission produced financial effects: %v/%v/%d", clean, err, calls)
	}
}

func TestNewTeamCohortRetiringDeveloperLeavesTrialTeamsAwaitingPro(t *testing.T) {
	for _, ended := range []bool{false, true} {
		f := newTeamCohortTestFixture(t)
		now := time.Now().UTC().Truncate(time.Second)
		f.h.Now = func() time.Time { return now }
		if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_local_trial')`, f.team); err != nil {
			t.Fatal(err)
		}
		if _, err := f.h.Pool.Exec(t.Context(), `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family='developer' AND state='published'),NULL)`); err != nil {
			t.Fatal(err)
		}
		want := entryTrial
		if ended {
			want = entryTrialEnded
			if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_trial_eligibility_cache SET eligible=false WHERE team_id=$1`, f.team); err != nil {
				t.Fatal(err)
			}
		}
		if state, _ := f.entryState(t, f.team); state != want {
			t.Fatalf("retiring Developer moved a %s team to %s", want, state)
		}
		var plans int
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_assignment WHERE team_id=$1`, f.team).Scan(&plans); err != nil || plans != 0 {
			t.Fatalf("retiring Developer assigned a plan: %d %v", plans, err)
		}
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/checkout", nil)
		f.h.createProCheckout(c, f.team, f.actor, billingCheckoutSessionRequest{Offer: "developer_monthly"})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_offer") {
			t.Fatalf("retired Developer checkout: %d %s", rec.Code, rec.Body.String())
		}
		terms, err := f.h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
		if err != nil {
			t.Fatal(err)
		}
		offer := proOffer{Key: terms.OfferKey, Name: terms.DisplayName, Price: "price_local_pro", Amount: terms.FeeCents, Months: 1, Credit: terms.MonthlyCreditCents, VersionID: terms.VersionID, Version: terms.Version, Family: terms.Family, Pricing: "v2", PricingV2: true, Limits: &terms.Limits, Grants: terms.Grants}
		params := StripeCreateCheckoutSessionParams{CustomerID: "cus_local_trial", OperationID: uuid.New(), ClientReferenceID: f.team.String(), BasePriceID: offer.Price, OneOffProduct: "prod_local_pro", AllowPromotionCodes: true, PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: 1, Credit: offer.Credit, VersionID: offer.VersionID, Version: offer.Version, Family: offer.Family, PricingV2: true, Limits: offer.Limits, Grants: offer.Grants}}
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "test unavailable", 503) }))
		f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
		admission, err := f.h.teamPricingState(t.Context(), f.team)
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/quote", nil)
		f.h.createProUpgrade(c, f.team, f.actor, offer, params, admission)
		provider.Close()
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s team could not buy Pro after Developer was retired: %d %s", want, rec.Code, rec.Body.String())
		}
	}
}

func TestNewTeamCohortTrialTeamCannotBuyPrepaidCredit(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("trial team reached the provider: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", 500)
	}))
	t.Cleanup(provider.Close)
	f.h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}
	r := gin.New()
	r.POST("/billing/prepaid/checkout", func(c *gin.Context) {
		c.Set("team_id", f.team.String())
		c.Set("actor_id", f.actor)
		f.h.CreatePrepaidCheckout(c)
	})
	for _, req := range []prepaidCheckoutBody{
		{AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"},
		{AmountCents: 500, OperationID: uuid.New(), SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"},
	} {
		rec := prepaidOperationPost(r, req)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "plan_required") {
			t.Fatalf("trial team prepaid purchase: %d %s", rec.Code, rec.Body)
		}
	}
	r.POST("/stripe/checkout-session", func(c *gin.Context) {
		c.Set("team_id", f.team.String())
		c.Set("actor_id", f.actor)
		f.h.CreateStripeCheckoutSession(c)
	})
	for _, body := range []string{`{"success_url":"https://console.example.com/ok","cancel_url":"https://console.example.com/cancel"}`, `{"offer":"free","success_url":"https://console.example.com/ok","cancel_url":"https://console.example.com/cancel"}`} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/stripe/checkout-session", strings.NewReader(body)))
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "plan_required") {
			t.Fatalf("trial team pay-as-you-go checkout: %d %s", rec.Code, rec.Body)
		}
	}
}

func TestNewTeamCohortTrialTeamIsNotOfferedFree(t *testing.T) {
	f := newTeamCohortTestFixture(t)
	get := func(path string, handle gin.HandlerFunc, team uuid.UUID) map[string]any {
		t.Helper()
		r := gin.New()
		r.GET(path, func(c *gin.Context) {
			c.Set("team_id", team.String())
			c.Set("actor_id", f.actor)
			handle(c)
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var v map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return v
	}
	fresh := get("/cap", f.h.GetBillingCapabilities, f.team)["fresh_entry"].(map[string]any)
	if fresh["choose_free"] != false || fresh["starter"] != false || fresh["auto_recharge"] != false || fresh["pro"] != true {
		t.Fatalf("trial team offers: %+v", fresh)
	}
	plan := get("/summary", f.h.GetBillingSummary, f.team)["plan"].(map[string]any)
	if plan["key"] != "trial" || plan["name"] != "Free trial" || plan["status"] != entryTrial {
		t.Fatalf("trial team summary plan: %+v", plan)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_trial_eligibility_cache SET eligible=false WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if plan = get("/summary", f.h.GetBillingSummary, f.team)["plan"].(map[string]any); plan["status"] != entryTrialEnded {
		t.Fatalf("ended trial summary plan: %+v", plan)
	}
}
