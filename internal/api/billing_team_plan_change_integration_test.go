//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

type renewalStripe struct {
	t              *testing.T
	mu             sync.Mutex
	sub            string
	customer       string
	endedAt        int64
	endAfterRead   int
	checkout       *StripeRetrievedCheckoutSession
	metadata       map[string]string
	invoices       []proPaidInvoice
	periodEnd      time.Time
	status         string
	cancel         bool
	writes         []string
	failWrite      bool
	renewOnWrite   bool
	cancelAt       int64
	owner          string
	reads          int
	cancelOnRead   int
	renewOnRead    int
	failAfterWrite bool
}

func (s *renewalStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/v1/invoices" && r.URL.Query().Get("customer") == s.customer && r.URL.Query().Get("subscription") == s.sub {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": s.invoices, "has_more": false})
		return
	}
	if s.checkout != nil && r.Method == http.MethodGet && r.URL.Path == "/v1/checkout/sessions/"+s.checkout.ID {
		_ = json.NewEncoder(w).Encode(s.checkout)
		return
	}
	if r.URL.Path != "/v1/subscriptions/"+s.sub {
		s.t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", 500)
		return
	}
	if r.Method == http.MethodGet {
		s.reads++
		if s.reads == s.renewOnRead {
			s.cancel = false
			s.owner = ""
		}
		if s.reads == s.cancelOnRead {
			s.cancel = true
			s.owner = ""
		}
	}
	if r.Method == http.MethodPost {
		if s.failWrite {
			http.Error(w, `{"error":{"message":"unavailable"}}`, 503)
			return
		}
		if s.renewOnWrite {
			s.periodEnd = s.periodEnd.AddDate(0, 1, 0)
			s.renewOnWrite = false
		}
		_ = r.ParseForm()
		s.cancel = r.PostForm.Get("cancel_at_period_end") == "true"
		s.owner = r.PostForm.Get("metadata[plan_change_cancellation]")
		s.writes = append(s.writes, "cancel_at_period_end="+r.PostForm.Get("cancel_at_period_end"))
		if s.failAfterWrite {
			s.failAfterWrite = false
			http.Error(w, "lost response", 503)
			return
		}
	}
	metadata := map[string]string{"plan_change_cancellation": s.owner}
	for k, v := range s.metadata {
		metadata[k] = v
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": s.sub, "customer": s.customer, "status": s.status, "ended_at": s.endedAt, "cancel_at_period_end": s.cancel, "cancel_at": s.cancelAt, "metadata": metadata,
		"items": map[string]any{"data": []map[string]any{{"id": "si_x", "current_period_start": s.periodEnd.AddDate(0, -1, 0).Unix(), "current_period_end": s.periodEnd.Unix()}}}})
	if r.Method == http.MethodGet && s.reads == s.endAfterRead {
		s.status, s.endedAt = "canceled", time.Now().Add(-time.Minute).Unix()
	}
}

func (s *renewalStripe) set(f func(*renewalStripe)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

type planChangeV2Fixture struct {
	h      *Handlers
	team   uuid.UUID
	stripe *renewalStripe
	actor  uuid.UUID
}

var planChangeTestKeys = map[string]string{planKindSubscription: "pro_monthly", planKindPrepaid: "starter", planKindCustom: "custom_example", planKindFree: "free"}

func newPlanChangeV2Fixture(t *testing.T, kind string) planChangeV2Fixture {
	t.Helper()
	h, team := newPlanAssignmentFixture(t)
	if on, err := h.pricingV2Enabled(t.Context()); err != nil || on {
		t.Fatalf("committed assignment fixture must start with entry off: %v %v", on, err)
	}
	f := planChangeV2Fixture{h: h, team: team, actor: uuid.New(), stripe: &renewalStripe{t: t, sub: "sub_" + uuid.NewString(), status: "active"}}
	srv := httptest.NewServer(f.stripe)
	t.Cleanup(srv.Close)
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	anchor := time.Now().UTC().AddDate(0, -2, -3).Truncate(time.Second)
	customer := "cus_" + uuid.NewString()
	f.stripe.customer = customer
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`,
		team, customer, f.stripe.sub, anchor); err != nil {
		t.Fatal(err)
	}
	_, end, err := h.currentBillingPeriod(t.Context(), team, pgtype.Timestamptz{Time: anchor, Valid: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.periodEnd = end
	a := planAssignment{Team: team, Terms: testPlanTerms(planChangeTestKeys[kind], kind, 1000, nil), Source: planSourceCheckout, Reason: "bought"}
	if kind == planKindSubscription {
		contract := uuid.New()
		conn, err := h.Pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		_, err = conn.Exec(t.Context(), `INSERT INTO billing_commercial_contract(id,team_id,offer_key,status,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor)
            VALUES($1,$2,'pro_monthly','active',$3,$4,$5,'price_pro',25000,1,25000,$3)`, contract, team, anchor, customer, f.stripe.sub)
		_, _ = conn.Exec(t.Context(), `RESET session_replication_role`)
		if err != nil {
			t.Fatal(err)
		}
		a.ContractID = &contract
	}
	if _, err = assignInTx(t, h, a); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f planChangeV2Fixture) intent(t *testing.T, target, key string, terms planTerms) teamPlanChangeRequest {
	t.Helper()
	current := f.plan(t)
	timing, _ := planChangeRule(current.Kind, terms.Kind)
	at := time.Now()
	if timing == planChangeEndOfPeriod {
		var err error
		_, at, err = f.h.planChangeBoundary(t.Context(), f.team, current, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	token, err := planChangeConsentToken(current, terms, timing, at)
	if err != nil {
		t.Fatal(err)
	}
	var expected *time.Time
	if timing == planChangeEndOfPeriod {
		expected = &at
	}
	return teamPlanChangeRequest{Team: f.team, Target: target, Key: key, Actor: f.actor, Via: "customer", Reason: "requested by the team", PreviewToken: token, ExpectedEffectiveAt: expected, ConfirmPausesRunning: true}
}

func (f planChangeV2Fixture) request(t *testing.T, target, key string) (teamPlanChange, error) {
	t.Helper()
	kind := map[string]string{"pro_monthly": planKindSubscription, "starter": planKindPrepaid, "free": planKindFree}[target]
	terms := testPlanTerms(target, kind, 1, nil)
	req := teamPlanChangeRequest{Team: f.team, Target: target, Key: key, Actor: f.actor, Via: "customer", Reason: "requested by the team"}
	if _, err := replayTeamPlanChange(t.Context(), f.h.Pool, req); err == nil {
		return f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms)
	}
	return f.h.scheduleTeamPlanChangeTo(t.Context(), f.intent(t, target, key, terms), terms)
}

func (f planChangeV2Fixture) tick(t *testing.T) {
	t.Helper()
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_plan_change SET next_check_at=clock_timestamp() WHERE team_id=$1 AND next_check_at<>'infinity'`, f.team); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.runDueTeamPlanChange(t.Context(), f.team); err != nil {
		t.Fatal(err)
	}
}

func (f planChangeV2Fixture) reload(t *testing.T, id uuid.UUID) teamPlanChange {
	t.Helper()
	c, err := getTeamPlanChange(t.Context(), f.h.Pool, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f planChangeV2Fixture) plan(t *testing.T) teamPlan {
	t.Helper()
	p, _, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// reachEffective moves a change's effective time into the past, as if the
// period had ended.
func (f planChangeV2Fixture) reachEffective(t *testing.T, id uuid.UUID) {
	t.Helper()
	conn, err := f.h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(t.Context(), `RESET session_replication_role`)
	if _, err = conn.Exec(t.Context(), `UPDATE team_plan_change SET effective_at=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestTeamPlanChangeStarterToFreeAppliesNow(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindPrepaid)
	sandbox := uuid.New()
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO sandbox(id,team_id,name,host_id,status,created_at) VALUES($1,$2,'example-running','default','active',clock_timestamp())`, sandbox, f.team); err != nil {
		t.Fatal(err)
	}
	c, err := f.request(t, "free", "k1")
	if err != nil || !c.PausesRunning || c.Subscription != nil || time.Since(c.EffectiveAt) > time.Minute {
		t.Fatalf("starter to free: %+v %v", c, err)
	}
	f.tick(t)
	c = f.reload(t, c.ID)
	var pausesAvailable bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_regprocedure('request_team_pause_all(uuid,text)') IS NOT NULL`).Scan(&pausesAvailable); err != nil {
		t.Fatal(err)
	}
	if !pausesAvailable {
		if c.State != "scheduled" || c.LastError == nil || f.plan(t).PlanKey != "starter" {
			t.Fatalf("free applied without durable pause support: %+v", c)
		}
		return
	}
	plan := f.plan(t)
	if c.State != "applied" || plan.PlanKey != "free" || plan.Source != planSourcePlanChange || plan.ID != *c.AppliedPlan {
		t.Fatalf("free not applied: %+v %+v", c, plan)
	}
	if max, _ := limitsOf(t, f.h, f.team); max != 1 {
		t.Fatalf("free limits not applied: %d", max)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "applied" {
		t.Fatalf("change completed with a running sandbox: %+v", c)
	}
	var targets int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_team_pause_target WHERE sandbox_id=$1 AND done_at IS NULL`, sandbox).Scan(&targets); err != nil || targets != 1 {
		t.Fatalf("running sandbox was not durably queued: %d %v", targets, err)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE sandbox SET status='paused' WHERE id=$1`, sandbox); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "completed" {
		t.Fatalf("change did not complete after durable pause requests settled: %+v", c)
	}
	if len(f.stripe.writes) != 0 {
		t.Fatalf("a team without a subscription touched Stripe: %v", f.stripe.writes)
	}
}

func TestTeamPlanChangeProDowngradeStopsRenewalAndUndoRestoresIt(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "k1")
	if err != nil || c.Subscription == nil || *c.Subscription != f.stripe.sub || !c.EffectiveAt.Equal(f.stripe.periodEnd) || !c.Undoable(time.Now()) {
		t.Fatalf("pro to free: %+v %v", c, err)
	}
	if again, err := f.request(t, "free", "k1"); err != nil || again.ID != c.ID {
		t.Fatalf("replay scheduled again: %+v %v", again, err)
	}
	if _, err = f.request(t, "free", "k2"); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("second pending change accepted: %v", err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.CancelRequestedAt == nil || c.CancelPreexisting || c.ProviderCancelAt == nil || !f.stripe.cancel || c.State != "scheduled" {
		t.Fatalf("renewal not stopped: %+v %v", c, f.stripe.writes)
	}
	if c, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); err != nil || c.State != "undone" {
		t.Fatalf("undo: %+v %v", c, err)
	}
	if _, err = f.request(t, "free", "replacement"); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("replacement raced renewal restoration: %v", err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.needsUndoReconciliation() || c.ProviderRenewedAt == nil || f.stripe.cancel {
		t.Fatalf("renewal not restored after undo: %+v %v", c, f.stripe.writes)
	}
	if again, err := f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); err != nil || again.State != "undone" {
		t.Fatalf("repeated undo: %v", err)
	}
	if plan := f.plan(t); plan.PlanKey != "pro_monthly" {
		t.Fatalf("undone change moved the team: %+v", plan)
	}
	c, err = f.request(t, "starter", "k3")
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	f.reachEffective(t, c.ID)
	f.stripe.set(func(s *renewalStripe) { s.status = "canceled" })
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("undo after the cutoff: %v", err)
	}
	f.tick(t)
	c = f.reload(t, c.ID)
	if plan := f.plan(t); c.State != "completed" || plan.PlanKey != "starter" || plan.Kind != planKindPrepaid {
		t.Fatalf("starter not applied at the period end: %+v %+v", c, plan)
	}
}

func TestTeamPlanChangeUndoWaitsForAnInFlightStripeWrite(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE team_plan_change SET lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '1 minute' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); !errors.Is(err, errTeamPlanChangeConflict) || !strings.Contains(err.Error(), "try again") {
		t.Fatalf("undo raced the worker: %v", err)
	}
	if c = f.reload(t, c.ID); c.State != "scheduled" {
		t.Fatalf("change undone while the worker held it: %+v", c)
	}
}

func TestTeamPlanChangeUndoAfterUnconfirmedRequestRestoresRenewal(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.Pool.Exec(t.Context(), `UPDATE team_plan_change SET provider_cancel_requested_at=clock_timestamp() WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancel = true; s.owner = c.ID.String() })
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.ProviderRenewedAt == nil || f.stripe.cancel {
		t.Fatalf("a cancellation whose response was lost stayed in place after undo: %+v", c)
	}
}

func TestTeamPlanChangeLeavesTheCustomersOwnCancellation(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	f.stripe.set(func(s *renewalStripe) { s.cancel = true })
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); !c.CancelPreexisting || c.ProviderCancelAt == nil || len(f.stripe.writes) != 0 {
		t.Fatalf("existing cancellation not recognised: %+v %v", c, f.stripe.writes)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if !f.stripe.cancel || len(f.stripe.writes) != 0 {
		t.Fatalf("undo turned renewal on against the customer's own cancellation: %v", f.stripe.writes)
	}
}

func TestTeamPlanChangeNotAppliedWhileStripeWouldRenew(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	f.stripe.set(func(s *renewalStripe) { s.cancel = false })
	f.reachEffective(t, c.ID)
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "scheduled" || c.LastError == nil || f.plan(t).PlanKey != "pro_monthly" {
		t.Fatalf("team moved off Pro while the subscription still renews: %+v", c)
	}
	g := newPlanChangeV2Fixture(t, planKindSubscription)
	g.stripe.set(func(s *renewalStripe) { s.failWrite = true })
	c, err = g.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	g.tick(t)
	g.reachEffective(t, c.ID)
	g.tick(t)
	if c = g.reload(t, c.ID); c.State != "scheduled" || c.LastError == nil {
		t.Fatalf("change applied although Stripe was never told not to renew: %+v", c)
	}
}

func TestTeamPlanChangeDefersWhenThePeriodAlreadyRenewed(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "starter", "k1")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.periodEnd = s.periodEnd.AddDate(0, 1, 0) })
	f.tick(t)
	c = f.reload(t, c.ID)
	if !c.EffectiveAt.Equal(f.stripe.periodEnd) || c.ProviderCancelAt == nil || !f.stripe.cancel {
		t.Fatalf("change not deferred to the renewed period end: %+v", c)
	}
}

func TestTeamPlanChangeTreatsAnEndedSubscriptionAsStopped(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.status = "canceled" })
	f.tick(t)
	if c = f.reload(t, c.ID); c.ProviderCancelAt == nil || !c.CancelPreexisting || len(f.stripe.writes) != 0 {
		t.Fatalf("ended subscription left the change stuck: %+v %v", c, f.stripe.writes)
	}
}

func TestTeamPlanChangeRefusals(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindPrepaid)
	for target, want := range map[string]string{"starter": "already", "pro_monthly": "purchased"} {
		if _, err := f.request(t, target, "k-"+target); !errors.Is(err, errTeamPlanChangeConflict) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", target, err)
		}
	}
	h, team := newPlanAssignmentFixture(t)
	if _, err := h.scheduleTeamPlanChangeTo(t.Context(), teamPlanChangeRequest{Team: team, Target: "free", Key: "k", Actor: uuid.New(), Via: "customer", Reason: "r"}, testPlanTerms("free", planKindFree, 1, nil)); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("team without a plan scheduled a change: %v", err)
	}
	g := newPlanChangeV2Fixture(t, planKindSubscription)
	terms := testPlanTerms("free", planKindFree, 1, nil)
	req := g.intent(t, "free", "k1", terms)
	g.stripe.set(func(s *renewalStripe) { s.status = "canceled" })
	if _, err := g.h.scheduleTeamPlanChangeTo(t.Context(), req, terms); !errors.Is(err, errTeamPlanChangeConflict) || !strings.Contains(err.Error(), "already ended") {
		t.Fatalf("downgrade scheduled on an ended subscription: %v", err)
	}
}

func TestTeamPlanChangeWithdrawnWhenTheTeamMovedFirst(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindCustom)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	eight := int32(8)
	if _, err = assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("custom_other", planKindCustom, 500, &eight), Source: planSourceStaff, Reason: "new deal"}); err != nil {
		t.Fatal(err)
	}
	f.reachEffective(t, c.ID)
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "undone" || f.plan(t).PlanKey != "custom_other" {
		t.Fatalf("stale change applied over the team's new plan: %+v", c)
	}
}

func TestTeamPlanChangeHistoryIsGuarded(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindCustom)
	c, err := f.request(t, "free", "k1")
	if err != nil {
		t.Fatal(err)
	}
	for name, stmt := range map[string]string{
		"apply early":     `UPDATE team_plan_change SET state='applied',applied_at=clock_timestamp(),applied_assignment_id=from_assignment_id WHERE id=$1`,
		"edit target":     `UPDATE team_plan_change SET target_plan_key='starter' WHERE id=$1`,
		"skip to done":    `UPDATE team_plan_change SET state='completed',completed_at=clock_timestamp() WHERE id=$1`,
		"move earlier":    `UPDATE team_plan_change SET effective_at=effective_at-interval '1 day' WHERE id=$1`,
		"confirm unasked": `UPDATE team_plan_change SET provider_cancel_at=clock_timestamp() WHERE id=$1`,
		"renew unasked":   `UPDATE team_plan_change SET provider_renewed_at=clock_timestamp() WHERE id=$1`,
		"delete":          `DELETE FROM team_plan_change WHERE id=$1`,
		"second pending":  `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key) SELECT team_id,from_assignment_id,'starter','prepaid',target_terms,target_limits,effective_at,false,requested_by,'staff','r','k2' FROM team_plan_change WHERE id=$1`,
	} {
		tag, err := f.h.Pool.Exec(t.Context(), stmt, c.ID)
		if err == nil && tag.RowsAffected() > 0 {
			t.Errorf("%s was allowed", name)
		}
	}
}

func TestTeamPlanChangeExitAndUndoContinueWhilePricingV2IsOff(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	on, err := f.h.pricingV2Enabled(t.Context())
	if err != nil || on {
		t.Fatalf("fixture must have entry switched off: %v %v", on, err)
	}
	terms, err := f.h.planTermsForPricingVersion(t.Context(), "starter", "v2")
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.h.scheduleTeamPlanChange(t.Context(), f.intent(t, "starter", "exit", terms))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE team_plan_change SET next_check_at='infinity' WHERE team_id<>$1`, f.team); err != nil {
		t.Fatal(err)
	}
	if worked, err := f.h.teamPlanChangeTick(t.Context()); err != nil || !worked {
		t.Fatalf("exit worker stalled with entry off: %v %v", worked, err)
	}
	if c = f.reload(t, c.ID); c.ProviderCancelAt == nil || !f.stripe.cancel {
		t.Fatalf("exit did not stop renewal: %+v", c)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "keep existing plan", "customer"); err != nil {
		t.Fatal(err)
	}
	if worked, err := f.h.teamPlanChangeTick(t.Context()); err != nil || !worked {
		t.Fatalf("undo worker stalled with entry off: %v %v", worked, err)
	}
	if c = f.reload(t, c.ID); c.ProviderRenewedAt == nil || f.stripe.cancel || c.UndoReason == nil || *c.UndoReason != "keep existing plan" {
		t.Fatalf("undo did not restore existing commitment: %+v", c)
	}
}

func TestTeamPlanChangeCancellationCrossingRenewalKeepsPaidPeriod(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "starter", "rollover")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.renewOnWrite = true })
	f.tick(t)
	updated := f.reload(t, c.ID)
	if updated.ProviderCancelAt == nil || !updated.EffectiveAt.Equal(f.stripe.periodEnd) || !updated.EffectiveAt.After(c.EffectiveAt) {
		t.Fatalf("renewed paid period was cut short: %+v", updated)
	}
	f.stripe.set(func(s *renewalStripe) { s.status = "canceled" })
	if replay, err := f.request(t, "starter", "rollover"); err != nil || replay.ID != c.ID {
		t.Fatalf("durable replay depended on ended subscription: %+v %v", replay, err)
	}
}

func TestTeamPlanChangeReassignmentBeforeCancellationDoesNotTouchStripe(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	c, err := f.request(t, "free", "stale")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("custom_other", planKindCustom, 900, nil), Source: planSourceStaff, Reason: "new agreement"}); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if updated := f.reload(t, c.ID); updated.State != "undone" || len(f.stripe.writes) != 0 {
		t.Fatalf("stale change canceled subscription: %+v %v", updated, f.stripe.writes)
	}
}

func TestTeamPlanChangeSingleConnectionAndUndoAfterReassignment(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	cfg := f.h.Pool.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.h = &Handlers{Pool: pool, DB: db.New(pool), Stripe: f.h.Stripe}
	c, err := f.request(t, "free", "single-connection")
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if !f.stripe.cancel {
		t.Fatal("single-connection worker did not cancel renewal")
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "keep plan", "customer"); err != nil {
		t.Fatal(err)
	}
	if _, err = assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("custom_other", planKindCustom, 900, nil), Source: planSourceStaff, Reason: "replacement agreement"}); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if len(f.stripe.writes) != 1 || !f.stripe.cancel || f.reload(t, c.ID).ProviderRenewedAt == nil {
		t.Fatalf("undo resurrected replaced subscription: %v", f.stripe.writes)
	}
}

func TestTeamPlanChangeStaffViewReportsPendingAndUndo(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO profile(id,email,provider) VALUES($1,'staff@superserve.ai','google')`, f.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO user_role_assignments(user_id,role_id,scope_type) SELECT $1,id,'platform' FROM roles WHERE name='platform_admin'`, f.actor); err != nil {
		t.Fatal(err)
	}
	view := func() *customerPendingPlanChange {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set(internalActorHeader, f.actor.String())
		c.Params = gin.Params{{Key: "team_id", Value: f.team.String()}}
		f.h.GetTeamPlanAssignments(c)
		var response struct {
			Pending json.RawMessage `json:"pending_change"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Pending) == 0 {
			t.Fatalf("staff view missing pending change status: %d %s", w.Code, w.Body.String())
		}
		var pending *customerPendingPlanChange
		if err := json.Unmarshal(response.Pending, &pending); err != nil {
			t.Fatal(err)
		}
		return pending
	}
	if pending := view(); pending != nil {
		t.Fatalf("unexpected pending change: %+v", pending)
	}
	change, err := f.request(t, "free", "staff-view")
	if err != nil {
		t.Fatal(err)
	}
	if pending := view(); pending == nil || pending.ID != change.ID || pending.TargetPlanKey != "free" || !pending.Undoable || !pending.PausesRunning || !pending.EffectiveAt.Equal(change.EffectiveAt) {
		t.Fatalf("staff cannot see scheduled downgrade and undo: %+v", pending)
	}
	if _, err := f.h.undoTeamPlanChange(t.Context(), f.team, change.ID, f.actor, "changed my mind", "customer"); err != nil {
		t.Fatal(err)
	}
	if pending := view(); pending != nil {
		t.Fatalf("undone change still pending: %+v", pending)
	}
}

func TestTeamPlanChangeCustomWithoutBillingAccountUsesOneConnection(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	if _, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("custom_example", planKindCustom, 100, nil), Source: planSourceStaff, Reason: "agreement"}); err != nil {
		t.Fatal(err)
	}
	cfg := h.Pool.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h = &Handlers{Pool: pool, DB: db.New(pool)}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, err := h.scheduleTeamPlanChangeTo(ctx, teamPlanChangeRequest{Team: team, Target: "free", Key: "custom-exit", Actor: uuid.New(), Via: "staff", Reason: "end agreement"}, testPlanTerms("free", planKindFree, 1, nil))
	if err != nil || c.State != "scheduled" || !c.EffectiveAt.After(time.Now()) {
		t.Fatalf("custom exit without billing account: %+v %v", c, err)
	}
}

func TestTeamPlanChangeConsentRejectsChangedPreviewWithoutScheduling(t *testing.T) {
	for _, scenario := range []string{"period", "limits", "assignment", "pause_confirmation", "expected_date", "missing_date"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPlanChangeV2Fixture(t, planKindSubscription)
			terms := testPlanTerms("free", planKindFree, 1, nil)
			req := f.intent(t, "free", "consent", terms)
			switch scenario {
			case "period":
				f.stripe.set(func(s *renewalStripe) { s.periodEnd = s.periodEnd.AddDate(0, 1, 0) })
			case "limits":
				terms.Limits.MaxConcurrent = int32p(2)
			case "assignment":
				current := f.plan(t)
				if _, err := assignInTx(t, f.h, planAssignment{Team: f.team, Terms: testPlanTerms("pro_monthly", planKindSubscription, 1000, nil), ContractID: current.ContractID, Source: planSourceStaff, Reason: "updated agreement"}); err != nil {
					t.Fatal(err)
				}
			case "pause_confirmation":
				req.ConfirmPausesRunning = false
			case "expected_date":
				changed := req.ExpectedEffectiveAt.Add(time.Second)
				req.ExpectedEffectiveAt = &changed
			case "missing_date":
				req.ExpectedEffectiveAt = nil
			}
			if _, err := f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms); !errors.Is(err, errTeamPlanChangeConflict) {
				t.Fatalf("changed consent was accepted: %v", err)
			}
			var count int
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_change WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 0 || len(f.stripe.writes) != 0 {
				t.Fatalf("rejected consent created work: %d %v %v", count, f.stripe.writes, err)
			}
		})
	}
}

func TestTeamPlanChangeImmediateConsentAndReplay(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindPrepaid)
	terms := testPlanTerms("free", planKindFree, 1, nil)
	req := f.intent(t, "free", "immediate-consent", terms)
	later, err := planChangeConsentToken(f.plan(t), terms, planChangeNow, time.Now().Add(time.Hour))
	if err != nil || later != req.PreviewToken {
		t.Fatalf("immediate preview expired with its display timestamp: %s %v", later, err)
	}
	withDate := req
	at := time.Now()
	withDate.ExpectedEffectiveAt = &at
	if _, err := f.h.scheduleTeamPlanChangeTo(t.Context(), withDate, terms); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("immediate change accepted a billing-period date precondition: %v", err)
	}
	c, err := f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms)
	if err != nil {
		t.Fatal(err)
	}
	terms.Limits.MaxConcurrent = int32p(2)
	if replay, err := f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms); err != nil || replay.ID != c.ID {
		t.Fatalf("recorded consent could not replay after target terms changed: %+v %v", replay, err)
	}
}

func TestTeamPlanChangeHistorySurvivesTeamDeletionWithoutRestoringRenewal(t *testing.T) {
	for _, stage := range []string{"scheduled", "cancelled", "undone"} {
		t.Run(stage, func(t *testing.T) {
			f := newPlanChangeV2Fixture(t, planKindCustom)
			c, err := scanTeamPlanChange(f.h.Pool.QueryRow(t.Context(), `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,subscription_id,requested_by,requested_via,reason,idempotency_key)
                VALUES($1,$2,'free','free','{}','{"max_concurrent":1}',$5,true,$3,$4,'customer','requested by the team','delete-team') RETURNING `+teamPlanChangeColumns, f.team, f.plan(t).ID, f.stripe.sub, f.actor, f.stripe.periodEnd))
			if err != nil {
				t.Fatal(err)
			}
			if stage != "scheduled" {
				f.tick(t)
			}
			if stage == "undone" {
				if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "changed my mind", "customer"); err != nil {
					t.Fatal(err)
				}
			}
			writes := len(f.stripe.writes)
			if err = f.h.DB.DeleteTeam(t.Context(), f.team); err != nil {
				t.Fatal(err)
			}
			retained := f.reload(t, c.ID)
			if retained.State != "undone" || retained.needsUndoReconciliation() || retained.FromAssignment != c.FromAssignment {
				t.Fatalf("deleted team has active work or lost history: %+v", retained)
			}
			if ran, err := f.h.runDueTeamPlanChange(t.Context(), f.team); err != nil || ran || len(f.stripe.writes) != writes {
				t.Fatalf("deleted team retried provider work: %v %v %v", ran, err, f.stripe.writes)
			}
			if _, err = f.h.Pool.Exec(t.Context(), `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key)
    SELECT team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,'deleted-team-insert' FROM team_plan_change WHERE id=$1`, c.ID); err == nil {
				t.Fatal("accepted new work for a deleted team")
			}
		})
	}
}

func TestTeamPlanChangeCancellationOwnershipSurvivesRetries(t *testing.T) {
	for _, scenario := range []string{"between_reads", "intent_before_write", "lost_write_response", "cancel_removed_between_reads"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPlanChangeV2Fixture(t, planKindSubscription)
			c, err := f.request(t, "starter", "ownership")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "between_reads" {
				f.stripe.set(func(s *renewalStripe) { s.reads = 0; s.cancelOnRead = 2 })
			}
			if scenario == "cancel_removed_between_reads" {
				f.stripe.set(func(s *renewalStripe) { s.cancel = true; s.reads = 0; s.renewOnRead = 2 })
			}
			if scenario == "intent_before_write" {
				if _, err = f.h.Pool.Exec(t.Context(), `UPDATE team_plan_change SET provider_cancel_requested_at=clock_timestamp() WHERE id=$1`, c.ID); err != nil {
					t.Fatal(err)
				}
				f.stripe.set(func(s *renewalStripe) { s.cancel = true })
			}
			if scenario == "lost_write_response" {
				f.stripe.set(func(s *renewalStripe) { s.failAfterWrite = true })
			}
			f.tick(t)
			f.tick(t)
			if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "keep plan", "customer"); err != nil {
				t.Fatal(err)
			}
			f.tick(t)
			shouldRemainCancelled := scenario != "lost_write_response" && scenario != "cancel_removed_between_reads"
			if f.stripe.cancel != shouldRemainCancelled || f.reload(t, c.ID).needsUndoReconciliation() {
				t.Fatalf("renewed independent cancellation or failed to restore owned cancellation: %+v %+v", f.stripe, f.reload(t, c.ID))
			}
		})
	}
}

func TestTeamPlanChangeExplicitCancellationCannotOutliveDowngrade(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = s.periodEnd.Add(24 * time.Hour).Unix() })
	if _, _, err := f.h.planChangeBoundary(t.Context(), f.team, f.plan(t), time.Now()); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("accepted later explicit cancellation: %v", err)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = 0 })
	c, err := f.request(t, "starter", "scheduled-before-cancel")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = s.periodEnd.Add(24 * time.Hour).Unix() })
	f.tick(t)
	if c = f.reload(t, c.ID); c.ProviderCancelAt != nil || c.State != "scheduled" || len(f.stripe.writes) != 0 {
		t.Fatalf("confirmed later cancellation: %+v", c)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = 0 })
	f.tick(t)
	f.reachEffective(t, c.ID)
	f.stripe.set(func(s *renewalStripe) {
		s.periodEnd = time.Now().Add(-time.Minute)
		s.cancelAt = time.Now().Add(24 * time.Hour).Unix()
		s.cancel = false
	})
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "scheduled" || f.plan(t).PlanKey != "pro_monthly" {
		t.Fatalf("downgraded before explicit cancellation: %+v", c)
	}
}

func TestTeamPlanChangeFreeEntryRequiresDeployedPauseSupport(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindCustom)
	ready, err := planChangePausesReady(t.Context(), f.h.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Skip("missing-prerequisite regression requires baseline schema")
	}
	req := f.intent(t, "free", "no-pause-support", testPlanTerms("free", planKindFree, 1, nil))
	if _, err = f.h.scheduleTeamPlanChange(t.Context(), req); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("accepted Free before deployment: %v", err)
	}
	var count int
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_change WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 0 || len(f.stripe.writes) != 0 {
		t.Fatalf("unavailable Free created work: %d %v", count, err)
	}
	c, err := f.request(t, "free", "committed-before-rollback")
	if err != nil {
		t.Fatal(err)
	}
	req.Key = "committed-before-rollback"
	if replay, err := f.h.scheduleTeamPlanChange(t.Context(), req); err != nil || replay.ID != c.ID {
		t.Fatalf("readiness blocked committed replay: %+v %v", replay, err)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "keep plan", "customer"); err != nil {
		t.Fatalf("readiness blocked undo: %v", err)
	}
}

func TestTeamPlanChangeRejectsEarlyExplicitCancellation(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	terms := testPlanTerms("starter", planKindPrepaid, 1, nil)
	req := f.intent(t, "starter", "early-cancel", terms)
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = s.periodEnd.Add(-2 * time.Hour).Unix() })
	if _, _, err := f.h.planChangeBoundary(t.Context(), f.team, f.plan(t), time.Now()); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("preview accepted earlier cancellation with later item boundary: %v", err)
	}
	if _, err := f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms); !errors.Is(err, errTeamPlanChangeConflict) {
		t.Fatalf("accepted early cancellation after preview: %v", err)
	}
	var count int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM team_plan_change WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 0 || len(f.stripe.writes) != 0 {
		t.Fatalf("early cancellation created work: %d %v %v", count, err, f.stripe.writes)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = 0 })
	c, err := f.request(t, "starter", "scheduled-before-early-cancel")
	if err != nil {
		t.Fatal(err)
	}
	f.stripe.set(func(s *renewalStripe) { s.cancelAt = s.periodEnd.Add(-2 * time.Hour).Unix() })
	f.tick(t)
	if c = f.reload(t, c.ID); c.ProviderCancelAt != nil || c.State != "scheduled" || !c.EffectiveAt.Equal(f.stripe.periodEnd) || len(f.stripe.writes) != 0 {
		t.Fatalf("confirmed mismatched early cancellation: %+v", c)
	}
}

func TestTeamPlanChangeDoesNotRollAnEndingSubscriptionIntoLaterCycle(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "period_end", true: "explicit"}[explicit], func(t *testing.T) {
			f := newPlanChangeV2Fixture(t, planKindSubscription)
			f.stripe.set(func(s *renewalStripe) {
				s.periodEnd = time.Now().Add(30 * time.Minute).Truncate(time.Second)
				s.cancel = true
				if explicit {
					s.cancelAt = s.periodEnd.Unix()
				}
			})
			if _, _, err := f.h.planChangeBoundary(t.Context(), f.team, f.plan(t), time.Now()); !errors.Is(err, errTeamPlanChangeConflict) {
				t.Fatalf("moved already-ending subscription into a later cycle: %v", err)
			}
			if len(f.stripe.writes) != 0 {
				t.Fatalf("changed an independent cancellation: %v", f.stripe.writes)
			}
		})
	}
}

func TestTeamPlanChangeCustomerCannotUndoStaffCancellation(t *testing.T) {
	f := newPlanChangeV2Fixture(t, planKindSubscription)
	terms := testPlanTerms("starter", planKindPrepaid, 1, nil)
	req := f.intent(t, "starter", "staff-cancellation", terms)
	req.Via = "staff"
	c, err := f.h.scheduleTeamPlanChangeTo(t.Context(), req, terms)
	if err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.ProviderCancelAt == nil || !f.stripe.cancel || len(f.stripe.writes) != 1 {
		t.Fatalf("staff cancellation not committed: %+v %v", c, f.stripe.writes)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, uuid.New(), "customer request", "customer"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("customer undid staff change: %v", err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "scheduled" || c.ProviderRenewedAt != nil || c.UndoReason != nil || !f.stripe.cancel || len(f.stripe.writes) != 1 {
		t.Fatalf("denied customer undo changed staff commitment/provider: %+v %v", c, f.stripe.writes)
	}
	for _, via := range []string{"customer", "staff"} {
		p, err := pendingCustomerPlanChange(t.Context(), f.h.Pool, f.team, via)
		if err != nil || p == nil || p.ID != c.ID || p.Undoable != (via == "staff") {
			t.Fatalf("%s pending undo authority: %+v %v", via, p, err)
		}
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, f.actor, "operator correction", "staff"); err != nil {
		t.Fatalf("staff undo denied: %v", err)
	}
	f.tick(t)
	if c = f.reload(t, c.ID); c.State != "undone" || c.ProviderRenewedAt == nil || f.stripe.cancel {
		t.Fatalf("operator could not undo owned cancellation: %+v %v", c, f.stripe.writes)
	}
	if _, err = f.h.undoTeamPlanChange(t.Context(), f.team, c.ID, uuid.New(), "replay", "customer"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("customer replay accessed undone staff change: %v", err)
	}
}
