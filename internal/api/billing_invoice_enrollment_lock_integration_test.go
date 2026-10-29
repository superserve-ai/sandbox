//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/config"
)

// invoiceEnrollmentLockFixture seeds a team ready for its first enrollment and
// a provider that parks the first subscription read until released.
func invoiceEnrollmentLockFixture(t *testing.T) (h *Handlers, team uuid.UUID, reached <-chan struct{}, release func()) {
	t.Helper()
	h, team = fundingTransitionFixture(t)
	ctx := t.Context()
	customer, sub := "cus_"+team.String(), "sub_"+team.String()
	if _, err := h.Pool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',now()-interval '1 month')`, team, customer, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team); err != nil {
		t.Fatal(err)
	}
	h.Config = &config.Config{BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", UsageUnit: "second", StripePriceID: "price_cpu", StripeEventName: "cpu", Billable: true}}}
	hit := make(chan struct{})
	gate := make(chan struct{})
	var once bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !once {
			once = true
			close(hit)
			<-gate
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, httpClient: srv.Client(), apiVersion: "2026-07-29.dahlia", secretKey: "sk_test_example"}
	return h, team, hit, func() { close(gate) }
}

// The team's invoice lock stays free while enrollment waits on the provider.
func TestInvoiceEnrollmentProviderCallHoldsNoAccountLock(t *testing.T) {
	h, team, reached, release := invoiceEnrollmentLockFixture(t)
	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		done <- h.enrollInvoiceAccount(ctx, team, &invoiceAccount{Price: "price_round", Event: "round", Meter: "mtr_round"})
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("enrollment never reached the provider")
	}
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String())
	waited := time.Since(started)
	release()
	<-done
	if err != nil {
		t.Fatalf("invoice lock was held across the provider call: %v after %s", err, waited)
	}
	t.Logf("invoice lock acquired during provider call in %s", waited)
	if waited > time.Second {
		t.Fatalf("invoice lock took %s during the provider call", waited)
	}
}

// A change to the rows the plan was computed from makes the record step skip.
func TestInvoiceEnrollmentRecordsOnlyUnchangedRows(t *testing.T) {
	h, team, _, release := invoiceEnrollmentLockFixture(t)
	release()
	ctx := t.Context()
	customer, sub := "cus_"+team.String(), "sub_"+team.String()
	if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_invoice_enrollment(team_id,customer_id,subscription_id,started_at) VALUES($1,$2,$3,now()) ON CONFLICT(team_id) DO UPDATE SET started_at=COALESCE(billing_invoice_enrollment.started_at,now())`, team, customer, sub); err != nil {
		t.Fatal(err)
	}
	var attempt time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&attempt); err != nil {
		t.Fatal(err)
	}
	plan := invoiceEnrollmentPlan{account: invoiceAccount{Customer: customer, Subscription: sub, Price: "price_round", Event: "round", Meter: "mtr_round"}, attempt: attempt, boundary: attempt}
	fingerprint, err := invoiceEnrollmentFingerprint(ctx, h.Pool, team, false)
	if err != nil {
		t.Fatal(err)
	}
	plan.fingerprint = fingerprint
	// A transition that keeps the customer and subscription but rewrites the
	// account row invalidates the plan.
	if _, err := h.Pool.Exec(ctx, `UPDATE team_billing_account SET updated_at=now() WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if err := h.recordInvoiceEnrollment(ctx, team, plan); err != errInvoiceEnrollmentChanged {
		t.Fatalf("plan from a rewritten account row was recorded: %v", err)
	}
	if plan.fingerprint, err = invoiceEnrollmentFingerprint(ctx, h.Pool, team, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, team, "sub_other_"+team.String()); err != nil {
		t.Fatal(err)
	}
	if err := h.recordInvoiceEnrollment(ctx, team, plan); err != errInvoiceEnrollmentChanged {
		t.Fatalf("changed association was recorded: %v", err)
	}
	var recorded int
	if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_invoice_account WHERE team_id=$1`, team).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatalf("enrollment recorded against a changed association: rows=%d err=%v", recorded, err)
	}
	// Restoring the association clears the attempt; the retry re-plans from
	// the fresh attempt the way enrollInvoiceAccount does.
	if _, err := h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, team, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_invoice_enrollment SET started_at=COALESCE(started_at,now()) WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if err := h.Pool.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&plan.attempt); err != nil {
		t.Fatal(err)
	}
	plan.boundary = plan.attempt
	// A pricing assignment whose window opens between planning and recording
	// changes nothing in the rows themselves but still invalidates the plan.
	if _, err := h.Pool.Exec(ctx, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,'payg',now()+interval '150 milliseconds')`, team); err != nil {
		t.Fatal(err)
	}
	if plan.fingerprint, err = invoiceEnrollmentFingerprint(ctx, h.Pool, team, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := h.recordInvoiceEnrollment(ctx, team, plan); err != errInvoiceEnrollmentChanged {
		t.Fatalf("plan from before a pricing window opened was recorded: %v", err)
	}
	if plan.fingerprint, err = invoiceEnrollmentFingerprint(ctx, h.Pool, team, false); err != nil {
		t.Fatal(err)
	}
	if err := h.recordInvoiceEnrollment(ctx, team, plan); err != nil {
		t.Fatal(err)
	}
	var completed bool
	if err := h.Pool.QueryRow(ctx, `SELECT a.subscription_id=$2 AND e.completed_at IS NOT NULL FROM billing_invoice_account a JOIN billing_invoice_enrollment e USING(team_id) WHERE a.team_id=$1`, team, sub).Scan(&completed); err != nil || !completed {
		t.Fatalf("unchanged rows were not recorded: completed=%v err=%v", completed, err)
	}
}

// A record transaction that began before a pricing window opened, and only
// got the lock after it did, must judge the window at the lock, not at its
// transaction start.
func TestInvoiceEnrollmentRecordJudgesWindowsAfterLockWait(t *testing.T) {
	h, team, _, release := invoiceEnrollmentLockFixture(t)
	release()
	ctx := t.Context()
	customer, sub := "cus_"+team.String(), "sub_"+team.String()
	if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_invoice_enrollment(team_id,customer_id,subscription_id,started_at) VALUES($1,$2,$3,now()) ON CONFLICT(team_id) DO UPDATE SET started_at=COALESCE(billing_invoice_enrollment.started_at,now())`, team, customer, sub); err != nil {
		t.Fatal(err)
	}
	plan := invoiceEnrollmentPlan{account: invoiceAccount{Customer: customer, Subscription: sub, Price: "price_round", Event: "round", Meter: "mtr_round"}}
	if err := h.Pool.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&plan.attempt); err != nil {
		t.Fatal(err)
	}
	plan.boundary = plan.attempt
	if _, err := h.Pool.Exec(ctx, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,'payg',now()+interval '500 milliseconds')`, team); err != nil {
		t.Fatal(err)
	}
	var err error
	if plan.fingerprint, err = invoiceEnrollmentFingerprint(ctx, h.Pool, team, false); err != nil {
		t.Fatal(err)
	}
	holder, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx)
	if _, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String()); err != nil {
		t.Fatal(err)
	}
	recorded := make(chan error, 1)
	go func() { recorded <- h.recordInvoiceEnrollment(context.WithoutCancel(ctx), team, plan) }()
	waitFor(t, h, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)`)
	waitFor(t, h, `SELECT EXISTS(SELECT 1 FROM team_pricing_plan WHERE team_id=$1 AND effective_from<statement_timestamp())`, team)
	if err = holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-recorded; err != errInvoiceEnrollmentChanged {
		t.Fatalf("plan from before a pricing window opened during the lock wait was recorded: %v", err)
	}
}

func waitFor(t *testing.T, h *Handlers, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ok bool
		if err := h.Pool.QueryRow(t.Context(), query, args...).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition never held: %s", query)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
