//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestOfferCompositionFundingReadiness(t *testing.T) {
	a, service, r, o := offerCompositionFixture(t)
	ctx := t.Context()
	if id, err := service.Enqueue(ctx, o.TeamID, o.AssignmentID); err != nil || id != o.ID {
		t.Fatal("admission did not preserve the accepted operation", id, err)
	}
	if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
		t.Fatal(err)
	}
	b, err := loadContractProviderBinding(ctx, a.h.Pool, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.h.Config.BillingUsageEntitlementsEnabled = true
	a.h.ProviderPairEntitlementAuthority = a
	wf := &pairWorkerFixture{h: a.h, b: b}
	provider := newPairFixture(t)
	provider.p.CustomerID = b.CustomerID
	configurePairWorkerProvider(t, wf, provider)
	client := *a.client
	client.secretKey = "sk_test_fixture"
	transport := client.httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	var balance atomic.Int64
	balance.Store(3000000)
	httpClient := *client.httpClient
	httpClient.Transport = stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		switch req.URL.Path {
		case "/v1/charges":
			_, _ = response.WriteString(`{"data":[]}`)
		case "/v1/billing/credit_balance_summary":
			if wf.grant == nil || req.URL.Query().Get("customer") != b.CustomerID || req.URL.Query().Get("filter[credit_grant]") != wf.grant.ID {
				t.Error("funding balance was not scoped to the issued grant")
			}
			amount := map[string]any{"monetary": map[string]any{"currency": "usd", "value": balance.Load()}}
			_ = json.NewEncoder(response).Encode(map[string]any{"balances": []any{map[string]any{"ledger_balance": amount, "available_balance": amount}}})
		default:
			if !provider.serve(response, req) {
				return transport.RoundTrip(req)
			}
		}
		return response.Result(), nil
	})
	client.httpClient = &httpClient
	a.h.Stripe = &client
	for range 2 {
		if _, err = a.h.reconcileUsageEntitlement(ctx, b.ContractID); err != nil {
			t.Fatal(err)
		}
	}
	if wf.posts.Load() != 1 {
		t.Fatal("reconciliation duplicated the grant", wf.posts.Load())
	}
	status, err := service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || status.Ready {
		t.Fatal("issued grant without funding observations became ready", status, err)
	}
	observe := func() {
		t.Helper()
		job, _ := claimFundingTestJob(t, a.h, o.TeamID)
		if err := a.h.processFundingJob(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	observe()
	status, err = service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || !status.Ready || status.State != "funding_ready" {
		readiness, readErr := a.Readiness(ctx, o)
		t.Fatal("actual no-card funding observation did not authorize readiness", status, err, readiness, readErr)
	}
	var card, cash bool
	if err = a.h.Pool.QueryRow(ctx, `SELECT payment_method_ready,cash_collected FROM billing_funding_account WHERE team_id=$1`, o.TeamID).Scan(&card, &cash); err != nil || card || cash {
		t.Fatal("fixture unexpectedly has payment authority", card, cash, err)
	}
	balance.Store(0)
	if _, err = a.h.Pool.Exec(ctx, `UPDATE billing_funding_account SET credit_checked_at=clock_timestamp()-interval '1 minute' WHERE team_id=$1`, o.TeamID); err != nil {
		t.Fatal(err)
	}
	observe()
	status, err = service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || status.Ready || status.State != "exhausted" {
		t.Fatal("exhausted credit remained ready", status, err)
	}
	var eligible bool
	if err = a.h.Pool.QueryRow(ctx, `SELECT team_sandbox_billing_eligible($1)`, o.TeamID).Scan(&eligible); err != nil || eligible {
		t.Fatal("no-card exhausted balance authorized sandbox access", eligible, err)
	}
	// Restore observed provider funds, then invalidate shared authority before
	// the regional drain. A current balance must not mask that invalidation.
	balance.Store(3000000)
	if _, err = a.h.Pool.Exec(ctx, `UPDATE billing_funding_account SET credit_checked_at=clock_timestamp()-interval '1 minute' WHERE team_id=$1`, o.TeamID); err != nil {
		t.Fatal(err)
	}
	observe()
	status, err = service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || !status.Ready || wf.posts.Load() != 1 {
		t.Fatal("fresh funding did not restore readiness for the original grant", status, wf.posts.Load(), err)
	}
	if _, err = a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	status, _ = service.Status(ctx, o.TeamID, o.AssignmentID)
	if status.Ready {
		t.Fatal("shared invalidation waited for regional drain before withdrawing readiness")
	}
}
