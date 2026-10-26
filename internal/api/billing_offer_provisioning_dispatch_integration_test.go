//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestOfferCompositionRevocationWaitsForDispatchResolution(t *testing.T) {
	a, service, r, o := offerCompositionFixture(t)
	ctx := t.Context()
	if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
	if err != nil {
		t.Fatal(err)
	}
	var delivery YCFinancialInvalidation
	for _, d := range deliveries {
		if d.AcceptanceID == r.ID {
			delivery = d
		}
	}
	if delivery.InvalidationID == uuid.Nil {
		t.Fatal("missing invalidation")
	}
	a.dispatchesResolved = nil
	if err = a.revokeFinancialDelivery(ctx, delivery); !errors.Is(err, provisioning.ErrUnavailable) {
		t.Fatal("missing dispatch proof allowed acknowledgement", err)
	}
	target := provisioning.InitialFinancialTarget(o.TeamID, o.AssignmentID)
	receipt, err := provisioning.LoadFinancialRevocationReceipt(ctx, a.h.Pool, target, delivery.InvalidationID)
	if err != nil || receipt.Authorization == nil || receipt.Authorization.ID != delivery.AuthorizationID || receipt.Authorization.OperationID != o.ID {
		t.Fatal("pending dispatch rolled back permanent denial or lost exact authority", receipt, err)
	}
	binding, err := loadContractProviderBinding(ctx, a.h.Pool, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = a.WithProviderPairAuthority(ctx, binding, func(context.Context, pgx.Tx) error {
		called = true
		return nil
	}); err == nil || called {
		t.Fatal("pending acknowledgement admitted a new dispatch", err)
	}
	pending := errors.New("synthetic unresolved dispatch")
	checks := 0
	a.dispatchesResolved = func(ctx context.Context, q db.DBTX, got ContractProviderBinding) error {
		checks++
		if got.ContractID != o.ID || got.Identity != binding.Identity {
			t.Fatal("dispatch check received another binding")
		}
		// This is an adapter boundary test. The materialization owner's composed
		// worker test separately proves the durable dispatch journal predicate.
		if _, err := provisioning.LoadFinancialRevocationReceipt(ctx, q, target, delivery.InvalidationID); err != nil {
			t.Fatal("dispatch check ran before committed denial", err)
		}
		return pending
	}
	for range 2 {
		if err = a.revokeFinancialDelivery(ctx, delivery); !errors.Is(err, pending) {
			t.Fatal("already-revoked retry bypassed unresolved dispatch", err)
		}
		state, err := a.admission.Service.FinancialState(ctx, r.ClaimID)
		if err != nil || state == nil || state.PendingInvalidations != 1 || state.State == "revoked" {
			t.Fatal("unresolved dispatch acknowledged effective revocation", state, err)
		}
	}
	if checks != 2 {
		t.Fatal("resolution was not rechecked on every retry", checks)
	}
	wrong := delivery
	wrong.AuthorizationID = uuid.New()
	if err = a.revokeFinancialDelivery(ctx, wrong); !errors.Is(err, provisioning.ErrConflict) || checks != 2 {
		t.Fatal("replayed revocation accepted another authorization", err, checks)
	}
	pending = nil
	if err = a.revokeFinancialDelivery(ctx, delivery); err != nil {
		t.Fatal(err)
	}
	state, err := a.admission.Service.FinancialState(ctx, r.ClaimID)
	if err != nil || state == nil || state.PendingInvalidations != 0 || state.State != "revoked" {
		t.Fatal("resolved dispatch did not permit acknowledgement", state, err)
	}
	replayed, err := provisioning.LoadFinancialRevocationReceipt(ctx, a.h.Pool, target, delivery.InvalidationID)
	if err != nil || replayed.AcknowledgementID != receipt.AcknowledgementID || replayed.FenceID != receipt.FenceID {
		t.Fatal("pending recovery replaced durable receipt", err)
	}
}

func TestOfferCompositionPausedGrantCannotOutrunRevocationAcknowledgement(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "confirmed"
		if lost {
			name = "lost_response"
		}
		t.Run(name, func(t *testing.T) {
			a, service, r, o := offerCompositionFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if a.dispatchesResolved == nil {
				t.Fatal("actual durable dispatch checker must be composed")
			}
			if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
				t.Fatal(err)
			}
			binding, err := loadContractProviderBinding(ctx, a.h.Pool, o.ID)
			if err != nil {
				t.Fatal(err)
			}
			a.h.Config.BillingUsageEntitlementsEnabled = true
			a.h.ProviderPairEntitlementAuthority = a
			wf := &pairWorkerFixture{h: a.h, b: binding}
			provider := newPairFixture(t)
			provider.p.CustomerID = binding.CustomerID
			configurePairWorkerProvider(t, wf, provider)
			wf.lost.Store(lost)
			client := *a.client
			transport := client.httpClient.Transport
			if transport == nil {
				transport = http.DefaultTransport
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			httpClient := *client.httpClient
			httpClient.Transport = stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost && req.URL.Path == "/v1/billing/credit_grants" {
					enteredOnce.Do(func() { close(entered) })
					select {
					case <-release:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
				}
				response := httptest.NewRecorder()
				if provider.serve(response, req) {
					return response.Result(), nil
				}
				return transport.RoundTrip(req)
			})
			client.httpClient = &httpClient
			a.h.Stripe = &client
			finished := make(chan error, 1)
			workerDone := make(chan struct{})
			go func() {
				defer close(workerDone)
				_, err := a.h.reconcileUsageEntitlement(ctx, binding.ContractID)
				finished <- err
			}()
			t.Cleanup(func() {
				cancel()
				unblock()
				<-workerDone
			})
			select {
			case <-entered:
			case err := <-finished:
				t.Fatal("worker did not reach provider boundary", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if _, err = a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
			if err != nil {
				t.Fatal(err)
			}
			var delivery YCFinancialInvalidation
			for _, d := range deliveries {
				if d.AcceptanceID == r.ID {
					delivery = d
				}
			}
			if delivery.InvalidationID == uuid.Nil {
				t.Fatal("missing actual shared invalidation")
			}
			for range 2 {
				if err = a.revokeFinancialDelivery(ctx, delivery); err == nil {
					t.Fatal("effective revocation acknowledged while admitted sender can still POST")
				}
				state, err := a.admission.Service.FinancialState(ctx, r.ClaimID)
				if err != nil || state == nil || state.PendingInvalidations != 1 || state.State == "revoked" || wf.posts.Load() != 0 {
					t.Fatal("paused dispatch did not retain pending acknowledgement", state, err, wf.posts.Load())
				}
			}
			unblock()
			select {
			case err = <-finished:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if (err != nil) != lost || wf.posts.Load() != 1 {
				t.Fatal("admitted dispatch outcome differs", err, wf.posts.Load())
			}
			if lost {
				if err = a.revokeFinancialDelivery(ctx, delivery); err == nil {
					t.Fatal("unknown provider outcome released acknowledgement")
				}
				if _, err = a.h.reconcileUsageEntitlement(ctx, binding.ContractID); err != nil {
					t.Fatal("historical grant recovery failed", err)
				}
			}
			if err = a.revokeFinancialDelivery(ctx, delivery); err != nil {
				t.Fatal("resolved dispatch remained unacknowledged", err)
			}
			requireFinancialState(t, a.admission.Service, r, "revoked", 0)
			_, _ = a.h.reconcileUsageEntitlement(ctx, binding.ContractID)
			if wf.posts.Load() != 1 {
				t.Fatal("late replay created another grant after effective revocation", wf.posts.Load())
			}
		})
	}
}

func TestOfferCompositionRevocationAfterGrantRejection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		proven bool
	}{
		{"validation", 400, `{"error":{"type":"invalid_request_error","code":"parameter_unknown"}}`, true},
		{"raw_status", 400, `rejected`, false},
		{"idempotency", 400, `{"error":{"type":"idempotency_error","message":"different parameters"}}`, false},
		{"rate_limit", 429, `{"error":{"type":"invalid_request_error","code":"parameter_unknown"}}`, false},
		{"server", 503, `{"error":{"type":"invalid_request_error","code":"parameter_unknown"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, service, r, o := offerCompositionFixture(t)
			ctx := t.Context()
			if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
				t.Fatal(err)
			}
			binding, err := loadContractProviderBinding(ctx, a.h.Pool, o.ID)
			if err != nil {
				t.Fatal(err)
			}
			a.h.Config.BillingUsageEntitlementsEnabled = true
			a.h.ProviderPairEntitlementAuthority = a
			wf := &pairWorkerFixture{h: a.h, b: binding}
			provider := newPairFixture(t)
			provider.p.CustomerID = binding.CustomerID
			configurePairWorkerProvider(t, wf, provider)
			client := *a.client
			transport := client.httpClient.Transport
			if transport == nil {
				transport = http.DefaultTransport
			}
			httpClient := *client.httpClient
			httpClient.Transport = stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
				response := httptest.NewRecorder()
				if provider.serve(response, req) {
					return response.Result(), nil
				}
				return transport.RoundTrip(req)
			})
			client.httpClient = &httpClient
			a.h.Stripe = &client
			posts := configurePairRejectionProvider(t, a.h, tc.status, tc.body)
			if _, err = a.h.reconcileUsageEntitlement(ctx, binding.ContractID); err == nil || posts.Load() != 1 {
				t.Fatal("expected exactly one rejected grant request", err, posts.Load())
			}
			if _, err = a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
			if err != nil {
				t.Fatal(err)
			}
			var delivery YCFinancialInvalidation
			for _, d := range deliveries {
				if d.AcceptanceID == r.ID {
					delivery = d
				}
			}
			if delivery.InvalidationID == uuid.Nil {
				t.Fatal("missing actual shared invalidation")
			}
			for range 2 {
				err = a.revokeFinancialDelivery(ctx, delivery)
				if tc.proven {
					if err != nil {
						t.Fatal("proven no-effect rejection blocked shared acknowledgement", err)
					}
					requireFinancialState(t, a.admission.Service, r, "revoked", 0)
				} else {
					if err == nil {
						t.Fatal("ambiguous response released shared acknowledgement")
					}
					state, readErr := a.admission.Service.FinancialState(ctx, r.ClaimID)
					if readErr != nil || state == nil || state.PendingInvalidations != 1 || state.State == "revoked" {
						t.Fatal("ambiguous response lost pending acknowledgement", state, readErr)
					}
				}
			}
			_, _ = a.h.reconcileUsageEntitlement(ctx, binding.ContractID)
			if posts.Load() != 1 {
				t.Fatal("rejection allowed a replacement grant request", posts.Load())
			}
		})
	}
}
