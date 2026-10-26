//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestProviderPairComposedWorker(t *testing.T) {
	for _, mode := range []string{"refresh", "permission_revoked", "recover_after_revocation"} {
		t.Run(mode, func(t *testing.T) {
			a, service, r, o := offerCompositionFixture(t)
			a.dispatchesResolved = CheckProviderPairDispatchesResolved
			ctx := t.Context()
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
			if _, err = a.h.Pool.Exec(ctx, `ALTER TABLE billing_provider_pair_waiver DISABLE TRIGGER billing_provider_pair_waiver_guard`); err != nil {
				t.Fatal(err)
			}
			_, err = a.h.Pool.Exec(ctx, `UPDATE billing_provider_pair_waiver SET authority_checked_at=clock_timestamp()-interval '2 minutes',authority_valid_until=clock_timestamp()-interval '90 seconds' WHERE contract_id=$1`, b.ContractID)
			_, enableErr := a.h.Pool.Exec(ctx, `ALTER TABLE billing_provider_pair_waiver ENABLE TRIGGER billing_provider_pair_waiver_guard`)
			if err != nil || enableErr != nil {
				t.Fatal(err, enableErr)
			}
			if mode == "permission_revoked" {
				if _, err = a.h.Pool.Exec(ctx, `DELETE FROM user_role_assignments WHERE user_id=$1 AND team_id=$2`, r.UserID, r.TeamID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "recover_after_revocation" {
				wf.lost.Store(true)
			}
			_, err = a.h.reconcileUsageEntitlement(ctx, b.ContractID)
			if mode == "permission_revoked" {
				if err == nil || wf.posts.Load() != 0 {
					t.Fatal("missing current regional permission authorized grant", err)
				}
				return
			}
			if mode == "recover_after_revocation" {
				if err == nil || wf.posts.Load() != 1 {
					t.Fatal("expected uncertain grant", err)
				}
				if _, err = a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
					t.Fatal(err)
				}
				deliveries, e := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
				if e != nil {
					t.Fatal(e)
				}
				found := false
				var pendingDelivery YCFinancialInvalidation
				for _, delivery := range deliveries {
					if delivery.AcceptanceID == r.ID {
						found = true
						pendingDelivery = delivery
						if e = a.revokeFinancialDelivery(ctx, delivery); !errors.Is(e, errProviderPairDispatchPending) {
							t.Fatal("unrecovered dispatch allowed effective revocation", e)
						}
					}
				}
				if !found {
					t.Fatal("missing actual invalidation delivery")
				}
				state, stateErr := a.admission.Service.FinancialState(ctx, r.ClaimID)
				if stateErr != nil || state == nil || state.PendingInvalidations != 1 || state.State == "revoked" {
					t.Fatal("unrecovered dispatch acknowledged revocation", state, stateErr)
				}
				_, err = a.h.reconcileUsageEntitlement(ctx, b.ContractID)
				if err != nil {
					t.Fatal(err)
				}
				if err = a.revokeFinancialDelivery(ctx, pendingDelivery); err != nil {
					t.Fatal("recovered dispatch did not permit acknowledgement", err)
				}
				requireFinancialState(t, a.admission.Service, r, "revoked", 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			e, err := a.h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: r.TeamID, Kind: "metered_usage"})
			if err != nil || e.State != "issued" || !e.PairedWaiverID.Valid || e.AmountCents != 3000000 || wf.posts.Load() != 1 {
				t.Fatalf("actual composed grant: %+v posts=%d err=%v", e, wf.posts.Load(), err)
			}
			var valid time.Time
			if err = a.h.Pool.QueryRow(context.Background(), `SELECT authority_valid_until FROM billing_provider_pair_waiver WHERE contract_id=$1`, b.ContractID).Scan(&valid); err != nil {
				t.Fatal(err)
			}
			if mode == "refresh" && !valid.After(time.Now()) {
				t.Fatal("actual adapter did not refresh expired waiver")
			}
		})
	}
}
