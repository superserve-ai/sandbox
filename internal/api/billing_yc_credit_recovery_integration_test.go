//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestYCComputeOnlyActiveRecovery(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "replay", true: "lost-response"}[lost], func(t *testing.T) {
			f := newEntitlementFixture(t, true, true, false, true)
			before, err := f.h.ycOperation(t.Context(), f.c.TeamID)
			if err != nil {
				t.Fatal(err)
			}
			beforeRaw, _ := json.Marshal(before)
			if lost {
				f.lost.Store(true)
			} else {
				f.noDispatch.Store(true)
			}
			if _, err = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err == nil {
				t.Fatal("expected provider uncertainty")
			}
			saved, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: "metered_usage"})
			if err != nil || saved.State != "uncertain" {
				t.Fatal(saved.State, err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _, _ = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID) }()
			}
			wg.Wait()
			if _, err = f.h.reconcileUsageEntitlement(t.Context(), f.c.ID); err != nil {
				t.Fatal(err)
			}
			issued, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.c.TeamID, Kind: "metered_usage"})
			if err != nil || issued.State != "issued" || !bytes.Equal(issued.RequestPayload, saved.RequestPayload) || issued.IdempotencyKey != saved.IdempotencyKey {
				t.Fatal("recovery changed saved issuance", err)
			}
			wantPosts := int32(2)
			if lost {
				wantPosts = 1
			}
			if f.grants.Load() != wantPosts {
				t.Fatal("duplicate dispatch", f.grants.Load())
			}
			f.mu.Lock()
			g := *f.grant
			f.mu.Unlock()
			if g.Amount.Monetary.Value != 3000000 || g.ExpiresAt != f.end.Unix()+1 {
				t.Fatal("incorrect allowance", g)
			}
			if err = creditScope(g, f.c.CustomerID, f.end.Unix(), []string{"price_cpu", "price_memory", "price_round"}); err != nil {
				t.Fatal(err)
			}
			if !lost && (f.requests[0] != f.requests[1] || f.keys[0] != f.keys[1]) {
				t.Fatal("replay changed request identity")
			}
			// A later configuration change cannot replace the frozen compute-only terms.
			f.h.Config.BillingResources = []config.BillingResourceConfig{{ResourceKey: "storage_gib", StripePriceID: "price_storage", StripeEventName: "storage_gib_hours", UsageUnit: "second", CheckoutEnabled: true, Billable: true}}
			err = f.h.withStorageSubscription(t.Context(), f.c.TeamID, true, true, func(pgx.Tx, StripeStorageSubscriptionParams) error {
				t.Error("storage activation reached provider without approved terms")
				return nil
			})
			if err == nil {
				t.Fatal("later storage configuration silently enabled charges")
			}
			activated, err := f.h.billingStorageBillingEnabled(t.Context(), f.c.TeamID)
			if err != nil || activated {
				t.Fatal("storage enabled", err)
			}
			states, err := f.h.billingSubscriptionResourceStates(t.Context(), f.c.TeamID, f.c.SubscriptionID, true)
			if err != nil || len(states) != 2 {
				t.Fatal("historical terms reinterpreted", states, err)
			}
			after, err := f.h.ycOperation(t.Context(), f.c.TeamID)
			if err != nil {
				t.Fatal(err)
			}
			afterRaw, _ := json.Marshal(after)
			if !bytes.Equal(beforeRaw, afterRaw) {
				t.Fatal("operation terms or anniversary changed")
			}
			if !issued.PeriodStart.Equal(f.start) || !issued.PeriodEnd.Equal(f.end) {
				t.Fatal("period shifted")
			}
		})
	}
}

func TestYCActivatedStorageRequiresCoverage(t *testing.T) {
	for _, computeOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "covered", true: "missing-storage"}[computeOnly], func(t *testing.T) {
			f := newEntitlementFixture(t, true, true, false, computeOnly)
			if _, err := f.h.Pool.Exec(t.Context(), `INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff) VALUES($1,now(),now())`, f.c.TeamID); err != nil {
				t.Fatal(err)
			}
			_, err := f.h.reconcileUsageEntitlement(t.Context(), f.c.ID)
			if computeOnly {
				if err == nil {
					t.Fatal("issued uncovered storage allowance")
				}
				var attempts int
				if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_usage_entitlement WHERE contract_id=$1 AND state='uncertain'`, f.c.ID).Scan(&attempts); err != nil || attempts != 0 || f.grants.Load() != 0 {
					t.Fatal("local failure recorded external attempt", attempts, err)
				}
			} else if err != nil || f.grants.Load() != 1 {
				t.Fatal("covered storage failed", err)
			}
		})
	}
}

func TestYCLocalRequestValidationRollsBackIntent(t *testing.T) {
	f := newEntitlementFixture(t, true, true, false, true)
	// Obtain normal eligibility evidence without creating an allowance.
	var observed time.Time
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": f.start, "period_end": f.end})
	c, err := f.h.DB.ObserveCommercialCollection(t.Context(), db.ObserveCommercialCollectionParams{TeamID: f.c.TeamID, ContractID: f.c.ID, ExpectedRevision: f.c.Revision, HasOverdueBalance: new(bool), CheckedAt: pgtype.Timestamptz{Time: observed, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: observed.Add(time.Minute), Valid: true}, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.h.DB.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := f.h.invoiceAccount(t.Context(), f.c.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.DB.UpsertTeamBillingPeriod(t.Context(), db.UpsertTeamBillingPeriodParams{TeamID: f.c.TeamID, PeriodStart: f.start, PeriodEnd: f.end, Status: "open"}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.ensureInvoiceCalendar(t.Context(), billing.ExportPeriod{TeamID: f.c.TeamID, Start: f.start, End: f.end}, a, f.h.Stripe.(*stripeHTTPClient)); err != nil {
		t.Fatal(err)
	}
	params := db.BeginImmediateUsageEntitlementIssuanceParams{TeamID: c.TeamID, ContractID: c.ID, EntitlementID: e.ID, InvoiceStart: pgtype.Timestamptz{Time: f.start, Valid: true}, InvoiceEnd: pgtype.Timestamptz{Time: f.end, Valid: true}, Prices: []byte(`[{"id":"price_cpu"},{"id":"price_memory"},{"id":"unexpected"}]`)}
	scope := []map[string]string{{"id": "price_cpu"}, {"id": "price_memory"}, {"id": "price_round"}}
	if _, err = f.h.beginValidatedUsageEntitlementIssuance(t.Context(), params, scope); err == nil {
		t.Fatal("accepted incorrect request")
	}
	after, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: c.TeamID, Kind: "metered_usage"})
	if err != nil || after.State != "pending" || after.FirstAttemptAt.Valid || len(after.RequestPayload) != 0 {
		t.Fatal("local failure left durable uncertainty", after, err)
	}
	params.Prices, _ = json.Marshal(scope)
	if _, err = f.h.beginValidatedUsageEntitlementIssuance(t.Context(), params, scope); err != nil {
		t.Fatal("corrected validation cannot retry", err)
	}
}
