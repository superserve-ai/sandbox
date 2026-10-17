//go:build integration

package api

import (
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
	"os"
	"strings"
	"testing"
	"time"
)

func TestYCActivationWakesEntitlement(t *testing.T) {
	for _, leased := range []bool{false, true} {
		t.Run(map[bool]string{false: "sleeping", true: "leased"}[leased], func(t *testing.T) {
			f := newEntitlementFixture(t, true, true, true)
			ctx := t.Context()
			token := uuid.New()
			if _, err := f.h.Pool.Exec(ctx, `UPDATE billing_entitlement_work SET lease_token=$2,lease_until=clock_timestamp()+interval '1 minute' WHERE contract_id=$1`, f.c.ID, token); err != nil {
				t.Fatal(err)
			}
			if leased {
				// This worker has observed pending, but activation commits before its ack.
				next, err := f.h.reconcileUsageEntitlement(ctx, f.c.ID)
				if err != nil || time.Until(next) < 23*time.Hour {
					t.Fatal("pending schedule", next, err)
				}
			} else {
				if err := f.h.processEntitlementJob(ctx, entitlementJob{Contract: f.c.ID, Token: token}); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = f.h.DB.WithTx(tx).ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: f.c.TeamID, ContractID: f.c.ID, ExpectedRevision: f.c.Revision}); err != nil {
				t.Fatal(err)
			}
			var due, owned bool
			if err = tx.QueryRow(ctx, `SELECT next_check_at<=clock_timestamp(),COALESCE(lease_token=$2,false) FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID, token).Scan(&due, &owned); err != nil || !due || owned != leased {
				t.Fatal("activation did not wake transactionally or stole lease", due, owned, err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if leased {
				// Existing workers acknowledge with their claimed token; even an older
				// binary's future schedule must not erase a wake that raced its lease.
				if _, err = f.h.Pool.Exec(ctx, `UPDATE billing_entitlement_work SET lease_token=NULL,lease_until=NULL,next_check_at=clock_timestamp()+interval '24 hours' WHERE contract_id=$1 AND lease_token=$2`, f.c.ID, token); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.h.Pool.QueryRow(ctx, `SELECT next_check_at<=clock_timestamp() AND lease_token IS NULL FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID).Scan(&due); err != nil || !due {
				t.Fatal("worker acknowledgement lost activation wake", err)
			}
		})
	}
}

func TestYCDeploymentWakesPreviouslyActiveEntitlement(t *testing.T) {
	migration, err := os.ReadFile("../../supabase/migrations/20261017000100_entitlement_activation_wakeup.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, backfill, ok := strings.Cut(string(migration), "-- Recover activations that committed before the new trigger was installed.")
	if !ok {
		t.Fatal("missing rollout wake")
	}
	for _, leased := range []bool{false, true} {
		t.Run(map[bool]string{false: "sleeping", true: "leased"}[leased], func(t *testing.T) {
			f := newEntitlementFixture(t, true, true, false, true)
			token := uuid.New()
			if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()+interval '24 hours',lease_token=CASE WHEN $3 THEN $2::uuid END,lease_until=CASE WHEN $3 THEN clock_timestamp()+interval '1 minute' END WHERE contract_id=$1`, f.c.ID, token, leased); err != nil {
				t.Fatal(err)
			}
			if _, err = f.h.Pool.Exec(t.Context(), backfill); err != nil {
				t.Fatal(err)
			}
			var due, owned bool
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT next_check_at<=clock_timestamp(),COALESCE(lease_token=$2,false) FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID, token).Scan(&due, &owned); err != nil || !due || owned != leased {
				t.Fatal("rollout stole lease or failed to wake", due, owned, err)
			}
			if leased {
				if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_work SET lease_token=NULL,lease_until=NULL,next_check_at=clock_timestamp()+interval '24 hours' WHERE contract_id=$1 AND lease_token=$2`, f.c.ID, token); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT next_check_at<=clock_timestamp() AND lease_token IS NULL FROM billing_entitlement_work WHERE contract_id=$1`, f.c.ID).Scan(&due); err != nil || !due {
				t.Fatal("stale ack lost deployment wake", err)
			}
		})
	}
}
