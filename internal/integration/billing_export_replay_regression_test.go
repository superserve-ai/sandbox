//go:build integration

package integration

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_ShadowHandoffRetriesPreserveExportedUsage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		historical bool
		zeroUsage  bool
	}{
		{name: "incremental"},
		{name: "incremental_zero_usage", zeroUsage: true},
		{name: "historical_legacy", historical: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			teamID, periodID, start, end := seedBillingPeriodForStripe(t, false, false)
			adminID := seedPlatformAdminProfile(t)
			if _, err := testQueries.ApproveTeamBillingPeriod(ctx, db.ApproveTeamBillingPeriodParams{
				TeamID: teamID, PeriodStart: start, PeriodEnd: end,
				ApprovedBy: pgtype.UUID{Bytes: adminID, Valid: true},
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
				VALUES ($1,$2,$3,'active')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			if tc.zeroUsage {
				if _, err := testPool.Exec(ctx, `UPDATE sandbox_compute_billing_interval
					SET started_at=$2::timestamptz,ended_at=$2::timestamptz+interval '2 hours' WHERE team_id=$1`, teamID, end); err != nil {
					t.Fatal(err)
				}
			}
			stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
			stripe.countedUsage = func(event, customer string, from, through time.Time) (string, error) {
				if customer != "cus_"+teamID.String() || !from.Equal(start) || !through.Equal(end) {
					return "", fmt.Errorf("unexpected summary scope: %s %s %s", customer, from, through)
				}
				total := new(big.Rat)
				for _, call := range stripe.reportCalls {
					if call.EventName == event && call.CustomerID == customer {
						quantity, ok := new(big.Rat).SetString(call.Value)
						if !ok {
							return "", fmt.Errorf("invalid reported quantity %q", call.Value)
						}
						total.Add(total, quantity)
					}
				}
				return total.FloatString(12), nil
			}
			router := newBillingRouter(t, stripe)
			path := "/internal/teams/" + teamID.String() + "/billing/periods/" + periodID + "/export"
			shadow := doInternal(router, http.MethodPost, path, adminID.String(), "")
			if shadow.Code != http.StatusOK {
				t.Fatalf("shadow export: %d %s", shadow.Code, shadow.Body.String())
			}
			if len(stripe.reportCalls) != 0 {
				t.Fatal("shadow export submitted Stripe usage")
			}
			if tc.historical {
				// Older shadow exports were completed before incremental enrollment existed.
				if _, err := testPool.Exec(ctx, `DELETE FROM billing_incremental_period WHERE team_id=$1`, teamID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := testPool.Exec(ctx, `UPDATE team_feature_flag SET enabled=true
				WHERE team_id=$1 AND key='billing_export_enabled'`, teamID); err != nil {
				t.Fatal(err)
			}
			live := doInternal(router, http.MethodPost, path, adminID.String(), "")
			if live.Code != http.StatusOK {
				t.Fatalf("first live export: %d %s", live.Code, live.Body.String())
			}
			wantCalls := 2
			if tc.zeroUsage {
				wantCalls = 0
			}
			if got := len(stripe.reportCalls); got != wantCalls {
				t.Fatalf("first live export submitted %d events, want %d", got, wantCalls)
			}
			var frozenCPU, frozenMemory string
			var exportedAt time.Time
			if err := testPool.QueryRow(ctx, `SELECT vcpu_seconds::text,memory_mib_seconds::text,exported_at
				FROM team_billing_usage WHERE team_id=$1 AND period_start=$2 AND period_end=$3`,
				teamID, start, end).Scan(&frozenCPU, &frozenMemory, &exportedAt); err != nil {
				t.Fatal(err)
			}
			// Late measurement changes require explicit correction, even when the
			// completed export had no provider events because usage was zero.
			if _, err := testPool.Exec(ctx, `UPDATE sandbox_compute_billing_interval
				SET started_at=$2::timestamptz,ended_at=$2::timestamptz+interval '3 hours' WHERE team_id=$1`, teamID, start); err != nil {
				t.Fatal(err)
			}
			retry := doInternal(router, http.MethodPost, path, adminID.String(), "")
			if retry.Code != http.StatusOK {
				t.Fatalf("live retry: %d %s", retry.Code, retry.Body.String())
			}
			if got := len(stripe.reportCalls); got != wantCalls {
				t.Fatalf("exported-period retry submitted additional usage: %d events, want %d", got, wantCalls)
			}
			var cpu, memory string
			var retryExportedAt time.Time
			if err := testPool.QueryRow(ctx, `SELECT vcpu_seconds::text,memory_mib_seconds::text,exported_at
				FROM team_billing_usage WHERE team_id=$1 AND period_start=$2 AND period_end=$3`,
				teamID, start, end).Scan(&cpu, &memory, &retryExportedAt); err != nil {
				t.Fatal(err)
			}
			if cpu != frozenCPU || memory != frozenMemory || !retryExportedAt.Equal(exportedAt) {
				t.Fatalf("retry changed frozen usage: (%s,%s,%s), want (%s,%s,%s)",
					cpu, memory, retryExportedAt, frozenCPU, frozenMemory, exportedAt)
			}
			if _, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, testPool, teamID, start, end); err != nil {
				t.Fatalf("finalize completed export: %v", err)
			}
			var enrolled bool
			if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_incremental_period
				WHERE team_id=$1 AND period_start=$2 AND period_end=$3)`, teamID, start, end).Scan(&enrolled); err != nil {
				t.Fatal(err)
			}
			if enrolled == tc.historical {
				t.Fatalf("incremental enrollment = %t, want %t", enrolled, !tc.historical)
			}
		})
	}
}
