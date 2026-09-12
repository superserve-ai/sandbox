//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialBalanceMigrationUpgradeConverges(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	cleanMigration, err := os.ReadFile("../../supabase/migrations/20260903000001_billing_trial_balance.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(cleanMigration)); err != nil {
		t.Fatal(err)
	}
	const definitionSQL = `SELECT pg_get_functiondef('get_team_trial_balance(uuid)'::regprocedure)`
	var fresh string
	if err := tx.QueryRow(ctx, definitionSQL).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile("testdata/trial_balance_before_corrections.sql")
	if err != nil {
		t.Fatal(err)
	}
	// The historical body contains invalid aggregate expressions. Restore it
	// without validation, as a dump restore can, then apply only the new migration.
	if _, err := tx.Exec(ctx, `SET LOCAL check_function_bodies = off`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(old)); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := tx.QueryRow(ctx, definitionSQL).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before == fresh {
		t.Fatal("historical fixture already matches the corrected definition")
	}
	if _, err := tx.Exec(ctx, `SET LOCAL check_function_bodies = on`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../supabase/migrations/20260910000004_trial_balance_corrections.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("upgrade trial balance: %v", err)
	}
	var upgraded string
	if err := tx.QueryRow(ctx, definitionSQL).Scan(&upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded != fresh {
		t.Fatal("upgraded trial balance differs from clean installation")
	}
	balance, err := db.New(tx).GetTeamTrialBalance(ctx, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if balance.State != "no_grant" || balance.Eligible {
		t.Fatalf("upgraded no-grant balance: state=%q eligible=%t", balance.State, balance.Eligible)
	}
}

func TestTrialBalanceExcludesExpiredGrants(t *testing.T) {
	for _, neverExpires := range []bool{false, true} {
		t.Run(fmt.Sprintf("never_expires=%t", neverExpires), func(t *testing.T) {
			ctx := context.Background()
			teamID := mustCreateTeam(t, ctx, "trial-mixed-expiry-"+uuid.NewString()[:8])
			sandboxID := seedPrivatePreviewSandbox(t, teamID, testDefaultHostID, "trial-mixed-expiry")
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			q := db.New(tx)
			// Team creation seeds a signup grant; this case supplies its own grants.
			if _, err := tx.Exec(ctx, `DELETE FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'`, teamID); err != nil {
				t.Fatal(err)
			}
			planKey := "trial-mixed-expiry-" + uuid.NewString()
			if _, err := tx.Exec(ctx, `INSERT INTO pricing_plan (key, name, currency, active)
				VALUES ($1, 'Trial test pricing', 'USD', true)`, planKey); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
				VALUES ($1, 'vcpu', 'second', 1, now() - interval '4 days')`, planKey); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
				VALUES ($1, $2, now() - interval '4 days')`, teamID, planKey); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO team_credit_grant
				(team_id, amount_usd, remaining_usd, reason, created_at, expires_at)
				VALUES ($1, 100, 100, 'signup trial credit', now() - interval '3 days', now() - interval '2 days'),
				       ($1, 5, 5, 'signup trial credit', now() - interval '1 day',
				        CASE WHEN $2 THEN NULL ELSE now() + interval '1 day' END)`, teamID, neverExpires); err != nil {
				t.Fatal(err)
			}
			// Historical usage must not consume the newer grant. The recent two
			// seconds cost $2 against only the unexpired $5 grant.
			if _, err := tx.Exec(ctx, `INSERT INTO sandbox_compute_billing_interval
				(sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
				VALUES ($1, $2, 1, 1, now() - interval '3 days', now() - interval '3 days' + interval '10 seconds', 'paused'),
				       ($1, $2, 1, 1, now() - interval '1 hour', now() - interval '1 hour' + interval '2 seconds', 'paused')`, sandboxID, teamID); err != nil {
				t.Fatal(err)
			}
			assertBalance := func(wantGrant, wantConsumed, wantRemaining float64, wantState string, wantEligible bool) {
				t.Helper()
				balance, err := q.GetTeamTrialBalance(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range []struct {
					name string
					got  pgtype.Numeric
					want float64
				}{
					{"grant", balance.GrantUsd, wantGrant},
					{"consumed", balance.ConsumedUsd, wantConsumed},
					{"remaining", balance.RemainingUsd, wantRemaining},
				} {
					got, err := value.got.Float64Value()
					if err != nil || !got.Valid || got.Float64 != value.want {
						t.Fatalf("%s = %v, error = %v, want %v", value.name, got, err, value.want)
					}
				}
				if balance.State != wantState || balance.Eligible != wantEligible {
					t.Fatalf("state=%q eligible=%t, want %q/%t", balance.State, balance.Eligible, wantState, wantEligible)
				}
				if err := q.RefreshTeamTrialEligibility(ctx, teamID); err != nil {
					t.Fatal(err)
				}
				eligible, err := q.IsTeamSandboxBillingEligible(ctx, teamID)
				if err != nil || eligible != wantEligible {
					t.Fatalf("enforcement eligible=%t, error=%v, want %t", eligible, err, wantEligible)
				}
			}
			assertBalance(5, 2, 3, "active", true)
			if _, err := tx.Exec(ctx, `UPDATE sandbox_compute_billing_interval
				SET ended_at = started_at + interval '6 seconds'
				WHERE team_id = $1 AND started_at > now() - interval '1 day'`, teamID); err != nil {
				t.Fatal(err)
			}
			assertBalance(5, 6, 0, "exhausted", false)
			if _, err := tx.Exec(ctx, `UPDATE team_credit_grant SET expires_at = now()
				WHERE team_id = $1 AND (expires_at IS NULL OR expires_at > now())`, teamID); err != nil {
				t.Fatal(err)
			}
			assertBalance(0, 0, 0, "expired", false)
		})
	}
}
