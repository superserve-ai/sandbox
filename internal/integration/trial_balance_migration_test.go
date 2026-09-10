//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
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
