//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestComputePauseIndexMigrationValidatesPrebuild(t *testing.T) {
	migration, err := os.ReadFile("../../supabase/migrations/20260924000012_sandbox_compute_pause_candidates.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Keep each prebuild scenario isolated in the test's rollback transaction.
	sql := strings.ReplaceAll(string(migration), "\nBEGIN;\n", "\n")
	sql = strings.ReplaceAll(sql, "\nCOMMIT;\n", "\n")
	for _, tc := range []struct {
		name, definition string
		wantError        bool
	}{
		{"fresh", "", false},
		{"correct", "(team_id, id) WHERE destroyed_at IS NULL AND status IN ('active', 'starting', 'resuming')", false},
		{"reversed keys", "(id, team_id) WHERE destroyed_at IS NULL AND status IN ('active', 'starting', 'resuming')", true},
		{"missing predicate", "(team_id, id)", true},
		{"wrong states", "(team_id, id) WHERE destroyed_at IS NULL AND status IN ('active', 'paused')", true},
		{"missing destroyed filter", "(team_id, id) WHERE status IN ('active', 'starting', 'resuming')", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, "DROP INDEX IF EXISTS public.idx_sandbox_compute_pause_candidates"); err != nil {
				t.Fatal(err)
			}
			if tc.definition != "" {
				if _, err := tx.Exec(ctx, "CREATE INDEX idx_sandbox_compute_pause_candidates ON public.sandbox "+tc.definition); err != nil {
					t.Fatal(err)
				}
			}
			_, err = tx.Exec(ctx, sql)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "unexpected definition") {
					t.Fatalf("want definition rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
