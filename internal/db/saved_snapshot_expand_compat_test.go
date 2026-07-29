package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readSavedSnapshotExpandSQL(t *testing.T) string {
	t.Helper()

	pattern := filepath.Join(
		"..", "..", "supabase", "migrations",
		"2026072900000*_saved_snapshot*.sql",
	)
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("find expand migrations: %v", err)
	}
	if len(paths) != 8 {
		t.Fatalf("found %d expand migrations, want 8", len(paths))
	}

	var sql strings.Builder
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read expand migration %s: %v", path, err)
		}
		sql.Write(raw)
		sql.WriteByte('\n')
	}
	return sql.String()
}

func TestSavedSnapshotExpandPreservesLegacyPauseCompatibility(t *testing.T) {
	sql := readSavedSnapshotExpandSQL(t)

	dropsLegacyIndex := regexp.MustCompile(
		`(?is)DROP\s+INDEX(?:\s+IF\s+EXISTS)?\s+(?:public\.)?snapshot_sandbox_unique\b`,
	)
	if dropsLegacyIndex.MatchString(sql) {
		t.Fatal("expand migration drops snapshot_sandbox_unique before old FinalizePause writers are retired")
	}
	if strings.Contains(sql, "CREATE UNIQUE INDEX snapshot_sandbox_runtime_unique") {
		t.Fatal("expand migration builds a hot-table index before the pre-contract maintenance gate")
	}
	if !strings.Contains(sql, "SET LOCAL lock_timeout = '5s'") {
		t.Fatal("expand migration does not bound lock acquisition time")
	}
	if !strings.Contains(sql, "SET LOCAL statement_timeout = '30s'") {
		t.Fatal("expand migration does not bound hot-table lock duration")
	}
	if !strings.Contains(sql, "expand requires the legacy non-partial snapshot_sandbox_unique index") {
		t.Fatal("expand migration does not verify its legacy conflict target")
	}
	if !strings.Contains(sql, "'sandbox_snapshots_v1',\n    false,") {
		t.Fatal("expand migration does not keep saved snapshots disabled by default")
	}
	if !strings.Contains(sql, "ON CONFLICT (key) DO UPDATE") ||
		!strings.Contains(sql, "WHERE key = 'sandbox_snapshots_v1'\n  AND enabled") {
		t.Fatal("expand migration does not disable existing global and team feature flags")
	}
	if !strings.Contains(sql, "CREATE TRIGGER trg_remember_sandbox_secret_env_key") {
		t.Fatal("expand migration does not preserve secret scrub history for legacy writers")
	}
	if !strings.Contains(sql, "deleted saved snapshot cannot be resurrected") {
		t.Fatal("expand migration does not enforce monotonic logical deletion")
	}
}

func TestSavedSnapshotExpandProtectsInternalLedgerWithRLS(t *testing.T) {
	sql := readSavedSnapshotExpandSQL(t)

	for _, table := range []string{
		"snapshot_storage_layer",
		"snapshot_storage_reference",
	} {
		if !strings.Contains(sql, "CREATE TABLE "+table) {
			t.Errorf("expand migration does not create %s", table)
		}
		if !strings.Contains(sql, "ALTER TABLE public."+table+" ENABLE ROW LEVEL SECURITY") {
			t.Errorf("expand migration does not enable RLS on %s", table)
		}
	}
}
