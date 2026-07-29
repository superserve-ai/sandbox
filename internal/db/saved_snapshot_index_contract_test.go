package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var savedSnapshotContractIndexNames = []string{
	"snapshot_sandbox_runtime_unique",
	"snapshot_team_source_idempotency_unique",
	"idx_snapshot_team_saved_created",
	"idx_snapshot_source_saved_created",
	"idx_snapshot_parent_saved",
	"idx_snapshot_saved_host",
	"idx_snapshot_saved_reconcile",
	"idx_sandbox_source_snapshot_pin",
	"idx_sandbox_destroyed_snapshot_pin",
	"idx_sandbox_snapshot_operation",
}

func readRepositoryFile(t *testing.T, parts ...string) string {
	t.Helper()

	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func TestSavedSnapshotIndexPrebuildContract(t *testing.T) {
	prebuild := readRepositoryFile(
		t,
		"scripts",
		"prebuild-saved-snapshot-indexes.sql",
	)

	if strings.Contains(prebuild, "\nBEGIN;") {
		t.Fatal("concurrent index prebuild must not run in a transaction")
	}
	concurrentBuild := regexp.MustCompile(
		`(?m)^CREATE (?:UNIQUE )?INDEX CONCURRENTLY IF NOT EXISTS `,
	)
	if got := len(concurrentBuild.FindAllString(prebuild, -1)); got != 10 {
		t.Fatalf("concurrent index builds = %d, want 10", got)
	}
	for _, indexName := range savedSnapshotContractIndexNames {
		if !strings.Contains(prebuild, indexName) {
			t.Errorf("prebuild is missing %s", indexName)
		}
	}
	for _, required := range []string{
		"pg_advisory_lock(20819, 20260729)",
		"pg_advisory_unlock(20819, 20260729)",
		"catalog.indisvalid",
		"catalog.indisready",
		"catalog.indislive",
		"actual_access_method <> 'btree'",
		"actual_keys IS DISTINCT FROM expected.key_columns",
		"actual_predicate IS DISTINCT FROM expected.predicate",
		"actual_definition IS DISTINCT FROM expected.definition",
	} {
		if !strings.Contains(prebuild, required) {
			t.Errorf("prebuild is missing exact catalog guard %q", required)
		}
	}
}

func TestSavedSnapshotIndexRecoveryIsInvalidOnly(t *testing.T) {
	recovery := readRepositoryFile(
		t,
		"scripts",
		"recover-saved-snapshot-indexes.sql",
	)

	for _, required := range []string{
		"pg_advisory_lock(20819, 20260729)",
		"pg_advisory_unlock(20819, 20260729)",
		"\\gexec",
		"AND NOT catalog.indisvalid",
		"indexed_table.relname = expected.table_name",
		"pg_get_indexdef(catalog.indexrelid) = expected.definition",
		"refusing recovery:",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("recovery is missing invalid-only guard %q", required)
		}
	}
	if strings.Contains(recovery, "DROP INDEX public.") {
		t.Fatal("recovery contains an unconditional literal DROP INDEX")
	}
}

func TestSavedSnapshotIndexMigrationHasFreshResetOnlyFallback(t *testing.T) {
	migration := readRepositoryFile(
		t,
		"supabase",
		"migrations",
		"20260729000010_saved_snapshot_indexes.sql",
	)

	for _, indexName := range savedSnapshotContractIndexNames {
		if !strings.Contains(migration, indexName) {
			t.Errorf("index migration is missing %s", indexName)
		}
	}
	for _, required := range []string{
		"pg_advisory_xact_lock(20819, 20260729)",
		"EXISTS (SELECT 1 FROM public.snapshot LIMIT 1)",
		"EXISTS (SELECT 1 FROM public.sandbox LIMIT 1)",
		"LOCK TABLE public.sandbox, public.snapshot IN SHARE MODE",
		"IF tables_are_populated AND missing_indexes IS NOT NULL",
		"require concurrent prebuild of all saved-snapshot indexes",
		"IF NOT tables_are_populated THEN",
		"EXECUTE expected.definition",
		"actual_valid",
		"actual_ready",
		"actual_live",
		"actual_keys IS DISTINCT FROM expected.key_columns",
		"actual_predicate IS DISTINCT FROM expected.predicate",
		"actual_definition IS DISTINCT FROM expected.definition",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("index migration is missing guard %q", required)
		}
	}
}

func TestSavedSnapshotContractMigrationIsDarkAtomicAndBounded(t *testing.T) {
	migration := readRepositoryFile(
		t,
		"supabase",
		"migrations",
		"20260729000011_saved_snapshot_contract.sql",
	)

	for _, required := range []string{
		"SET LOCAL lock_timeout = '5s'",
		"SET LOCAL statement_timeout = '30s'",
		"pg_advisory_xact_lock(20819, 20260729)",
		"LOCK TABLE public.feature_flag, public.team_feature_flag",
		"LOCK TABLE public.sandbox IN SHARE ROW EXCLUSIVE MODE",
		"LOCK TABLE public.snapshot IN ACCESS EXCLUSIVE MODE",
		"key = 'sandbox_snapshots_v1'",
		"AND NOT enabled",
		"WHERE kind = 'saved'",
		"WHERE source_snapshot_id IS NOT NULL",
		"WHERE snapshot_operation_id IS NOT NULL",
		"pg_get_expr(",
		"pg_get_indexdef(catalog.indexrelid)",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("contract migration is missing guard %q", required)
		}
	}

	dropLast := regexp.MustCompile(
		`(?s)DROP INDEX public\.snapshot_sandbox_unique;\s*COMMIT;\s*$`,
	)
	if !dropLast.MatchString(migration) {
		t.Fatal("legacy index drop is not the final operation before COMMIT")
	}
}

func TestMigrationCDPrebuildsEveryDatabaseBeforePush(t *testing.T) {
	workflow := readRepositoryFile(t, ".github", "workflows", "cd.yml")

	for _, required := range []string{
		"group: cd-migrate",
		"cancel-in-progress: false",
		"scripts/prebuild-saved-snapshot-indexes.sql",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("migration CD is missing %q", required)
		}
	}
	if strings.Contains(workflow, "recover-saved-snapshot-indexes.sql") {
		t.Fatal("migration CD must never invoke index recovery automatically")
	}

	orderedSteps := []string{
		"Prebuild and verify saved-snapshot indexes in staging",
		"Push migrations to staging",
		"Prebuild and verify saved-snapshot indexes in production primary",
		"Prebuild and verify saved-snapshot indexes in production usw",
		"Push migrations to production primary",
		"Push migrations to usw cell",
	}
	lastPosition := -1
	for _, step := range orderedSteps {
		position := strings.Index(workflow, step)
		if position < 0 {
			t.Fatalf("migration CD is missing step %q", step)
		}
		if position <= lastPosition {
			t.Fatalf("migration CD step %q is out of order", step)
		}
		lastPosition = position
	}
}
