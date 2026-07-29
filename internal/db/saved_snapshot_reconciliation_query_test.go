package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavedSnapshotRetryDeferralPreservesSourceLifecycleFence(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "queries", "snapshots.sql"))
	if err != nil {
		t.Fatalf("read snapshot queries: %v", err)
	}
	queries := string(raw)

	deferQuery := namedSQLQuery(t, queries, "DeferSavedSnapshotReconciliation")
	for _, guard := range []string{
		"id = sqlc.arg(snapshot_id)",
		"team_id = sqlc.arg(team_id)",
		"kind = 'saved'",
		"status = sqlc.arg(expected_status)::snapshot_status",
		"deleted_at IS NULL",
		"updated_at = sqlc.arg(observed_updated_at)",
	} {
		if !strings.Contains(deferQuery, guard) {
			t.Errorf("retry deferral is missing guard %q", guard)
		}
	}
	if !strings.Contains(deferQuery, "SET updated_at = GREATEST(now(), updated_at + interval '1 microsecond')") {
		t.Fatal("retry deferral does not strictly advance the reconciliation timestamp")
	}

	fallbackQuery := namedSQLQuery(t, queries, "FailSavedSnapshotSourceAfterRevocation")
	for _, fence := range []string{
		"intent.created_at AS intent_created_at",
		"source.updated_at <= intent.created_at",
		"source.updated_at <= locked.intent_created_at",
	} {
		if !strings.Contains(fallbackQuery, fence) {
			t.Errorf("source failure fallback is missing immutable lifecycle fence %q", fence)
		}
	}
	for _, widenedFence := range []string{
		"intent.updated_at AS intent_updated_at",
		"source.updated_at <= intent.updated_at",
		"source.updated_at <= locked.intent_updated_at",
	} {
		if strings.Contains(fallbackQuery, widenedFence) {
			t.Errorf("retry-mutable updated_at widens the source lifecycle fence: found %q", widenedFence)
		}
	}
}

func namedSQLQuery(t *testing.T, queries, name string) string {
	t.Helper()
	marker := "-- name: " + name + " "
	start := strings.Index(queries, marker)
	if start < 0 {
		t.Fatalf("missing query %s", name)
	}
	query := queries[start+len(marker):]
	if end := strings.Index(query, "-- name: "); end >= 0 {
		query = query[:end]
	}
	return query
}
