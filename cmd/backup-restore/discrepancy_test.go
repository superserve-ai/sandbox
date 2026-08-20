package main

import (
	"strings"
	"testing"
)

// A textual pin on the query's semantics-bearing clauses (head-pointer
// join, bucket-scoped existence coverage, selection predicates). No SQL
// parser is in the module, so this test does not execute the query.
func TestDiscrepancyQueryInvariants(t *testing.T) {
	mustContain := []string{
		// The join target is the head pointer, never snapshot history.
		"LEFT JOIN snapshot s ON s.id = sb.snapshot_id",
		// Coverage is existence of a backup_generation row scoped to the
		// audited bucket, matching how the uploader and sweep track
		// coverage: a sandbox whose only rows point at a different
		// (rotated-out) bucket must enumerate as uncovered.
		"NOT EXISTS (SELECT 1 FROM backup_generation bg WHERE bg.sandbox_id = sb.id AND bg.bucket = $2)",
		// Selection: paused, live, with the optional host filter.
		"sb.status = 'paused'",
		"sb.destroyed_at IS NULL",
		"($1 = '' OR sb.host_id = $1)",
	}
	for _, s := range mustContain {
		if !strings.Contains(discrepancyQuery, s) {
			t.Errorf("query lost required clause %q", s)
		}
	}
	mustNotContain := []string{
		// A lateral newest-by-created_at join would misclassify NULL
		// heads with historical rows; recency over backup_generation is
		// irrelevant to existence-based coverage.
		"LATERAL",
		"created_at DESC",
		"completed_at",
	}
	for _, s := range mustNotContain {
		if strings.Contains(discrepancyQuery, s) {
			t.Errorf("query must not contain %q", s)
		}
	}
}
