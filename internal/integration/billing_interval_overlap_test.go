//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The rollup scheduler's overlap predicate is spelled for sargability (see
// intervalTeamSetCTE), which is only safe if it selects exactly what the
// COALESCE form did. On a billing path that equivalence is proved against
// Postgres rather than argued: both spellings run over the same rows across
// windows hitting every boundary, and must select identically.

const (
	oldOverlapPredicate = `COALESCE(i.ended_at, LEAST(now(), $2)) > $1`
	newOverlapPredicate = `(i.ended_at IS NULL OR i.ended_at > $1)`
)

// selectOverlapping runs one spelling of the overlap predicate against one
// interval table, scoped to a team so concurrent fixtures cannot bleed in.
func selectOverlapping(t *testing.T, table, predicate string, teamID uuid.UUID, from, to time.Time) []uuid.UUID {
	t.Helper()
	q := `SELECT i.id FROM ` + table + ` i
	      WHERE i.started_at < $2
	        AND $1 < LEAST(now(), $2)
	        AND ` + predicate + `
	        AND i.team_id = $3
	      ORDER BY i.id`
	rows, err := testPool.Query(context.Background(), q, from, to, teamID)
	if err != nil {
		t.Fatalf("%s [%s]: %v", table, predicate, err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return ids
}

// interval describes one fixture row relative to the primary window [W0, W1).
type interval struct {
	label string
	start time.Duration // offset from W0
	end   *time.Duration
	// inWindow is membership in the primary window, asserted explicitly so the
	// test cannot pass by both spellings being equally wrong.
	inWindow bool
}

func dur(d time.Duration) *time.Duration { return &d }

func TestIntegration_BillingIntervalOverlapPredicateEquivalence(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	// Anchor a day back so the fixture windows are unaffected by the wall clock
	// crossing an hour boundary mid-test.
	w0 := time.Now().UTC().Truncate(time.Hour).Add(-24 * time.Hour)
	w1 := w0.Add(time.Hour)

	hour := time.Hour
	cases := []interval{
		{"closed-entirely-before", -3 * hour, dur(-2 * hour), false},
		// Boundary: ended_at == W0. `> $1` is strict, so it does not overlap.
		{"closed-ends-at-window-start", -2 * hour, dur(0), false},
		{"closed-overlaps-start", -30 * time.Minute, dur(30 * time.Minute), true},
		{"closed-entirely-inside", 10 * time.Minute, dur(20 * time.Minute), true},
		{"closed-overlaps-end", 30 * time.Minute, dur(90 * time.Minute), true},
		// Boundary: started_at == W1. `< $2` is strict, so it does not overlap.
		{"closed-starts-at-window-end", hour, dur(2 * hour), false},
		{"closed-spans-window", -hour, dur(2 * hour), true},
		{"closed-entirely-after", 2 * hour, dur(3 * hour), false},
		// Zero-length interval exactly at W0: starts before W1 but ends at W0.
		{"closed-zero-length-at-start", 0, dur(0), false},
		{"open-started-before", -5 * hour, nil, true},
		{"open-started-inside", 30 * time.Minute, nil, true},
		{"open-started-at-window-end", hour, nil, false},
		{"open-started-after", 2 * hour, nil, false},
	}

	// Both tables carry the same predicate, and both FK to (sandbox_id, team_id).
	// storage's end_reason CHECK admits only 'deleted', which compute accepts
	// too, so one reason serves both inserts.
	idsByLabel := map[string]map[string]uuid.UUID{
		"sandbox_compute_billing_interval": {},
		"sandbox_storage_interval":         {},
	}
	for _, c := range cases {
		sandboxID := insertSandboxAt(t, teamID, "ivl-"+uuid.New().String()[:8], "active", w0)
		start := w0.Add(c.start)
		var end *time.Time
		var reason *string
		if c.end != nil {
			e := w0.Add(*c.end)
			r := "deleted"
			end, reason = &e, &r
		}

		var computeID, storageID uuid.UUID
		if err := testPool.QueryRow(ctx,
			`INSERT INTO sandbox_compute_billing_interval
			   (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
			 VALUES ($1, $2, 1, 512, $3, $4, $5) RETURNING id`,
			sandboxID, teamID, start, end, reason,
		).Scan(&computeID); err != nil {
			t.Fatalf("insert compute interval %s: %v", c.label, err)
		}
		if err := testPool.QueryRow(ctx,
			`INSERT INTO sandbox_storage_interval
			   (sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason)
			 VALUES ($1, $2, 1024, $3, $4, $5) RETURNING id`,
			sandboxID, teamID, start, end, reason,
		).Scan(&storageID); err != nil {
			t.Fatalf("insert storage interval %s: %v", c.label, err)
		}
		idsByLabel["sandbox_compute_billing_interval"][c.label] = computeID
		idsByLabel["sandbox_storage_interval"][c.label] = storageID
	}

	now := time.Now().UTC()
	windows := []struct {
		name     string
		from, to time.Time
	}{
		{"primary-hour", w0, w1},
		{"wide", w0.Add(-3 * hour), w0.Add(3 * hour)},
		{"empty-region", w0.Add(-10 * hour), w0.Add(-9 * hour)},
		// Straddles now(), so LEAST(now(), $2) resolves to now() rather than $2 —
		// the case where the two spellings could diverge if the guard were dropped.
		{"straddles-now", now.Add(-hour), now.Add(hour)},
		// Entirely in the future: the guard is false, so both must select nothing.
		{"future", now.Add(2 * hour), now.Add(3 * hour)},
	}

	for table := range idsByLabel {
		for _, w := range windows {
			oldIDs := selectOverlapping(t, table, oldOverlapPredicate, teamID, w.from, w.to)
			newIDs := selectOverlapping(t, table, newOverlapPredicate, teamID, w.from, w.to)

			if len(oldIDs) != len(newIDs) {
				t.Fatalf("%s/%s: predicates disagree on count: old=%d new=%d",
					table, w.name, len(oldIDs), len(newIDs))
			}
			for i := range oldIDs {
				if oldIDs[i] != newIDs[i] {
					t.Fatalf("%s/%s: predicates disagree at %d: old=%s new=%s",
						table, w.name, i, oldIDs[i], newIDs[i])
				}
			}
		}

		// Equivalence alone would hold if both spellings were wrong in the same
		// way, so pin the primary window's membership to the intended semantics.
		got := map[uuid.UUID]bool{}
		for _, id := range selectOverlapping(t, table, newOverlapPredicate, teamID, w0, w1) {
			got[id] = true
		}
		for _, c := range cases {
			id := idsByLabel[table][c.label]
			if got[id] != c.inWindow {
				t.Errorf("%s: %s in primary window = %v, want %v",
					table, c.label, got[id], c.inWindow)
			}
		}
		if len(got) == 0 {
			t.Fatalf("%s: primary window selected nothing — fixture is not exercising the predicate", table)
		}
	}
}
