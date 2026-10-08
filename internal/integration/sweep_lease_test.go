//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Every replica runs the sweep each tick; only one may do the work, or the
// population is swept N times over.
func TestIntegration_SweepLeaseAdmitsOneHolder(t *testing.T) {
	ctx := context.Background()
	name := "sweep-test-" + uuid.NewString()

	var won int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := testQueries.ClaimSweepLease(ctx, db.ClaimSweepLeaseParams{
				Name: name, LockedBy: uuid.NewString(), LeaseSeconds: 120,
			})
			switch {
			case err == nil:
				atomic.AddInt32(&won, 1)
			case errors.Is(err, pgx.ErrNoRows):
			default:
				t.Errorf("claim: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d of 8 contenders held the lease, want exactly 1", won)
	}
}

// A cursor kept in process memory restarts its successor at the beginning of
// the population. Held in the lease row, a handover resumes mid-sweep.
func TestIntegration_SweepCursorSurvivesAHandover(t *testing.T) {
	ctx := context.Background()
	name := "sweep-test-" + uuid.NewString()
	first, second := uuid.NewString(), uuid.NewString()
	page := uuid.New()

	if _, err := testQueries.ClaimSweepLease(ctx, db.ClaimSweepLeaseParams{
		Name: name, LockedBy: first, LeaseSeconds: 120,
	}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := testQueries.AdvanceSweepCursor(ctx, db.AdvanceSweepCursorParams{
		Name: name, LockedBy: first, CursorID: pgtype.UUID{Bytes: page, Valid: true},
	}); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// The holder's lease lapses and another replica takes over.
	if _, err := testPool.Exec(ctx,
		`UPDATE sweep_lease SET locked_until = now() - interval '1 second' WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}
	got, err := testQueries.ClaimSweepLease(ctx, db.ClaimSweepLeaseParams{
		Name: name, LockedBy: second, LeaseSeconds: 120,
	})
	if err != nil {
		t.Fatalf("successor claim: %v", err)
	}
	if !got.Valid || uuid.UUID(got.Bytes) != page {
		t.Fatalf("successor resumed at %v, want the page the first holder reached (%s)", got, page)
	}

	// A lapsed holder must not move the cursor its successor is working from.
	if err := testQueries.AdvanceSweepCursor(ctx, db.AdvanceSweepCursorParams{
		Name: name, LockedBy: first, CursorID: pgtype.UUID{},
	}); err != nil {
		t.Fatal(err)
	}
	var still pgtype.UUID
	if err := testPool.QueryRow(ctx, `SELECT cursor_id FROM sweep_lease WHERE name = $1`, name).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if !still.Valid || uuid.UUID(still.Bytes) != page {
		t.Fatalf("a lapsed holder reset the cursor to %v", still)
	}
}
