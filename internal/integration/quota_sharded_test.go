//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// insertSandboxRow drives the quota trigger directly with a minimal counted
// row, concurrently safe on the shared pool. Returns the generated ID so
// lifecycle tests can transition the row afterwards.
func insertSandboxRow(ctx context.Context, teamID uuid.UUID, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		ID:         id,
		TeamID:     teamID,
		Name:       name,
		Status:     db.SandboxStatusStarting,
		VcpuCount:  1,
		MemoryMib:  1,
		HostID:     "default",
		Metadata:   []byte(`{}`),
		TemplateID: pgtype.UUID{},
	})
	return id, err
}

func isQuotaErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "SS001"
}

func activeCount(t *testing.T, teamID uuid.UUID) int {
	t.Helper()
	var n int
	err := testPool.QueryRow(context.Background(),
		`SELECT COALESCE(active_sandbox_count, 0) FROM team_active_sandbox_counts WHERE team_id = $1`,
		teamID).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0 // no shard rows yet reads as zero
	}
	if err != nil {
		t.Fatalf("query active count: %v", err)
	}
	return n
}

// The hard limit must hold exactly under a concurrent burst — the failure mode
// of a sharded counter without a boundary check. All admissions here take the
// exact path (max <= margin), so exactly max rows are admitted and the rest
// fail with SS001.
func TestIntegration_QuotaHardLimitUnderConcurrentBurst(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	const max = 50
	const attempts = 200
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = $2 WHERE id = $1`, teamID, max); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	var admitted, rejected, unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := insertSandboxRow(ctx, teamID, fmt.Sprintf("burst-%d", i))
			switch {
			case err == nil:
				admitted.Add(1)
			case isQuotaErr(err):
				rejected.Add(1)
			default:
				unexpected.Add(1)
				t.Errorf("insert %d: unexpected error: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if n := admitted.Load(); n != max {
		t.Fatalf("expected exactly %d admitted, got %d (rejected=%d unexpected=%d)",
			max, n, rejected.Load(), unexpected.Load())
	}
	if got := activeCount(t, teamID); got != max {
		t.Fatalf("view count %d != admitted %d", got, max)
	}
}

// Same burst shape for a team whose limit exceeds the fast-path margin, so
// admissions cross from the lock-free region into the boundary region
// mid-burst. The committed total must still never exceed the limit.
func TestIntegration_QuotaHardLimitAcrossFastPathBoundary(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	const max = 200 // > margin (128): starts on the fast path, ends on the boundary path
	const attempts = 260
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = $2 WHERE id = $1`, teamID, max); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := insertSandboxRow(ctx, teamID, fmt.Sprintf("band-%d", i)); err == nil {
				admitted.Add(1)
			} else if !isQuotaErr(err) {
				t.Errorf("insert %d: unexpected error: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if n := admitted.Load(); n > max {
		t.Fatalf("hard limit crossed: %d admitted > max %d", n, max)
	}
	if got := activeCount(t, teamID); got > max {
		t.Fatalf("view count %d exceeds max %d", got, max)
	}
}

// The watcher's drift check must flag a shard sum that disagrees with the
// counted truth — drift has no other detection path, and a low-biased sum
// silently widens the team's quota.
func TestIntegration_QuotaCounterDriftDetection(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	if _, err := insertSandboxRow(ctx, teamID, "drift-probe"); err != nil {
		t.Fatalf("create: %v", err)
	}
	driftFor := func() (db.ListQuotaCounterDriftRow, bool) {
		t.Helper()
		rows, err := testQueries.ListQuotaCounterDrift(ctx)
		if err != nil {
			t.Fatalf("drift query: %v", err)
		}
		for _, r := range rows {
			if r.TeamID == teamID {
				return r, true
			}
		}
		return db.ListQuotaCounterDriftRow{}, false
	}

	if r, found := driftFor(); found {
		t.Fatalf("clean state reported as drift: sum=%d true=%d", r.ShardSum, r.TrueCount)
	}

	// Simulate the undetectable-by-triggers fault: a stray decrement biasing
	// the sum below truth (the quota-widening direction).
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt) VALUES ($1, 15, -1)
		 ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt - 1`, teamID); err != nil {
		t.Fatalf("inject drift: %v", err)
	}
	r, found := driftFor()
	if !found {
		t.Fatal("low-biased shard sum not reported as drift")
	}
	if r.ShardSum != r.TrueCount-1 {
		t.Errorf("drift row sum=%d true=%d, want sum = true-1", r.ShardSum, r.TrueCount)
	}

	// Repair and confirm the report clears.
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt) VALUES ($1, 15, 1)
		 ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt + 1`, teamID); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if r, found := driftFor(); found {
		t.Fatalf("repaired state still reported as drift: sum=%d true=%d", r.ShardSum, r.TrueCount)
	}

	// Dormant undercount: a negative raw sum with zero counted sandboxes must
	// still be reported — the floored view reads 0 here and would hide it.
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox WHERE team_id = $1`, teamID); err != nil {
		t.Fatalf("clear sandboxes: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_sandbox_counter AS c (team_id, shard, cnt) VALUES ($1, 14, -1)
		 ON CONFLICT (team_id, shard) DO UPDATE SET cnt = c.cnt - 1`, teamID); err != nil {
		t.Fatalf("inject dormant drift: %v", err)
	}
	r, found = driftFor()
	if !found {
		t.Fatal("dormant negative sum (no counted sandboxes) not reported as drift")
	}
	if r.ShardSum != -1 || r.TrueCount != 0 {
		t.Errorf("dormant drift row sum=%d true=%d, want -1/0", r.ShardSum, r.TrueCount)
	}
}

// Increments and decrements can land on different shards, so individual shard
// rows go negative; the summed view must stay correct across the lifecycle and
// floor at zero.
func TestIntegration_QuotaShardSumTracksLifecycle(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	ids := make([]uuid.UUID, 3)
	for i := range ids {
		var err error
		if ids[i], err = insertSandboxRow(ctx, teamID, fmt.Sprintf("lc-%d", i)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if got := activeCount(t, teamID); got != 3 {
		t.Fatalf("after 3 creates: count %d", got)
	}

	// Leave the counted set two different ways: destroy and fail.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET destroyed_at = now(), status = 'deleted' WHERE id = $1`, ids[0]); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'failed' WHERE id = $1`, ids[1]); err != nil {
		t.Fatalf("fail: %v", err)
	}
	if got := activeCount(t, teamID); got != 1 {
		t.Fatalf("after destroy+fail: count %d, want 1", got)
	}

	// Hard DELETE of the last counted row releases it too.
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox WHERE id = $1`, ids[2]); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := activeCount(t, teamID); got != 0 {
		t.Fatalf("after delete: count %d, want 0", got)
	}
}
