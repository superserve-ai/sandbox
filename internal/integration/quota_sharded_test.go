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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// insertSandboxRow drives the quota trigger directly with a minimal counted
// row, concurrently safe on the shared pool.
func insertSandboxRow(ctx context.Context, teamID uuid.UUID, name string) error {
	_, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
		ID:         uuid.New(),
		TeamID:     teamID,
		Name:       name,
		Status:     db.SandboxStatusStarting,
		VcpuCount:  1,
		MemoryMib:  1,
		HostID:     "default",
		Metadata:   []byte(`{}`),
		TemplateID: pgtype.UUID{},
	})
	return err
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
	if err != nil {
		// No shard rows yet reads as zero.
		return 0
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
			err := insertSandboxRow(ctx, teamID, fmt.Sprintf("burst-%d", i))
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

	const max = 100 // > margin (64): starts on the fast path, ends on the boundary path
	const attempts = 160
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = $2 WHERE id = $1`, teamID, max); err != nil {
		t.Fatalf("set max_sandboxes: %v", err)
	}

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := insertSandboxRow(ctx, teamID, fmt.Sprintf("band-%d", i)); err == nil {
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

// Increments and decrements land on random shards, so individual shard rows go
// negative; the summed view must stay correct across the lifecycle and floor
// at zero.
func TestIntegration_QuotaShardSumTracksLifecycle(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	ids := make([]uuid.UUID, 3)
	for i := range ids {
		ids[i] = uuid.New()
		if _, err := testQueries.CreateSandbox(ctx, db.CreateSandboxParams{
			ID: ids[i], TeamID: teamID, Name: fmt.Sprintf("lc-%d", i),
			Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 1,
			HostID: "default", Metadata: []byte(`{}`),
		}); err != nil {
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
