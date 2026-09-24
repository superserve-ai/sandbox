//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func insertSnapshotRow(ctx context.Context, teamID, sandboxID uuid.UUID, key *string) (uuid.UUID, error) {
	var id uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO sandbox_snapshot (team_id, sandbox_id, kind, host_id, vcpu_count, memory_mib, disk_mib, base_path, idempotency_key)
		VALUES ($1, $2, 'mem+fs', 'default', 1, 1024, 4096, '/base.ext4', $3)
		RETURNING id`, teamID, sandboxID, key).Scan(&id)
	return id, err
}

func TestSandboxSnapshotSchema(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_snapshots = 3, max_snapshots_per_sandbox = 2 WHERE id = $1`, teamID); err != nil {
		t.Fatal(err)
	}
	a, err := insertSandboxRow(ctx, teamID, "snap-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := insertSandboxRow(ctx, teamID, "snap-b")
	if err != nil {
		t.Fatal(err)
	}

	// Per-sandbox cap: two live rows, the third is refused.
	first, err := insertSnapshotRow(ctx, teamID, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, a, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, a, nil); pgCode(err) != "SS002" {
		t.Fatalf("third snapshot of one sandbox: want SS002, got %v", err)
	}

	// A failed capture stops counting; a deleted one too.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'failed' WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	third, err := insertSnapshotRow(ctx, teamID, a, nil)
	if err != nil {
		t.Fatalf("after a failed row: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET deleted_at = now() WHERE id = $1`, third); pgCode(err) != "23514" {
		t.Fatalf("deleted without deleting: want 23514, got %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'deleting', deleted_at = now() WHERE id = $1`, third); err != nil {
		t.Fatal(err)
	}

	// Team cap counts across sandboxes: a(1 live) + b(2) = 3, the next is refused.
	key := "retry-1"
	keyed, err := insertSnapshotRow(ctx, teamID, b, &key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, b, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, a, nil); pgCode(err) != "SS002" {
		t.Fatalf("over team cap: want SS002, got %v", err)
	}

	// An idempotent retry surfaces as the unique violation, not as quota.
	if _, err := insertSnapshotRow(ctx, teamID, b, &key); pgCode(err) != "23505" {
		t.Fatalf("idempotent retry: want 23505, got %v", err)
	}

	// A ready row must name its artifacts.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'ready' WHERE id = $1`, keyed); pgCode(err) != "23514" {
		t.Fatalf("ready without artifacts: want 23514, got %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'ready', overlay_path = '/o', snapshot_path = '/v', mem_path = '/m' WHERE id = $1`, keyed); err != nil {
		t.Fatalf("ready with artifacts: %v", err)
	}

	// Failed and deleted rows left the count, so they can never come back.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'ready', overlay_path = '/o', snapshot_path = '/v', mem_path = '/m' WHERE id = $1`, first); err == nil {
		t.Fatal("reviving a failed snapshot should be refused")
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET deleted_at = NULL WHERE id = $1`, third); err == nil {
		t.Fatal("undeleting a snapshot should be refused")
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'deleting' WHERE id = $1`, first); err != nil {
		t.Fatalf("failed to deleting is the one allowed exit: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET sandbox_id = $1 WHERE id = $2`, a, keyed); err == nil {
		t.Fatal("moving a snapshot to another sandbox should be refused")
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'ready', overlay_path = '/o', snapshot_path = '/v', mem_path = '/m' WHERE id = $1`, first); err == nil {
		t.Fatal("deleting is terminal; deleting to ready should be refused")
	}
	var live int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_snapshot WHERE team_id = $1 AND status IN ('creating', 'ready')`, teamID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live > 3 {
		t.Fatalf("live snapshots exceed the team cap: %d", live)
	}

	// A row being deleted has given its slot back: with the team cap raised to
	// four, the three live rows plus the one in deleting still admit an insert.
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_snapshots = 4 WHERE id = $1`, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, a, nil); err != nil {
		t.Fatalf("insert next to a deleting row: %v", err)
	}

	// Tenant boundaries: a snapshot belongs to its sandbox's team, and a fork
	// can only point at a snapshot of its own team.
	otherTeam, _ := seedTeamAndKey(t)
	if _, err := insertSnapshotRow(ctx, otherTeam, a, nil); pgCode(err) != "23503" {
		t.Fatalf("snapshot of another team's sandbox: want 23503, got %v", err)
	}
	otherSandbox, err := insertSandboxRow(ctx, otherTeam, "snap-other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET source_snapshot_id = $1 WHERE id = $2`, keyed, otherSandbox); pgCode(err) != "23503" {
		t.Fatalf("fork pointing at another team's snapshot: want 23503, got %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET source_snapshot_id = $1 WHERE id = $2`, keyed, a); err != nil {
		t.Fatalf("fork pointing at own team's snapshot: %v", err)
	}

	// Live snapshots pin their template build and block template deletion,
	// even with no sandbox left on it.
	base := "/base.ext4"
	refs, err := testQueries.CountActiveSandboxesAtBasePath(ctx, &base)
	if err != nil || refs == 0 {
		t.Fatalf("base path referenced by live snapshots: refs=%d err=%v", refs, err)
	}
	pinned, err := testQueries.ListPinnedBuildPaths(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pinned {
		if p != nil && *p == base {
			found = true
		}
	}
	if !found {
		t.Fatal("snapshot base path missing from the pinned build paths")
	}
	tpl := insertTemplateAt(t, teamID, "snap-tpl", time.Now())
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_snapshots = 10, max_snapshots_per_sandbox = 10 WHERE id = $1`, teamID); err != nil {
		t.Fatal(err)
	}
	var pinning uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO sandbox_snapshot (team_id, sandbox_id, template_id, kind, host_id, vcpu_count, memory_mib, disk_mib, base_path)
		VALUES ($1, $2, $3, 'fs', 'default', 1, 1024, 4096, '/tpl-base.ext4')
		RETURNING id`, teamID, b, tpl).Scan(&pinning); err != nil {
		t.Fatal(err)
	}
	del, err := testQueries.SoftDeleteTemplateIfUnused(ctx, db.SoftDeleteTemplateIfUnusedParams{ID: tpl, TeamID: teamID})
	if err != nil || !del.Found || del.Deleted || del.LiveCount != 1 {
		t.Fatalf("template with a live snapshot: %+v err=%v", del, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'deleting' WHERE id = $1`, pinning); err != nil {
		t.Fatal(err)
	}
	del, err = testQueries.SoftDeleteTemplateIfUnused(ctx, db.SoftDeleteTemplateIfUnusedParams{ID: tpl, TeamID: teamID})
	if err != nil || !del.Deleted {
		t.Fatalf("template after its snapshot is deleting: %+v err=%v", del, err)
	}
}

// The in-flight limit is the trigger's, counted under the team lock, so a
// burst of inserts cannot pass it; an idempotent retry is not a new capture.
func TestSandboxSnapshotInFlightLimit(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_snapshots_in_flight = 1 WHERE id = $1`, teamID); err != nil {
		t.Fatal(err)
	}
	sb, err := insertSandboxRow(ctx, teamID, "snap-flight")
	if err != nil {
		t.Fatal(err)
	}
	key := "flight-1"
	first, err := insertSnapshotRow(ctx, teamID, sb, &key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, sb, nil); pgCode(err) != "SS003" {
		t.Fatalf("second capture in flight: want SS003, got %v", err)
	}
	if _, err := insertSnapshotRow(ctx, teamID, sb, &key); pgCode(err) != "23505" {
		t.Fatalf("idempotent retry at the in-flight limit: want 23505, got %v", err)
	}
	// Six at once against a limit of one: exactly one gets in.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'failed' WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := insertSnapshotRow(ctx, teamID, sb, nil); err == nil {
				admitted.Add(1)
			} else if pgCode(err) != "SS003" {
				t.Errorf("burst insert: %v", err)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("burst admitted %d captures past a limit of one", admitted.Load())
	}
}

// A snapshot insert holds its team-row lock until commit; sandbox creation
// for the same team must not wait on it.
func TestSandboxSnapshotInsertDoesNotBlockSandboxCreate(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	src, err := insertSandboxRow(ctx, teamID, "snap-lock-src")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO sandbox_snapshot (team_id, sandbox_id, kind, host_id, vcpu_count, memory_mib, disk_mib, base_path)
		VALUES ($1, $2, 'fs', 'default', 1, 1024, 4096, '/base.ext4')`, teamID, src); err != nil {
		t.Fatal(err)
	}
	// Bounded wait: a lock conflict shows up as a timeout, not a hang.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := insertSandboxRow(waitCtx, teamID, "snap-lock-other"); err != nil {
		t.Fatalf("sandbox insert blocked behind an open snapshot insert: %v", err)
	}
}
