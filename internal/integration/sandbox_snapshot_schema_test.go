//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET deleted_at = now() WHERE id = $1`, third); err != nil {
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
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'ready', overlay_path = '/o', snapshot_path = '/v', mem_path = '/m' WHERE id = $1`, first); err == nil {
		t.Fatal("deleting is terminal; deleting to ready should be refused")
	}
	var live int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_snapshot WHERE team_id = $1 AND deleted_at IS NULL AND status IN ('creating', 'ready')`, teamID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live > 3 {
		t.Fatalf("live snapshots exceed the team cap: %d", live)
	}
}
