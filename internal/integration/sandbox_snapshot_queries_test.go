//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

// The control plane's snapshot queries against the real triggers: a row is
// ready only once, is deleted only through deleting, and cannot be deleted
// while its capture may still commit.
func TestSandboxSnapshotQueries(t *testing.T) {
	ctx := context.Background()
	q := db.New(testPool)
	teamID, _ := seedTeamAndKey(t)
	sandboxID, err := insertSandboxRow(ctx, teamID, "snap-q")
	if err != nil {
		t.Fatal(err)
	}
	key := "deploy-1"
	create := func(kind string, key *string) db.SandboxSnapshot {
		t.Helper()
		row, err := q.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
			ID: uuid.New(), TeamID: teamID, SandboxID: sandboxID, Kind: kind, IdempotencyKey: key,
			HostID: "default", VcpuCount: 1, MemoryMib: 1024, DiskMib: 4096, BasePath: "/base.ext4",
			NetworkConfig: []byte("{}"), SecretBindings: []byte("[]"),
		})
		if err != nil {
			t.Fatalf("create %s: %v", kind, err)
		}
		return row
	}
	fs := create("fs", &key)
	if fs.Status != "creating" {
		t.Fatalf("new row status %q", fs.Status)
	}
	if n, _ := q.CountTeamSnapshotsCreating(ctx, teamID); n != 1 {
		t.Fatalf("creating count %d, want 1", n)
	}
	if _, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: fs.ID, TeamID: teamID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("delete of a creating row: want no rows, got %v", err)
	}
	if got, err := q.GetSandboxSnapshotByIdempotencyKey(ctx, db.GetSandboxSnapshotByIdempotencyKeyParams{TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: &key}); err != nil || got.ID != fs.ID {
		t.Fatalf("by key: %v %v", got.ID, err)
	}

	overlay := "/saved/x/overlay.ext4"
	ready, err := q.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: fs.ID, OverlayPath: &overlay, SizeBytes: 4096})
	if err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	if ready.Status != "ready" || !ready.ReadyAt.Valid || ready.SizeBytes != 4096 {
		t.Fatalf("ready row: %+v", ready)
	}
	if _, err := q.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: fs.ID, OverlayPath: &overlay, SizeBytes: 1}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second mark ready: want no rows, got %v", err)
	}
	if n, _ := q.MarkSandboxSnapshotFailed(ctx, fs.ID); n != 0 {
		t.Fatalf("failing a ready row changed %d rows", n)
	}
	name := "golden"
	if renamed, err := q.RenameSandboxSnapshot(ctx, db.RenameSandboxSnapshotParams{ID: fs.ID, TeamID: teamID, Name: &name}); err != nil || renamed.Name == nil || *renamed.Name != name {
		t.Fatalf("rename: %v", err)
	}
	if _, err := q.GetSandboxSnapshot(ctx, db.GetSandboxSnapshotParams{ID: fs.ID, TeamID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("another team's read: want no rows, got %v", err)
	}

	// Newest first; the second row is newer.
	mem := create("mem+fs", nil)
	rows, err := q.ListSandboxSnapshots(ctx, db.ListSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID})
	if err != nil || len(rows) != 2 || rows[0].ID != mem.ID {
		t.Fatalf("list: %d rows, err %v", len(rows), err)
	}
	if n, _ := q.CountSandboxSnapshots(ctx, db.CountSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID}); n != 2 {
		t.Fatalf("count %d, want 2", n)
	}

	// Deleting is the only way out, and a deleted row is gone from every read.
	deleting, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: fs.ID, TeamID: teamID})
	if err != nil || deleting.Status != "deleting" {
		t.Fatalf("begin delete: %+v %v", deleting.Status, err)
	}
	if n, _ := q.MarkSandboxSnapshotDeleted(ctx, fs.ID); n != 1 {
		t.Fatalf("mark deleted changed %d rows", n)
	}
	if _, err := q.GetSandboxSnapshot(ctx, db.GetSandboxSnapshotParams{ID: fs.ID, TeamID: teamID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted row still readable: %v", err)
	}
	if n, _ := q.CountSandboxSnapshots(ctx, db.CountSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID}); n != 1 {
		t.Fatalf("count after delete %d, want 1", n)
	}

	// The sweep sees an old creating row and any deleting row, never a fresh one.
	old := create("fs", nil)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET created_at = now() - interval '1 hour' WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	vmstate, memFile := "/saved/m/vmstate.snap", "/saved/m/mem.diff"
	if _, err := q.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: mem.ID, OverlayPath: &overlay, SnapshotPath: &vmstate, MemPath: &memFile, SizeBytes: 1}); err != nil {
		t.Fatalf("mark mem+fs ready: %v", err)
	}
	if _, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: mem.ID, TeamID: teamID}); err != nil {
		t.Fatal(err)
	}
	fresh := create("fs", nil)
	stuck, err := q.ListStuckSandboxSnapshots(ctx, db.ListStuckSandboxSnapshotsParams{CreatingBefore: time.Now().Add(-15 * time.Minute), RowLimit: 50})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range stuck {
		seen[r.ID] = true
	}
	if !seen[old.ID] || !seen[mem.ID] || seen[fresh.ID] {
		t.Fatalf("stuck rows: old=%v deleting=%v fresh=%v", seen[old.ID], seen[mem.ID], seen[fresh.ID])
	}
}
