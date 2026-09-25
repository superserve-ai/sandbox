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
	params := func(kind string, key *string) db.CreateSandboxSnapshotParams {
		return db.CreateSandboxSnapshotParams{
			ID: uuid.New(), TeamID: teamID, SandboxID: sandboxID, Kind: kind, IdempotencyKey: key,
			SecretBindings: []byte("[]"), SweepAfter: time.Now().Add(15 * time.Minute),
		}
	}
	// The row takes what it records from a source still live: not one
	// starting, and not one without an overlay.
	if _, err := q.CreateSandboxSnapshot(ctx, params("mem+fs", nil)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("snapshot of a starting sandbox: want no rows, got %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', base_path = '/base.ext4', disk_mib = 4096 WHERE id = $1`, sandboxID); err != nil {
		t.Fatal(err)
	}
	key := "deploy-1"
	create := func(kind string, key *string) db.SandboxSnapshot {
		t.Helper()
		row, err := q.CreateSandboxSnapshot(ctx, params(kind, key))
		if err != nil {
			t.Fatalf("create %s: %v", kind, err)
		}
		return row
	}
	fs := create("fs", &key)
	if fs.Status != "creating" {
		t.Fatalf("new row status %q", fs.Status)
	}
	if fs.HostID != "default" || fs.BasePath != "/base.ext4" || fs.DiskMib != 4096 || fs.VcpuCount != 1 {
		t.Fatalf("row did not take the source's values: %+v", fs)
	}
	if _, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: fs.ID, TeamID: teamID, StaleBefore: time.Now().Add(-time.Hour)}); !errors.Is(err, pgx.ErrNoRows) {
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
	deleting, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: fs.ID, TeamID: teamID, StaleBefore: time.Now().Add(-time.Hour)})
	if err != nil || deleting.Status != "deleting" {
		t.Fatalf("begin delete: %+v %v", deleting.Status, err)
	}
	if n, _ := q.MarkSandboxSnapshotDeleted(ctx, fs.ID); n != 1 {
		t.Fatalf("mark deleted changed %d rows", n)
	}
	if _, err := q.GetSandboxSnapshot(ctx, db.GetSandboxSnapshotParams{ID: fs.ID, TeamID: teamID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted row still readable: %v", err)
	}
	// The key still names it, so its request learns it was deleted.
	if got, err := q.GetSandboxSnapshotByIdempotencyKey(ctx, db.GetSandboxSnapshotByIdempotencyKeyParams{TeamID: teamID, SandboxID: sandboxID, IdempotencyKey: &key}); err != nil || got.ID != fs.ID || !got.DeletedAt.Valid {
		t.Fatalf("by key after delete: %v %v deleted=%v", got.ID, err, got.DeletedAt.Valid)
	}
	if n, _ := q.CountSandboxSnapshots(ctx, db.CountSandboxSnapshotsParams{TeamID: teamID, SandboxID: sandboxID}); n != 1 {
		t.Fatalf("count after delete %d, want 1", n)
	}

	// The sweep claims a creating row once it is due and a deleting row at
	// once, never a fresh row, and a claimed row is not due again until its
	// retry time; a capture whose answer was lost is due at once.
	old := create("fs", nil)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET sweep_after = now() - interval '1 hour' WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	vmstate, memFile := "/saved/m/vmstate.snap", "/saved/m/mem.diff"
	if _, err := q.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: mem.ID, OverlayPath: &overlay, SnapshotPath: &vmstate, MemPath: &memFile, SizeBytes: 1}); err != nil {
		t.Fatalf("mark mem+fs ready: %v", err)
	}
	if _, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: mem.ID, TeamID: teamID, StaleBefore: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	fresh := create("fs", nil)
	claim := func() map[uuid.UUID]bool {
		t.Helper()
		rows, err := q.ClaimStuckSandboxSnapshots(ctx, db.ClaimStuckSandboxSnapshotsParams{RetryAt: time.Now().Add(time.Minute), RowLimit: 50})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[uuid.UUID]bool{}
		for _, r := range rows {
			seen[r.ID] = true
		}
		return seen
	}
	seen := claim()
	if !seen[old.ID] || !seen[mem.ID] || seen[fresh.ID] {
		t.Fatalf("claimed rows: old=%v deleting=%v fresh=%v", seen[old.ID], seen[mem.ID], seen[fresh.ID])
	}
	if seen = claim(); seen[old.ID] || seen[mem.ID] {
		t.Fatalf("claimed again before their retry time: old=%v deleting=%v", seen[old.ID], seen[mem.ID])
	}
	if n, err := q.ScheduleSandboxSnapshotSweep(ctx, fresh.ID); err != nil || n != 1 {
		t.Fatalf("schedule: %d %v", n, err)
	}
	if seen = claim(); !seen[fresh.ID] {
		t.Fatal("a released capture was not claimed at once")
	}
	// A deleted row is nobody's: the host refuses its id from then on.
	if n, _ := q.ScheduleSandboxSnapshotSweep(ctx, fs.ID); n != 0 {
		t.Fatalf("a deleted row was scheduled for the sweep (%d rows)", n)
	}
	if seen = claim(); seen[fs.ID] {
		t.Fatal("a deleted row was claimed")
	}

	// A destroyed source gives no snapshot, whatever was read of it before.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET destroyed_at = now(), status = 'deleted' WHERE id = $1`, sandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateSandboxSnapshot(ctx, params("mem+fs", nil)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("snapshot of a destroyed sandbox: want no rows, got %v", err)
	}

	// A capture unsettled for an hour is the user's to retire.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET created_at = now() - interval '2 hours' WHERE id = $1`, fresh.ID); err != nil {
		t.Fatal(err)
	}
	retired, err := q.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: fresh.ID, TeamID: teamID, StaleBefore: time.Now().Add(-time.Hour)})
	if err != nil || retired.Status != "deleting" {
		t.Fatalf("delete of a stale capture: %v %v", retired.Status, err)
	}
}
