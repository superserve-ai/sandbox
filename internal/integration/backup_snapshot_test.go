//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
)

func insertSavedSnapshot(t *testing.T, teamID, sandboxID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO sandbox_snapshot (team_id, sandbox_id, kind, host_id, vcpu_count, memory_mib, disk_mib, base_path)
		VALUES ($1, $2, 'mem+fs', 'host-a', 1, 1024, 4096, '/var/lib/sandbox/base.ext4')
		RETURNING id`, teamID, sandboxID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func recordSnapshotGeneration(t *testing.T, snapshotID uuid.UUID, bucket, generation string) {
	t.Helper()
	files := []byte(`[{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `","base_sha256":"` + gcBaseSHA + `"}]`)
	if _, err := testQueries.RecordSnapshotBackupGeneration(context.Background(), db.RecordSnapshotBackupGenerationParams{
		SnapshotID: pgtype.UUID{Bytes: snapshotID, Valid: true}, Generation: generation, Bucket: bucket,
		CompletedAt: time.Now().UTC().Add(-time.Hour), Files: files,
	}); err != nil {
		t.Fatal(err)
	}
}

// A saved snapshot's backup is its own row: the sandbox it came from being
// deleted does not make it purgeable, deleting the snapshot does, and a late
// report of a purged generation reopens its purge.
func TestIntegration_BackupGC_SnapshotBackupsFollowTheSnapshot(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	bucket := "gc-" + uuid.NewString()
	source := createAndDeleteSandbox(t, apiKey, false)
	kept := insertSavedSnapshot(t, teamID, source)
	gone := insertSavedSnapshot(t, teamID, source)
	genKept := "5555555555555555555555555555555555555555555555555555555555555555"
	genGone := "6666666666666666666666666666666666666666666666666666666666666666"
	recordSnapshotGeneration(t, kept, bucket, genKept)
	recordSnapshotGeneration(t, gone, bucket, genGone)

	claim := func() []db.ClaimSnapshotBackupGenerationsToPurgeRow {
		rows, err := testQueries.ClaimSnapshotBackupGenerationsToPurge(ctx, db.ClaimSnapshotBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: 900, BatchSize: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	sandboxClaim := func() int {
		rows, err := testQueries.ClaimBackupGenerationsToPurge(ctx, db.ClaimBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: 900, BatchSize: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	// Deleting the source sandbox leaves its snapshots' backups alone.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'deleted', destroyed_at = now() WHERE id = $1`, source); err != nil {
		t.Fatal(err)
	}
	if n := sandboxClaim(); n != 0 {
		t.Fatalf("the sandbox purge claimed %d snapshot generations", n)
	}
	if rows := claim(); len(rows) != 0 {
		t.Fatalf("live snapshots' backups claimed: %+v", rows)
	}

	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'deleting', deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	rows := claim()
	if len(rows) != 1 || rows[0].SnapshotID.Bytes != gone || rows[0].Generation != genGone {
		t.Fatalf("claimed %+v, want only the deleted snapshot's generation", rows)
	}
	// A fork restores from the live snapshot's backup, never one being purged.
	if gen, err := testQueries.LatestSnapshotBackupGeneration(ctx, pgtype.UUID{Bytes: kept, Valid: true}); err != nil || gen != genKept {
		t.Fatalf("live snapshot's generation = %q (err %v), want %s", gen, err, genKept)
	}
	if _, err := testQueries.LatestSnapshotBackupGeneration(ctx, pgtype.UUID{Bytes: gone, Valid: true}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a generation claimed for purge was offered: err = %v", err)
	}
	if n, err := testQueries.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: rows[0].ID, ClaimedAt: rows[0].ClaimedAt}); err != nil || n != 1 {
		t.Fatalf("mark purged: n=%d err=%v", n, err)
	}
	if rows := claim(); len(rows) != 0 {
		t.Fatalf("a purged generation was claimed again: %+v", rows)
	}
	// A host whose upload finished after the purge reports it: purge again.
	recordSnapshotGeneration(t, gone, bucket, genGone)
	if rows := claim(); len(rows) != 1 || rows[0].Generation != genGone {
		t.Fatalf("a late report did not reopen the purge: %+v", rows)
	}
}

// memAdmin is an in-memory bucket for the garbage collector.
type memAdmin struct {
	bucket  string
	objects map[string]bool
}

func (m *memAdmin) Identity() string { return m.bucket }
func (m *memAdmin) NewReader(context.Context, string) (io.ReadCloser, error) {
	return nil, backup.ErrObjectNotFound
}
func (m *memAdmin) Delete(_ context.Context, object string) error {
	delete(m.objects, object)
	return nil
}
func (m *memAdmin) List(_ context.Context, prefix string) ([]backup.ObjectInfo, error) {
	var out []backup.ObjectInfo
	for name := range m.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, backup.ObjectInfo{Name: name})
		}
	}
	return out, nil
}

// An upload abandoned when its snapshot was deleted leaves objects with no
// manifest and no database row; the daily walk removes them, and leaves a
// live snapshot's backup alone.
func TestIntegration_BackupGC_WalkPurgesADeletedSnapshotsLeftovers(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	source := createAndDeleteSandbox(t, apiKey, false)
	live := insertSavedSnapshot(t, teamID, source)
	gone := insertSavedSnapshot(t, teamID, source)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET status = 'deleting', deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	liveObj := "snapshots/" + live.String() + "/gen-1/rootfs.ext4.p1"
	store := &memAdmin{bucket: "walk-" + uuid.NewString(), objects: map[string]bool{
		liveObj: true,
		"snapshots/" + gone.String() + "/half-done/rootfs.ext4.p1": true,
	}}
	h := &api.Handlers{DB: testQueries, BackupGC: store}
	if purged := h.WalkBucketBackups(ctx); purged != 1 {
		t.Fatalf("walk purged %d generations, want the deleted snapshot's one", purged)
	}
	if len(store.objects) != 1 || !store.objects[liveObj] {
		t.Fatalf("objects left = %v, want only the live snapshot's", store.objects)
	}
}

// A backup generation has exactly one owner out of sandbox, template and
// saved snapshot.
func TestIntegration_BackupGeneration_HasExactlyOneOwner(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	source := createAndDeleteSandbox(t, apiKey, false)
	snap := insertSavedSnapshot(t, teamID, source)
	gen := "7777777777777777777777777777777777777777777777777777777777777777"
	for name, owners := range map[string][2]any{
		"sandbox and snapshot": {source, snap},
		"no owner":             {nil, nil},
	} {
		_, err := testPool.Exec(ctx, `
			INSERT INTO backup_generation (sandbox_id, snapshot_id, generation, bucket, completed_at, files)
			VALUES ($1, $2, $3, 'b', now(), '[]')`, owners[0], owners[1], gen)
		if err == nil {
			t.Fatalf("%s: row accepted", name)
		}
	}
}
