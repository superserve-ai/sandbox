//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

const gcBaseSHA = "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a"

func recordGeneration(t *testing.T, sandboxID uuid.UUID, bucket, generation string, completedAt time.Time) {
	t.Helper()
	files := []byte(`[{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `","base_sha256":"` + gcBaseSHA + `"},` +
		`{"name":"vmstate.snap","size_bytes":128,"sha256":"` + vmstateSHA + `"}]`)
	if _, err := testQueries.RecordSandboxBackupGeneration(context.Background(), db.RecordSandboxBackupGenerationParams{
		SandboxID: pgtype.UUID{Bytes: sandboxID, Valid: true}, Generation: generation, Bucket: bucket, CompletedAt: completedAt, Files: files,
	}); err != nil {
		t.Fatal(err)
	}
}

func createAndDeleteSandbox(t *testing.T, apiKey string, deleted bool) uuid.UUID {
	t.Helper()
	r := newRouter(t)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"backup-gc"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	if deleted {
		if dw := do(r, "DELETE", "/sandboxes/"+sid, apiKey, ""); dw.Code != http.StatusNoContent {
			t.Fatalf("delete: %d %s", dw.Code, dw.Body.String())
		}
	}
	return uuid.MustParse(sid)
}

// Only a deleted sandbox's generations in the job's own bucket are leased;
// a purged row is never leased again, and a lease a dead worker left
// behind is taken over once it expires.
func TestIntegration_BackupGC_ClaimsOnlyDeletedSandboxesInItsBucket(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	bucket := "gc-" + uuid.NewString()
	deleted := createAndDeleteSandbox(t, apiKey, true)
	live := createAndDeleteSandbox(t, apiKey, false)
	gen1 := "1111111111111111111111111111111111111111111111111111111111111111"
	gen2 := "2222222222222222222222222222222222222222222222222222222222222222"
	gen3 := "3333333333333333333333333333333333333333333333333333333333333333"
	now := time.Now().UTC()
	recordGeneration(t, deleted, bucket, gen1, now.Add(-2*time.Hour))
	recordGeneration(t, deleted, "other-bucket", gen2, now.Add(-2*time.Hour))
	recordGeneration(t, live, bucket, gen3, now.Add(-2*time.Hour))

	claim := func() []db.ClaimBackupGenerationsToPurgeRow {
		rows, err := testQueries.ClaimBackupGenerationsToPurge(ctx, db.ClaimBackupGenerationsToPurgeParams{
			Bucket: bucket, LeaseSeconds: 900, BatchSize: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		var mine []db.ClaimBackupGenerationsToPurgeRow
		for _, row := range rows {
			if row.SandboxID.Bytes == deleted || row.SandboxID.Bytes == live {
				mine = append(mine, row)
			}
		}
		return mine
	}
	rows := claim()
	if len(rows) != 1 || rows[0].Generation != gen1 {
		t.Fatalf("claimed %+v, want only the deleted sandbox's generation in this bucket", rows)
	}
	if len(claim()) != 0 {
		t.Fatal("a leased generation was claimed again before its lease expired")
	}
	if _, err := testPool.Exec(ctx, `UPDATE backup_generation SET purge_claimed_at = now() - interval '20 minutes' WHERE id = $1`, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	again := claim()
	if len(again) != 1 || again[0].ID != rows[0].ID {
		t.Fatalf("an expired lease was not taken over: %+v", again)
	}
	// The old claim token no longer finishes the purge; the new one does.
	if n, err := testQueries.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: rows[0].ID, ClaimedAt: rows[0].ClaimedAt}); err != nil || n != 0 {
		t.Fatalf("a stale claim marked the generation purged: n=%d err=%v", n, err)
	}
	if n, err := testQueries.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: again[0].ID, ClaimedAt: again[0].ClaimedAt}); err != nil || n != 1 {
		t.Fatalf("the current claim did not mark the generation purged: n=%d err=%v", n, err)
	}
	if len(claim()) != 0 {
		t.Fatal("a purged generation was claimed")
	}
	// An exact redelivery of the original report, from a host that still
	// holds the objects, makes the purged generation purgeable again.
	recordGeneration(t, deleted, bucket, gen1, now.Add(-2*time.Hour))
	redelivered := claim()
	if len(redelivered) != 1 || redelivered[0].Generation != gen1 {
		t.Fatalf("an exactly redelivered report did not reopen the purge: %+v", redelivered)
	}
	if n, err := testQueries.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: redelivered[0].ID, ClaimedAt: redelivered[0].ClaimedAt}); err != nil || n != 1 {
		t.Fatalf("mark after redelivery: n=%d err=%v", n, err)
	}
	// A purged generation no longer counts as the sandbox's backup; the
	// other bucket's generation, untouched by this job, still does.
	latest, err := testQueries.LatestSandboxBackup(ctx, pgtype.UUID{Bytes: deleted, Valid: true})
	if err != nil || latest.Generation != gen2 {
		t.Fatalf("latest backup = %+v, %v; want the unpurged generation", latest, err)
	}
	// A late upload of the purged generation makes it purgeable again, and
	// a report landing mid-purge takes the claim away from the worker.
	recordGeneration(t, deleted, bucket, gen1, now)
	reclaimed := claim()
	if len(reclaimed) != 1 || reclaimed[0].Generation != gen1 {
		t.Fatalf("a re-uploaded generation was not claimed again: %+v", reclaimed)
	}
	recordGeneration(t, deleted, bucket, gen1, now.Add(time.Minute))
	if n, err := testQueries.MarkBackupGenerationPurged(ctx, db.MarkBackupGenerationPurgedParams{ID: reclaimed[0].ID, ClaimedAt: reclaimed[0].ClaimedAt}); err != nil || n != 0 {
		t.Fatalf("a generation reported during its purge was marked purged: n=%d err=%v", n, err)
	}
	// Only ids the database knows as deleted are orphan-sweep targets.
	known, err := testQueries.DeletedSandboxIDs(ctx, []uuid.UUID{deleted, live, uuid.New()})
	if err != nil || len(known) != 1 || known[0] != deleted {
		t.Fatalf("deleted ids = %v, %v; want only the deleted sandbox", known, err)
	}
}

// One replica takes a bucket's walk per interval; a claim that aged past
// the interval is taken again.
func TestIntegration_BackupGC_WalkClaimIsSingletonPerInterval(t *testing.T) {
	ctx := context.Background()
	bucket := "gc-walk-" + uuid.NewString()
	claim := func() int64 {
		n, err := testQueries.ClaimBackupWalk(ctx, db.ClaimBackupWalkParams{Bucket: bucket, IntervalSeconds: 3600})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if claim() != 1 {
		t.Fatal("the first walk was not claimed")
	}
	if claim() != 0 {
		t.Fatal("a second replica claimed the walk within the interval")
	}
	if _, err := testPool.Exec(ctx, `UPDATE backup_walk SET started_at = now() - interval '2 hours' WHERE bucket = $1`, bucket); err != nil {
		t.Fatal(err)
	}
	if claim() != 1 {
		t.Fatal("an expired walk claim was not taken again")
	}
}
