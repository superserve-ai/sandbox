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

// seedPausedSandbox creates a sandbox through the API and records a completed
// pause in the database, so resume claims do not depend on host dispatch.
func seedPausedSandbox(t *testing.T, teamID uuid.UUID, apiKey string) uuid.UUID {
	t.Helper()
	r := newRouter(t)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"claim-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	id, err := uuid.Parse(sid)
	if err != nil {
		t.Fatalf("parse sandbox id %q: %v", sid, err)
	}
	operation := uuid.New()
	claimed, err := testQueries.BeginPause(context.Background(), db.BeginPauseParams{
		ID: id, TeamID: teamID, PauseOpID: pgtype.UUID{Bytes: operation, Valid: true}, LeaseSeconds: 90,
	})
	if err != nil {
		t.Fatalf("begin pause: %v", err)
	}
	memPath := "/snapshots/mem.snap"
	if _, err := testQueries.FinalizePause(context.Background(), db.FinalizePauseParams{
		ID: id, TeamID: teamID, PauseOpID: claimed.PauseOpID,
		PauseOpLeaseVersion: &claimed.PauseOpLeaseVersion,
		Path:                "/snapshots/disk.snap", MemPath: &memPath, Trigger: "manual",
	}); err != nil {
		t.Fatalf("finalize pause: %v", err)
	}
	return id
}

// The claim must block on the advisory lock a secret attach holds; a claim
// that skipped the lock could flip the row to resuming under an in-flight
// attach and resume a guest that never receives the new binding. Mocked
// handler tests cannot see this; only the planner can drop the lock call.
func TestIntegration_ClaimResume_WaitsForAttachLock(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sandboxID := seedPausedSandbox(t, teamID, apiKey)

	holder, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	defer holder.Rollback(ctx)
	if err := testQueries.WithTx(holder).LockSandboxForSecretWrites(ctx, sandboxID.String()); err != nil {
		t.Fatalf("take attach lock: %v", err)
	}

	type result struct {
		row db.ClaimResumeRow
		err error
	}
	done := make(chan result, 1)
	go func() {
		row, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{
			ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String(),
		})
		done <- result{row, err}
	}()

	select {
	case res := <-done:
		t.Fatalf("claim returned while the attach lock was held (err=%v)", res.err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatalf("release attach lock: %v", err)
	}
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("claim after lock release: %v", res.err)
		}
		if res.row.Sandbox.Status != db.SandboxStatusResuming {
			t.Errorf("claimed status = %q, want resuming", res.row.Sandbox.Status)
		}
		if res.row.SnapPath == nil || *res.row.SnapPath != "/snapshots/disk.snap" {
			t.Errorf("claimed snap_path = %v, want the paused snapshot's path", res.row.SnapPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("claim did not proceed after the attach lock was released")
	}
}

// The claim holds the attach lock for its own transaction, visible in
// pg_locks, so a concurrent attach waits on it rather than the reverse
// only.
func TestIntegration_ClaimResume_HoldsAttachLock(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sandboxID := seedPausedSandbox(t, teamID, apiKey)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := testQueries.WithTx(tx).ClaimResume(ctx, db.ClaimResumeParams{
		ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String(),
	}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	var held int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()`,
	).Scan(&held); err != nil {
		t.Fatalf("read pg_locks: %v", err)
	}
	if held == 0 {
		t.Fatal("ClaimResume did not take the attach advisory lock")
	}
}

// The claim leaves the auto-delete deadline on the row, and a revert leaves
// it as it found it, so a resume that fails before reaching the daemon
// cannot postpone deletion.
func TestIntegration_ClaimResume_LeavesDeadlineForRevert(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sandboxID := seedPausedSandbox(t, teamID, apiKey)
	if _, err := testPool.Exec(ctx,
		`UPDATE sandbox SET auto_delete_at = now() - interval '1 hour' WHERE id = $1`, sandboxID,
	); err != nil {
		t.Fatalf("seed deadline: %v", err)
	}

	claimed, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{
		ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String(),
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !claimed.Sandbox.AutoDeleteAt.Valid || !claimed.Sandbox.AutoDeleteAt.Time.Before(time.Now()) {
		t.Fatalf("claim left auto_delete_at = %v, want the past deadline untouched", claimed.Sandbox.AutoDeleteAt)
	}

	if err := testQueries.RevertResumeToPaused(ctx, db.RevertResumeToPausedParams{ID: sandboxID, TeamID: teamID}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	row, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if row.Status != db.SandboxStatusPaused || !row.AutoDeleteAt.Valid || !row.AutoDeleteAt.Time.Equal(claimed.Sandbox.AutoDeleteAt.Time) {
		t.Fatalf("after revert status=%s auto_delete_at=%v, want paused with %v",
			row.Status, row.AutoDeleteAt.Time, claimed.Sandbox.AutoDeleteAt.Time)
	}
}

// An auto-delete patch made while the row is resuming leaves the deadline
// NULL for the return to paused, so the revert arms it from the patched
// window: disabling leaves no deadline, a new or repeated window arms a
// fresh one.
func TestIntegration_RevertResumeToPaused_ArmsPatchedWindow(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sandboxID := seedPausedSandbox(t, teamID, apiKey)

	claimPatchRevert := func(patched *int32) {
		t.Helper()
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET auto_delete_seconds = 3600, auto_delete_at = now() - interval '1 hour' WHERE id = $1`, sandboxID,
		); err != nil {
			t.Fatalf("seed window: %v", err)
		}
		if _, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{
			ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String(),
		}); err != nil {
			t.Fatalf("claim: %v", err)
		}
		if _, err := testQueries.UpdateSandboxAutoDelete(ctx, db.UpdateSandboxAutoDeleteParams{
			ID: sandboxID, TeamID: teamID, AutoDeleteSeconds: patched,
		}); err != nil {
			t.Fatalf("patch window: %v", err)
		}
		if err := testQueries.RevertResumeToPaused(ctx, db.RevertResumeToPausedParams{ID: sandboxID, TeamID: teamID}); err != nil {
			t.Fatalf("revert: %v", err)
		}
	}
	read := func() db.Sandbox {
		t.Helper()
		row, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if row.Status != db.SandboxStatusPaused {
			t.Fatalf("status = %s, want paused", row.Status)
		}
		return row
	}

	claimPatchRevert(nil)
	if row := read(); row.AutoDeleteSeconds != nil || row.AutoDeleteAt.Valid {
		t.Fatalf("disabled while resuming, after revert seconds=%v at=%v, want none", row.AutoDeleteSeconds, row.AutoDeleteAt.Time)
	}

	for _, window := range []int32{7200, 3600} {
		claimPatchRevert(&window)
		row := read()
		if row.AutoDeleteSeconds == nil || *row.AutoDeleteSeconds != window {
			t.Fatalf("after revert seconds=%v, want %d", row.AutoDeleteSeconds, window)
		}
		if !row.AutoDeleteAt.Valid || !row.AutoDeleteAt.Time.After(time.Now()) {
			t.Fatalf("window %d patched while resuming, after revert at=%v, want a fresh deadline in the future", window, row.AutoDeleteAt.Time)
		}
	}
}

// The claim carries the snapshot's timestamp, and the injection record
// lands on the row: the two sides of the resume-time secrets reuse check.
func TestIntegration_ClaimResume_CarriesSnapshotTimeAndSecretEnvRecord(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sandboxID := seedPausedSandbox(t, teamID, apiKey)
	var snapshotCreatedAt pgtype.Timestamptz
	if err := testPool.QueryRow(ctx, `
		SELECT s.created_at FROM snapshot s
		JOIN sandbox sb ON sb.snapshot_id = s.id AND sb.team_id = s.team_id
		WHERE sb.id = $1 AND sb.team_id = $2
	`, sandboxID, teamID).Scan(&snapshotCreatedAt); err != nil {
		t.Fatalf("read pause snapshot timestamp: %v", err)
	}

	fingerprint, ip := "abc123", "10.0.0.5"
	if err := testQueries.RecordSandboxSecretEnv(ctx, db.RecordSandboxSecretEnvParams{
		ID: sandboxID, SecretEnvFingerprint: &fingerprint, SecretEnvIp: &ip,
		SecretEnvExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	claimed, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{
		ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String(),
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !claimed.SnapCreatedAt.Valid || !claimed.SnapCreatedAt.Time.Equal(snapshotCreatedAt.Time) {
		t.Fatalf("snap_created_at = %v, want the pause's timestamp %v", claimed.SnapCreatedAt, snapshotCreatedAt)
	}
	sb := claimed.Sandbox
	if sb.SecretEnvFingerprint == nil || *sb.SecretEnvFingerprint != fingerprint || sb.SecretEnvIp == nil || *sb.SecretEnvIp != ip ||
		!sb.SecretEnvInjectedAt.Valid || !sb.SecretEnvExpiresAt.Valid {
		t.Fatalf("claimed row secret env = %v/%v/%v/%v, want the recorded values", sb.SecretEnvFingerprint, sb.SecretEnvIp, sb.SecretEnvInjectedAt, sb.SecretEnvExpiresAt)
	}
}
