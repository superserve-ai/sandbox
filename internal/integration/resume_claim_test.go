//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// seedPausedSandbox creates and pauses a sandbox through the API and waits
// for the pause to finalize, so the row is claimable.
func seedPausedSandbox(t *testing.T, apiKey string) uuid.UUID {
	t.Helper()
	r := newRouter(t)
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"claim-box"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, "")
	if pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	waitBookkeeping()
	id, err := uuid.Parse(sid)
	if err != nil {
		t.Fatalf("parse sandbox id %q: %v", sid, err)
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
	sandboxID := seedPausedSandbox(t, apiKey)

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
	sandboxID := seedPausedSandbox(t, apiKey)

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
