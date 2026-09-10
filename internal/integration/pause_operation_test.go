//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// The pause operation contract, against real Postgres: a pause is owned by a
// lease, every terminal write is fenced to the lease that holds it, and rows
// the contract does not cover are left alone.

func pauseOpID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func leaseVersion(v int64) *int64 { return &v }

type pauseOpState struct {
	status       string
	opID         pgtype.UUID
	leaseVersion int64
	leased       bool
	attention    bool
}

func readPauseOp(t *testing.T, id uuid.UUID) pauseOpState {
	t.Helper()
	var s pauseOpState
	if err := testPool.QueryRow(context.Background(), `
		SELECT status::text, pause_op_id, pause_op_lease_version,
		       pause_op_lease_until IS NOT NULL AND pause_op_lease_until > now(),
		       pause_op_attention_at IS NOT NULL
		FROM sandbox WHERE id = $1`, id).
		Scan(&s.status, &s.opID, &s.leaseVersion, &s.leased, &s.attention); err != nil {
		t.Fatalf("read sandbox: %v", err)
	}
	return s
}

func seedActiveSandbox(t *testing.T, teamID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO sandbox (team_id, name, status, host_id)
		VALUES ($1, $2, 'active', $3) RETURNING id`, teamID, name, testDefaultHostID).Scan(&id); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	return id
}

func beginPause(t *testing.T, id, teamID, op uuid.UUID) db.BeginPauseRow {
	t.Helper()
	row, err := testQueries.BeginPause(context.Background(), db.BeginPauseParams{
		ID: id, TeamID: teamID, PauseOpID: pauseOpID(op), LeaseSeconds: 90,
	})
	if err != nil {
		t.Fatalf("BeginPause: %v", err)
	}
	return row
}

func expireLease(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`UPDATE sandbox SET pause_op_lease_until = now() - interval '1 second',
		                    pause_op_started_at = now() - interval '5 minutes'
		 WHERE id = $1`, id); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
}

func claimPending(t *testing.T) []db.ClaimPendingPausesRow {
	t.Helper()
	rows, err := testQueries.ClaimPendingPauses(context.Background(), db.ClaimPendingPausesParams{
		LeaseSeconds: 60, MinAgeSeconds: 120, MaxRows: 10,
	})
	if err != nil {
		t.Fatalf("ClaimPendingPauses: %v", err)
	}
	return rows
}

func finalize(id, teamID, op uuid.UUID, version int64) error {
	mem := "/snapshots/mem.snap"
	_, err := testQueries.FinalizePause(context.Background(), db.FinalizePauseParams{
		ID: id, TeamID: teamID,
		PauseOpID: pauseOpID(op), PauseOpLeaseVersion: leaseVersion(version),
		Path: "/snapshots/vmstate.snap", MemPath: &mem, Trigger: "manual", PauseToken: op.String(),
		ManifestFileNames: []string{}, ManifestPaths: []string{}, ManifestSizes: []int64{},
		ManifestAllocatedBytes: []int64{}, ManifestDigests: []string{}, ManifestBasePaths: []string{},
	})
	return err
}

func TestIntegration_PauseOperation_BeginPauseLeasesTheOperation(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-lease")
	op := uuid.New()

	row := beginPause(t, id, teamID, op)
	if !row.PauseOpID.Valid || row.PauseOpID.Bytes != op || row.PauseOpLeaseVersion != 1 || !row.PauseOpStartedAt.Valid {
		t.Fatalf("BeginPause did not record the operation: %+v", row)
	}
	if got := readPauseOp(t, id); got.status != "pausing" || !got.leased {
		t.Fatalf("after BeginPause: %+v, want pausing and leased", got)
	}

	// The caller still owns it: nothing to claim.
	if rows := claimPending(t); len(rows) != 0 {
		t.Fatalf("claimed %d rows while the caller's lease is live", len(rows))
	}

	// Once the caller's lease is gone, one claim takes it and bumps the version;
	// a second claim finds it leased again.
	expireLease(t, id)
	rows := claimPending(t)
	if len(rows) != 1 || rows[0].ID != id || rows[0].PauseOpLeaseVersion != 2 || rows[0].PauseOpID.Bytes != op {
		t.Fatalf("claim = %+v, want the row at version 2 with the same operation", rows)
	}
	if rows := claimPending(t); len(rows) != 0 {
		t.Fatalf("claimed %d rows while a reconciler's lease is live", len(rows))
	}
	if got := readPauseOp(t, id); got.status != "pausing" || got.leaseVersion != 2 {
		t.Fatalf("after claim: %+v", got)
	}
}

func TestIntegration_PauseOperation_FinalizeIsFencedToTheCurrentLease(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-fence")
	op := uuid.New()
	beginPause(t, id, teamID, op)
	expireLease(t, id)
	if rows := claimPending(t); len(rows) != 1 {
		t.Fatalf("claim = %d rows, want 1", len(rows))
	}

	// The caller whose lease was reclaimed cannot commit its late result.
	if err := finalize(id, teamID, op, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale finalize err = %v, want no rows", err)
	}
	if got := readPauseOp(t, id); got.status != "pausing" {
		t.Fatalf("stale finalize changed the row: %+v", got)
	}

	// The current lease holder can.
	if err := finalize(id, teamID, op, 2); err != nil {
		t.Fatalf("current finalize: %v", err)
	}
	got := readPauseOp(t, id)
	if got.status != "paused" || got.leased || got.opID.Bytes != op {
		t.Fatalf("after finalize: %+v, want paused, unleased, operation kept as the token record", got)
	}
}

func TestIntegration_PauseOperation_LateResultCannotTouchALaterPause(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-late")
	first := uuid.New()
	beginPause(t, id, teamID, first)
	if err := finalize(id, teamID, first, 1); err != nil {
		t.Fatalf("first finalize: %v", err)
	}

	// Resumed, then paused again under a new operation.
	if _, err := testPool.Exec(context.Background(), `UPDATE sandbox SET status = 'active' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	second := uuid.New()
	beginPause(t, id, teamID, second)

	// Everything the first operation could still say is refused.
	if err := finalize(id, teamID, first, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("late finalize err = %v, want no rows", err)
	}
	n, err := testQueries.RevertPauseToActive(context.Background(), db.RevertPauseToActiveParams{
		SandboxID: id, TeamID: teamID, PauseOpID: pauseOpID(first), PauseOpLeaseVersion: leaseVersion(1),
	})
	if err != nil || n != 0 {
		t.Fatalf("late revert = %d, %v; want 0 rows", n, err)
	}
	failed, err := testQueries.MarkSandboxFailed(context.Background(), db.MarkSandboxFailedParams{
		ID: id, ObservedStatus: db.SandboxStatusPausing, PauseOpID: pauseOpID(first), PauseOpLeaseVersion: leaseVersion(1),
	})
	if err != nil || failed != 0 {
		t.Fatalf("late mark-failed = %d, %v; want 0 rows", failed, err)
	}
	if got := readPauseOp(t, id); got.status != "pausing" || got.opID.Bytes != second || got.leaseVersion != 2 {
		t.Fatalf("second operation disturbed: %+v", got)
	}
}

func TestIntegration_PauseOperation_DecidedOutcomesAreFencedToo(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-decided")
	op := uuid.New()
	beginPause(t, id, teamID, op)
	expireLease(t, id)
	claimPending(t) // version 2

	// A stale worker can neither revert nor fail the operation.
	n, err := testQueries.RevertPauseToActive(context.Background(), db.RevertPauseToActiveParams{
		SandboxID: id, TeamID: teamID, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: leaseVersion(1),
	})
	if err != nil || n != 0 {
		t.Fatalf("stale revert = %d, %v; want 0", n, err)
	}
	failed, err := testQueries.MarkSandboxFailed(context.Background(), db.MarkSandboxFailedParams{
		ID: id, ObservedStatus: db.SandboxStatusPausing, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: leaseVersion(1),
	})
	if err != nil || failed != 0 {
		t.Fatalf("stale mark-failed = %d, %v; want 0", failed, err)
	}

	// The current holder can fail it (the host said the VM is gone), and the
	// lease is released with it.
	failed, err = testQueries.MarkSandboxFailed(context.Background(), db.MarkSandboxFailedParams{
		ID: id, ObservedStatus: db.SandboxStatusPausing, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: leaseVersion(2),
	})
	if err != nil || failed != 1 {
		t.Fatalf("current mark-failed = %d, %v; want 1", failed, err)
	}
	if got := readPauseOp(t, id); got.status != "failed" || got.leased {
		t.Fatalf("after mark-failed: %+v", got)
	}
}

func TestIntegration_PauseOperation_RevertClearsTheOperation(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-revert")
	op := uuid.New()
	beginPause(t, id, teamID, op)

	n, err := testQueries.RevertPauseToActive(context.Background(), db.RevertPauseToActiveParams{
		SandboxID: id, TeamID: teamID, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: leaseVersion(1),
	})
	if err != nil || n != 1 {
		t.Fatalf("revert = %d, %v; want 1", n, err)
	}
	got := readPauseOp(t, id)
	if got.status != "active" || got.opID.Valid || got.leased {
		t.Fatalf("after revert: %+v, want active with no operation", got)
	}
	// Nothing left for a late finalize to match.
	if err := finalize(id, teamID, op, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("finalize after revert err = %v, want no rows", err)
	}
}

func TestIntegration_PauseOperation_DeletedAndLegacyRowsAreLeftAlone(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)

	deleted := seedActiveSandbox(t, teamID, "pause-op-deleted")
	op := uuid.New()
	beginPause(t, deleted, teamID, op)
	expireLease(t, deleted)
	if _, err := testPool.Exec(context.Background(), `UPDATE sandbox SET destroyed_at = now() WHERE id = $1`, deleted); err != nil {
		t.Fatal(err)
	}

	// A row still 'pausing' from before this contract carries no operation.
	var legacy uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO sandbox (team_id, name, status, host_id, updated_at)
		VALUES ($1, 'pause-op-legacy', 'pausing', $2, now() - interval '1 hour') RETURNING id`,
		teamID, testDefaultHostID).Scan(&legacy); err != nil {
		t.Fatal(err)
	}

	for _, row := range claimPending(t) {
		if row.ID == deleted || row.ID == legacy {
			t.Fatalf("claimed a row the contract does not cover: %s", row.ID)
		}
	}
	if err := finalize(deleted, teamID, op, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("finalize of a deleted row err = %v, want no rows", err)
	}
}

func TestIntegration_PauseOperation_ReleaseAndAttentionAreFenced(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-release")
	op := uuid.New()
	beginPause(t, id, teamID, op)
	expireLease(t, id)
	claimPending(t) // version 2

	release := func(version int64) int64 {
		n, err := testQueries.ReleasePauseLease(context.Background(), db.ReleasePauseLeaseParams{
			ID: id, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: version, RetryAfterSeconds: 60,
		})
		if err != nil {
			t.Fatalf("ReleasePauseLease: %v", err)
		}
		return n
	}
	if n := release(1); n != 0 {
		t.Fatalf("stale release = %d rows, want 0", n)
	}
	if n := release(2); n != 1 {
		t.Fatalf("current release = %d rows, want 1", n)
	}
	// Released with a retry delay: not claimable yet.
	if rows := claimPending(t); len(rows) != 0 {
		t.Fatalf("claimed %d rows inside the retry delay", len(rows))
	}
	expireLease(t, id)
	rows := claimPending(t)
	if len(rows) != 1 || rows[0].PauseOpLeaseVersion != 3 {
		t.Fatalf("claim after delay = %+v, want version 3", rows)
	}

	attention := func(version int64) int64 {
		n, err := testQueries.MarkPauseAttention(context.Background(), db.MarkPauseAttentionParams{
			ID: id, PauseOpID: pauseOpID(op), PauseOpLeaseVersion: version,
		})
		if err != nil {
			t.Fatalf("MarkPauseAttention: %v", err)
		}
		return n
	}
	if n := attention(2); n != 0 {
		t.Fatalf("stale attention = %d, want 0", n)
	}
	if n := attention(3); n != 1 {
		t.Fatalf("attention = %d, want 1", n)
	}
	if n := attention(3); n != 0 {
		t.Fatalf("second attention = %d, want 0 (flagged once)", n)
	}
	if got := readPauseOp(t, id); !got.attention || got.status != "pausing" {
		t.Fatalf("after attention: %+v, want flagged and still pausing", got)
	}
}

func TestIntegration_PauseOperation_ClaimIsExclusiveAcrossReplicas(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "pause-op-replicas")
	beginPause(t, id, teamID, uuid.New())
	expireLease(t, id)
	ctx := context.Background()

	// Replica A claims inside a transaction it has not committed.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rowsA, err := testQueries.WithTx(tx).ClaimPendingPauses(ctx, db.ClaimPendingPausesParams{
		LeaseSeconds: 60, MinAgeSeconds: 120, MaxRows: 10,
	})
	if err != nil || len(rowsA) != 1 {
		t.Fatalf("replica A claim = %+v, %v; want the row", rowsA, err)
	}

	// Replica B skips the locked row rather than waiting on it.
	done := make(chan int, 1)
	go func() {
		rows, err := testQueries.ClaimPendingPauses(ctx, db.ClaimPendingPausesParams{
			LeaseSeconds: 60, MinAgeSeconds: 120, MaxRows: 10,
		})
		if err != nil {
			done <- -1
			return
		}
		done <- len(rows)
	}()
	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("replica B claimed %d rows while A held the lock", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replica B blocked on A's row instead of skipping it")
	}

	// After A commits, the lease A took keeps B off the row.
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := claimPending(t); len(rows) != 0 {
		t.Fatalf("replica B claimed %d rows under A's lease", len(rows))
	}
}

func TestIntegration_PauseOperation_ReaperClaimMintsTheOperation(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	var id uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO sandbox (team_id, name, status, host_id, timeout_seconds, created_at)
		VALUES ($1, 'pause-op-reaper', 'active', $2, 60, now() - interval '10 minutes') RETURNING id`,
		teamID, testDefaultHostID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	rows, err := testQueries.ClaimExpiredSandboxes(context.Background(), db.ClaimExpiredSandboxesParams{Limit: 10, LeaseSeconds: 90})
	if err != nil {
		t.Fatalf("ClaimExpiredSandboxes: %v", err)
	}
	var claimed *db.ClaimExpiredSandboxesRow
	for i := range rows {
		if rows[i].ID == id {
			claimed = &rows[i]
		}
	}
	if claimed == nil || !claimed.PauseOpID.Valid || claimed.PauseOpLeaseVersion != 1 {
		t.Fatalf("reaper claim = %+v, want the row with a minted operation at version 1", claimed)
	}
	if got := readPauseOp(t, id); got.status != "pausing" || !got.leased || got.opID.Bytes != claimed.PauseOpID.Bytes {
		t.Fatalf("after reaper claim: %+v", got)
	}
}
