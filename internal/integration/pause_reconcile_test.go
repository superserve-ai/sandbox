//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// The reconciler runs against the shared test database, so a tick may also
// pick up rows other tests abandoned in 'pausing'. Assertions therefore read
// the test's own row and compare host call counts between ticks rather than
// expecting exact totals.

func pauseHandlers(t *testing.T, vmd *stubVMD) *api.Handlers {
	t.Helper()
	h := api.NewHandlers(vmd, testQueries, &config.Config{
		SystemTeamID:  testSystemTeamID.String(),
		DefaultHostID: testDefaultHostID,
	})
	h.Pool = testPool
	registerTestHandlers(h)
	return h
}

func abandonedPause(t *testing.T, teamID uuid.UUID, name string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	id := seedActiveSandbox(t, teamID, name)
	op := uuid.New()
	beginPause(t, id, teamID, op)
	expireLease(t, id)
	return id, op
}

func undecidedHost() *stubVMD {
	return &stubVMD{pauseErr: status.Error(codes.DeadlineExceeded, "pause timed out")}
}

func TestIntegration_PauseReconcile_FinishesAnAbandonedPause(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id, op := abandonedPause(t, teamID, "reconcile-finish")

	pauseHandlers(t, &stubVMD{}).ReconcilePendingPausesOnce(context.Background(), zerolog.Nop())

	if got := readPauseOp(t, id); got.status != "paused" || got.leased {
		t.Fatalf("after reconcile: %+v, want paused with the lease cleared", got)
	}
	var token string
	if err := testPool.QueryRow(context.Background(),
		`SELECT pause_token FROM snapshot WHERE sandbox_id = $1`, id).Scan(&token); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if token != op.String() {
		t.Fatalf("snapshot pause_token = %q, want the operation id %s", token, op)
	}
}

func TestIntegration_PauseReconcile_UndecidedIsRetriedAfterBackoff(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id, op := abandonedPause(t, teamID, "reconcile-undecided")
	vmd := undecidedHost()
	h := pauseHandlers(t, vmd)

	h.ReconcilePendingPausesOnce(context.Background(), zerolog.Nop())
	got := readPauseOp(t, id)
	if got.status != "pausing" || got.opID.Bytes != op || !got.leased || got.attention {
		t.Fatalf("after undecided attempt: %+v, want still pausing, same operation, backoff lease, no attention", got)
	}

	calls := vmd.pauseCalls.Load()
	h.ReconcilePendingPausesOnce(context.Background(), zerolog.Nop())
	if vmd.pauseCalls.Load() != calls {
		t.Fatal("row was retried inside its backoff")
	}
}

func TestIntegration_PauseReconcile_GoneFromResolvedHostFails(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id, _ := abandonedPause(t, teamID, "reconcile-gone")

	pauseHandlers(t, &stubVMD{pauseErr: status.Error(codes.NotFound, "no such vm")}).
		ReconcilePendingPausesOnce(context.Background(), zerolog.Nop())

	if got := readPauseOp(t, id); got.status != "failed" || got.leased {
		t.Fatalf("after NotFound: %+v, want failed with the lease cleared", got)
	}
}

func TestIntegration_PauseReconcile_FlagsAttentionPastThreshold(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	id, _ := abandonedPause(t, teamID, "reconcile-attention")
	if _, err := testPool.Exec(context.Background(),
		`UPDATE sandbox SET pause_op_started_at = now() - interval '31 minutes' WHERE id = $1`, id); err != nil {
		t.Fatalf("age operation: %v", err)
	}

	pauseHandlers(t, undecidedHost()).ReconcilePendingPausesOnce(context.Background(), zerolog.Nop())

	if got := readPauseOp(t, id); got.status != "pausing" || !got.attention {
		t.Fatalf("after aged undecided attempt: %+v, want still pausing and flagged", got)
	}
}

func createActive(t *testing.T, r *gin.Engine, apiKey, name string) uuid.UUID {
	t.Helper()
	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"`+name+`"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	return uuid.MustParse(mustJSON(t, cw)["id"].(string))
}

func TestIntegration_PauseHandler_UndecidedHostLeavesPausing(t *testing.T) {
	_, apiKey := seedTeamAndKey(t)
	vmd := undecidedHost()
	h := pauseHandlers(t, vmd)
	r := api.SetupRouter(t.Context(), h, testPool)
	id := createActive(t, r, apiKey, "pause-undecided")

	if pw := do(r, "POST", "/sandboxes/"+id.String()+"/pause", apiKey, ""); pw.Code != http.StatusAccepted || !strings.Contains(pw.Body.String(), `"pausing"`) {
		t.Fatalf("pause: %d %s, want accepted as pausing", pw.Code, pw.Body.String())
	}
	h.WaitAsyncBookkeeping()

	if got := readPauseOp(t, id); got.status != "pausing" || !got.opID.Valid || got.leased {
		t.Fatalf("after undecided pause: %+v, want pausing with the operation kept and its lease released", got)
	}
	if n := vmd.pauseCalls.Load(); n != 2 {
		t.Fatalf("host attempts = %d, want the foreground's two", n)
	}
}

// The host's answer lands after the row has moved on to a newer run: a
// NotFound then must not fail what is now an active sandbox.
func TestIntegration_PauseHandler_LateNotFoundCannotFailANewerState(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "late-notfound")
	vmd := &stubVMD{pauseFn: func(ctx context.Context, _, _ string) (string, string, []vmdclient.ManifestEntry, string, error) {
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET status = 'active', pause_op_lease_version = pause_op_lease_version + 1 WHERE id = $1`, id); err != nil {
			t.Error(err)
		}
		return "", "", nil, "", status.Error(codes.NotFound, "no such vm")
	}}
	h := pauseHandlers(t, vmd)
	r := api.SetupRouter(t.Context(), h, testPool)

	if pw := do(r, "POST", "/sandboxes/"+id.String()+"/pause", apiKey, ""); pw.Code != http.StatusGone {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	h.WaitAsyncBookkeeping()

	if got := readPauseOp(t, id); got.status != "active" {
		t.Fatalf("late NotFound changed the newer state to %s", got.status)
	}
}

// Same race through the generation finalize path (no legacy unique index):
// a snapshot that arrives after the row started resuming must not turn it
// back into paused.
func TestIntegration_PauseHandler_GenerationFinalizeCannotUndoAResume(t *testing.T) {
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `DROP INDEX IF EXISTS snapshot_sandbox_unique`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(ctx,
			`CREATE UNIQUE INDEX IF NOT EXISTS snapshot_sandbox_unique ON snapshot (sandbox_id)`); err != nil {
			t.Error(err)
		}
	})
	teamID, apiKey := seedTeamAndKey(t)
	id := seedActiveSandbox(t, teamID, "late-finalize")
	vmd := &stubVMD{pauseFn: func(ctx context.Context, _, token string) (string, string, []vmdclient.ManifestEntry, string, error) {
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET status = 'resuming', pause_op_lease_version = pause_op_lease_version + 1 WHERE id = $1`, id); err != nil {
			t.Error(err)
		}
		return "/snapshots/disk.snap", "/snapshots/mem.snap", nil, token, nil
	}}
	h := pauseHandlers(t, vmd)
	r := api.SetupRouter(t.Context(), h, testPool)

	if pw := do(r, "POST", "/sandboxes/"+id.String()+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	h.WaitAsyncBookkeeping()

	if got := readPauseOp(t, id); got.status != "resuming" {
		t.Fatalf("late finalize changed resuming to %s", got.status)
	}
}

// A tick claims only what its workers can start at once. Rows it has not
// claimed can be finished and resumed elsewhere meanwhile; none of them may
// then receive a pause RPC from this tick.
func TestIntegration_PauseReconcile_ClaimsOnlyWhatItCanDispatch(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	for i := 0; i < 20; i++ {
		abandonedPause(t, teamID, fmt.Sprintf("reconcile-wave-%d", i))
	}
	started := make(chan uuid.UUID, 4)
	release := make(chan struct{})
	var calls, stale atomic.Int32
	vmd := &stubVMD{pauseFn: func(ctx context.Context, id, token string) (string, string, []vmdclient.ManifestEntry, string, error) {
		if calls.Add(1) <= 4 {
			started <- uuid.MustParse(id)
			<-release
		} else {
			var st string
			if err := testPool.QueryRow(ctx, `SELECT status::text FROM sandbox WHERE id = $1`, id).Scan(&st); err != nil {
				t.Error(err)
			}
			if st == "active" {
				stale.Add(1)
			}
		}
		return "/snapshots/disk.snap", "/snapshots/mem.snap", nil, token, nil
	}}
	h := pauseHandlers(t, vmd)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ReconcilePendingPausesOnce(ctx, zerolog.Nop())
	}()

	var running []uuid.UUID
	for i := 0; i < 4; i++ {
		select {
		case id := <-started:
			running = append(running, id)
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("workers did not start")
		}
	}
	// Everything not in flight is finished elsewhere and resumed.
	_, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', pause_op_id = NULL, pause_op_lease_until = NULL
		WHERE team_id = $1 AND NOT (id = ANY($2::uuid[]))`, teamID, running)
	close(release)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if n := stale.Load(); n != 0 {
		t.Fatalf("%d pause RPCs went to sandboxes that were already running again", n)
	}
}

// A pause the reaper started and the reconciler finished is still recorded
// as a timeout pause: the snapshot's trigger and the activity action carry
// the original cause, not the fact that reconciliation did the last step.
func TestIntegration_PauseReconcile_KeepsTheOriginalCause(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO sandbox (team_id, name, status, host_id, timeout_seconds, created_at)
		VALUES ($1, 'reconcile-cause', 'active', $2, 60, now() - interval '10 minutes') RETURNING id`,
		teamID, testDefaultHostID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.ClaimExpiredSandbox(ctx, db.ClaimExpiredSandboxParams{ID: id, LeaseSeconds: 90}); err != nil {
		t.Fatalf("reaper claim: %v", err)
	}
	expireLease(t, id)

	h := pauseHandlers(t, &stubVMD{})
	h.ReconcilePendingPausesOnce(ctx, zerolog.Nop())
	h.WaitAsyncBookkeeping()

	var trigger string
	if err := testPool.QueryRow(ctx, `SELECT trigger FROM snapshot WHERE sandbox_id = $1`, id).Scan(&trigger); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if trigger != "timeout" {
		t.Fatalf("snapshot trigger = %q, want the reaper's timeout", trigger)
	}
	var logged int
	for deadline := time.Now().Add(2 * time.Second); ; {
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM activity WHERE sandbox_id = $1 AND action = 'timeout_paused'`, id).Scan(&logged); err != nil {
			t.Fatal(err)
		}
		if logged > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no timeout_paused activity was recorded for the reconciled pause")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A pause a user asked for that the reconciler had to finish is still
// attributed to that user, not recorded as system-initiated.
func TestIntegration_PauseReconcile_KeepsTheRequestingActor(t *testing.T) {
	ctx := context.Background()
	teamID, _, profileID := seedTeamKeyAndProfile(t)
	id := seedActiveSandbox(t, teamID, "reconcile-actor")
	if _, err := testQueries.BeginPause(ctx, db.BeginPauseParams{
		ID: id, TeamID: teamID, PauseOpID: pauseOpID(uuid.New()), LeaseSeconds: 90, ActorID: pauseOpID(profileID),
	}); err != nil {
		t.Fatalf("BeginPause: %v", err)
	}
	expireLease(t, id)

	h := pauseHandlers(t, &stubVMD{})
	h.ReconcilePendingPausesOnce(ctx, zerolog.Nop())
	h.WaitAsyncBookkeeping()

	for deadline := time.Now().Add(2 * time.Second); ; {
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM activity WHERE sandbox_id = $1 AND action = 'paused' AND actor_id = $2`, id, profileID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("paused activity attributed to the requester = %d rows, want 1", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
