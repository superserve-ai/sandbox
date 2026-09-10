//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
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

	if pw := do(r, "POST", "/sandboxes/"+id.String()+"/pause", apiKey, ""); pw.Code != http.StatusInternalServerError {
		t.Fatalf("pause: %d %s, want the request's own error", pw.Code, pw.Body.String())
	}
	h.WaitAsyncBookkeeping()

	if got := readPauseOp(t, id); got.status != "pausing" || !got.opID.Valid || got.leased {
		t.Fatalf("after undecided pause: %+v, want pausing with the operation kept and its lease released", got)
	}
	if n := vmd.pauseCalls.Load(); n != 2 {
		t.Fatalf("host attempts = %d, want the foreground's two", n)
	}
}
