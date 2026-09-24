//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func enforceComputeForTeam(t *testing.T, h *api.Handlers, teamID uuid.UUID) (*abuse.ConfigComputeSource, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "compute.json")
	content := fmt.Sprintf(`{"mode":"enforce","restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create"]}]}`, teamID)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	h.ComputeRestrictions = &abuse.ComputeEvaluator{Source: source}
	return source, path
}

func assertComputePauseAccounting(t *testing.T, id uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if n := countOpenIntervals(t, ctx, id); n != 0 {
		t.Fatalf("open active intervals = %d, want 0", n)
	}
	if n := countOpenComputeBillingIntervals(t, ctx, id); n != 0 {
		t.Fatalf("open compute billing intervals = %d, want 0", n)
	}
	var active, billing int
	if err := testPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM sandbox_active_interval WHERE sandbox_id = $1),
		       (SELECT count(*) FROM sandbox_compute_billing_interval WHERE sandbox_id = $1)`, id).
		Scan(&active, &billing); err != nil {
		t.Fatal(err)
	}
	if active != 1 || billing != 1 {
		t.Fatalf("accounting interval rows = active:%d billing:%d, want one of each", active, billing)
	}
}

func assertSystemComputePause(t *testing.T, id uuid.UUID, wantOp uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var trigger string
	var snapshotToken string
	if err := testPool.QueryRow(ctx, `
		SELECT n.trigger, n.pause_token
		FROM sandbox s JOIN snapshot n ON n.id = s.snapshot_id
		WHERE s.id = $1`, id).Scan(&trigger, &snapshotToken); err != nil {
		t.Fatal(err)
	}
	op, err := uuid.Parse(snapshotToken)
	if err != nil || op == uuid.Nil || trigger != "abuse" || (wantOp != uuid.Nil && op != wantOp) {
		t.Fatalf("pause cause = trigger:%q token:%q, want abuse and operation %s", trigger, snapshotToken, wantOp)
	}
	for deadline := time.Now().Add(2 * time.Second); ; {
		var activities int
		if err := testPool.QueryRow(ctx, `
			SELECT count(*) FROM activity
			WHERE sandbox_id = $1 AND action = 'abuse_paused' AND actor_id IS NULL`, id).Scan(&activities); err != nil {
			t.Fatal(err)
		}
		if activities == 1 {
			break
		}
		if activities > 1 || time.Now().After(deadline) {
			t.Fatalf("system pause activities = %d, want 1", activities)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return op
}

func TestIntegration_ComputeReconciliation_CandidateStates(t *testing.T) {
	ctx := context.Background()
	teamID, key := seedTeamAndKey(t)
	r := newRouter(t)
	starting := createActive(t, r, key, "compute-candidate-starting")
	resuming := createActive(t, r, key, "compute-candidate-resuming")
	paused := seedActiveSandbox(t, teamID, "compute-candidate-paused")
	destroyed := seedActiveSandbox(t, teamID, "compute-candidate-destroyed")
	for _, row := range []struct {
		id     uuid.UUID
		status string
	}{
		{starting, "starting"},
		{resuming, "resuming"},
		{paused, "paused"},
	} {
		if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = $2::sandbox_status WHERE id = $1`, row.id, row.status); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET destroyed_at = now() WHERE id = $1`, destroyed); err != nil {
		t.Fatal(err)
	}
	assertCandidates := func(want map[uuid.UUID]db.SandboxStatus) {
		t.Helper()
		rows, err := testQueries.ListComputePauseCandidates(ctx, db.ListComputePauseCandidatesParams{
			TeamID: teamID, AfterID: uuid.Nil, PageLimit: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(want) {
			t.Fatalf("candidate rows = %+v, want %v", rows, want)
		}
		for _, row := range rows {
			if row.TeamID != teamID || row.Status != want[row.ID] {
				t.Fatalf("candidate row = %+v, want %v", row, want)
			}
		}
	}
	assertCandidates(map[uuid.UUID]db.SandboxStatus{
		starting: db.SandboxStatusStarting,
		resuming: db.SandboxStatusResuming,
	})

	vmd := &stubVMD{}
	h := pauseHandlers(t, vmd)
	enforceComputeForTeam(t, h, teamID)
	h.ReconcileComputeOnce(ctx)
	if vmd.pauseCalls.Load() != 0 || readPauseOp(t, starting).status != "starting" || readPauseOp(t, resuming).status != "resuming" {
		t.Fatal("transitional candidates were not deferred")
	}
	for _, id := range []uuid.UUID{starting, resuming} {
		if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	assertCandidates(map[uuid.UUID]db.SandboxStatus{
		starting: db.SandboxStatusActive,
		resuming: db.SandboxStatusActive,
	})
	h.ReconcileComputeOnce(ctx)
	h.WaitAsyncBookkeeping()
	if vmd.pauseCalls.Load() != 2 || readPauseOp(t, starting).status != "paused" || readPauseOp(t, resuming).status != "paused" {
		t.Fatal("active candidates were not paused exactly once")
	}
}

func TestIntegration_ComputeReconciliation_PausesOnceAndClosesAccounting(t *testing.T) {
	ctx := context.Background()
	teamID, key := seedTeamAndKey(t)
	id := createActive(t, newRouter(t), key, "compute-containment-success")
	if countOpenIntervals(t, ctx, id) != 1 || countOpenComputeBillingIntervals(t, ctx, id) != 1 {
		t.Fatal("active sandbox must start with one open active and billing interval")
	}
	vmd := &stubVMD{}
	h := pauseHandlers(t, vmd)
	enforceComputeForTeam(t, h, teamID)

	h.ReconcileComputeOnce(ctx)
	h.WaitAsyncBookkeeping()
	got := readPauseOp(t, id)
	if got.status != "paused" || got.opID.Valid || got.leased || vmd.pauseCalls.Load() != 1 {
		t.Fatalf("first sweep: state=%+v host calls=%d, want one finalized pause", got, vmd.pauseCalls.Load())
	}
	assertComputePauseAccounting(t, id)
	op := assertSystemComputePause(t, id, uuid.Nil)

	h.ReconcileComputeOnce(ctx)
	h.WaitAsyncBookkeeping()
	if after := readPauseOp(t, id); after.status != "paused" || after.opID != got.opID || vmd.pauseCalls.Load() != 1 {
		t.Fatalf("duplicate sweep: state=%+v host calls=%d, want unchanged pause", after, vmd.pauseCalls.Load())
	}
	assertComputePauseAccounting(t, id)
	assertSystemComputePause(t, id, op)
}

func TestIntegration_ComputeReconciliation_PendingPauseUsesRecovery(t *testing.T) {
	ctx := context.Background()
	teamID, key := seedTeamAndKey(t)
	id := createActive(t, newRouter(t), key, "compute-containment-recovery")
	vmd := undecidedHost()
	h := pauseHandlers(t, vmd)
	source, path := enforceComputeForTeam(t, h, teamID)

	h.ReconcileComputeOnce(ctx)
	h.WaitAsyncBookkeeping()
	pending := readPauseOp(t, id)
	if pending.status != "pausing" || !pending.opID.Valid || vmd.pauseCalls.Load() != 2 {
		t.Fatalf("pending sweep: state=%+v host calls=%d, want one pending claim and its host retry", pending, vmd.pauseCalls.Load())
	}
	var trigger string
	var systemActor bool
	if err := testPool.QueryRow(ctx, `SELECT pause_op_trigger, pause_op_actor_id IS NULL FROM sandbox WHERE id = $1`, id).Scan(&trigger, &systemActor); err != nil {
		t.Fatal(err)
	}
	if trigger != "abuse" || !systemActor {
		t.Fatalf("pending cause = trigger:%q system actor:%t, want abuse and no actor", trigger, systemActor)
	}
	assertComputePauseAccounting(t, id)
	h.ReconcileComputeOnce(ctx)
	if vmd.pauseCalls.Load() != 2 || readPauseOp(t, id).opID != pending.opID {
		t.Fatal("duplicate sweep dispatched or replaced the pending pause")
	}
	if err := os.WriteFile(path, []byte(`{"mode":"enforce","restrictions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	source.Refresh(ctx)
	if decision := h.ComputeRestrictions.Evaluate(teamID, abuse.ActionResume); decision.Outcome != "allowed" {
		t.Fatalf("policy after restriction removal = %+v, want allowed", decision)
	}

	expireLease(t, id)
	recoveredVMD := &stubVMD{}
	recovery := pauseHandlers(t, recoveredVMD)
	recovery.ReconcilePendingPausesOnce(ctx, zerolog.Nop())
	recovery.WaitAsyncBookkeeping()
	got := readPauseOp(t, id)
	if got.status != "paused" || got.opID.Valid || got.leased {
		t.Fatalf("recovery: state=%+v, want original operation finalized", got)
	}
	assertComputePauseAccounting(t, id)
	assertSystemComputePause(t, id, uuid.UUID(pending.opID.Bytes))
}
