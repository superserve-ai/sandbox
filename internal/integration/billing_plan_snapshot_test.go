//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type billingPlanSnapshotTrace struct {
	once     sync.Once
	advance  func(context.Context) error
	err      error
	advanced bool
}

func (tr *billingPlanSnapshotTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "-- name: GetTeamEffectiveLimits ") {
		tr.once.Do(func() { tr.advanced = true; tr.err = tr.advance(ctx) })
	}
	return ctx
}

func (*billingPlanSnapshotTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestIntegration_BillingPlanReadUsesOneSnapshot(t *testing.T) {
	team, key := seedTeamAndKey(t)
	var beforeAssignment uuid.UUID
	beforePending, afterPending, actor := uuid.New(), uuid.New(), uuid.New()
	if err := testPool.QueryRow(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'before','custom','{"display_name":"Before"}','{"max_concurrent":10,"max_vcpu":1}',clock_timestamp(),'staff','initial assignment') RETURNING id`, team).Scan(&beforeAssignment); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_change(id,team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key)
        VALUES($1,$2,$3,'free','free','{"display_name":"Free"}','{"max_concurrent":1}',clock_timestamp()+interval '2 days',true,$4,'customer','original exit','before')`, beforePending, team, beforeAssignment, actor); err != nil {
		t.Fatal(err)
	}
	trace := &billingPlanSnapshotTrace{advance: func(ctx context.Context) error {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `UPDATE team_plan_change SET state='undone',undone_at=clock_timestamp(),undo_reason='replacement agreement' WHERE id=$1`, beforePending); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1 AND effective_to IS NULL`, team); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'after','custom','{"display_name":"After"}','{"max_concurrent":200,"max_vcpu":4}',clock_timestamp(),'staff','replacement assignment')`, team); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_plan_change(id,team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,requested_by,requested_via,reason,idempotency_key)
            SELECT $1,team_id,id,'free','free','{"display_name":"Free"}','{"max_concurrent":1}',clock_timestamp()+interval '3 days',true,$3,'customer','replacement exit','after'
            FROM team_plan_assignment WHERE team_id=$2 AND effective_to IS NULL`, afterPending, team, actor); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}}
	cfg := testPool.Config().Copy()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	r := newBillingRouterWithPool(t, nil, pool)
	check := func(wantKey, wantName string, wantMax, wantVCPU int, wantPending uuid.UUID) {
		t.Helper()
		w := do(r, http.MethodGet, "/billing/plan", key, "")
		var response struct {
			Plan struct {
				Key    string `json:"plan_key"`
				Name   string `json:"display_name"`
				Limits struct {
					Max  int `json:"max_concurrent"`
					VCPU int `json:"max_vcpu"`
				} `json:"limits"`
			} `json:"plan"`
			Pending *struct {
				ID uuid.UUID `json:"id"`
			} `json:"pending_change"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatalf("billing read %d %s", w.Code, w.Body)
		}
		if response.Plan.Key != wantKey || response.Plan.Name != wantName || response.Plan.Limits.Max != wantMax || response.Plan.Limits.VCPU != wantVCPU || response.Pending == nil || response.Pending.ID != wantPending {
			t.Fatalf("inconsistent billing snapshot: %s", w.Body)
		}
	}
	check("before", "Before", 10, 1, beforePending)
	if !trace.advanced || trace.err != nil {
		t.Fatalf("concurrent replacement not committed: %t %v", trace.advanced, trace.err)
	}
	check("after", "After", 200, 4, afterPending)
}
