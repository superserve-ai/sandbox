//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

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
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'before','custom','{"display_name":"Before"}','{"max_concurrent":10,"max_vcpu":1}',clock_timestamp(),'staff','initial assignment')`, team); err != nil {
		t.Fatal(err)
	}
	trace := &billingPlanSnapshotTrace{advance: func(ctx context.Context) error {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1 AND effective_to IS NULL`, team); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'after','custom','{"display_name":"After"}','{"max_concurrent":200,"max_vcpu":4}',clock_timestamp(),'staff','replacement assignment')`, team); err != nil {
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
	check := func(wantKey, wantName string, wantMax, wantVCPU int) {
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
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatalf("billing read %d %s", w.Code, w.Body)
		}
		if response.Plan.Key != wantKey || response.Plan.Name != wantName || response.Plan.Limits.Max != wantMax || response.Plan.Limits.VCPU != wantVCPU {
			t.Fatalf("inconsistent billing snapshot: %s", w.Body)
		}
	}
	check("before", "Before", 10, 1)
	if !trace.advanced || trace.err != nil {
		t.Fatalf("concurrent replacement not committed: %t %v", trace.advanced, trace.err)
	}
	check("after", "After", 200, 4)
}
