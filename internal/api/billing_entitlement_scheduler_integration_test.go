//go:build integration

package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestEntitlementClaimSnapshotAndIdleQueries(t *testing.T) {
	h, _ := fundingTransitionFixture(t)
	ctx := t.Context()
	schema := "scheduler_" + uuid.New().String()[:8]
	if _, err := h.Pool.Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.billing_entitlement_work (LIKE public.billing_entitlement_work INCLUDING ALL)`); err != nil {
		t.Fatal(err)
	}
	base := h.Pool
	t.Cleanup(func() {
		if _, err := base.Exec(context.WithoutCancel(ctx), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	cfg := base.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.Pool, h.DB = pool, db.New(pool)
	counter := countPairWorkerQueries(t, h)
	for _, retry := range []bool{false, true} {
		before := counter.calls.Load()
		jobs, delay, err := h.claimUsageEntitlementsWithDelay(ctx, retry, 4, 0)
		if err != nil || len(jobs) != 0 || delay != 5*time.Second || counter.calls.Load()-before != 1 {
			t.Fatal("empty lane requires one read and bounded discovery", jobs, delay, err, counter.calls.Load()-before)
		}
	}
	if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id,next_check_at) VALUES($1,'infinity')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if jobs, delay, err := h.claimUsageEntitlementsWithDelay(ctx, false, 4, 0); err != nil || len(jobs) != 0 || delay != 5*time.Second {
		t.Fatal("dormant work caused rapid polling", jobs, delay, err)
	}
	due, future := uuid.New(), uuid.New()
	if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id,next_check_at) VALUES($1,clock_timestamp()-interval '1 second'),($2,clock_timestamp()+interval '2 seconds')`, due, future); err != nil {
		t.Fatal(err)
	}
	jobs, delay, err := h.claimUsageEntitlementsWithDelay(ctx, false, 4, 0)
	if err != nil || len(jobs) != 1 || jobs[0].Contract != due || delay < time.Second || delay > 2*time.Second {
		t.Fatal("claim snapshot did not exclude its own rows or honor near due work", jobs, delay, err)
	}
	// Another replica holds an eligible row across our claim snapshot. Skipping
	// that lock must neither duplicate its claim nor lose it after release.
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp()-interval '1 second' WHERE contract_id=$1`, future); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT contract_id FROM billing_entitlement_work WHERE contract_id=$1 FOR UPDATE`, future); err != nil {
		t.Fatal(err)
	}
	jobs, delay, err = h.claimUsageEntitlementsWithDelay(ctx, false, 4, 0)
	if err != nil || len(jobs) != 0 || delay > 5*time.Second {
		t.Fatal("concurrent locked row was claimed or lost", jobs, delay, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, delay, err = h.claimUsageEntitlementsWithDelay(ctx, false, 4, 0)
	if err != nil || len(jobs) != 1 || jobs[0].Contract != future || delay != 5*time.Second {
		t.Fatal("released earlier work was not discovered", jobs, delay, err)
	}
}
