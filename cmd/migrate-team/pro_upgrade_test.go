//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const insertMigrationProUpgrade = `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state)
 VALUES($1,$2,$3,'cus_example','pro_monthly','{}',now(),now(),now()+interval '1 month',now(),100,'prepared')`

func TestProUpgradeHistoryBlocksMigration(t *testing.T) {
	ctx := context.Background()
	for _, side := range []string{"source", "destination"} {
		t.Run(side, func(t *testing.T) {
			f := &fixture{team: uuid.New(), owner: uuid.New()}
			mustExec(t, srcPool, `INSERT INTO team(id,name) VALUES($1,'upgrade-' || $1::uuid::text)`, f.team)
			owner := srcPool
			if side == "destination" {
				owner = dstPool
				mustExec(t, dstPool, `INSERT INTO team(id,name) VALUES($1,'upgrade-' || $1::uuid::text)`, f.team)
			}
			mustExec(t, owner, insertMigrationProUpgrade, uuid.New(), f.team, f.owner)
			for _, state := range []string{"prepared", "expired", "ended"} {
				mustExec(t, owner, `UPDATE billing_pro_upgrade SET state=$2 WHERE team_id=$1`, f.team, state)
				for _, phase := range []string{phasePlan, phaseCopy, phaseValidate, phaseDetach, phasePurge, phaseReleaseRollups} {
					if err := run(ctx, f.cfg(phase)); err == nil || !strings.Contains(err.Error(), "Pro upgrade history") {
						t.Fatalf("%s state=%s: %v", phase, state, err)
					}
				}
			}
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if side == "source" {
				err = lockSourcePromotionMigration(ctx, tx, f.team)
			} else {
				err = checkAssignmentReferences(ctx, srcPool, tx, f.team)
			}
			if err == nil || !strings.Contains(err.Error(), "Pro upgrade history") {
				t.Fatalf("locked recheck: %v", err)
			}
		})
	}
}

func TestProUpgradeEntryWaitsForMigrationFence(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	mustExec(t, srcPool, `INSERT INTO team(id,name) VALUES($1,'upgrade-' || $1::uuid::text)`, team)
	tx, err := srcPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = lockSourcePromotionMigration(ctx, tx, team); err != nil {
		t.Fatal(err)
	}
	entry, err := srcPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Rollback(ctx)
	if _, err = entry.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = entry.Exec(ctx, insertMigrationProUpgrade, uuid.New(), team, uuid.New())
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Fatalf("entry did not wait for migration: %v", err)
	}
	entry.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO stripe_promotion_migration_fence(team_id) VALUES($1)`, team); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = srcPool.Exec(ctx, insertMigrationProUpgrade, uuid.New(), team, uuid.New())
	if !errors.As(err, &pe) || pe.Code != "23505" || !strings.Contains(pe.Message, "regional migration") {
		t.Fatalf("entry bypassed committed fence: %v", err)
	}
}
