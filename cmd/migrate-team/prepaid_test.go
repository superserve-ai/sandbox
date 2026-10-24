//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPrepaidMigrationRefused(t *testing.T) {
	ctx := context.Background()
	for _, side := range []string{"source", "destination"} {
		for _, state := range []string{"free", "prepaid", "ended-prepaid", "pending", "uncertain", "failed", "issued", "disabled-settings", "funding", "enrolment"} {
			t.Run(side+"/"+state, func(t *testing.T) {
				team := uuid.New()
				name := "prepaid-migration-" + team.String()
				mustExec(t, srcPool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, name)
				mustExec(t, dstPool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, name)
				pool := srcPool
				if side == "destination" {
					pool = dstPool
				}
				switch state {
				case "free", "prepaid", "ended-prepaid":
					kind := state
					if state == "ended-prepaid" {
						kind = "prepaid"
					}
					mustExec(t, pool, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,$2,$2,'{}','{"max_concurrent":1}',clock_timestamp(),'staff','fixture authority')`, team, kind)
					if state == "ended-prepaid" {
						mustExec(t, pool, `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1`, team)
					}
				case "disabled-settings":
					mustExec(t, pool, `INSERT INTO billing_prepaid_auto_recharge(team_id,enabled) VALUES($1,false)`, team)
				case "funding":
					mustExec(t, pool, `UPDATE billing_funding_account SET prepaid=true,enforce=true,observe=true WHERE team_id=$1`, team)
				case "enrolment":
					mustExec(t, pool, `UPDATE billing_funding_account SET prepaid_enrolment_due_at=clock_timestamp() WHERE team_id=$1`, team)
				default:
					seedMigrationPurchase(t, pool, team, state)
				}
				sourceBefore := scanString(t, srcPool, `SELECT to_jsonb(t)::text FROM team t WHERE id=$1`, team)
				destBefore := scanString(t, dstPool, `SELECT to_jsonb(t)::text FROM team t WHERE id=$1`, team)
				auditBefore := scanString(t, pool, `SELECT COALESCE(jsonb_agg(to_jsonb(p))::text,'[]') FROM billing_prepaid_purchase p WHERE team_id=$1`, team)
				for _, phase := range []string{phasePlan, phaseCopy, phaseValidate, phaseDetach, phasePurge, phaseReleaseRollups} {
					cfg := config{teamID: team, sourceURL: srcURL, destURL: dstURL, phase: phase, destHostID: destHostID, destRegion: destRegion, confirmTeamName: name}
					if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), side+": refusing team migration:") {
						t.Fatalf("%s did not refuse unsupported authority: %v", phase, err)
					}
				}
				if scanString(t, srcPool, `SELECT to_jsonb(t)::text FROM team t WHERE id=$1`, team) != sourceBefore || scanString(t, dstPool, `SELECT to_jsonb(t)::text FROM team t WHERE id=$1`, team) != destBefore {
					t.Fatal("refused migration changed ownership or limits")
				}
				if scanString(t, pool, `SELECT COALESCE(jsonb_agg(to_jsonb(p))::text,'[]') FROM billing_prepaid_purchase p WHERE team_id=$1`, team) != auditBefore {
					t.Fatal("refused migration changed purchase authority")
				}
			})
		}
	}
}

func seedMigrationPurchase(t *testing.T, pool *pgxpool.Pool, team uuid.UUID, state string) {
	t.Helper()
	id := uuid.New()
	mustExec(t, pool, `INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key) VALUES($1,$2,$3,'checkout',500,$4,'','')`, id, team, "cus_"+team.String(), uuid.New())
	switch state {
	case "uncertain":
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET payment_state='uncertain',payment_first_attempt_at=clock_timestamp() WHERE id=$1`, id)
	case "failed":
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET payment_state='failed',failure_reason='checkout expired' WHERE id=$1`, id)
	case "issued":
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('customer',customer_id,'amount_cents',amount_cents) WHERE id=$1`, id)
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET credit_state='pending',credit_request=jsonb_build_object('customer',customer_id,'category','paid','amount',jsonb_build_object('type','monetary','monetary',jsonb_build_object('currency','usd','value',amount_cents)),'priority',50,'applicability_config',jsonb_build_object('scope',jsonb_build_object('price_type','metered')),'metadata',jsonb_build_object('prepaid_purchase_id',id::text)) WHERE id=$1`, id)
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET credit_state='uncertain',credit_first_attempt_at=clock_timestamp() WHERE id=$1`, id)
		mustExec(t, pool, `UPDATE billing_prepaid_purchase SET credit_state='issued',stripe_credit_grant_id=$2,credit_evidence=credit_request||jsonb_build_object('id',$2::text),credited_at=clock_timestamp() WHERE id=$1`, id, "credgr_"+id.String())
	}
}

func TestPrepaidMigrationRechecksLockedAuthority(t *testing.T) {
	ctx := context.Background()
	for _, side := range []string{"source", "destination"} {
		t.Run(side, func(t *testing.T) {
			pool := srcPool
			if side == "destination" {
				pool = dstPool
			}
			team := uuid.New()
			mustExec(t, pool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "locked-prepaid-"+team.String())
			if err := checkPrepaidMigration(ctx, pool, team); err != nil {
				t.Fatal(err)
			}
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(ctx)
			if _, err = writer.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{}','{"max_concurrent":1}',clock_timestamp(),'staff','concurrent entry')`, team); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var tx pgx.Tx
				var err error
				if side == "source" {
					tx, err = pool.Begin(ctx)
					if err == nil {
						err = lockSourceAssignments(ctx, tx, team)
					}
				} else {
					tx, err = lockPrepaidDestination(ctx, pool, team)
				}
				if tx != nil {
					tx.Rollback(ctx)
				}
				done <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var waiting bool
				if err = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query IN ('SELECT id FROM team WHERE id=$1 FOR UPDATE','SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE'))`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-done:
					t.Fatal("refusal did not serialize with new authority", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("refusal never reached owner lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err == nil || !strings.Contains(err.Error(), "prepaid financial-authority transfer") {
				t.Fatal("new authority escaped locked recheck", err)
			}
		})
	}
}
