//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/integrationdb"
)

func TestIntegration_PricingAdoptionBarrier(t *testing.T) {
	ctx := t.Context()
	admin := testPool
	name := "adoption_" + uuid.NewString()[:8] + "_test"
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	testPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testPool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	testSystemTeamID, err := integrationdb.Reset(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}

	financialTeams := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, team := range financialTeams {
		if _, err := testPool.Exec(ctx, `INSERT INTO team(id,name) VALUES($1::uuid,'concurrent-financial-'||$1::uuid::text);`, team); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{}','{"max_concurrent":1}',clock_timestamp(),'migration','local fixture')`, team); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team); err != nil {
				t.Fatal(err)
			}
		}
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	var initial, epoch uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT billing_prepare_pricing_adoption('usw',$1,'operator@example.com','local adoption test')`, testSystemTeamID).Scan(&initial); err != nil {
		t.Fatal(err)
	}
	pending, foreign := uuid.New(), uuid.New()
	exec(`INSERT INTO team(id,name,home_region) VALUES($1,'pending-adoption','usw'),($2,'foreign-residual','use')`, pending, foreign)
	exec(`INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`, pending)
	exec(`UPDATE billing_pricing_switch SET pricing_version='v2'`)
	var model string
	var open bool
	if err := tx.QueryRow(ctx, `SELECT * FROM billing_pricing_public_state()`).Scan(&model, &open, &epoch); err != nil {
		t.Fatal(err)
	}
	if model != "legacy" || open || epoch == initial {
		t.Fatalf("preparing public state=%s/%t/%s previous=%s", model, open, epoch, initial)
	}
	reject := func(sql, code string, args ...any) {
		t.Helper()
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, sql, args...); pgCode(err) != code {
			t.Fatalf("expected %s, got %v", code, err)
		}
		if err := sp.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reject(`SELECT billing_assert_pricing_entry_open($1,'legacy')`, "55000", epoch)
	reject(`SELECT billing_capture_pricing_adoption('use',$1,'operator@example.com','wrong binding')`, "P0001", testSystemTeamID)
	reject(`SELECT billing_release_pricing_adoption('usw',$1,$2,'operator@example.com','no evidence','{}')`, "P0001", testSystemTeamID, epoch)
	denied, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Rollback(context.Background())
	if _, err := denied.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Exec(ctx, `INSERT INTO team(name) VALUES('concurrent-adoption-signup')`); pgCode(err) != "55P03" {
		t.Fatalf("signup escaped switch/release fencing: %v", err)
	}
	denied.Rollback(ctx)
	exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
 SELECT t.id,'free','free','{}','{"max_concurrent":1}',clock_timestamp(),'migration','local adoption test'
 FROM team t WHERE t.id NOT IN ($1,$2,$3) AND NOT EXISTS(SELECT 1 FROM team_plan_assignment a WHERE a.team_id=t.id AND a.effective_to IS NULL)`, testSystemTeamID, pending, foreign)
	evidence, err := json.Marshal(map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": testSystemTeamID.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "local-fixture", "worker_reference": "local-fixture"})
	if err != nil {
		t.Fatal(err)
	}

	release := func() map[string]any {
		t.Helper()
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT billing_release_pricing_adoption('usw',$1,$2,'operator@example.com','local adoption test',$3::jsonb)`, testSystemTeamID, epoch, evidence).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for i, team := range financialTeams[:2] {
		producer, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer producer.Rollback(context.Background())
		query := `UPDATE team_billing_account SET checkout_may_exist=true WHERE team_id=$1`
		if i == 1 {
			query = `INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`
		}
		if _, err := producer.Exec(ctx, query, team); err != nil {
			t.Fatal(err)
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, `SELECT billing_release_pricing_adoption('usw',$1,$2,'operator@example.com','concurrent financial authority',$3::jsonb)`, testSystemTeamID, epoch, evidence); pgCode(err) != "55P03" {
			t.Fatalf("release escaped financial lock case=%d: %v", i, err)
		}
		if err := sp.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := producer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	between, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer between.Rollback(context.Background())
	if _, err := between.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE`, financialTeams[2]); err != nil {
		t.Fatal(err)
	}
	var releasePID int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&releasePID); err != nil {
		t.Fatal(err)
	}
	type releaseResult struct {
		raw []byte
		err error
	}
	resultCh := make(chan releaseResult, 1)
	go func() {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT billing_release_pricing_adoption('usw',$1,$2,'operator@example.com','between-phase account creation',$3::jsonb)`, testSystemTeamID, epoch, evidence).Scan(&raw)
		resultCh <- releaseResult{raw, err}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, releasePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("release did not wait for team lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := between.Exec(ctx, `INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`, financialTeams[2]); err != nil {
		t.Fatal(err)
	}
	if err := between.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-resultCh
	if result.err != nil {
		t.Fatal(result.err)
	}
	var blocked map[string]any
	if err := json.Unmarshal(result.raw, &blocked); err != nil {
		t.Fatal(err)
	}
	accountWriter, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accountWriter.Rollback(context.Background())
	if _, err := accountWriter.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := accountWriter.Exec(ctx, `UPDATE team_billing_account SET checkout_may_exist=false WHERE team_id=$1`, financialTeams[2]); pgCode(err) != "55P03" {
		t.Fatalf("between-phase account escaped final lock: %v", err)
	}
	accountWriter.Rollback(ctx)
	if blocked["deferred"] != float64(4) {
		t.Fatalf("release missed newly committed obligations: %v", blocked)
	}
	exec(`UPDATE team_billing_account SET checkout_may_exist=false WHERE team_id=ANY($1)`, financialTeams)
	if blocked["released"] != false || blocked["unassigned"] != float64(2) {
		t.Fatalf("release ignored pending/foreign unassigned teams: %v", blocked)
	}
	var residuals int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM billing_pricing_adoption_inventory WHERE epoch=$1 AND present AND assignment_id IS NULL`, epoch).Scan(&residuals); err != nil || residuals != 2 {
		t.Fatalf("durable residuals=%d %v", residuals, err)
	}
	var deferredReason string
	if err := tx.QueryRow(ctx, `SELECT reason FROM billing_pricing_adoption_inventory WHERE epoch=$1 AND team_id=$2`, epoch, pending).Scan(&deferredReason); err != nil || deferredReason != "checkout_pending" {
		t.Fatalf("durable reason=%s %v", deferredReason, err)
	}
	exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
 SELECT id,'free','free','{}','{"max_concurrent":1}',clock_timestamp(),'migration','local adoption test' FROM team WHERE id IN ($1,$2)`, pending, foreign)
	if result := release(); result["released"] != false || result["unassigned"] != float64(0) || result["deferred"] != float64(1) {
		t.Fatalf("assignment hid unresolved checkout: %v", result)
	}
	if err := tx.QueryRow(ctx, `SELECT reason FROM billing_pricing_adoption_inventory WHERE epoch=$1 AND team_id=$2`, epoch, pending).Scan(&deferredReason); err != nil || deferredReason != "checkout_pending" {
		t.Fatalf("assigned checkout reason=%s %v", deferredReason, err)
	}
	exec(`UPDATE team_billing_account SET checkout_may_exist=false WHERE team_id=$1`, pending)
	exec(`INSERT INTO billing_pricing_adoption_credit_hold(team_id,reason) VALUES($1,'credit_unknown')`, foreign)
	if result := release(); result["released"] != false || result["deferred"] != float64(1) {
		t.Fatalf("assignment hid unresolved provider credit: %v", result)
	}
	exec(`DELETE FROM billing_pricing_adoption_credit_hold WHERE team_id=$1`, foreign)
	exec(`UPDATE team_billing_account SET stripe_customer_id='cus_changed_source' WHERE team_id=$1`, financialTeams[0])
	if result := release(); result["released"] != false || result["deferred"] != float64(1) {
		t.Fatalf("migration assignment hid changed financial source: %v", result)
	}
	exec(`UPDATE team_billing_account SET stripe_customer_id=NULL WHERE team_id=$1`, financialTeams[0])
	var pauseSandbox uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO sandbox(team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib) VALUES($1,'adoption-worker-proof','active','default',1,1024,4096) RETURNING id`, pending).Scan(&pauseSandbox); err != nil {
		t.Fatal(err)
	}
	exec(`SELECT request_team_pause_all($1,'plan_switch_free')`, pending)
	if result := release(); result["released"] != false || result["unassigned"] != float64(0) {
		t.Fatalf("unsettled pause target did not block release: %v", result)
	}
	exec(`UPDATE billing_team_pause_target SET done_at=clock_timestamp() WHERE done_at IS NULL`)
	released := release()
	if released["released"] != true || released["unassigned"] != float64(0) {
		t.Fatalf("zero residual release=%v", released)
	}
	if err := tx.QueryRow(ctx, `SELECT * FROM billing_pricing_public_state()`).Scan(&model, &open, &epoch); err != nil || model != "v2" || !open {
		t.Fatalf("released state=%s/%t %v", model, open, err)
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := savepoint.Exec(ctx, `SELECT billing_assert_pricing_entry_open($1,'legacy')`, epoch); pgCode(err) != "55000" {
		t.Fatalf("stale preparing model passed released assertion: %v", err)
	}
	savepoint.Rollback(ctx)
	var asserted uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT billing_assert_pricing_entry_open($1,'v2')`, epoch).Scan(&asserted); err != nil || asserted != epoch {
		t.Fatalf("released assertion=%s %v", asserted, err)
	}
	oldEpoch := epoch
	exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	if err := tx.QueryRow(ctx, `SELECT * FROM billing_pricing_public_state()`).Scan(&model, &open, &epoch); err != nil || model != "legacy" || open || epoch == oldEpoch {
		t.Fatalf("rollback state=%s/%t/%s %v", model, open, epoch, err)
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version='v2'`)
	if err := tx.QueryRow(ctx, `SELECT * FROM billing_pricing_public_state()`).Scan(&model, &open, &epoch); err != nil || model != "legacy" || open {
		t.Fatalf("second rollout auto released: %s/%t %v", model, open, err)
	}
	var newborn uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO team(name) VALUES('preparing-newborn') RETURNING id`).Scan(&newborn); err != nil {
		t.Fatal(err)
	}
	var assigned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND kind='free' AND effective_to IS NULL)`, newborn).Scan(&assigned); err != nil || !assigned {
		t.Fatalf("preparing newborn planless: %v %v", assigned, err)
	}
	savepoint, err = tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := savepoint.Exec(ctx, `SELECT billing_release_pricing_adoption('usw',$1,$2,'operator@example.com','stale epoch',$3::jsonb)`, testSystemTeamID, oldEpoch, evidence); pgCode(err) != "55000" {
		t.Fatalf("old epoch released new rollout: %v", err)
	}
	savepoint.Rollback(ctx)
}

func TestIntegration_PricingAdoptionPublicStateFailsClosed(t *testing.T) {
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy'`); err != nil {
		t.Fatal(err)
	}
	check := func(q pgx.Tx, missing bool) {
		t.Helper()
		rows, err := q.Query(ctx, `SELECT * FROM billing_pricing_public_state()`)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			n++
			var model string
			var open bool
			var epoch *uuid.UUID
			if err := rows.Scan(&model, &open, &epoch); err != nil {
				t.Fatal(err)
			}
			if model != "legacy" || open || (missing && epoch != nil) {
				t.Fatalf("unsafe public state=%s/%t/%v", model, open, epoch)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		if n != 1 {
			t.Fatalf("public state returned %d rows", n)
		}
	}
	check(tx, false)
	sp, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Exec(ctx, `SELECT billing_assert_pricing_entry_open()`); pgCode(err) != "55000" {
		t.Fatalf("OFF passed v2 entry assertion: %v", err)
	}
	if err := sp.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"billing_pricing_switch", "billing_pricing_adoption"} {
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, `ALTER TABLE `+pgx.Identifier{table}.Sanitize()+` DISABLE TRIGGER ALL`); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, `DELETE FROM `+pgx.Identifier{table}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		check(sp, true)
		if err := sp.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='v2'`); err != nil {
		t.Fatal(err)
	}
	var epoch uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT epoch FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []string{"region", "system_team_id", "epoch", "worker_sha", "verified_worker", "deployment_reference"} {
		evidence := map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": testSystemTeamID.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "local-fixture", "worker_reference": "local-fixture"}
		delete(evidence, broken)
		raw, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2::jsonb`, testSystemTeamID, raw); err != nil {
			t.Fatal(err)
		}
		check(tx, true)
	}
}

func TestIntegration_PricingAdoptionCLIBlocksResidualRelease(t *testing.T) {
	ctx := t.Context()
	if _, err := testPool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy'`); err != nil {
		t.Fatal(err)
	}
	fixture, router, key := newProFixture(t, "pro_monthly")
	team := fixture.team
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`, team); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	})
	cli := func(expectFailure bool, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "go", append([]string{"run", "../../cmd/pricing-v2-migrate"}, args...)...)
		cmd.Env = append(os.Environ(), "DATABASE_URL="+testPool.Config().ConnString(), "TEAM_CREATION_REGION=usw", "SYSTEM_TEAM_ID="+testSystemTeamID.String(), "STRIPE_SECRET_KEY=")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if (err != nil) != expectFailure {
			t.Fatalf("CLI failure=%t err=%v stdout=%s stderr=%s", expectFailure, err, stdout.String(), stderr.String())
		}
		return stdout.Bytes()
	}
	authority := []string{"--confirm", "--actor", "operator@example.com", "--reason", "local CLI adoption test"}
	cli(false, append([]string{"prepare"}, authority...)...)
	if _, err := testPool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='v2'`); err != nil {
		t.Fatal(err)
	}
	public := getPublicPlans(t, router)
	if public.PricingVersion != "legacy" {
		t.Fatalf("preparing exposed public v2: %+v", public)
	}
	for _, card := range public.Cards {
		if card.Monthly != nil && card.Monthly.Available {
			t.Fatal("preparing exposed subscription entry")
		}
	}
	var choicesBefore, choicesAfter int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_signup_choice WHERE team_id=$1`, team).Scan(&choicesBefore); err != nil {
		t.Fatal(err)
	}
	response := do(router, http.MethodPost, "/stripe/plan-choice", key, `{"offer":"free"}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("preparing old-unassigned Free entry=%d %s", response.Code, response.Body.String())
	}
	var assignedAfter int
	if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_signup_choice WHERE team_id=$1),(SELECT count(*) FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL)`, team).Scan(&choicesAfter, &assignedAfter); err != nil || choicesAfter != choicesBefore || assignedAfter != 0 {
		t.Fatalf("blocked Free wrote choice: %d/%d %v", choicesBefore, choicesAfter, err)
	}
	captured := cli(false, append([]string{"capture"}, authority...)...)
	var snapshot struct {
		Epoch      uuid.UUID `json:"epoch"`
		Unassigned int       `json:"unassigned"`
		Released   bool      `json:"released"`
	}
	if err := json.Unmarshal(captured, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Unassigned < 1 {
		t.Fatal("pending team missing from exhaustive capture")
	}
	var reason string
	if err := testPool.QueryRow(ctx, `SELECT reason FROM billing_pricing_adoption_inventory WHERE epoch=$1 AND team_id=$2 AND present`, snapshot.Epoch, team).Scan(&reason); err != nil || reason != "checkout_pending" {
		t.Fatalf("CLI capture not durably visible: %s %v", reason, err)
	}
	evidence, err := json.Marshal(map[string]any{"epoch": snapshot.Epoch.String(), "region": "usw", "system_team_id": testSystemTeamID.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "local-fixture", "worker_reference": "local-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, evidence, 0600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"release"}, authority...)
	args = append(args, "--epoch", snapshot.Epoch.String(), "--evidence-file", path)
	blocked := cli(true, args...)
	if err := json.Unmarshal(blocked, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Released || snapshot.Unassigned < 1 {
		t.Fatalf("CLI release ignored residuals: %s", blocked)
	}
	var open bool
	if err := testPool.QueryRow(ctx, `SELECT entry_open FROM billing_pricing_public_state()`).Scan(&open); err != nil || open {
		t.Fatalf("blocked CLI opened public entry: %v %v", open, err)
	}
	var events int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_pricing_adoption_event WHERE epoch=$1 AND action='release_blocked'`, snapshot.Epoch).Scan(&events); err != nil || events < 1 {
		t.Fatalf("blocked attempt not durable: %d %v", events, err)
	}
}
