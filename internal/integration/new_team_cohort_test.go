//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func cohortFixture(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	// Roles are cluster-wide, as in the existing promotion test harness. These
	// databases are isolated and never name a provider or deployment database.
	rolloutExec(t, testPool, `DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN',r); END IF; END LOOP; END $$`)
	pool := promotionIsolatedDatabase(t, true)
	system, actor := uuid.New(), uuid.New()
	rolloutExec(t, pool, `INSERT INTO team(id,name) VALUES($1,'cohort-system')`, system)
	rolloutExec(t, pool, `INSERT INTO profile(id,email) VALUES($1,'cohort@example.invalid')`, actor)
	// Production runs the zero-template Free step on the catalog's Free.
	var free uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO billing_plan_version SELECT (jsonb_populate_record(NULL::billing_plan_version,to_jsonb(v)||jsonb_build_object(
  'id',gen_random_uuid(),'version',(SELECT max(version)+1 FROM billing_plan_version WHERE family='free'),'state','draft','max_templates',0,
  'created_by',NULL,'published_by',NULL,'published_at',NULL,'retired_by',NULL,'retired_at',NULL))).*
 FROM billing_plan_version v WHERE v.family='free' AND v.pricing_version='v2' AND v.state='published' RETURNING id`).Scan(&free); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `SELECT publish_billing_plan_version($1,NULL)`, free)
	for _, family := range []string{"developer", "pro"} {
		cohortPublishSubscription(t, pool, family)
	}
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=0.07,max_sandboxes=2,max_vcpu=3,max_memory_mib=5120,max_disk_mib=9216 WHERE singleton`)
	return pool, system, actor
}

func cohortPublishSubscription(t *testing.T, pool *pgxpool.Pool, family string) {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO billing_plan_version(family,version,pricing_version,kind,public,self_serve,display_name,monthly_fee_cents,credit_schedule,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)
 VALUES($1,(SELECT COALESCE(max(version),0)+1 FROM billing_plan_version WHERE family=$1),'v2','subscription',true,true,$1,3100,
  jsonb_build_array(jsonb_build_object('start_months',0,'repeat',NULL,'every_months',1,'amount_cents',3100,'expires_after_months',1)),7,3,3072,9216,4) RETURNING id`, family).Scan(&id); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `SELECT publish_billing_plan_version($1,NULL)`, id)
}

func cohortRelease(t *testing.T, pool *pgxpool.Pool, system uuid.UUID) uuid.UUID {
	t.Helper()
	epoch, err := cohortTryRelease(t, pool, system)
	if err != nil {
		t.Fatal(err)
	}
	return epoch
}

func cohortTryRelease(t *testing.T, pool *pgxpool.Pool, system uuid.UUID) (uuid.UUID, error) {
	t.Helper()
	var epoch uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT billing_prepare_new_team_gate('use',$1,'local-test','genuine new teams only')`, system).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{"region": "use", "system_team_id": system, "epoch": epoch, "cohort_contract": 1, "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "writers": []map[string]any{
		{"role": "api", "cohort_contract": 1, "verified": true, "source_sha": "1111111111111111111111111111111111111111", "reference": "disposable-test-api", "digest": "local-test"},
		{"role": "workers", "cohort_contract": 1, "verified": true, "source_sha": "1111111111111111111111111111111111111111", "reference": "disposable-test-worker", "digest": "local-test"},
		{"role": "console", "cohort_contract": 1, "verified": true, "source_sha": "2222222222222222222222222222222222222222", "reference": "disposable-test-ui", "digest": "local-test"}}})
	err := pool.QueryRow(t.Context(), `SELECT billing_release_new_team_gate('use',$1,$2,'local-test','verified test-only writers',$3)`, system, epoch, evidence).Scan(&epoch)
	return epoch, err
}

func cohortCreate(t *testing.T, pool *pgxpool.Pool, actor uuid.UUID) uuid.UUID {
	t.Helper()
	var team uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM create_team_with_signup_trial($1,$2,'use','first_team')`, "cohort-"+uuid.NewString(), actor).Scan(&team); err != nil {
		t.Fatal(err)
	}
	return team
}

func TestIntegration_NewTeamCohortPreservesOldAndRotatesAdmission(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	old := uuid.New()
	rolloutExec(t, pool, `INSERT INTO team(id,name) VALUES($1,'old-legacy')`, old)
	rolloutExec(t, pool, `INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`, old)
	var before []byte
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object('team',to_jsonb(t),'account',to_jsonb(a)) FROM team t JOIN team_billing_account a ON a.team_id=t.id WHERE t.id=$1`, old).Scan(&before); err != nil {
		t.Fatal(err)
	}
	epoch := cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	var model, source string
	var open bool
	var current, enrolled *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT * FROM billing_team_pricing_state($1)`, team).Scan(&model, &source, &open, &current, &enrolled); err != nil {
		t.Fatal(err)
	}
	if model != "v2" || source != "new_team" || !open || current == nil || *current != epoch || enrolled == nil || *enrolled != epoch {
		t.Fatalf("wrong new state %s %s %v %v %v", model, source, open, current, enrolled)
	}
	var reason string
	var plans, count int
	var pending, eligible bool
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team_plan_assignment WHERE team_id=$1),o.reason,billing_team_awaiting_plan($1),team_sandbox_billing_eligible($1) FROM team_signup_promotion_outcome o WHERE o.team_id=$1`, team).Scan(&plans, &reason, &pending, &eligible); err != nil {
		t.Fatal(err)
	}
	if plans != 0 || reason != "first_user_claim" && reason != "first_identity_claim" || !pending || !eligible {
		t.Fatalf("new team did not start on its trial: plans=%d reason=%s awaiting=%v eligible=%v", plans, reason, pending, eligible)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND amount_usd=0.07`, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("signup trial was not the configured grant: %d %v", count, err)
	}
	rolloutExec(t, pool, `SELECT billing_close_new_team_gate($1,'local-test','hold fresh entry')`, epoch)
	if err := pool.QueryRow(t.Context(), `SELECT * FROM billing_team_pricing_state($1)`, team).Scan(&model, &source, &open, &current, &enrolled); err != nil {
		t.Fatal(err)
	}
	if model != "v2" || open || *current == epoch || *enrolled != epoch {
		t.Fatalf("closed state lost enrollment: %s/%v/%v/%v", model, open, current, enrolled)
	}
	second := cohortRelease(t, pool, system)
	if err := pool.QueryRow(t.Context(), `SELECT * FROM billing_team_pricing_state($1)`, team).Scan(&model, &source, &open, &current, &enrolled); err != nil {
		t.Fatal(err)
	}
	if !open || *current != second || *enrolled != epoch {
		t.Fatal("reopen orphaned/rewrote original cohort")
	}
	if err := pool.QueryRow(t.Context(), `SELECT * FROM billing_team_pricing_state($1)`, old).Scan(&model, &source, &open, &current, &enrolled); err != nil {
		t.Fatal(err)
	}
	if model != "legacy" || source != "legacy" || !open || current != nil || enrolled != nil {
		t.Fatal("public gate adopted an old team")
	}
	var after []byte
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object('team',to_jsonb(t),'account',to_jsonb(a)) FROM team t JOIN team_billing_account a ON a.team_id=t.id WHERE t.id=$1`, old).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("old access or checkout history changed")
	}
}

func TestIntegration_NewTeamCohortRejectsUntrustedCreationAndOldWriters(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	epoch := cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	reject := func(sql, code string, args ...any) {
		t.Helper()
		_, err := pool.Exec(t.Context(), sql, args...)
		if pgCode(err) != code {
			t.Fatalf("wanted %s, got %v for %s", code, err, sql)
		}
	}
	reject(`INSERT INTO team(id,name,created_at) VALUES($1,'backdated-import','2020-01-01')`, "55000", uuid.New())
	reject(`SELECT id FROM create_team_with_signup_trial('foreign-home',$1,'usw','first_team')`, "55000", actor)
	reject(`UPDATE billing_new_team_enrollment SET enrollment_epoch=gen_random_uuid() WHERE team_id=$1`, "P0001", team)
	reject(`DELETE FROM billing_new_team_enrollment WHERE team_id=$1`, "P0001", team)
	// Even a prior API replica cannot durably accept a legacy metered lease.
	rolloutExec(t, pool, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	reject(`UPDATE team_billing_account SET checkout_initializing_at=clock_timestamp(),checkout_pending_attempt_ids=ARRAY[$2::uuid] WHERE team_id=$1`, "55000", team, uuid.New())
	// New consent is stamped, unchanged replay survives close, disable survives,
	// and a later re-enable is fresh even when its amount/actor are unchanged.
	rolloutExec(t, pool, `INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,threshold_cents,amount_cents,updated_by,admission_source,admission_epoch) VALUES($1,true,500,500,$2,'new_team',$3)`, team, actor, epoch)
	rolloutExec(t, pool, `SELECT billing_close_new_team_gate($1,'local-test','test closed consent')`, epoch)
	rolloutExec(t, pool, `UPDATE billing_prepaid_auto_recharge SET enabled=true WHERE team_id=$1`, team)
	rolloutExec(t, pool, `UPDATE billing_prepaid_auto_recharge SET enabled=false WHERE team_id=$1`, team)
	reject(`UPDATE billing_prepaid_auto_recharge SET enabled=true WHERE team_id=$1`, "55000", team)
	var forbidden bool
	if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('service_role','billing_new_team_enrollment','INSERT') OR has_function_privilege('service_role','billing_insert_signup_team(uuid,text,uuid,text,text)','EXECUTE') OR has_function_privilege('authenticated','billing_team_pricing_state(uuid)','EXECUTE')`).Scan(&forbidden); err != nil || forbidden {
		t.Fatalf("cohort authority ACL leaked: %v/%v", forbidden, err)
	}
}

func TestIntegration_NewTeamCohortCreationHoldsGateAndRollsBackAtomically(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	epoch := cohortRelease(t, pool, system)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var team uuid.UUID
	if err = tx.QueryRow(t.Context(), `SELECT id FROM create_team_with_signup_trial('cohort-rollback',$1,'use','first_team')`, actor).Scan(&team); err != nil {
		t.Fatal(err)
	}
	closeTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTx.Rollback(context.Background())
	rolloutExec(t, closeTx, `SET LOCAL lock_timeout='100ms'`)
	if _, err = closeTx.Exec(t.Context(), `SELECT billing_close_new_team_gate($1,'local-test','race')`, epoch); pgCode(err) != "55P03" {
		t.Fatalf("gate close escaped in-flight enrollment: %v", err)
	}
	_ = closeTx.Rollback(t.Context())
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team WHERE id=$1)+(SELECT count(*) FROM billing_new_team_enrollment WHERE team_id=$1)+(SELECT count(*) FROM team_plan_assignment WHERE team_id=$1)`, team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial signup committed: %d %v", count, err)
	}
	// A direct historical import is fenced by the same gate lock, not its date.
	importTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer importTx.Rollback(context.Background())
	id := uuid.New()
	rolloutExec(t, importTx, `SELECT set_config('superserve.migrating_team_id',$1,true)`, id.String())
	if _, err = importTx.Exec(t.Context(), `INSERT INTO team(id,name) VALUES($1,'import')`, id); pgCode(err) != "55000" {
		t.Fatalf("historical import enrolled: %v", err)
	}
}

func TestIntegration_NewTeamCohortServiceRPCAndDeferredIntegrity(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	cohortRelease(t, pool, system)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	rolloutExec(t, tx, `SET LOCAL ROLE service_role`)
	var team uuid.UUID
	if err = tx.QueryRow(t.Context(), `SELECT id FROM create_team_with_signup_trial('service-created',$1,'use','first_team')`, actor).Scan(&team); err != nil {
		t.Fatalf("trusted RPC cannot invoke protected helper: %v", err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatalf("actual enrollment failed deferred validation: %v", err)
	}
	bad, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Rollback(context.Background())
	rolloutExec(t, bad, `INSERT INTO billing_new_team_enrollment(team_id,region,enrollment_epoch,creator_user_id,source)
 SELECT gen_random_uuid(),'use',enrollment_epoch,creator_user_id,'trusted_signup' FROM billing_new_team_enrollment WHERE team_id=$1`, team)
	if err = bad.Commit(t.Context()); pgCode(err) != "23503" && pgCode(err) != "23514" {
		t.Fatalf("orphan enrollment committed: %v", err)
	}
}

func TestIntegration_NewTeamCohortPaidFirstNeedsSellableSubscriptions(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	retire := `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family=$1 AND pricing_version='v2' AND state='published'),NULL)`
	rolloutExec(t, pool, retire, "developer")
	cohortRelease(t, pool, system)
	onFree := cohortCreate(t, pool, actor)
	var kind string
	var pending bool
	var trialGrants int
	if err := pool.QueryRow(t.Context(), `SELECT a.kind,billing_team_awaiting_plan($1),(SELECT count(*) FROM team_credit_grant WHERE team_id=$1) FROM team_plan_assignment a WHERE a.team_id=$1 AND a.effective_to IS NULL`, onFree).Scan(&kind, &pending, &trialGrants); err != nil || kind != "free" || pending || trialGrants != 0 {
		t.Fatalf("retiring Developer did not stop trial signups (want today's Free): %s awaiting=%v grants=%d %v", kind, pending, trialGrants, err)
	}
	cohortRequireCatalogFree(t, pool, onFree)
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=NULL WHERE singleton`)
	cohortPublishSubscription(t, pool, "developer")
	unconfigured := cohortCreate(t, pool, actor)
	if err := pool.QueryRow(t.Context(), `SELECT a.kind,billing_team_awaiting_plan($1) FROM team_plan_assignment a WHERE a.team_id=$1 AND a.effective_to IS NULL`, unconfigured).Scan(&kind, &pending); err != nil || kind != "free" || pending {
		t.Fatalf("signup without a configured trial was not kept on Free: %s %v %v", kind, pending, err)
	}
	cohortRequireCatalogFree(t, pool, unconfigured)
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=0.07 WHERE singleton`)
	rolloutExec(t, pool, retire, "developer")
	if _, err := pool.Exec(t.Context(), retire, "free"); pgCode(err) != "55000" {
		t.Fatalf("Free retired while signups still fall back to it: %v", err)
	}
	cohortPublishSubscription(t, pool, "developer")
	rolloutExec(t, pool, retire, "free")
	if !cohortAwaitingPlan(t, pool, cohortCreate(t, pool, actor)) {
		t.Fatal("signup with sellable plans and no Free was not awaiting its plan")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE billing_trial_policy SET credit_usd=NULL WHERE singleton`); pgCode(err) != "55000" {
		t.Fatalf("trial unconfigured with no Free to fall back on: %v", err)
	}
}

func cohortAwaitingPlan(t *testing.T, pool *pgxpool.Pool, team uuid.UUID) bool {
	t.Helper()
	var pending bool
	if err := pool.QueryRow(t.Context(), `SELECT billing_team_awaiting_plan($1)`, team).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	return pending
}

func TestIntegration_NewTeamCohortTrialUsesConfiguredCreditLimitsAndFences(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=0.07,max_sandboxes=2,max_vcpu=3,max_memory_mib=5120,max_disk_mib=9216 WHERE singleton`)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	var credit float64
	var concurrent, vcpu, memory, disk, templates int
	var state string
	var eligible bool
	if err := pool.QueryRow(t.Context(), `SELECT g.amount_usd::float8,l.max_concurrent,l.max_vcpu,l.max_memory_mib,l.max_disk_mib,l.max_templates,billing_team_entry_state($1),team_sandbox_billing_eligible($1)
 FROM team_credit_grant g CROSS JOIN team_effective_limits($1) l WHERE g.team_id=$1 AND g.reason='signup trial credit'`, team).Scan(&credit, &concurrent, &vcpu, &memory, &disk, &templates, &state, &eligible); err != nil {
		t.Fatal(err)
	}
	if credit != 0.07 || concurrent != 2 || vcpu != 3 || memory != 5120 || disk != 9216 || templates != 0 || state != "trial" || !eligible {
		t.Fatalf("trial did not freeze configured terms: credit=%v limits=%d/%d/%d/%d templates=%d state=%s eligible=%v", credit, concurrent, vcpu, memory, disk, templates, state, eligible)
	}
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=1 WHERE singleton`)
	if err := pool.QueryRow(t.Context(), `SELECT amount_usd::float8 FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, team).Scan(&credit); err != nil || credit != 0.07 {
		t.Fatalf("a running trial followed later configuration: %v %v", credit, err)
	}
	rolloutExec(t, pool, `UPDATE team_trial_eligibility_cache SET eligible=false WHERE team_id=$1`, team)
	if err := pool.QueryRow(t.Context(), `SELECT billing_team_entry_state($1),team_sandbox_billing_eligible($1)`, team).Scan(&state, &eligible); err != nil || state != "trial_ended" || eligible {
		t.Fatalf("used-up trial kept compute: %s %v %v", state, eligible, err)
	}
	second := cohortCreate(t, pool, actor)
	var reason string
	if err := pool.QueryRow(t.Context(), `SELECT o.reason,billing_team_entry_state($1),EXISTS(SELECT 1 FROM team_credit_grant WHERE team_id=$1) FROM team_signup_promotion_outcome o WHERE o.team_id=$1`, second).Scan(&reason, &state, &eligible); err != nil || (reason != "user_already_claimed" && reason != "identity_already_claimed") || state != "trial_ended" || eligible {
		t.Fatalf("second team for the same user got another trial: %s %s grant=%v %v", reason, state, eligible, err)
	}
}

func TestIntegration_NewTeamCohortReleaseNeedsFreeOrSellableTrial(t *testing.T) {
	retire := `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family=$1 AND pricing_version='v2' AND state='published'),NULL)`
	smallFree := func(t *testing.T, p *pgxpool.Pool) {
		t.Helper()
		var small uuid.UUID
		if err := p.QueryRow(t.Context(), `INSERT INTO billing_plan_version SELECT (jsonb_populate_record(NULL::billing_plan_version,to_jsonb(v)||jsonb_build_object(
  'id',gen_random_uuid(),'version',(SELECT max(version)+1 FROM billing_plan_version WHERE family='free'),'state','draft','max_template_vcpu',1,'max_template_memory_mib',1024,
  'created_by',NULL,'published_by',NULL,'published_at',NULL,'retired_by',NULL,'retired_at',NULL))).*
 FROM billing_plan_version v WHERE v.family='free' AND v.pricing_version='v2' AND v.state='published' RETURNING id`).Scan(&small); err != nil {
			t.Fatal(err)
		}
		rolloutExec(t, p, `SELECT publish_billing_plan_version($1,NULL)`, small)
	}
	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *pgxpool.Pool)
		opens   bool
	}{
		{"neither", func(t *testing.T, p *pgxpool.Pool) {
			rolloutExec(t, p, retire, "free")
			rolloutExec(t, p, retire, "developer")
		}, false},
		{"usable Free only", func(t *testing.T, p *pgxpool.Pool) { rolloutExec(t, p, retire, "developer") }, true},
		{"sellable trial only", func(t *testing.T, p *pgxpool.Pool) { rolloutExec(t, p, retire, "free") }, true},
		{"Free below the template shape", func(t *testing.T, p *pgxpool.Pool) { rolloutExec(t, p, retire, "developer"); smallFree(t, p) }, false},
		{"trial below the template shape", func(t *testing.T, p *pgxpool.Pool) {
			rolloutExec(t, p, retire, "free")
			rolloutExec(t, p, `UPDATE billing_trial_policy SET max_memory_mib=3072 WHERE singleton`)
		}, false},
		// Sellable plans without a configured trial do not open it, and an
		// undersized Free is no fallback either.
		{"trial unconfigured and Free below the shape", func(t *testing.T, p *pgxpool.Pool) {
			rolloutExec(t, p, `UPDATE billing_trial_policy SET credit_usd=NULL WHERE singleton`)
			smallFree(t, p)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, system, _ := cohortFixture(t)
			tc.prepare(t, pool)
			_, err := cohortTryRelease(t, pool, system)
			if tc.opens && err != nil {
				t.Fatalf("gate stayed closed: %v", err)
			}
			if !tc.opens && pgCode(err) != "55000" {
				t.Fatalf("gate opened: %v", err)
			}
		})
	}
}

// cohortRequireCatalogFree checks a signup got today's Free: the published v2
// Free version and its caps, whatever shape the catalog currently has.
func cohortRequireCatalogFree(t *testing.T, pool *pgxpool.Pool, team uuid.UUID) {
	t.Helper()
	var same bool
	if err := pool.QueryRow(t.Context(), `SELECT a.plan_version_id=v.id
  AND (a.limits->>'max_concurrent')::int IS NOT DISTINCT FROM v.max_sandboxes
  AND (a.limits->>'max_vcpu')::int IS NOT DISTINCT FROM v.max_template_vcpu
  AND (a.limits->>'max_memory_mib')::int IS NOT DISTINCT FROM v.max_template_memory_mib
  AND (a.limits->>'max_disk_mib')::int IS NOT DISTINCT FROM v.max_template_disk_mib
  AND (a.limits->>'max_templates')::int IS NOT DISTINCT FROM v.max_templates
 FROM team_plan_assignment a, billing_plan_version v
 WHERE a.team_id=$1 AND a.effective_to IS NULL AND v.family='free' AND v.pricing_version='v2' AND v.state='published'`, team).Scan(&same); err != nil || !same {
		t.Fatalf("signup did not get the catalog's published Free: %v %v", same, err)
	}
}

func TestIntegration_NewTeamCohortFreeSignupsKeepFrozenFreeThroughGoLiveAndRollback(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	retire := `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family=$1 AND pricing_version='v2' AND state='published'),NULL)`
	rolloutExec(t, pool, retire, "developer")
	cohortRelease(t, pool, system)
	early := cohortCreate(t, pool, actor)
	cohortRequireCatalogFree(t, pool, early)
	snapshot := func() string {
		t.Helper()
		var s string
		if err := pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(a) ORDER BY a.effective_from)::text||'|'||(SELECT to_jsonb(e)::text FROM billing_new_team_enrollment e WHERE e.team_id=$1)||'|'||
  (SELECT jsonb_build_array(max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)::text FROM team WHERE id=$1)
 FROM team_plan_assignment a WHERE a.team_id=$1`, early).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	eligible := func() bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(t.Context(), `SELECT team_sandbox_billing_eligible($1) AND billing_team_entry_state($1)='active'`, early).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	before := snapshot()
	if !eligible() {
		t.Fatal("early Free team has no compute")
	}
	check := func(step string) {
		t.Helper()
		if after := snapshot(); after != before || !eligible() {
			t.Fatalf("%s changed an early Free team:\nbefore %s\nafter  %s", step, before, after)
		}
	}
	newSignup := func() uuid.UUID {
		t.Helper()
		other := uuid.New()
		rolloutExec(t, pool, `INSERT INTO profile(id,email) VALUES($1,$2)`, other, other.String()+"@example.invalid")
		return cohortCreate(t, pool, other)
	}
	cohortPublishSubscription(t, pool, "developer")
	if !cohortAwaitingPlan(t, pool, newSignup()) {
		t.Fatal("go-live did not start new signups on the trial")
	}
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET credit_usd=0.09,max_sandboxes=3 WHERE singleton`)
	check("go-live")
	rolloutExec(t, pool, retire, "developer")
	check("rollback")
	cohortPublishSubscription(t, pool, "developer")
	rolloutExec(t, pool, retire, "free")
	check("retiring Free after go-live")
}

func TestIntegration_NewTeamCohortPaidFirstUsesCheckoutSellability(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	rolloutExec(t, pool, `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family='developer' AND pricing_version='v2' AND state='published'),NULL)`)
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO billing_plan_version(family,version,pricing_version,kind,public,self_serve,display_name,monthly_fee_cents,credit_schedule,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)
 VALUES('developer',(SELECT max(version)+1 FROM billing_plan_version WHERE family='developer'),'v2','subscription',true,true,'developer',3100,
  jsonb_build_array(jsonb_build_object('start_months',0,'repeat',NULL,'every_months',1,'amount_cents',3100,'expires_after_months',2)),7,3,3072,9216,4) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `SELECT publish_billing_plan_version($1,NULL)`, id)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	if cohortAwaitingPlan(t, pool, team) {
		t.Fatal("signup started a trial although checkout cannot sell Developer")
	}
	cohortRequireCatalogFree(t, pool, team)
}

func TestIntegration_NewTeamCohortOpenCheckoutDoesNotExtendTrial(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	rolloutExec(t, pool, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status) VALUES($1,'cus_trial','sub_unpaid','active')
 ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id='cus_trial',stripe_subscription_id='sub_unpaid',stripe_subscription_status='active'`, team)
	var state string
	var remaining float64
	var refreshed bool
	if err := pool.QueryRow(t.Context(), `SELECT b.state,b.remaining_usd::float8,refresh_team_trial_eligibility($1) FROM get_team_trial_balance($1) b`, team).Scan(&state, &remaining, &refreshed); err != nil {
		t.Fatal(err)
	}
	if state != "active" || remaining != 0.07 || !refreshed {
		t.Fatalf("an unpaid checkout subscription changed the trial: state=%s remaining=%v eligible=%v", state, remaining, refreshed)
	}
	rolloutExec(t, pool, `UPDATE team_credit_grant SET expires_at=now()-interval '1 second' WHERE team_id=$1 AND reason='signup trial credit'`, team)
	if err := pool.QueryRow(t.Context(), `SELECT b.state,refresh_team_trial_eligibility($1) FROM get_team_trial_balance($1) b`, team).Scan(&state, &refreshed); err != nil {
		t.Fatal(err)
	}
	if state == "ended_by_billing_activation" || refreshed {
		t.Fatalf("an unpaid checkout subscription kept an expired trial eligible: state=%s eligible=%v", state, refreshed)
	}
}

func TestIntegration_NewTeamCohortFallbackChecksSerialize(t *testing.T) {
	pool, system, _ := cohortFixture(t)
	cohortRelease(t, pool, system)
	retireFree, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer retireFree.Rollback(context.Background())
	rolloutExec(t, retireFree, `SELECT retire_billing_plan_version((SELECT id FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published'),NULL)`)
	rolloutExec(t, retireFree, `SET CONSTRAINTS ALL IMMEDIATE`)
	clearTrial, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clearTrial.Rollback(context.Background())
	rolloutExec(t, clearTrial, `SET LOCAL lock_timeout='200ms'`)
	rolloutExec(t, clearTrial, `UPDATE billing_trial_policy SET credit_usd=NULL WHERE singleton`)
	if _, err = clearTrial.Exec(t.Context(), `SET CONSTRAINTS ALL IMMEDIATE`); pgCode(err) != "55P03" {
		t.Fatalf("clearing the trial checked the fallback while Free was being retired: %v", err)
	}
	_ = clearTrial.Rollback(t.Context())
	if err = retireFree.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `UPDATE billing_trial_policy SET credit_usd=NULL WHERE singleton`); pgCode(err) != "55000" {
		t.Fatalf("trial cleared after Free was retired: %v", err)
	}
	for _, sql := range []string{`DELETE FROM billing_trial_policy`, `TRUNCATE billing_trial_policy`} {
		if _, err = pool.Exec(t.Context(), sql); err == nil {
			t.Fatalf("%s removed the trial policy after Free was retired", sql)
		}
	}
}

func TestIntegration_NewTeamCohortTrialTemplateAndSnapshotCaps(t *testing.T) {
	pool, system, actor := cohortFixture(t)
	cohortRelease(t, pool, system)
	team := cohortCreate(t, pool, actor)
	templates := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(t.Context(), `SELECT max_templates FROM team_effective_limits($1)`, team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := templates(); n != 0 {
		t.Fatalf("an unset trial template cap allowed %d templates", n)
	}
	rolloutExec(t, pool, `UPDATE team SET max_snapshots=5 WHERE id=$1`, team)
	sandbox := uuid.New()
	if _, err := db.New(pool).CreateSandbox(t.Context(), db.CreateSandboxParams{ID: sandbox, TeamID: team, Name: "trial-snap", Status: db.SandboxStatusStarting, VcpuCount: 1, MemoryMib: 1, HostID: "default", Metadata: []byte(`{}`), PreviewAccess: preview.AccessPublic}); err != nil {
		t.Fatal(err)
	}
	snapshot := func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO sandbox_snapshot(team_id,sandbox_id,kind,host_id,vcpu_count,memory_mib,disk_mib,base_path) VALUES($1,$2,'mem+fs','default',1,1024,4096,'/base.ext4')`, team, sandbox)
		return err
	}
	if err := snapshot(); err != nil {
		t.Fatalf("an unset trial snapshot cap refused the team's own cap: %v", err)
	}
	rolloutExec(t, pool, `UPDATE billing_trial_policy SET max_templates=1,max_snapshots=1 WHERE singleton`)
	if n := templates(); n != 1 {
		t.Fatalf("trial template cap not applied: %d", n)
	}
	if err := snapshot(); pgCode(err) != "SS002" {
		t.Fatalf("trial snapshot cap not applied: %v", err)
	}
	var remaining string
	if err := pool.QueryRow(t.Context(), `SELECT remaining_usd::text FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, team).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `UPDATE team_credit_grant SET remaining_usd=0 WHERE team_id=$1 AND reason='signup trial credit'`, team)
	if n := templates(); n != 0 {
		t.Fatalf("an exhausted trial may still build %d templates", n)
	}
	rolloutExec(t, pool, `UPDATE team_credit_grant SET remaining_usd=$2::numeric WHERE team_id=$1 AND reason='signup trial credit'`, team, remaining)
	if n := templates(); n != 1 {
		t.Fatalf("restored trial lost its template cap: %d", n)
	}
	rolloutExec(t, pool, `INSERT INTO team_trial_eligibility_cache(team_id,eligible) VALUES($1,false) ON CONFLICT(team_id) DO UPDATE SET eligible=false`, team)
	if n := templates(); n != 0 {
		t.Fatalf("a team denied the trial may still build %d templates", n)
	}
	var cap int
	if err := pool.QueryRow(t.Context(), `SELECT max_snapshots FROM team WHERE id=$1`, team).Scan(&cap); err != nil || cap != 5 {
		t.Fatalf("the trial snapshot cap was written onto the team: %d %v", cap, err)
	}
}
