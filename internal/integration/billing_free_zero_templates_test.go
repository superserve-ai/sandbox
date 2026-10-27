//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_FreeZeroTemplates(t *testing.T) {
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	sql, err := os.ReadFile("../../scripts/billing/free-zero-templates.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(sql))
	exec(`UPDATE billing_pricing_switch SET pricing_version='v2'`)
	actor := uuid.New()
	exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1::uuid,$1::uuid::text||'@example.com','google',$1::uuid::text)`, actor)
	var old uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	team := uuid.New()
	exec(`INSERT INTO team(id,name) VALUES($1,'Free zero fixture')`, team)
	var assignment uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, team).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	// Store an already exhausted allowance window. Its exact persisted state must
	// survive both dry-run and commit; the evaluator must retain its original floor.
	var beforeSince time.Time
	if err = tx.QueryRow(ctx, `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&beforeSince); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO billing_free_allowance VALUES($1,$2::timestamptz,$2::timestamptz+interval '24 hours',.02,.02,$2::timestamptz+interval '24 hours',$2::timestamptz)`, team, beforeSince)
	snapshot := func() string {
		var s string
		if e := tx.QueryRow(ctx, `SELECT jsonb_build_object('allowance',(SELECT to_jsonb(a) FROM billing_free_allowance a WHERE team_id=$1),'billing',(SELECT to_jsonb(b) FROM team_billing_account b WHERE team_id=$1),'funding',(SELECT to_jsonb(f) FROM billing_funding_account f WHERE team_id=$1),'templates',(SELECT jsonb_agg(to_jsonb(t)) FROM template t WHERE team_id=$1))::text`, team).Scan(&s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	exec(`INSERT INTO template(team_id,name,build_spec) VALUES($1,'existing-free-artifact','{"from":"python:3.11"}')`, team)
	before := snapshot()
	replacement := uuid.New()
	callPublish := func(id uuid.UUID) error {
		_, e := tx.Exec(ctx, `SELECT pg_temp.publish_free_zero_templates($1,$2,$3,'disable Free templates',true)`, old, id, actor)
		return e
	}
	reject := func(q string, args ...any) {
		t.Helper()
		exec("SAVEPOINT rejected")
		if _, e := tx.Exec(ctx, q, args...); e == nil {
			t.Fatal("unsafe operation accepted")
		}
		exec("ROLLBACK TO SAVEPOINT rejected")
	}
	reject(`SELECT pg_temp.publish_free_zero_templates($1,$2,$3,'disable Free templates',false)`, old, replacement, actor)
	exec("SAVEPOINT dry_run")
	if err = callPublish(replacement); err != nil {
		t.Fatal(err)
	}
	exec("ROLLBACK TO SAVEPOINT dry_run")
	if err = callPublish(replacement); err != nil {
		t.Fatal(err)
	}
	if err = callPublish(replacement); err != nil {
		t.Fatalf("publish replay: %v", err)
	}
	if snapshot() != before {
		t.Fatal("publication changed team financial state")
	}
	// Publication changes new signups, never existing frozen assignments.
	var cap int
	if err = tx.QueryRow(ctx, `SELECT max_templates FROM team_effective_limits($1)`, team).Scan(&cap); err != nil || cap != 10 {
		t.Fatalf("old frozen cap=%d %v", cap, err)
	}
	fresh := uuid.New()
	exec(`INSERT INTO team(id,name) VALUES($1,'Fresh Free zero')`, fresh)
	if err = tx.QueryRow(ctx, `SELECT max_templates FROM team_effective_limits($1)`, fresh).Scan(&cap); err != nil || cap != 0 {
		t.Fatalf("new signup cap=%d %v", cap, err)
	}
	// Every unsafe target must abort without clearing an override or payment fence.
	for _, tc := range []struct{ name, setup string }{
		{"override", `UPDATE team SET max_templates=25 WHERE id=$1`},
		{"custom", `UPDATE team SET limits_customized=true WHERE id=$1`},
		{"pause request", `INSERT INTO billing_team_pause_request(assignment_id,team_id) SELECT id,team_id FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`},
		{"payment fence", `INSERT INTO team_billing_account(team_id,checkout_initializing_at) VALUES($1,clock_timestamp()) ON CONFLICT(team_id) DO UPDATE SET checkout_initializing_at=EXCLUDED.checkout_initializing_at`},
		{"pending prepaid intent", `INSERT INTO billing_prepaid_checkout_operation(id,team_id,actor_id,amount_cents,success_url,cancel_url) VALUES(gen_random_uuid(),$1,'00000000-0000-0000-0000-000000000001',500,'https://example.com/success','https://example.com/cancel')`},
		{"commercial history", `INSERT INTO billing_commercial_contract(team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor) VALUES($1,'custom-test',now(),'cus_test','sub_test','price_test',25000,1,25000,now())`},
		{"pending quote", `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents) VALUES(gen_random_uuid(),$1,'00000000-0000-0000-0000-000000000001','cus_test','pro_monthly','{}',now(),now(),now()+interval '1 month',now(),25000)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec("SAVEPOINT unsafe_target")
			if tc.name == "commercial history" {
				exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,commercial_billing_anchor) VALUES($1,'cus_test','sub_test',now()) ON CONFLICT(team_id) DO UPDATE SET stripe_customer_id=EXCLUDED.stripe_customer_id,stripe_subscription_id=EXCLUDED.stripe_subscription_id,commercial_billing_anchor=EXCLUDED.commercial_billing_anchor`, team)
			}
			exec(tc.setup, team)
			reject(`SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'disable Free templates')`, team, assignment, replacement, actor)
			exec("ROLLBACK TO SAVEPOINT unsafe_target")
		})
	}
	// An immutable version reference alone does not make a customized migration
	// snapshot ordinary. Build new history through its normal insert/close guards.
	for _, custom := range []struct{ name, terms, limits string }{
		{"changed allowance", `jsonb_set(terms,'{allowance}','{"period":"day_window","on_exhausted":"pause","amount_cents":999}')`, `limits`},
		{"changed resource cap", `terms`, `jsonb_set(limits,'{max_vcpu}','8')`},
		{"extra term", `terms||'{"custom_entitlement":true}'::jsonb`, `limits`},
		{"extra limit", `terms`, `limits||'{"custom_limit":null}'::jsonb`},
	} {
		t.Run(custom.name, func(t *testing.T) {
			exec("SAVEPOINT customized_snapshot")
			var target uuid.UUID
			if e := tx.QueryRow(ctx, `WITH closed AS (UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE id=$1 RETURNING *) INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,reason) SELECT team_id,plan_key,kind,plan_version_id,`+custom.terms+`,`+custom.limits+`,effective_to,'migration','custom migration fixture' FROM closed RETURNING id`, assignment).Scan(&target); e != nil {
				t.Fatal(e)
			}
			var historyBefore, historyAfter string
			history := `SELECT jsonb_agg(to_jsonb(a) ORDER BY effective_from,id)::text FROM team_plan_assignment a WHERE team_id=$1`
			if e := tx.QueryRow(ctx, history, team).Scan(&historyBefore); e != nil {
				t.Fatal(e)
			}
			state := snapshot()
			reject(`SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'disable Free templates')`, team, target, replacement, actor)
			if e := tx.QueryRow(ctx, history, team).Scan(&historyAfter); e != nil {
				t.Fatal(e)
			}
			if historyBefore != historyAfter || state != snapshot() {
				t.Fatal("rejection changed customized history or allowance state")
			}
			exec("ROLLBACK TO SAVEPOINT customized_snapshot")
		})
	}
	var next uuid.UUID
	q := `SELECT pg_temp.transition_free_zero_templates($1,$2,$3,$4,'disable Free templates')`
	exec("SAVEPOINT transition_dry_run")
	exec(q, team, assignment, replacement, actor)
	exec("ROLLBACK TO SAVEPOINT transition_dry_run")
	if snapshot() != before {
		t.Fatal("dry-run modified allowance or financial state")
	}
	if err = tx.QueryRow(ctx, q, team, assignment, replacement, actor).Scan(&next); err != nil {
		t.Fatal(err)
	}
	var replay uuid.UUID
	if err = tx.QueryRow(ctx, q, team, assignment, replacement, actor).Scan(&replay); err != nil || replay != next {
		t.Fatalf("transition replay=%s %v", replay, err)
	}
	if snapshot() != before {
		t.Fatal("transition changed allowance, account or funding")
	}
	var since time.Time
	var blocked bool
	if err = tx.QueryRow(ctx, `SELECT f.free_since,billing_free_allowance_blocked($1),l.max_templates FROM billing_free_plan($1) f,team_effective_limits($1) l`, team).Scan(&since, &blocked, &cap); err != nil || !since.Equal(beforeSince) || !blocked || cap != 0 {
		t.Fatalf("since=%s blocked=%v cap=%d err=%v", since, blocked, cap, err)
	}
	var preserved bool
	if err = tx.QueryRow(ctx, `SELECT p.effective_to=n.effective_from AND p.terms-ARRAY['version_id','version']=n.terms-ARRAY['version_id','version'] AND p.limits-'max_templates'=n.limits-'max_templates' FROM team_plan_assignment p,team_plan_assignment n WHERE p.id=$1 AND n.id=$2`, assignment, next).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("history/terms not preserved %v %v", preserved, err)
	}
}

func TestIntegration_FreeZeroTemplatesContinuityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, middle       string
		gap, changed, zero bool
		expectHours        int
	}{
		{name: "continuous", expectHours: 3},
		{name: "paid reentry", middle: "custom", expectHours: 1},
		{name: "gap", gap: true, expectHours: 1},
		{name: "changed allowance", changed: true, expectHours: 1},
		{name: "zero length", zero: true, expectHours: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			tx, e := testPool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(context.Background())
			exec := func(q string, args ...any) {
				t.Helper()
				if _, e := tx.Exec(ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
			team := uuid.New()
			exec(`INSERT INTO team(id,name) VALUES($1,'Free continuity boundary')`, team)
			var now time.Time
			if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
				t.Fatal(e)
			}
			allowance := `{"period":"day_window","amount_cents":5,"on_exhausted":"pause"}`
			add := func(kind string, start time.Time) uuid.UUID {
				t.Helper()
				id := uuid.New()
				exec(`INSERT INTO team_plan_assignment(id,team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,$2,'test',$3,jsonb_build_object('allowance',$4::jsonb),'{"max_concurrent":2}', $5,'staff','continuity test')`, id, team, kind, allowance, start)
				return id
			}
			end := func(id uuid.UUID, at time.Time) {
				exec(`UPDATE team_plan_assignment SET effective_to=$2 WHERE id=$1`, id, at)
			}
			first := add("free", now.Add(-3*time.Hour))
			endAt := now.Add(-time.Hour)
			if tc.gap || tc.middle != "" {
				endAt = now.Add(-2 * time.Hour)
			}
			end(first, endAt)
			if tc.middle != "" {
				middle := add(tc.middle, endAt)
				end(middle, now.Add(-time.Hour))
			}
			if tc.zero {
				z := add("free", endAt)
				end(z, endAt)
			}
			if tc.changed {
				allowance = `{"period":"day_window","amount_cents":10,"on_exhausted":"pause"}`
			}
			current := add("free", now.Add(-time.Hour))
			var since time.Time
			if e = tx.QueryRow(ctx, `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&since); e != nil || !since.Equal(now.Add(-time.Duration(tc.expectHours)*time.Hour)) {
				t.Fatalf("floor=%s err=%v", since, e)
			}
			end(current, now)
			add("prepaid", now)
			var count int
			if e = tx.QueryRow(ctx, `SELECT count(*) FROM billing_free_plan($1)`, team).Scan(&count); e != nil || count != 0 {
				t.Fatalf("paid inherits Free=%d %v", count, e)
			}
		})
	}
}

// Caller-supplied continuity must never backdate entitlement or rewrite an
// immutable assignment. Old rows with NULL retain their pre-migration floor.
func TestIntegration_FreeZeroTemplatesStoredFloorAuthority(t *testing.T) {
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(q string, args ...any) {
		t.Helper()
		exec("SAVEPOINT bad_floor")
		if _, e := tx.Exec(ctx, q, args...); e == nil {
			t.Fatal("forged continuity accepted")
		}
		exec("ROLLBACK TO SAVEPOINT bad_floor")
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	team := uuid.New()
	exec(`INSERT INTO team(id,name) VALUES($1,'Legacy Free floor')`, team)
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()-interval '2 hours'`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	// Emulate a row that existed before this additive nullable-column migration.
	// The existing immutable-history guard stays enabled throughout.
	exec(`ALTER TABLE team_plan_assignment DISABLE TRIGGER team_plan_assignment_continuity`)
	first := uuid.New()
	exec(`INSERT INTO team_plan_assignment(id,team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,$2,'free','free','{"allowance":{"period":"day_window","amount_cents":5,"on_exhausted":"pause"}}','{"max_concurrent":2}',$3,'migration','legacy NULL fixture')`, first, team, at)
	exec(`ALTER TABLE team_plan_assignment ENABLE TRIGGER team_plan_assignment_continuity`)
	var since time.Time
	if err = tx.QueryRow(ctx, `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&since); err != nil || !since.Equal(at) {
		t.Fatalf("legacy floor=%s %v", since, err)
	}
	reject(`UPDATE team_plan_assignment SET free_allowance_since=effective_from-interval '1 hour' WHERE id=$1`, first)
	nextAt := at.Add(time.Hour)
	exec(`UPDATE team_plan_assignment SET effective_to=$2 WHERE id=$1`, first, nextAt)
	insert := `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason,free_allowance_since) SELECT team_id,plan_key,$2,terms,limits,$3,'migration','stored floor fixture',$4 FROM team_plan_assignment WHERE id=$1`
	reject(insert, first, "free", nextAt, at.Add(-time.Hour))
	reject(insert, first, "free", nextAt, nextAt)
	reject(insert, first, "prepaid", nextAt, at)
	reject(insert, first, "free", time.Now().Add(time.Hour), at)
	exec(insert, first, "free", nextAt, at)
	if err = tx.QueryRow(ctx, `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&since); err != nil || !since.Equal(at) {
		t.Fatalf("inherited legacy floor=%s %v", since, err)
	}
	reject(`UPDATE team_plan_assignment SET free_allowance_since=effective_from WHERE team_id=$1 AND effective_to IS NULL`, team)
}

// A large assignment history must not turn one admission lookup into a scan of
// the team's past assignments. Inspect the actual database plan.
func TestIntegration_FreeZeroTemplatesAdmissionReadsCurrentRowOnly(t *testing.T) {
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	team := uuid.New()
	exec(`INSERT INTO team(id,name) VALUES($1,'Long Free history')`, team)
	exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{"allowance":{"period":"day_window","amount_cents":5,"on_exhausted":"pause"}}','{"max_concurrent":2}',clock_timestamp()-interval '2 days','migration','history fixture')`, team)
	exec(`SELECT set_config('test.continuity_team',$1,true)`, team.String())
	exec(`DO $$ DECLARE target uuid:=current_setting('test.continuity_team')::uuid; a team_plan_assignment; at_time timestamptz; BEGIN
 FOR i IN 1..1000 LOOP
  SELECT * INTO STRICT a FROM team_plan_assignment WHERE team_id=target AND effective_to IS NULL;
  at_time:=a.effective_from+interval '1 minute';
  UPDATE team_plan_assignment SET effective_to=at_time WHERE id=a.id;
  INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
   VALUES(target,a.plan_key,a.kind,a.terms,a.limits,at_time,'migration','history fixture');
 END LOOP; END $$`)
	var encoded []byte
	if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT free_since FROM billing_free_plan($1)`, team).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var plans []map[string]any
	if err = json.Unmarshal(encoded, &plans); err != nil {
		t.Fatal(err)
	}
	assignmentScans := 0
	var inspect func(map[string]any)
	inspect = func(node map[string]any) {
		if node["Node Type"] == "Recursive Union" || node["Node Type"] == "WorkTable Scan" {
			t.Fatalf("recursive history admission: %s", encoded)
		}
		if node["Relation Name"] == "team_plan_assignment" {
			assignmentScans++
			if node["Node Type"] == "Seq Scan" {
				t.Fatalf("admission scans history: %s", encoded)
			}
			if node["Actual Rows"] != float64(1) || node["Actual Loops"] != float64(1) {
				t.Fatalf("admission visits assignment history: %s", encoded)
			}
		}
		if children, ok := node["Plans"].([]any); ok {
			for _, child := range children {
				inspect(child.(map[string]any))
			}
		}
	}
	inspect(plans[0]["Plan"].(map[string]any))
	if assignmentScans != 1 {
		t.Fatalf("assignment scan count=%d: %s", assignmentScans, encoded)
	}
	t.Logf("1001-assignment admission plan: %s", encoded)
}

func TestIntegration_FreeZeroTemplatesNullAndMissingAllowance(t *testing.T) {
	for _, tc := range []struct {
		name, prior, next string
		carry             bool
	}{
		{"JSON null", `{"allowance":null}`, `{"allowance":null}`, true},
		{"missing to null", `{}`, `{"allowance":null}`, false},
		{"null to missing", `{"allowance":null}`, `{}`, false},
		{"scalar to object", `{"allowance":"invalid"}`, `{"allowance":{"amount_cents":5}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			exec := func(q string, args ...any) {
				t.Helper()
				if _, e := tx.Exec(ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
			team := uuid.New()
			exec(`INSERT INTO team(id,name) VALUES($1,'Non-object allowance boundary')`, team)
			var start time.Time
			if err = tx.QueryRow(ctx, `SELECT clock_timestamp()-interval '2 hours'`).Scan(&start); err != nil {
				t.Fatal(err)
			}
			exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free',$2::jsonb,'{"max_concurrent":2}',$3,'staff','initial non-object allowance')`, team, tc.prior, start)
			next := start.Add(time.Hour)
			exec(`UPDATE team_plan_assignment SET effective_to=$2 WHERE team_id=$1 AND effective_to IS NULL`, team, next)
			exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free',$2::jsonb,'{"max_concurrent":2}',$3,'staff','next non-object allowance')`, team, tc.next, next)
			var since time.Time
			if err = tx.QueryRow(ctx, `SELECT free_since FROM billing_free_plan($1)`, team).Scan(&since); err != nil {
				t.Fatal(err)
			}
			expected := next
			if tc.carry {
				expected = start
			}
			if !since.Equal(expected) {
				t.Fatalf("floor=%s expected=%s", since, expected)
			}
		})
	}
}
