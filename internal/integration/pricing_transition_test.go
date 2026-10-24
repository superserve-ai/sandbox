//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/integrationdb"
)

func TestPricingOperatorTransition(t *testing.T) {
	ctx := t.Context()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL required")
	}
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if !strings.HasSuffix(admin.Config().ConnConfig.Database, "_test") {
		t.Fatal("disposable _test database required")
	}
	name := "transition_" + uuid.NewString()[:8] + "_test"
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	}()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['service_role','anon','authenticated'] LOOP IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN',r); END IF; END LOOP; END $$;
 ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO service_role;
 ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO service_role,anon,authenticated;`)
	if _, err = integrationdb.Reset(ctx, pool); err != nil {
		t.Fatal(err)
	}
	exec(`GRANT USAGE ON SCHEMA public TO service_role,anon,authenticated`)
	actor := uuid.New()
	exec(`INSERT INTO profile(id,email,provider) VALUES($1,'operator@example.com','google')`, actor)
	exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type) SELECT $1,r.id,'platform' FROM roles r WHERE r.name='platform_admin'`, actor)
	var grants int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE user_id=$1`, actor).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("actor grants=%d err=%v", grants, err)
	}
	var trigger string
	if err = pool.QueryRow(ctx, `SELECT pg_get_triggerdef(oid,false) FROM pg_trigger WHERE tgname='billing_pricing_adoption_reset'`).Scan(&trigger); err != nil {
		t.Fatal(err)
	}
	t.Log(trigger)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE service_role`); err != nil {
		t.Fatal(err)
	}
	var model, state string
	var by *uuid.UUID
	var reason *string
	var at any
	var epoch uuid.UUID
	var changed bool
	err = tx.QueryRow(ctx, `SELECT * FROM billing_transition_pricing_version('legacy',$1,'valid reason')`, actor).Scan(&model, &by, &reason, &at, &epoch, &state, &changed)
	if err != nil {
		t.Fatal(err)
	}
	if model != "legacy" || by != nil || reason != nil || changed {
		t.Fatalf("unexpected noop %s/%v/%v/%v", model, by, reason, changed)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	expect := func(sql, code, marker string, args ...any) {
		t.Helper()
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `SET LOCAL ROLE service_role`); e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, sql, args...)
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code || pe.ConstraintName != marker {
			t.Fatalf("expected %s/%s got %v", code, marker, e)
		}
	}
	expect(`UPDATE billing_pricing_switch SET pricing_version='v2'`, "42501", "")
	expect(`INSERT INTO billing_pricing_switch_audit(actor_id,from_version,to_version,reason) VALUES($1,'legacy','v2','invalid')`, "42501", "", actor)
	expect(`SELECT * FROM billing_transition_pricing_version('legacy',$1,'valid reason')`, "42501", "billing_pricing_transition_actor", uuid.New())
	expect(`SELECT * FROM billing_transition_pricing_version(NULL,$1,'valid reason')`, "22023", "billing_pricing_transition_input", actor)
	for _, role := range []string{"anon", "authenticated"} {
		t.Run("denied_"+role, func(t *testing.T) {
			tx, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('legacy',$1,'reason')`, actor)
			checkTransitionError(t, e, "42501", "")
		})
	}
	for _, reason := range []string{"", strings.Repeat("界", 501)} {
		expect(`SELECT * FROM billing_transition_pricing_version('legacy',$1,$2)`, "22023", "billing_pricing_transition_input", actor, reason)
	}
	t.Run("lifecycle_noop_rollback", func(t *testing.T) {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		team := uuid.New()
		if _, e = tx.Exec(ctx, `INSERT INTO team(id,name) VALUES($1,'existing-example')`, team); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,'free','free','{}','{"max_concurrent":1}',clock_timestamp(),'migration','fixture')`, team); e != nil {
			t.Fatal(e)
		}
		before := transitionSnapshot(t, tx)
		first := callTransition(t, tx, actor, "v2", strings.Repeat("界", 500))
		if !first.changed || first.model != "v2" || first.state != "preparing" || first.epoch == epoch || first.by == nil || *first.by != actor || first.reason == nil || *first.reason != strings.Repeat("界", 500) {
			t.Fatalf("bad transition %+v", first)
		}
		var public string
		var opened bool
		if e = tx.QueryRow(ctx, `SELECT pricing_version,entry_open FROM billing_pricing_public_state()`).Scan(&public, &opened); e != nil || public != "legacy" || opened {
			t.Fatalf("public exposure %s/%t err=%v", public, opened, e)
		}
		after := transitionSnapshot(t, tx)
		if after == before {
			t.Fatal("transition did not change durable state")
		}
		var audit, event int
		if e = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_pricing_switch_audit),(SELECT count(*) FROM billing_pricing_adoption_event WHERE action='switch_reset')`).Scan(&audit, &event); e != nil || audit != 1 || event != 1 {
			t.Fatalf("audit/event=%d/%d err=%v", audit, event, e)
		}
		if _, e = tx.Exec(ctx, `UPDATE billing_pricing_adoption SET state='released',region='usw',system_team_id=$1,evidence='{}',released_at=clock_timestamp()`, team); e != nil {
			t.Fatal(e)
		}
		released := transitionSnapshot(t, tx)
		noop := callTransition(t, tx, actor, "v2", "another reason")
		if noop.changed || noop.at != first.at || noop.reason == nil || *noop.reason != *first.reason || transitionSnapshot(t, tx) != released {
			t.Fatal("no-op mutated released evidence/metadata/audits")
		}
		if _, e = tx.Exec(ctx, `UPDATE billing_plan_version SET state='retired',retired_at=clock_timestamp() WHERE family='free' AND pricing_version='v2' AND state='published'`); e != nil {
			t.Fatal(e)
		}
		back := callTransition(t, tx, actor, "legacy", "rollback")
		if !back.changed || back.epoch == first.epoch || back.state != "preparing" {
			t.Fatalf("bad rollback %+v", back)
		}
		stable := transitionSnapshot(t, tx)
		sp, e := tx.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = sp.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('v2',$1,'unusable catalog')`, actor)
		checkTransitionError(t, e, "55000", "billing_pricing_transition_prerequisite")
		sp.Rollback(ctx)
		if transitionSnapshot(t, tx) != stable {
			t.Fatal("failed v2 entry mutated state")
		}
		var assignments int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, team).Scan(&assignments); e != nil || assignments != 1 {
			t.Fatalf("rollback lost commitment %d %v", assignments, e)
		}
	})
	t.Run("reenable_new_epoch", func(t *testing.T) {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		first := callTransition(t, tx, actor, "v2", "first")
		back := callTransition(t, tx, actor, "legacy", "back")
		next := callTransition(t, tx, actor, "v2", "again")
		if first.epoch == back.epoch || next.epoch == back.epoch || next.epoch == first.epoch {
			t.Fatal("epoch reused")
		}
	})
	t.Run("revoked_noop", func(t *testing.T) {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `UPDATE user_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1`, actor); e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('legacy',$1,'reason')`, actor)
		checkTransitionError(t, e, "42501", "billing_pricing_transition_actor")
	})
	t.Run("wrong_isolation", func(t *testing.T) {
		tx, e := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		_, e = tx.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('legacy',$1,'reason')`, actor)
		checkTransitionError(t, e, "55000", "billing_pricing_transition_prerequisite")
	})
	mutations := map[string]string{
		"disabled":          `ALTER TABLE billing_pricing_switch DISABLE TRIGGER billing_pricing_adoption_reset`,
		"wrong_event":       `DROP TRIGGER billing_pricing_adoption_reset ON billing_pricing_switch; CREATE TRIGGER billing_pricing_adoption_reset AFTER INSERT ON billing_pricing_switch FOR EACH ROW EXECUTE FUNCTION billing_pricing_adoption_rotate()`,
		"wrong_column":      `DROP TRIGGER billing_pricing_adoption_reset ON billing_pricing_switch; CREATE TRIGGER billing_pricing_adoption_reset AFTER UPDATE OF reason ON billing_pricing_switch FOR EACH ROW WHEN (OLD.pricing_version IS DISTINCT FROM NEW.pricing_version) EXECUTE FUNCTION billing_pricing_adoption_rotate()`,
		"wrong_when":        `DROP TRIGGER billing_pricing_adoption_reset ON billing_pricing_switch; CREATE TRIGGER billing_pricing_adoption_reset AFTER UPDATE OF pricing_version ON billing_pricing_switch FOR EACH ROW WHEN (false) EXECUTE FUNCTION billing_pricing_adoption_rotate()`,
		"missing_singleton": `DELETE FROM billing_pricing_adoption_inventory; ALTER TABLE billing_pricing_adoption DISABLE TRIGGER billing_pricing_adoption_retained; DELETE FROM billing_pricing_adoption`,
	}
	for label, mutation := range mutations {
		t.Run(label, func(t *testing.T) {
			tx, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, mutation); e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('legacy',$1,'reason')`, actor)
			checkTransitionError(t, e, "55000", "billing_pricing_transition_prerequisite")
		})
	}
	for _, fault := range []string{"reset", "sync", "sync_no_data", "audit", "no_rotation"} {
		t.Run("atomic_fault_"+fault, func(t *testing.T) {
			tx, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			sql := `CREATE FUNCTION transition_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault'; END $$; CREATE TRIGGER transition_fixture_fault BEFORE INSERT ON billing_pricing_switch_audit FOR EACH ROW EXECUTE FUNCTION transition_fixture_fault()`
			if fault == "reset" || fault == "sync" || fault == "sync_no_data" {
				fn := "billing_pricing_adoption_rotate"
				if fault == "sync" || fault == "sync_no_data" {
					fn = "sync_all_billing_plan_offers"
				}
				sql = "CREATE OR REPLACE FUNCTION " + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault'; END $$`
			}
			if fault == "sync_no_data" {
				sql = `CREATE OR REPLACE FUNCTION sync_all_billing_plan_offers() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected dependency no-data failure' USING ERRCODE='P0002'; END $$`
			}
			if fault == "no_rotation" {
				sql = `CREATE OR REPLACE FUNCTION billing_pricing_adoption_rotate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`
			}
			if _, e = tx.Exec(ctx, sql); e != nil {
				t.Fatal(e)
			}
			before := transitionSnapshot(t, tx)
			sp, e := tx.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = sp.Exec(ctx, `SET LOCAL ROLE service_role`); e != nil {
				t.Fatal(e)
			}
			_, e = sp.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('v2',$1,'fault')`, actor)
			code, marker := "P0001", ""
			if fault == "sync_no_data" {
				code = "P0002"
			}
			if fault == "no_rotation" {
				code = "55000"
				marker = "billing_pricing_transition_prerequisite"
			}
			checkTransitionError(t, e, code, marker)
			if e = sp.Rollback(ctx); e != nil {
				t.Fatal(e)
			}
			if transitionSnapshot(t, tx) != before {
				t.Fatal("partial transition survived fault")
			}
		})
	}
	t.Run("admission_and_release_serialization", func(t *testing.T) {
		holder, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer holder.Rollback(ctx)
		if _, e = holder.Exec(ctx, `SET LOCAL ROLE service_role; SELECT * FROM billing_lock_pricing_public_state()`); e != nil {
			t.Fatal(e)
		}
		blocked, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer blocked.Rollback(ctx)
		if _, e = blocked.Exec(ctx, `SET LOCAL lock_timeout='100ms'; SET LOCAL ROLE service_role`); e != nil {
			t.Fatal(e)
		}
		_, e = blocked.Exec(ctx, `SELECT * FROM billing_transition_pricing_version('v2',$1,'fenced')`, actor)
		checkTransitionError(t, e, "55P03", "")
		blocked.Rollback(ctx)
		holder.Rollback(ctx)
		transition, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer transition.Rollback(ctx)
		callTransition(t, transition, actor, "v2", "transition holding gate")
		for _, sql := range []string{`SELECT * FROM billing_lock_pricing_public_state()`, `SELECT billing_release_pricing_adoption('usw','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','fixture','fixture','{}')`} {
			peer, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = peer.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); e != nil {
				t.Fatal(e)
			}
			_, e = peer.Exec(ctx, sql)
			checkTransitionError(t, e, "55P03", "")
			peer.Rollback(ctx)
		}
	})

	for _, scenario := range []struct {
		name, first, second string
		changes             int
	}{
		{"same_target", "v2", "v2", 1},
		{"opposite_two_changes", "v2", "legacy", 2},
		{"opposite_one_change", "legacy", "v2", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			exec(`UPDATE billing_pricing_switch SET pricing_version='legacy'`)
			var audits, events int
			if e := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_pricing_switch_audit),(SELECT count(*) FROM billing_pricing_adoption_event WHERE action='switch_reset')`).Scan(&audits, &events); e != nil {
				t.Fatal(e)
			}
			first, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer first.Rollback(ctx)
			a := callTransition(t, first, actor, scenario.first, "first serialized request")
			second, e := pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer second.Rollback(ctx)
			if _, e = second.Exec(ctx, `SET LOCAL ROLE service_role; SET LOCAL statement_timeout='3s'`); e != nil {
				t.Fatal(e)
			}
			type outcome struct {
				r   transitionResult
				err error
			}
			results := make(chan outcome, 1)
			go func() {
				var b transitionResult
				e := second.QueryRow(ctx, `SELECT * FROM billing_transition_pricing_version($1,$2,'second serialized request')`, scenario.second, actor).Scan(&b.model, &b.by, &b.reason, &b.at, &b.epoch, &b.state, &b.changed)
				if e == nil {
					e = second.Commit(ctx)
				}
				results <- outcome{b, e}
			}()
			select {
			case b := <-results:
				t.Fatalf("second request escaped first lock: %+v", b)
			case <-time.After(50 * time.Millisecond):
			}
			if e = first.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			b := <-results
			if b.err != nil {
				t.Fatal(b.err)
			}
			var final string
			var nextAudits, nextEvents int
			if e = pool.QueryRow(ctx, `SELECT pricing_version,(SELECT count(*) FROM billing_pricing_switch_audit),(SELECT count(*) FROM billing_pricing_adoption_event WHERE action='switch_reset') FROM billing_pricing_switch`).Scan(&final, &nextAudits, &nextEvents); e != nil {
				t.Fatal(e)
			}
			actual := 0
			if a.changed {
				actual++
			}
			if b.r.changed {
				actual++
			}
			if final != scenario.second || actual != scenario.changes || nextAudits-audits != scenario.changes || nextEvents-events != scenario.changes {
				t.Fatalf("serialized state=%s actual=%d audit/event delta=%d/%d", final, actual, nextAudits-audits, nextEvents-events)
			}
		})
	}

}

func checkTransitionError(t *testing.T, err error, code, marker string) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != code || pe.ConstraintName != marker {
		t.Fatalf("expected %s/%s, got %v", code, marker, err)
	}
}

type transitionResult struct {
	model   string
	by      *uuid.UUID
	reason  *string
	at      time.Time
	epoch   uuid.UUID
	state   string
	changed bool
}

func callTransition(t *testing.T, tx pgx.Tx, actor uuid.UUID, target, reason string) transitionResult {
	t.Helper()
	var r transitionResult
	if _, e := tx.Exec(t.Context(), `SET LOCAL ROLE service_role`); e != nil {
		t.Fatal(e)
	}
	e := tx.QueryRow(t.Context(), `SELECT * FROM billing_transition_pricing_version($1,$2,$3)`, target, actor, reason).Scan(&r.model, &r.by, &r.reason, &r.at, &r.epoch, &r.state, &r.changed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(t.Context(), `RESET ROLE`); e != nil {
		t.Fatal(e)
	}
	return r
}

func transitionSnapshot(t *testing.T, tx pgx.Tx) string {
	t.Helper()
	var state string
	err := tx.QueryRow(t.Context(), `SELECT jsonb_build_object('switch',(SELECT to_jsonb(s) FROM billing_pricing_switch s),'adoption',(SELECT to_jsonb(a) FROM billing_pricing_adoption a),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM billing_pricing_switch_audit a),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM billing_pricing_adoption_event e),'offers',(SELECT jsonb_agg(to_jsonb(o) ORDER BY offer_key) FROM billing_plan o))::text`).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
