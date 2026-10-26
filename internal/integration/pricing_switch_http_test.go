//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_PricingSwitchHTTPRestrictedRole(t *testing.T) {
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy'`)
	})
	exec(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN; END IF; END $$;
 CREATE ROLE pricing_switch_http_test NOLOGIN BYPASSRLS IN ROLE service_role;
 GRANT USAGE ON SCHEMA public TO pricing_switch_http_test;
 GRANT SELECT ON ALL TABLES IN SCHEMA public TO pricing_switch_http_test;
 GRANT EXECUTE ON FUNCTION billing_transition_pricing_version(text,uuid,text),billing_pricing_public_state() TO service_role;
 UPDATE billing_pricing_switch SET pricing_version='legacy',changed_by=NULL,reason=NULL;`)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DROP OWNED BY pricing_switch_http_test; DROP ROLE pricing_switch_http_test`)
	})
	admin := seedPlatformAdminProfile(t).String()
	outsider := seedSuperserveEmailProfile(t).String()
	cfg := testPool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["role"] = "pricing_switch_http_test"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, sql := range []string{`SELECT pricing_version FROM billing_pricing_switch FOR UPDATE`, `INSERT INTO billing_pricing_switch_audit(actor_id,from_version,to_version,reason) VALUES(NULL,'legacy','v2','denied')`} {
		_, err := pool.Exec(ctx, sql)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("raw write/lock unexpectedly allowed: %v", err)
		}
	}
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	h := api.NewHandlers(&stubVMD{}, db.New(pool), &config.Config{SystemTeamID: testSystemTeamID.String()})
	h.Pool = pool
	r := api.SetupRouter(ctx, h, pool)
	call := func(target, reason string, want int) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"pricing_version": target, "reason": reason})
		w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, string(body))
		if w.Code != want {
			t.Fatalf("switch %s: %d %s", target, w.Code, w.Body)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", outsider, `{"pricing_version":"v2","reason":"denied"}`); w.Code != http.StatusForbidden {
		t.Fatalf("outsider: %d %s", w.Code, w.Body)
	}
	if w := doInternal(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"v2","reason":"denied"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("internal token: %d %s", w.Code, w.Body)
	}
	snapshot := func() string {
		t.Helper()
		var result string
		if err := testPool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(s) FROM billing_pricing_switch s),(SELECT to_jsonb(a) FROM billing_pricing_adoption a),(SELECT count(*) FROM billing_pricing_switch_audit),(SELECT count(*) FROM billing_pricing_adoption_event))::text`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	noop := call("legacy", "retry must preserve nullable metadata", http.StatusOK)
	if noop["changed_by"] != nil || noop["reason"] != nil || snapshot() != before {
		t.Fatalf("initial no-op changed state: %+v", noop)
	}
	first := call("v2", "activate", http.StatusOK)
	after := snapshot()
	retry := call("v2", "different retry reason", http.StatusOK)
	if after == before || snapshot() != after || first["changed_at"] != retry["changed_at"] || retry["reason"] != "activate" {
		t.Fatalf("transition/no-op receipt mismatch: %+v %+v", first, retry)
	}
	public := getPublicPlans(t, r)
	if public.PricingVersion != "legacy" || len(public.Plans) != 0 {
		t.Fatalf("switch released entry: %+v", public)
	}
	call("legacy", "restore", http.StatusOK)
	stable := snapshot()
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `ALTER TABLE billing_pricing_switch ENABLE TRIGGER billing_pricing_adoption_reset`)
	})
	exec(`ALTER TABLE billing_pricing_switch DISABLE TRIGGER billing_pricing_adoption_reset`)
	call("v2", "missing prerequisite", http.StatusConflict)
	exec(`ALTER TABLE billing_pricing_switch ENABLE TRIGGER billing_pricing_adoption_reset`)
	if snapshot() != stable {
		t.Fatal("prerequisite failure changed state")
	}
	// An untagged dependency error must remain an infrastructure failure.
	exec(`CREATE FUNCTION pricing_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected dependency failure' USING ERRCODE='55000'; END $$;
 CREATE TRIGGER pricing_http_fault BEFORE INSERT ON billing_pricing_switch_audit FOR EACH ROW EXECUTE FUNCTION pricing_http_fault()`)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DROP TRIGGER IF EXISTS pricing_http_fault ON billing_pricing_switch_audit; DROP FUNCTION IF EXISTS pricing_http_fault()`)
	})
	call("v2", "dependency failure", http.StatusInternalServerError)
	if snapshot() != stable {
		t.Fatal("dependency failure partially changed state")
	}
}
