package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestYCClaimAdmissionTransactions(t *testing.T) {
	dsn := os.Getenv("YC_CLAIM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL URL required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	database := "claim_admission_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`CREATE SCHEMA auth;CREATE TABLE auth.users(id uuid PRIMARY KEY,email text,email_confirmed_at timestamptz,deleted_at timestamptz,created_at timestamptz DEFAULT now());
 CREATE TABLE public.team(id uuid PRIMARY KEY,created_at timestamptz NOT NULL);
 CREATE TABLE public.stripe_promotion_migration_fence(team_id uuid PRIMARY KEY);
 CREATE TABLE public.team_billing_account(team_id uuid PRIMARY KEY,stripe_customer_id text,stripe_subscription_id text,checkout_initializing_at timestamptz,stripe_activation_credit_reserved_at timestamptz,stripe_activation_credit_grant_id text);
 CREATE TABLE public.billing_signup_choice(team_id uuid PRIMARY KEY,state text,offer_key text);
 CREATE TABLE public.billing_commercial_contract(id uuid PRIMARY KEY,team_id uuid);`)
	exec(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN; END IF; END $$;`)
	for _, path := range []string{filepath.Join("..", "..", "supabase", "shared-auth-migrations", "20261016174553_yc_claim_authority.sql"), os.Getenv("YC_AUTHORITY_TEST_MIGRATION"), filepath.Join("..", "..", "supabase", "migrations", "20261016174554_yc_claim_team_intent.sql")} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		exec(string(b))
	}
	// Exercise the runtime grants and RLS as a non-owner, not just postgres.
	roleTx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = roleTx.Exec(ctx, `SET LOCAL ROLE service_role; SELECT * FROM public.yc_claim_team_intent; UPDATE public.yc_claim_team_intent SET released_at=now() WHERE false; INSERT INTO public.yc_claim_team_intent(team_id,claim_id,user_id) SELECT NULL,NULL,NULL WHERE false`); e != nil {
		t.Fatal(e)
	}
	roleTx.Rollback(ctx)
	h := &Handlers{Pool: pool, PromotionAuthPool: pool}
	rpc := func(op string, p gin.H) map[string]any {
		t.Helper()
		raw, e := h.ycClaimRPC(ctx, op, p)
		if e != nil {
			t.Fatal(e)
		}
		v := map[string]any{}
		if e = json.Unmarshal(raw, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	create := func(email string, oldTeam bool) gin.H {
		t.Helper()
		raw := rpc("submit", gin.H{"submitted_email": email, "founder_email": email, "verification_reference": strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("a", 32), "company_identity": "https://www.ycombinator.com/companies/" + strings.Split(email, "@")[0], "evidence": gin.H{"verified": true, "name": "Synthetic Founder"}, "state": "awaiting_confirmation", "reason": "email_match", "confirmation_token": strings.Repeat("a", 43), "token_hash": strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("b", 32)})
		// Retrieve the synthetic test hash as owner; HTTP never exposes it.
		var hash string
		if e := pool.QueryRow(ctx, "SELECT token_hash FROM yc_claim WHERE id=$1", raw["id"]).Scan(&hash); e != nil {
			t.Fatal(e)
		}
		rpc("confirm", gin.H{"id": raw["id"], "token_hash": hash})
		user, team := uuid.New(), uuid.New()
		exec("INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),$3)", user, email, time.Now().Add(time.Second))
		created := time.Now().Add(time.Second)
		if oldTeam {
			created = time.Now().Add(-time.Hour)
		}
		exec("INSERT INTO team VALUES($1,$2)", team, created)
		exec("INSERT INTO billing_signup_choice VALUES($1,'selecting',NULL)", team)
		return gin.H{"id": raw["id"], "user_id": user, "team_id": team, "home_region": "use", "token_hash": hash}
	}
	moving := create("moving@example.test", false)
	exec("INSERT INTO stripe_promotion_migration_fence VALUES($1)", moving["team_id"])
	if _, e := h.ycBindWithIntent(ctx, "bind", moving); e == nil || !strings.Contains(e.Error(), "migration") {
		t.Fatalf("migration fence bypassed: %v", e)
	}
	p := create("fresh@example.test", false)
	// A missing shared function models an unavailable billing rollout. Local
	// admission remains fenced and exact retry can resume after availability.
	exec("ALTER FUNCTION reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid) RENAME TO held_reserve_yc_activation_authority")
	if _, e := h.ycBindWithIntent(ctx, "bind", p); e == nil {
		t.Fatal("missing shared billing authority accepted")
	}
	var intents int
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_team_intent WHERE team_id=$1 AND released_at IS NULL", p["team_id"]).Scan(&intents); e != nil || intents != 1 {
		t.Fatalf("lost admission fence %d %v", intents, e)
	}
	if _, e := pool.Exec(ctx, "UPDATE billing_signup_choice SET state='committed',offer_key='free' WHERE team_id=$1", p["team_id"]); e == nil {
		t.Fatal("checkout bypassed pending claim")
	}
	if _, e := pool.Exec(ctx, "UPDATE team_billing_account SET checkout_initializing_at=now() WHERE team_id=$1", p["team_id"]); e == nil {
		t.Fatal("legacy checkout bypassed pending claim")
	}
	exec("ALTER FUNCTION held_reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid) RENAME TO reserve_yc_activation_authority")
	out, e := h.ycBindWithIntent(ctx, "bind", p)
	if e != nil {
		t.Fatal(e)
	}
	var result struct {
		State string `json:"state"`
	}
	json.Unmarshal(out, &result)
	if result.State != "bound" {
		t.Fatal(string(out))
	}
	if _, e = h.ycBindWithIntent(ctx, "bind", p); e != nil {
		t.Fatal("exact retry failed", e)
	}
	// Existing teams and completed plan choices never acquire a local/global reservation.
	for _, old := range []bool{true, false} {
		input := create("blocked"+strings.ReplaceAll(uuid.NewString(), "-", "")+"@example.test", old)
		if !old {
			exec("UPDATE billing_signup_choice SET state='committed',offer_key='free' WHERE team_id=$1", input["team_id"])
		}
		out, e = h.ycBindWithIntent(ctx, "bind", input)
		if e != nil {
			t.Fatal(e)
		}
		json.Unmarshal(out, &result)
		if result.State != "manual_review" {
			t.Fatal(string(out))
		}
		if e = pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_team_intent WHERE team_id=$1", input["team_id"]).Scan(&intents); e != nil || intents != 0 {
			t.Fatal("ineligible team reserved")
		}
	}
	// A terminal decision after shared prepare must wait for a not-yet-visible
	// local intent, then release it. Otherwise checkout is stranded after rejection.
	race := create("rejection-race@example.test", false)
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT id FROM team WHERE id=$1 FOR UPDATE", race["team_id"]); e != nil {
		t.Fatal(e)
	}
	race["team_created_at"] = time.Now().Add(time.Second)
	race["team_eligible"] = true
	rpc("prepare", race)
	rpc("reject", gin.H{"id": race["id"], "actor_id": uuid.New(), "reason": "synthetic withdrawal", "evidence_reference": "case-synthetic", "home_region": "use"})
	finished := make(chan error, 1)
	go func() {
		finished <- h.ycReleaseClaimIntent(ctx, uuid.MustParse(race["id"].(string)), race["team_id"].(uuid.UUID))
	}()
	select {
	case e = <-finished:
		t.Fatalf("release skipped in-flight admission: %v", e)
	case <-time.After(30 * time.Millisecond):
	}
	if _, e = tx.Exec(ctx, "INSERT INTO yc_claim_team_intent(team_id,claim_id,user_id) VALUES($1,$2,$3)", race["team_id"], race["id"], race["user_id"]); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-finished; e != nil {
		t.Fatal(e)
	}
	var released bool
	if e = pool.QueryRow(ctx, "SELECT released_at IS NOT NULL FROM yc_claim_team_intent WHERE claim_id=$1", race["id"]).Scan(&released); e != nil || !released {
		t.Fatal("successful rejection stranded intent", e)
	}
	if _, e = h.ycClaimRPC(ctx, "bind", race); e == nil {
		t.Fatal("late bind reopened rejection")
	}
	exec("UPDATE billing_signup_choice SET state='committed',offer_key='free' WHERE team_id=$1", race["team_id"])

}
