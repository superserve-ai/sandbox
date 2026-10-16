package ycclaims

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The URL must point at an isolated disposable local database. Each run creates
// its own database; it never resets an existing application's schema.
func TestClaimTransactions(t *testing.T) {
	dsn := os.Getenv("YC_CLAIM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set YC_CLAIM_TEST_DATABASE_URL for PostgreSQL transaction tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	db := "claim_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{db}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{db}.Sanitize()+" WITH (FORCE)")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = db
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,email text,email_confirmed_at timestamptz,deleted_at timestamptz,created_at timestamptz NOT NULL DEFAULT now());`)
	migration, err := os.ReadFile(filepath.Join("..", "..", "supabase", "shared-auth-migrations", "20261016174553_yc_claim_authority.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	// Billing owns this dependency. Supply its actual migration to exercise the
	// release contract without copying its schema or implementation into claims.
	authority := os.Getenv("YC_AUTHORITY_TEST_MIGRATION")
	if authority == "" {
		t.Fatal("YC_AUTHORITY_TEST_MIGRATION must point to the billing authority migration")
	}
	data, err := os.ReadFile(authority)
	if err != nil {
		t.Fatal(err)
	}
	exec(string(data))
	rpc := func(op string, p map[string]any) (map[string]any, error) {
		b, _ := json.Marshal(p)
		var out []byte
		err := pool.QueryRow(ctx, "SELECT public.yc_claim_rpc($1,$2::jsonb)", op, b).Scan(&out)
		v := map[string]any{}
		if err == nil {
			err = json.Unmarshal(out, &v)
		}
		return v, err
	}
	must := func(op string, p map[string]any) map[string]any {
		t.Helper()
		v, e := rpc(op, p)
		if e != nil {
			t.Fatalf("%s: %v", op, e)
		}
		return v
	}
	submit := func(email, company string) map[string]any {
		return must("submit", map[string]any{"submitted_email": email, "founder_email": email, "verification_reference": Hash(uuid.NewString()), "company_identity": company, "evidence": map[string]any{"verified": true, "name": "Synthetic Founder"}, "state": "awaiting_confirmation", "reason": "email_match", "confirmation_token": strings.Repeat("a", 43), "token_hash": Hash(email)})
	}
	user := func(email string, old bool) string {
		id := uuid.NewString()
		created := time.Now().Add(time.Second)
		if old {
			created = time.Now().Add(-time.Hour)
		}
		exec("INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),$3)", id, email, created)
		return id
	}
	bind := func(c map[string]any, u, team, region string) map[string]any {
		return map[string]any{"id": c["id"], "user_id": u, "team_id": team, "home_region": region, "token_hash": Hash(c["submitted_email"].(string)), "team_created_at": time.Now().Add(time.Second), "team_eligible": true}
	}
	company := "https://www.ycombinator.com/companies/synthetic-example"
	c := submit("founder@example.test", company)
	id := c["id"]
	if _, err = rpc("confirm", map[string]any{"id": id, "token_hash": Hash("wrong")}); err == nil {
		t.Fatal("wrong token accepted")
	}
	c = must("confirm", map[string]any{"id": id, "token_hash": Hash("founder@example.test")})
	if c["state"] != "confirmed" {
		t.Fatal(c)
	}
	u := user("founder@example.test", false)
	team := uuid.NewString()
	if _, err = rpc("bind", bind(c, user("intruder@example.test", false), team, "use")); err == nil {
		t.Fatal("wrong account accepted")
	}
	must("prepare", bind(c, u, team, "use"))
	c = must("bind", bind(c, u, team, "use"))
	if c["state"] != "bound" || c["approval_id"] == nil {
		t.Fatal(c)
	}
	again := must("bind", bind(c, u, team, "use"))
	if again["approval_id"] != c["approval_id"] {
		t.Fatal("binding was replaced")
	}
	if _, err = rpc("bind", bind(c, u, uuid.NewString(), "use")); err == nil {
		t.Fatal("reassigned claim")
	}
	lookup := must("lookup", map[string]any{"user_id": u})
	if len(lookup["claims"].([]any)) != 1 {
		t.Fatal(lookup)
	}
	pending := must("pending", map[string]any{})
	if len(pending["claims"].([]any)) != 1 {
		t.Fatal(pending)
	}
	// Independent founder verification links still contend for one company.
	c2 := submit("cofounder@example.test", company)
	must("confirm", map[string]any{"id": c2["id"], "token_hash": Hash("cofounder@example.test")})
	second := bind(c2, user("cofounder@example.test", false), uuid.NewString(), "usw")
	must("prepare", second)
	if _, err = rpc("bind", second); err == nil {
		t.Fatal("duplicate company accepted")
	}
	// An unrelated prior customer cannot automatically migrate; review is durable.
	old := submit("old@example.test", "https://www.ycombinator.com/companies/old-example")
	must("confirm", map[string]any{"id": old["id"], "token_hash": Hash("old@example.test")})
	old = must("bind", bind(old, user("old@example.test", true), uuid.NewString(), "use"))
	if old["state"] != "manual_review" {
		t.Fatal(old)
	}
	if must("operator-get", map[string]any{"id": old["id"]})["state"] != "manual_review" {
		t.Fatal("review not persisted")
	}
	// Expiration never authorizes a first binding; revocation cannot be replayed.
	expired := submit("expired@example.test", "https://www.ycombinator.com/companies/expired-example")
	exec("UPDATE public.yc_claim SET token_expires_at=now()-interval '1 second' WHERE id=$1", expired["id"])
	if _, err = rpc("confirm", map[string]any{"id": expired["id"], "token_hash": Hash("expired@example.test")}); err == nil {
		t.Fatal("expired token accepted")
	}
	must("revoke", map[string]any{"id": id, "actor_id": uuid.NewString(), "reason": "verified withdrawal", "home_region": "use", "evidence_reference": "operator-case-synthetic"})
	if _, err = rpc("bind", bind(c, u, team, "use")); err == nil {
		t.Fatal("revocation reopened")
	}
	var revoked bool
	if err = pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM public.yc_company_activation_authority WHERE approval_id=$1", c["approval_id"]).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("revocation not handed off: %v", err)
	}
	// Two regions race with distinct founders: the shared authority chooses one.
	raceCompany := "https://www.ycombinator.com/companies/race-example"
	inputs := make([]map[string]any, 2)
	for i, email := range []string{"race1@example.test", "race2@example.test"} {
		claim := submit(email, raceCompany)
		must("confirm", map[string]any{"id": claim["id"], "token_hash": Hash(email)})
		inputs[i] = bind(claim, user(email, false), uuid.NewString(), []string{"use", "usw"}[i])
		must("prepare", inputs[i])
	}
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for _, p := range inputs {
		wg.Add(1)
		go func(p map[string]any) { defer wg.Done(); _, e := rpc("bind", p); out <- e }(p)
	}
	wg.Wait()
	close(out)
	success := 0
	for e := range out {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("got %d company bindings", success)
	}
	// Denied email requests cannot drain the global allowance.
	for range 125 {
		must("budget", map[string]any{"email_hash": Hash("limited@example.test")})
	}
	if !must("budget", map[string]any{"email_hash": Hash("another@example.test")})["allowed"].(bool) {
		t.Fatal("denied requests exhausted global capacity")
	}
	for i := 0; i < 125; i++ {
		must("budget", map[string]any{"email_hash": Hash(uuid.NewString())})
	}
	var bucketsBefore, bucketsAfter int
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_rate").Scan(&bucketsBefore)
	for range 125 {
		must("budget", map[string]any{"email_hash": Hash(uuid.NewString())})
	}
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_rate").Scan(&bucketsAfter)
	if bucketsAfter != bucketsBefore {
		t.Fatal("global denial grew email buckets")
	}

	// An existing account cannot erase provenance by deleting and recreating it.
	deletedUser := user("recreated@example.test", true)
	recreated := submit("recreated@example.test", "https://www.ycombinator.com/companies/recreated-example")
	must("confirm", map[string]any{"id": recreated["id"], "token_hash": Hash("recreated@example.test")})
	exec("DELETE FROM auth.users WHERE id=$1", deletedUser)
	recreated = must("prepare", bind(recreated, user("recreated@example.test", false), uuid.NewString(), "use"))
	if recreated["state"] != "manual_review" {
		t.Fatal("recreated account authorized")
	}
	// Deletion before capture is also retained in the lifecycle tombstone.
	deletedBefore := user("before@example.test", true)
	exec("DELETE FROM auth.users WHERE id=$1", deletedBefore)
	before := submit("before@example.test", "https://www.ycombinator.com/companies/before-example")
	must("confirm", map[string]any{"id": before["id"], "token_hash": Hash("before@example.test")})
	before = must("prepare", bind(before, user("before@example.test", false), uuid.NewString(), "use"))
	if before["state"] != "manual_review" {
		t.Fatal("prior deletion forgotten")
	}
	// A fresh user cannot select a prior team or committed commercial state.
	existingTeam := submit("new-admin@example.test", "https://www.ycombinator.com/companies/new-admin-example")
	must("confirm", map[string]any{"id": existingTeam["id"], "token_hash": Hash("new-admin@example.test")})
	oldTeamInput := bind(existingTeam, user("new-admin@example.test", false), uuid.NewString(), "use")
	oldTeamInput["team_created_at"] = time.Now().Add(-time.Hour)
	oldTeamInput["team_eligible"] = false
	if must("prepare", oldTeamInput)["state"] != "manual_review" {
		t.Fatal("old team accepted")
	}
	// An audited prior operator approval can adopt a later verified claim without
	// invoking the one-off migration exception or changing its approval identity.
	adoptCompany := "https://www.ycombinator.com/companies/adoption-example"
	adoptTeam := uuid.NewString()
	adoptUser := user("adopt@example.test", true)
	var approval string
	if err = pool.QueryRow(ctx, "SELECT approval_id FROM public.reserve_yc_activation_authority($1,$2,'use',$3,'operator','prior-approved-evidence',NULL)", adoptCompany, adoptTeam, uuid.NewString()).Scan(&approval); err != nil {
		t.Fatal(err)
	}
	adopt := submit("adopt@example.test", adoptCompany)
	adoptInput := bind(adopt, adoptUser, adoptTeam, "use")
	adoptInput["actor_id"] = uuid.NewString()
	adoptInput["reason"] = "verified prior approval adoption"
	adoptInput["evidence_reference"] = "prior-approved-evidence"
	adoptInput["team_eligible"] = false
	must("prepare-approve", adoptInput)
	adopt = must("approve", adoptInput)
	if adopt["approval_id"] != approval {
		t.Fatal("prior approval replaced")
	}
	must("billing-status", map[string]any{"id": adopt["id"], "team_id": adoptTeam, "approval_id": approval, "contract_id": uuid.NewString(), "state": "awaiting_payment_method"})
	if _, err = rpc("billing-status", map[string]any{"id": adopt["id"], "team_id": adoptTeam, "approval_id": approval, "contract_id": uuid.NewString(), "state": "active"}); err == nil {
		t.Fatal("original contract replaced")
	}

	if _, err = pool.Exec(ctx, "UPDATE public.yc_claim SET founder_email='changed@example.test' WHERE id=$1", id); err == nil {
		t.Fatal("evidence was mutable")
	}
	if _, err = pool.Exec(ctx, "DELETE FROM public.yc_claim_decision WHERE claim_id=$1", id); err == nil {
		t.Fatal("audit was mutable")
	}
	for _, role := range []string{"anon", "authenticated", "service_role", "promotion_evidence_proxy"} {
		var allowed bool
		if err = pool.QueryRow(ctx, "SELECT has_table_privilege($1,'public.yc_claim','SELECT')", role).Scan(&allowed); err != nil || allowed {
			t.Fatalf("table exposure %s %v", role, err)
		}
	}
}
