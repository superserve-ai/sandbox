package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func staffAssertion(t *testing.T, key ed25519.PrivateKey, actor uuid.UUID, method, path, body string, change func(*ycStaffClaims)) string {
	t.Helper()
	digest := sha256.Sum256([]byte(body))
	claims := ycStaffClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "promotion-auth-adapter", Subject: actor.String(), Audience: jwt.ClaimStrings{"yc-staff"}, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Operation: "read", Method: method, Path: path, BodySHA256: hex.EncodeToString(digest[:]), Provider: "google", EmailVerified: true}
	if method == http.MethodPost {
		claims.Operation = "decision"
	}
	if change != nil {
		change(&claims)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestYCStaffAssertionBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	actor := uuid.New()
	path := "/internal/yc/staff/claims/decision"
	body := `{"decision":"approve"}`
	route := gin.New()
	route.POST(path, YCStaffAuth(), func(c *gin.Context) {
		if got := actorIDFromContext(c); got == nil || *got != actor || c.GetHeader("X-Actor-User-Id") != "" {
			t.Error("actor not derived exclusively from signature")
		}
		c.Status(204)
	})
	for _, tc := range []struct {
		name   string
		change func(*ycStaffClaims)
		body   string
		absent bool
		want   int
	}{
		{name: "verified", want: 204},
		{name: "actor header only", absent: true, want: 403},
		{name: "promotion audience", change: func(c *ycStaffClaims) { c.Audience = jwt.ClaimStrings{"promotion-account"} }, want: 403},
		{name: "mixed audience", change: func(c *ycStaffClaims) { c.Audience = jwt.ClaimStrings{"yc-staff", "promotion-account"} }, want: 403},
		{name: "wrong operation", change: func(c *ycStaffClaims) { c.Operation = "read" }, want: 403},
		{name: "wrong path", change: func(c *ycStaffClaims) { c.Path = "/internal/yc/staff/claims" }, want: 403},
		{name: "wrong method", change: func(c *ycStaffClaims) { c.Method = "GET" }, want: 403},
		{name: "non Google", change: func(c *ycStaffClaims) { c.Provider = "email" }, want: 403},
		{name: "unverified", change: func(c *ycStaffClaims) { c.EmailVerified = false }, want: 403},
		{name: "expired", change: func(c *ycStaffClaims) {
			c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		}, want: 403},
		{name: "long lived", change: func(c *ycStaffClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute)) }, want: 403},
		{name: "changed body", body: `{"decision":"revoke"}`, want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := body
			if tc.body != "" {
				payload = tc.body
			}
			req := httptest.NewRequest("POST", path, strings.NewReader(payload))
			req.Header.Set("X-Actor-User-Id", uuid.NewString())
			if !tc.absent {
				req.Header.Set("X-YC-Staff-Assertion", staffAssertion(t, key, actor, "POST", path, body, tc.change))
			}
			w := httptest.NewRecorder()
			route.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func staffTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("YC_CLAIM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL URL required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	database := "staff_claim_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	// Dispatch, revoke, regional admission, shared prepare, and the lock observer
	// must have independent sessions even on small CI runners (default pool: 4).
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)")
		admin.Close(ctx)
	})
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,email text,email_confirmed_at timestamptz,deleted_at timestamptz,created_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE profile(id uuid PRIMARY KEY,provider text,email text);
 CREATE TABLE roles(id uuid PRIMARY KEY,scope_type text);
 CREATE TABLE permissions(id uuid PRIMARY KEY,name text);
 CREATE TABLE role_permissions(role_id uuid,permission_id uuid);
 CREATE TABLE user_role_assignments(user_id uuid,role_id uuid,scope_type text,team_id uuid,revoked_at timestamptz);
 CREATE TABLE team_memberships(team_id uuid,user_id uuid,status text);
 CREATE TABLE team(id uuid PRIMARY KEY,created_at timestamptz NOT NULL,home_region text);
 CREATE TABLE stripe_promotion_migration_fence(team_id uuid PRIMARY KEY);
 CREATE TABLE team_billing_account(team_id uuid PRIMARY KEY,stripe_customer_id text,stripe_subscription_id text,checkout_initializing_at timestamptz,stripe_activation_credit_reserved_at timestamptz,stripe_activation_credit_grant_id text);
 CREATE TABLE billing_signup_choice(team_id uuid PRIMARY KEY,state text,offer_key text);
 CREATE TABLE billing_commercial_contract(id uuid PRIMARY KEY,team_id uuid);`)
	for _, name := range []string{"20261016070000_yc_company_activation_authority.sql", "20261016174553_yc_claim_authority.sql", "20261020224623_yc_staff_claim_approval_notification.sql"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "supabase", "shared-auth-migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		exec(string(b))
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "supabase", "migrations", "20261016174554_yc_claim_team_intent.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(string(b))
	return pool
}

func TestYCStaffDatabasePermissionsAndTransactions(t *testing.T) {
	pool := staffTestPool(t)
	ctx := context.Background()
	h := &Handlers{Pool: pool, PromotionAuthPool: pool}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	reader, writer, customer, nonGoogle, spoof, unverified := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, actor := range []uuid.UUID{reader, writer, customer, nonGoogle, spoof, unverified} {
		provider, email := "google", "staff@superserve.ai"
		if actor == nonGoogle {
			provider = "email"
		}
		if actor == spoof {
			email = "staff@superserve.ai.example.test"
		}
		exec("INSERT INTO profile VALUES($1,$2,$3)", actor, provider, email)
	}
	readRole, writeRole, readPermission, writePermission := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO roles VALUES($1,'platform'),($2,'platform')", readRole, writeRole)
	exec("INSERT INTO permissions VALUES($1,'platform:billing:read'),($2,'platform:billing:write')", readPermission, writePermission)
	exec("INSERT INTO role_permissions VALUES($1,$2),($3,$4),($3,$2)", readRole, readPermission, writeRole, writePermission)
	exec("INSERT INTO user_role_assignments VALUES($1,$2,'platform',NULL,NULL)", reader, readRole)
	for _, actor := range []uuid.UUID{writer, nonGoogle, spoof, unverified} {
		exec("INSERT INTO user_role_assignments VALUES($1,$2,'platform',NULL,NULL)", actor, writeRole)
	}
	router := gin.New()
	router.GET("/internal/yc/staff/claims", YCStaffAuth(), h.ListStaffYCClaims)
	router.POST("/internal/yc/staff/claims/decision", YCStaffAuth(), h.DecideStaffYCClaim)
	request := func(actor uuid.UUID, method, path, body string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Actor-User-Id", writer.String())
		req.Header.Set("X-YC-Staff-Assertion", staffAssertion(t, key, actor, method, path, body, func(c *ycStaffClaims) {
			if actor == unverified {
				c.EmailVerified = false
			}
		}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}
	for _, tc := range []struct {
		actor       uuid.UUID
		read, write int
	}{{reader, 200, 403}, {writer, 200, 400}, {customer, 403, 403}, {nonGoogle, 403, 403}, {spoof, 403, 403}, {unverified, 403, 403}} {
		if got := request(tc.actor, "GET", "/internal/yc/staff/claims", ""); got != tc.read {
			t.Fatalf("read status %d want %d", got, tc.read)
		}
		if got := request(tc.actor, "POST", "/internal/yc/staff/claims/decision", `{}`); got != tc.write {
			t.Fatalf("write status %d want %d", got, tc.write)
		}
	}
	exec("UPDATE user_role_assignments SET revoked_at=now() WHERE user_id=$1", writer)
	if got := request(writer, "POST", "/internal/yc/staff/claims/decision", `{}`); got != 403 {
		t.Fatal("revoked permission accepted")
	}
	rpc := func(op string, p gin.H) map[string]any {
		t.Helper()
		raw, err := h.ycClaimRPC(ctx, op, p)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err = json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	staff := func(op string, p gin.H) (map[string]any, error) {
		raw, err := h.ycStaffRPC(ctx, op, p)
		out := map[string]any{}
		if err == nil {
			err = json.Unmarshal(raw, &out)
		}
		return out, err
	}
	must := func(op string, p gin.H) map[string]any {
		t.Helper()
		out, err := staff(op, p)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return out
	}
	create := func() gin.H {
		t.Helper()
		email := uuid.NewString() + "@example.test"
		user, team := uuid.New(), uuid.New()
		claim := rpc("submit", gin.H{"submitted_email": email, "founder_email": "founder@example.test", "company_identity": "https://www.ycombinator.com/companies/" + uuid.NewString(), "evidence": gin.H{"verified": true}, "verification_reference": ycclaims.Hash(email), "state": "manual_review", "reason": "email_mismatch"})
		exec("INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),clock_timestamp())", user, email)
		return gin.H{"id": claim["id"], "user_id": user, "team_id": team, "home_region": "use", "team_created_at": time.Now().Add(time.Second), "team_eligible": true, "actor_id": writer, "request_id": uuid.New(), "expected_revision": 0, "reason": "Reviewed verified signup", "evidence_reference": "synthetic-review"}
	}
	// Exercise the authenticated handler through regional intent and shared commit.
	httpClaim := create()
	teamRole, teamPermission := uuid.New(), uuid.New()
	exec("INSERT INTO roles VALUES($1,'team')", teamRole)
	exec("INSERT INTO permissions VALUES($1,'billing:write')", teamPermission)
	exec("INSERT INTO role_permissions VALUES($1,$2)", teamRole, teamPermission)
	exec("INSERT INTO user_role_assignments VALUES($1,$2,'team',$3,NULL)", httpClaim["user_id"], teamRole, httpClaim["team_id"])
	exec("INSERT INTO team_memberships VALUES($1,$2,'active')", httpClaim["team_id"], httpClaim["user_id"])
	exec("INSERT INTO team VALUES($1,clock_timestamp(),'use')", httpClaim["team_id"])
	exec("INSERT INTO billing_signup_choice VALUES($1,'selecting',NULL)", httpClaim["team_id"])
	exec("UPDATE user_role_assignments SET revoked_at=NULL WHERE user_id=$1", writer)
	payload := gin.H{}
	for _, k := range []string{"id", "user_id", "team_id", "request_id", "expected_revision", "reason", "evidence_reference"} {
		payload[k] = httpClaim[k]
	}
	payload["decision"] = "approve"
	body, _ := json.Marshal(payload)
	for range 2 {
		if got := request(writer, "POST", "/internal/yc/staff/claims/decision", string(body)); got != 200 {
			t.Fatalf("HTTP approval/replay status %d", got)
		}
	}
	httpResult := rpc("operator-get", gin.H{"id": httpClaim["id"]})
	if httpResult["state"] != "bound" || httpResult["acceptance_required"] != true {
		t.Fatal("HTTP approval did not preserve acceptance boundary")
	}
	// Keep this completed test fixture out of the mail worker cases below.
	exec("UPDATE yc_claim_approval_mail SET sent_at=now() WHERE claim_id=$1", httpClaim["id"])
	old := create()
	exec("UPDATE auth.users SET created_at=now()-interval '1 day' WHERE id=$1", old["user_id"])
	if _, err := staff("prepare-approve", old); err == nil {
		t.Fatal("historical signup accepted")
	}
	p := create()
	must("prepare-approve", p)
	// Outbox failure must roll the approval and company reservation back together.
	exec(`CREATE FUNCTION fail_approval_mail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic crash'; END $$;
 CREATE TRIGGER fail_approval_mail BEFORE INSERT ON yc_claim_approval_mail FOR EACH ROW EXECUTE FUNCTION fail_approval_mail();`)
	if _, err := staff("approve", p); err == nil {
		t.Fatal("injected outbox failure succeeded")
	}
	before := rpc("operator-get", gin.H{"id": p["id"]})
	if before["state"] != "manual_review" || before["approval_id"] != nil || before["acceptance_required"] != false {
		t.Fatalf("partial approval: %v", before)
	}
	exec("DROP TRIGGER fail_approval_mail ON yc_claim_approval_mail")
	approved := must("approve", p)
	if approved["state"] != "bound" || approved["acceptance_required"] != true || approved["billing_contract_id"] != nil {
		t.Fatalf("approval accepted or provisioned: %v", approved)
	}
	team := p["team_id"].(uuid.UUID)
	approvalInput := ycApproval{ClaimID: p["id"].(string), CompanyIdentity: approved["company_identity"].(string), Region: "use", SignupEmail: approved["submitted_email"].(string), FounderEmail: "founder@example.test"}
	blocked := func(err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "requires customer acceptance") {
			t.Fatalf("acceptance gate: %v", err)
		}
	}
	blocked(h.ycAuthorityPreflight(ctx, team, approvalInput))
	_, gateErr := h.ycClaimApproval(ctx, team, approvalInput)
	blocked(gateErr)
	approvalInput.ClaimID = ""
	_, gateErr = h.reserveYCAuthority(ctx, team, writer, approvalInput)
	blocked(gateErr)
	operation := ycOperation{Team: team, ID: uuid.MustParse(approved["approval_id"].(string)), Request: approvalInput}
	blocked(h.verifyYCAuthority(ctx, operation))
	release, gateErr := h.lockYCAuthority(ctx, operation)
	if release != nil {
		release()
	}
	blocked(gateErr)
	// Old binaries call these signatures without any Go acceptance preflight.
	_, gateErr = pool.Exec(ctx, `SELECT public.reserve_yc_activation_authority($1,$2,'use',$3,'operator','synthetic',NULL)`, approvalInput.CompanyIdentity, team, writer)
	blocked(gateErr)
	var oldDispatchAllowed bool
	if err := pool.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, operation.ID, team).Scan(&oldDispatchAllowed); err != nil || oldDispatchAllowed {
		t.Fatalf("old dispatch bypassed acceptance: %t %v", oldDispatchAllowed, err)
	}
	pending := must("activation-pending", gin.H{})
	for _, row := range pending["claims"].([]any) {
		if row.(map[string]any)["id"] == p["id"] {
			t.Fatal("unaccepted claim entered legacy handoff")
		}
	}
	legacyTeam := uuid.New()
	legacyInput := ycApproval{CompanyIdentity: "https://www.ycombinator.com/companies/" + uuid.NewString(), Region: "use", Evidence: "synthetic"}
	if _, err := h.reserveYCAuthority(ctx, legacyTeam, writer, legacyInput); err != nil {
		t.Fatalf("historical operator path broken: %v", err)
	}
	if approved["confirmation_status"] == "confirmed" {
		t.Fatal("approval forged confirmation")
	}
	var n int
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_approval_mail WHERE claim_id=$1", p["id"]).Scan(&n)
	if n != 1 {
		t.Fatal("missing outbox")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := staff("approve", p); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_decision WHERE claim_id=$1 AND decision='operator'", p["id"]).Scan(&n)
	if n != 1 {
		t.Fatal("duplicated decision")
	}
	altered := gin.H{}
	for k, v := range p {
		altered[k] = v
	}
	altered["team_id"] = uuid.New()
	if _, err := staff("approve", altered); err == nil {
		t.Fatal("changed retry target accepted")
	}
	// Forwarded link cannot reveal the bound claim to a different verified account.
	other := uuid.New()
	exec("INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,'other@example.test',now())", other)
	if _, err := h.ycClaimRPC(ctx, "account-get", gin.H{"id": p["id"], "user_id": other}); err == nil {
		t.Fatal("forwarded claim transferred")
	}
	sender := &staffMailSender{fail: true}
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); !found || err == nil {
		t.Fatal("failure not recorded")
	}
	if rpc("operator-get", gin.H{"id": p["id"]})["state"] != "bound" {
		t.Fatal("delivery failure lost approval")
	}
	exec("UPDATE yc_claim_approval_mail SET next_attempt_at=now() WHERE claim_id=$1", p["id"])
	sender.fail = false
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); !found || err != nil {
		t.Fatalf("delivery retry %t %v", found, err)
	}
	if len(sender.messages) != 2 || sender.messages[0].IdempotencyKey != sender.messages[1].IdempotencyKey || sender.messages[0].To != sender.messages[1].To || strings.Contains(sender.messages[0].Text, "token=") {
		t.Fatal("notification identity changed")
	}
	if !strings.Contains(sender.messages[0].Text, "/yc/accept?claim=") {
		t.Fatal("resume link missing")
	}
	// An old revision cannot revoke. A valid revocation and replay cannot reapprove.
	revoke := gin.H{"id": p["id"], "actor_id": writer, "request_id": uuid.New(), "expected_revision": 0, "reason": "Review withdrawn", "evidence_reference": "synthetic-review", "home_region": "use"}
	if _, err := staff("revoke", revoke); err == nil {
		t.Fatal("stale decision accepted")
	}
	revoke["expected_revision"] = approved["revision"]
	revoked := must("revoke", revoke)
	if revoked["state"] != "revoked" {
		t.Fatal("revoke failed")
	}
	replay := must("approve", p)
	if replay["state"] != "revoked" {
		t.Fatal("replay restored approval")
	}
	retry := gin.H{}
	for k, v := range revoke {
		retry[k] = v
	}
	retry["request_id"] = uuid.New()
	retry["expected_revision"] = revoked["revision"]
	if _, err := staff("retry-approval-email", retry); err == nil {
		t.Fatal("revoked approval resent")
	}
	exec("UPDATE yc_claim_approval_mail SET sent_at=NULL,next_attempt_at=now() WHERE claim_id=$1", p["id"])
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); found || err != nil {
		t.Fatal("revoked claim leased")
	}
	// Recover a worker crash using the original message identity; stale ack cannot
	// complete a new lease or reset a delivered message.
	q := create()
	must("prepare-approve", q)
	must("approve", q)
	lease1, lease2 := uuid.New(), uuid.New()
	raw, err := h.ycApprovalMailRPC(ctx, "lease", gin.H{"lease_id": lease1})
	if err != nil {
		t.Fatal(err)
	}
	var job ycMailJob
	json.Unmarshal(raw, &job)
	exec("UPDATE yc_claim_approval_mail SET lease_until=now()-interval '1 second' WHERE claim_id=$1", q["id"])
	raw, err = h.ycApprovalMailRPC(ctx, "lease", gin.H{"lease_id": lease2})
	if err != nil {
		t.Fatal(err)
	}
	var unavailable ycMailJob
	json.Unmarshal(raw, &unavailable)
	if unavailable.ClaimID != uuid.Nil {
		t.Fatal("ambiguous crashed submission automatically retried")
	}
	status := rpc("operator-get", gin.H{"id": q["id"]})
	if status["approval_notification"].(map[string]any)["status"] != "delivery_unknown" {
		t.Fatal("crash ambiguity hidden")
	}
	must("retry-approval-email", gin.H{"id": q["id"], "actor_id": writer, "request_id": uuid.New(), "expected_revision": status["revision"], "reason": "Confirmed resend with operator", "evidence_reference": "synthetic-review", "home_region": "use"})
	raw, err = h.ycApprovalMailRPC(ctx, "lease", gin.H{"lease_id": lease2})
	if err != nil {
		t.Fatal(err)
	}
	var recovered ycMailJob
	json.Unmarshal(raw, &recovered)
	if recovered.MessageID != job.MessageID || recovered.ClaimID == uuid.Nil {
		t.Fatal("crash recovery changed message")
	}
	h.ycApprovalMailRPC(ctx, "finish", gin.H{"id": q["id"], "message_id": job.MessageID, "lease_id": lease1, "success": true})
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_approval_mail WHERE claim_id=$1 AND sent_at IS NOT NULL", q["id"]).Scan(&n)
	if n != 0 {
		t.Fatal("stale lease acknowledged")
	}
	h.ycApprovalMailRPC(ctx, "finish", gin.H{"id": q["id"], "message_id": job.MessageID, "lease_id": lease2, "success": true})
	h.ycApprovalMailRPC(ctx, "finish", gin.H{"id": q["id"], "message_id": job.MessageID, "lease_id": lease2, "success": false})
	pool.QueryRow(ctx, "SELECT count(*) FROM yc_claim_approval_mail WHERE claim_id=$1 AND sent_at IS NOT NULL", q["id"]).Scan(&n)
	if n != 1 {
		t.Fatal("stale ack reset delivery")
	}
	unknownClaim := create()
	must("prepare-approve", unknownClaim)
	must("approve", unknownClaim)
	sender.unknown = true
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); !found || err == nil {
		t.Fatal("ambiguous SMTP submission not surfaced")
	}
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); found || err != nil {
		t.Fatal("ambiguous SMTP submission automatically retried")
	}
	unknownResult := rpc("operator-get", gin.H{"id": unknownClaim["id"]})
	if unknownResult["approval_notification"].(map[string]any)["status"] != "delivery_unknown" || unknownResult["state"] != "bound" {
		t.Fatal("unknown delivery lost approval or status")
	}
	lostAck := create()
	must("prepare-approve", lostAck)
	must("approve", lostAck)
	exec(`CREATE FUNCTION fail_approval_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sent_at IS NOT NULL THEN RAISE EXCEPTION 'synthetic lost ack'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fail_approval_ack BEFORE UPDATE ON yc_claim_approval_mail FOR EACH ROW EXECUTE FUNCTION fail_approval_ack();`)
	sender.unknown = false
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); !found || err == nil {
		t.Fatal("lost successful delivery acknowledgement not surfaced")
	}
	exec("DROP TRIGGER fail_approval_ack ON yc_claim_approval_mail")
	exec("UPDATE yc_claim_approval_mail SET lease_until=now()-interval '1 second' WHERE claim_id=$1", lostAck["id"])
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); found || err != nil {
		t.Fatal("lost acknowledgement automatically resent")
	}
	rejected := create()
	must("prepare-approve", rejected)
	must("approve", rejected)
	sender.rejected = true
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); !found || err == nil {
		t.Fatal("permanent rejection not surfaced")
	}
	rejection := rpc("operator-get", gin.H{"id": rejected["id"]})["approval_notification"].(map[string]any)
	if rejection["attempts"] != float64(1) || rejection["status"] != "delivery_failed" {
		t.Fatalf("permanent rejection fabricated attempts: %v", rejection)
	}
	if found, err := h.deliverYCApprovalMail(ctx, sender, "https://console.example.test", "hello@example.test"); found || err != nil {
		t.Fatal("permanent rejection automatically retried")
	}
	sender.rejected = false
	exhausted := create()
	must("prepare-approve", exhausted)
	must("approve", exhausted)
	exec("UPDATE yc_claim_approval_mail SET attempts=8,created_at=now()-interval '31 minutes' WHERE claim_id=$1", exhausted["id"])
	exec("UPDATE auth.users SET email='changed@example.test' WHERE id=$1", exhausted["user_id"])
	exec("UPDATE yc_claim_approval_mail SET created_at=now()-interval '31 minutes' WHERE claim_id=$1", unknownClaim["id"])
	// Cancelled rows and accepted deliveries are old too, but must not count.
	exec("UPDATE yc_claim_approval_mail SET created_at=now()-interval '31 minutes' WHERE claim_id IN ($1,$2)", p["id"], q["id"])
	recent := create()
	must("prepare-approve", recent)
	must("approve", recent)
	metric := &staffBacklogRecorder{Recorder: telemetry.NewNoopRecorder()}
	previous := currentTelemetryRecorder()
	SetTelemetryRecorder(metric)
	t.Cleanup(func() { SetTelemetryRecorder(previous) })
	if err := h.observeYCApprovalBacklog(ctx); err != nil {
		t.Fatal(err)
	}
	if metric.state != "yc_approval_notification" || metric.count != 2 || metric.age < 30*60 {
		t.Fatalf("backlog misclassified: %+v", metric)
	}
	if err := (&Handlers{}).observeYCApprovalBacklog(ctx); err == nil || metric.count != -1 {
		t.Fatal("failed observation left a misleading healthy/stale count")
	}
}

type staffBacklogRecorder struct {
	telemetry.Recorder
	telemetry.NoopBillingRecorder
	state string
	count int64
	age   float64
}

func (r *staffBacklogRecorder) RecordBillingBacklog(_ context.Context, state string, count int64, age float64) {
	r.state = state
	r.count = count
	r.age = age
}

type staffMailSender struct {
	rejected bool
	unknown  bool
	fail     bool
	messages []EmailMessage
}

func (s *staffMailSender) SendEmail(_ context.Context, m EmailMessage) error {
	s.messages = append(s.messages, m)
	if s.rejected {
		return &rejectedEmailError{err: errors.New("synthetic permanent rejection")}
	}
	if s.unknown {
		return &unknownEmailOutcomeError{err: errors.New("synthetic ambiguous delivery")}
	}
	if s.fail {
		return errors.New("synthetic delivery failure")
	}
	return nil
}

// Exercise shared SQL signatures used by older binaries, with separate sessions
// for admission, authority ownership, and dispatch.
func TestYCStaffAuthorityConcurrency(t *testing.T) {
	pool := staffTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h := &Handlers{Pool: pool, PromotionAuthPool: pool}
	actor := uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	create := func(t *testing.T) gin.H {
		t.Helper()
		email := uuid.NewString() + "@example.test"
		raw, err := h.ycClaimRPC(ctx, "submit", gin.H{"submitted_email": email, "founder_email": "founder@example.test", "company_identity": "https://www.ycombinator.com/companies/" + uuid.NewString(), "evidence": gin.H{"verified": true}, "verification_reference": ycclaims.Hash(email), "state": "manual_review", "reason": "email_mismatch"})
		if err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		if err = json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		user, team := uuid.New(), uuid.New()
		exec("INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),clock_timestamp())", user, email)
		exec("INSERT INTO team VALUES($1,clock_timestamp(),'use')", team)
		exec("INSERT INTO billing_signup_choice VALUES($1,'selecting',NULL)", team)
		return gin.H{"id": c["id"], "company_identity": c["company_identity"], "user_id": user, "team_id": team, "home_region": "use", "actor_id": actor, "request_id": uuid.New(), "expected_revision": 0, "reason": "Synthetic review", "evidence_reference": "synthetic", "team_created_at": time.Now().Add(time.Second), "team_eligible": true}
	}
	call := func(op string, p gin.H) {
		t.Helper()
		if _, err := h.ycStaffRPC(ctx, op, p); err != nil {
			t.Fatal(err)
		}
	}
	observe := func(t *testing.T, label, query string, args ...any) int {
		t.Helper()
		observation, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		for {
			var value int
			if err := pool.QueryRow(observation, query, args...).Scan(&value); err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if value != 0 {
				return value
			}
			select {
			case <-observation.Done():
				t.Fatalf("%s: %v", label, observation.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}

	t.Run("concurrent manual authority cannot be adopted", func(t *testing.T) {
		p := create(t)
		call("prepare-approve", p)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SELECT public.reserve_yc_activation_authority($1,$2,'use',$3,'operator','synthetic',NULL)`, p["company_identity"], p["team_id"], actor); err != nil {
			t.Fatal(err)
		}
		var ownerPID int
		if err = tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&ownerPID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, e := h.ycStaffRPC(ctx, "approve", p); done <- e }()
		// Wait for the staff transaction's INSERT conflict, not an arbitrary delay.
		for {
			var blocked bool
			if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", ownerPID).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case e := <-done:
				t.Fatalf("approval did not wait for reservation: %v", e)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil || !strings.Contains(err.Error(), "manual recovery") {
			t.Fatalf("adopted concurrent manual authority: %v", err)
		}
		var unchanged bool
		if err = pool.QueryRow(ctx, `SELECT state='manual_review' AND NOT acceptance_required AND approval_id IS NULL AND NOT EXISTS(SELECT FROM yc_claim_approval_mail WHERE claim_id=c.id) FROM yc_claim c WHERE id=$1`, p["id"]).Scan(&unchanged); err != nil || !unchanged {
			t.Fatalf("partial staff approval: %t %v", unchanged, err)
		}
		// Already-visible manual authority is rejected as well.
		if _, err = h.ycStaffRPC(ctx, "approve", p); err == nil {
			t.Fatal("adopted prior manual authority")
		}
	})
	t.Run("uncommitted approval cannot dispatch and committed approval blocks old callers", func(t *testing.T) {
		p := create(t)
		call("prepare-approve", p)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var raw []byte
		if err = tx.QueryRow(ctx, `SELECT public.yc_staff_claim_rpc('approve',$1::jsonb)`, p).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		json.Unmarshal(raw, &c)
		var allowed bool
		if err = pool.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, c["approval_id"], p["team_id"]).Scan(&allowed); err != nil || allowed {
			t.Fatalf("uncommitted dispatch: %t %v", allowed, err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = pool.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, c["approval_id"], p["team_id"]).Scan(&allowed); err != nil || allowed {
			t.Fatalf("committed unaccepted dispatch: %t %v", allowed, err)
		}
		if _, err = pool.Exec(ctx, `SELECT public.reserve_yc_activation_authority($1,$2,'use',$3,'operator','synthetic',NULL)`, p["company_identity"], p["team_id"], actor); err == nil {
			t.Fatal("old reservation bypassed acceptance")
		}
	})
	t.Run("legacy admission retry completes while dispatch owns authority", func(t *testing.T) {
		p := create(t)
		raw, err := h.ycBindWithIntent(ctx, "approve", p)
		if err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		json.Unmarshal(raw, &c)
		operation := ycOperation{Team: p["team_id"].(uuid.UUID), ID: uuid.MustParse(c["approval_id"].(string)), Request: ycApproval{Region: "use", CompanyIdentity: p["company_identity"].(string)}}
		release, err := h.lockYCAuthority(ctx, operation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { release() }()
		retryCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		if _, err = h.ycBindWithIntent(retryCtx, "approve", p); err != nil {
			t.Fatalf("dispatch/admission lock inversion: %v", err)
		}
		// Regional work can proceed once admission released its account lock.
		regional, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer regional.Rollback(ctx)
		if _, err = regional.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE NOWAIT`, operation.Team); err != nil {
			t.Fatal(err)
		}
		// Revocation must wait for dispatch, then deny every subsequent dispatch.
		revocation := make(chan error, 1)
		go func() {
			_, e := h.ycClaimRPC(ctx, "revoke", gin.H{"id": p["id"], "actor_id": actor, "reason": "Synthetic withdrawal", "evidence_reference": "synthetic", "home_region": "use"})
			revocation <- e
		}()
		for {
			var waiting bool
			if err = pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT public.yc_claim_rpc%')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case e := <-revocation:
				t.Fatalf("revocation bypassed dispatch: %v", e)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
		regional.Rollback(ctx)
		release()
		release = func() {}
		if err = <-revocation; err != nil {
			t.Fatal(err)
		}
		var allowed bool
		if err = pool.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, operation.ID, operation.Team).Scan(&allowed); err != nil || allowed {
			t.Fatalf("revoked dispatch: %t %v", allowed, err)
		}
	})
	t.Run("admission breaks three party wait and revoke wins retry", func(t *testing.T) {
		p := create(t)
		raw, err := h.ycBindWithIntent(ctx, "approve", p)
		if err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		json.Unmarshal(raw, &c)
		operation := ycOperation{Team: p["team_id"].(uuid.UUID), ID: uuid.MustParse(c["approval_id"].(string)), Request: ycApproval{Region: "use", CompanyIdentity: p["company_identity"].(string)}}
		release, err := h.lockYCAuthority(ctx, operation)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { release() }()
		revoked := make(chan error, 1)
		go func() {
			_, e := h.ycClaimRPC(ctx, "revoke", gin.H{"id": p["id"], "actor_id": actor, "reason": "Synthetic withdrawal", "evidence_reference": "synthetic", "home_region": "use"})
			revoked <- e
		}()
		revokePID := observe(t, "revocation waits for dispatch", `SELECT COALESCE((SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT public.yc_claim_rpc%' LIMIT 1),0)`)
		// Revocation now owns the claim and waits for dispatch's authority.
		prepared := make(chan struct{})
		admitted := make(chan error, 1)
		calls := 0
		go func() {
			_, e := h.ycBindWithIntentRPC(ctx, "approve", p, func(callCtx context.Context, op string, payload any) (json.RawMessage, error) {
				calls++
				close(prepared) // reached only after acquiring the regional account
				return h.ycClaimRPC(callCtx, op, payload)
			})
			admitted <- e
		}()
		setup, stopSetup := context.WithTimeout(ctx, time.Second)
		defer stopSetup()
		select {
		case <-prepared:
		case err := <-admitted:
			t.Fatalf("admission ended before shared prepare: %v", err)
		case <-setup.Done():
			t.Fatalf("admission did not acquire regional locks: %v", setup.Err())
		}
		stopSetup()
		admissionPID := observe(t, "admission waits for revocation", `SELECT COALESCE((SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1),0)`, revokePID)
		// Dispatch needs the account now held by admission, completing the cycle.
		dispatched := make(chan error, 1)
		go func() {
			_, e := pool.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, operation.Team)
			dispatched <- e
		}()
		observe(t, "dispatch waits for regional admission", `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT team_id FROM team_billing_account%'`)
		if err = <-admitted; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("admission must fail retryably: %v", err)
		}
		if calls != 1 {
			t.Fatalf("timeout proceeded to final approval: %d calls", calls)
		}
		// Context cancellation must terminate the server statement too. Otherwise
		// it could finish after the Go caller released its regional fence.
		observe(t, "cancelled shared statement terminates", `SELECT CASE WHEN NOT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND state<>'idle') THEN 1 ELSE 0 END`, admissionPID)
		response := httptest.NewRecorder()
		request, _ := gin.CreateTestContext(response)
		ycClaimError(request, err)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("contention was not retryable: %d", response.Code)
		}
		if err = <-dispatched; err != nil {
			t.Fatalf("admission retained regional lock: %v", err)
		}
		release()
		release = func() {}
		if err = <-revoked; err != nil {
			t.Fatal(err)
		}
		// The retry reaches persisted revoked state; it cannot revive authority.
		if _, err = h.ycBindWithIntent(ctx, "approve", p); err == nil || !strings.Contains(err.Error(), "operator recovery") {
			t.Fatalf("retry defeated revocation: %v", err)
		}
		var valid bool
		if err = pool.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, operation.ID, operation.Team).Scan(&valid); err != nil || valid {
			t.Fatalf("revoked dispatch: %t %v", valid, err)
		}
		var contracts int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_contract WHERE team_id=$1`, operation.Team).Scan(&contracts); err != nil || contracts != 0 {
			t.Fatalf("admission provisioned billing: %d %v", contracts, err)
		}
	})

	t.Run("lost prepare response preserves intent and reconciles on retry", func(t *testing.T) {
		p := create(t)
		calls := 0
		_, err := h.ycBindWithIntentRPC(ctx, "approve", p, func(callCtx context.Context, op string, payload any) (json.RawMessage, error) {
			calls++
			if _, e := h.ycStaffRPC(callCtx, op, payload); e != nil {
				return nil, e
			}
			return nil, context.DeadlineExceeded // shared commit succeeded; response lost
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
			t.Fatalf("lost response advanced approval: %d %v", calls, err)
		}
		var preserved bool
		if err = pool.QueryRow(ctx, `SELECT intent_team_id=$2 AND intent_user_id=$3 AND approval_id IS NULL AND state='manual_review' FROM yc_claim WHERE id=$1`, p["id"], p["team_id"], p["user_id"]).Scan(&preserved); err != nil || !preserved {
			t.Fatalf("shared prepare lost: %t %v", preserved, err)
		}
		var count int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM yc_claim_team_intent WHERE team_id=$1`, p["team_id"]).Scan(&count); err != nil || count != 0 {
			t.Fatalf("regional transaction leaked: %d %v", count, err)
		}
		for range 2 {
			if _, err = h.ycBindWithIntentRPC(ctx, "approve", p, h.ycStaffRPC); err != nil {
				t.Fatalf("reconcile retry: %v", err)
			}
		}
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM yc_claim_decision WHERE claim_id=$1 AND decision='operator'`, p["id"]).Scan(&count); err != nil || count != 1 {
			t.Fatalf("duplicated decision: %d %v", count, err)
		}
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM yc_claim_approval_mail WHERE claim_id=$1`, p["id"]).Scan(&count); err != nil || count != 1 {
			t.Fatalf("duplicated notification: %d %v", count, err)
		}
	})

}
