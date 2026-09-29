//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
)

// Apply only production migrations, without promotiontest's profile trigger or
// any preseeded Auth evidence. Fresh actors must work through the signed API.
func teamCreationDatabase(t *testing.T, beforeMigrations ...func(*pgxpool.Pool)) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	// Ensure conditional production grants are present before migrations run.
	rolloutExec(t, testPool, `DO $$ DECLARE r text; BEGIN
		FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
				EXECUTE format('CREATE ROLE %I NOLOGIN',r);
			END IF;
		END LOOP;
	END $$`)
	name := "team_creation_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := testPool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg := testPool.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := testPool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated database: %v", err)
		}
	})
	for _, setup := range beforeMigrations {
		setup(pool)
	}
	if err := applyMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

type teamCreationClient struct {
	t       *testing.T
	router  *gin.Engine
	private ed25519.PrivateKey
	handler *api.Handlers
}

func newTeamCreationClient(t *testing.T, pool *pgxpool.Pool) *teamCreationClient {
	return newTeamCreationClientForRegion(t, pool, "use")
}

func newTeamCreationClientForRegion(t *testing.T, pool *pgxpool.Pool, region string) *teamCreationClient {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", "team-creation-test-token")
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	next := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", ed25519.SeedSize)))
	h := &api.Handlers{Pool: pool, Config: &config.Config{TeamCreationRegion: region, TeamCreationKeys: map[string]ed25519.PublicKey{"test": public, "next": next.Public().(ed25519.PublicKey)}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &teamCreationClient{t: t, router: api.SetupRouter(ctx, h, pool), private: private, handler: h}
}

func teamCreationReadOnlyPool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readPool.Close)
	return readPool
}

func teamCreationServiceRolePool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	var bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT rolbypassrls FROM pg_roles WHERE rolname='service_role'`).Scan(&bypassRLS); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, pool, `ALTER ROLE service_role BYPASSRLS`)
	cfg := pool.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET ROLE service_role`)
		return err
	}
	servicePool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		servicePool.Close()
		if bypassRLS {
			rolloutExec(t, pool, `ALTER ROLE service_role BYPASSRLS`)
		} else {
			rolloutExec(t, pool, `ALTER ROLE service_role NOBYPASSRLS`)
		}
	})
	return servicePool
}

func teamCreationClaims(actor uuid.UUID, requestID, name string) map[string]any {
	return teamCreationClaimsForRegion(actor, requestID, name, "use")
}

func teamCreationClaimsForRegion(actor uuid.UUID, requestID, name, region string) map[string]any {
	now := time.Now().UTC()
	stamp := now.Format("2006-01-02T15:04:05.000000Z")
	return map[string]any{
		"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation", "sub": actor.String(), "iat": now.Unix(), "exp": now.Unix() + 120,
		"request_id": requestID, "name": name, "region": region, "authorization": "create",
		"policy":   map[string]any{"version": 1, "mode": "first_team", "session": "passed", "captcha": "passed", "preauth": "passed", "google_onboarding": "passed", "additional_team": "not_applicable"},
		"identity": map[string]any{"email": actor.String() + "@example.com", "email_verified": true, "auth_updated_at": stamp, "observed_at": stamp},
	}
}
func (client *teamCreationClient) call(claims map[string]any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	client.t.Helper()
	body, _ := json.Marshal(map[string]any{"request_id": claims["request_id"], "name": claims["name"], "region": claims["region"]})
	payload, err := json.Marshal(claims)
	if err != nil {
		client.t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"team-creation+jwt","kid":"test"}`))
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	assertion := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(client.private, []byte(message)))
	request := httptest.NewRequest("POST", "/internal/teams", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer team-creation-test-token")
	request.Header.Set("X-Team-Creation-Assertion", assertion)
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	client.router.ServeHTTP(response, request)
	return response
}
func teamCreationRecover(claims map[string]any) map[string]any {
	recovery := make(map[string]any)
	for k, v := range claims {
		recovery[k] = v
	}
	delete(recovery, "policy")
	delete(recovery, "identity")
	recovery["authorization"] = "recover"
	return recovery
}
func teamCreationStatus(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if code != "" {
		var result struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error.Code != code {
			t.Fatalf("error response %s: %v", response.Body.String(), err)
		}
	}
}
func teamCreationID(t *testing.T, response *httptest.ResponseRecorder) uuid.UUID {
	t.Helper()
	teamCreationStatus(t, response, 200, "")
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 || result["name"] == "" || result["region"] != "use" {
		t.Fatalf("unexpected result shape: %s", response.Body.String())
	}
	return uuid.MustParse(result["id"])
}

func teamCreationSnapshot(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	teamCreationStatus(t, response, http.StatusOK, "")
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Fatalf("unexpected result shape: %s", response.Body.String())
	}
	return result
}
func teamCreationCount(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
func teamCreationOutcome(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, want string) {
	t.Helper()
	var outcome string
	if err := pool.QueryRow(context.Background(), `SELECT outcome FROM team_signup_promotion_outcome WHERE team_id=$1`, id).Scan(&outcome); err != nil || outcome != want {
		t.Fatalf("outcome=%s want=%s err=%v", outcome, want, err)
	}
	grants := teamCreationCount(t, pool, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit' AND amount_usd=5 AND remaining_usd=5`, id)
	expected := 0
	if want == "granted" {
		expected = 1
	}
	if grants != expected {
		t.Fatalf("grants=%d want=%d", grants, expected)
	}
}

func TestIntegration_TeamCreationRequestPrivileges(t *testing.T) {
	ctx := context.Background()
	// Supabase roles must exist when the production migration applies its ACLs.
	rolloutExec(t, testPool, `DO $$ DECLARE r text; BEGIN
		FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
				EXECUTE format('CREATE ROLE %I NOLOGIN',r);
			END IF;
		END LOOP;
	END $$`)
	pool := teamCreationDatabase(t, func(pool *pgxpool.Pool) {
		// Defaults are database-local and must precede table creation.
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon,authenticated,service_role`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated,service_role`)
	})
	actor, teamID, requestID := uuid.New(), uuid.New(), uuid.NewString()
	rolloutExec(t, pool, `INSERT INTO team(id,name,home_region) VALUES($1,'Role test team','use')`, teamID)
	for _, role := range []string{"service_role", "anon", "authenticated"} {
		t.Run(role, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var superuser, bypass bool
			if err := tx.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=$1`, role).Scan(&superuser, &bypass); err != nil || superuser {
				t.Fatalf("role must be non-superuser: %s super=%t err=%v", role, superuser, err)
			}
			if role == "service_role" {
				// Emulate Supabase's role attribute in vanilla Postgres without
				// changing the migration's request-table grants.
				rolloutExec(t, tx, `ALTER ROLE service_role BYPASSRLS`)
			} else if bypass {
				t.Fatalf("ordinary role %s unexpectedly bypasses RLS", role)
			}
			rolloutExec(t, tx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize())
			var currentRole string
			if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&currentRole); err != nil || currentRole != role {
				t.Fatalf("current role=%q want=%q err=%v", currentRole, role, err)
			}
			var canCreate bool
			if err := tx.QueryRow(ctx, `SELECT has_function_privilege(current_user, 'create_team_with_signup_trial(text,uuid,text,text)', 'EXECUTE')`).Scan(&canCreate); err != nil || canCreate != (role == "service_role") {
				t.Fatalf("policy provisioning privilege for %s=%t err=%v", role, canCreate, err)
			}
			const insert = `INSERT INTO team_creation_requests(actor_id,cell,request_id,name,region,team_id) VALUES($1,'use',$2,'Role test team','use',$3)`
			const recover = `SELECT r.name, r.region, CASE WHEN r.deleted_at IS NULL THEN t.id END
				FROM team_creation_requests r LEFT JOIN team t ON t.id=r.team_id
				WHERE r.actor_id=$1 AND r.cell='use' AND r.request_id=$2`
			if role == "service_role" {
				rolloutExec(t, tx, insert, actor, requestID, teamID)
				rolloutExec(t, tx, `RESET ROLE`)
				if !bypass {
					rolloutExec(t, tx, `ALTER ROLE service_role NOBYPASSRLS`)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				// Recovery uses a new transaction over the committed result.
				// Fixture role attributes and the legacy team read grant roll back.
				tx, err = pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				rolloutExec(t, tx, `ALTER ROLE service_role BYPASSRLS`)
				rolloutExec(t, tx, `GRANT SELECT ON team TO service_role`)
				rolloutExec(t, tx, `SET LOCAL ROLE service_role`)
				var name, region string
				var recoveredID uuid.UUID
				if err := tx.QueryRow(ctx, recover, actor, requestID).Scan(&name, &region, &recoveredID); err != nil || name != "Role test team" || region != "use" || recoveredID != teamID {
					t.Fatalf("service recovery name=%q region=%q id=%s err=%v", name, region, recoveredID, err)
				}
			} else {
				localIdentityError(t, tx, "42501", insert, actor, requestID, teamID)
				localIdentityError(t, tx, "42501", `SELECT * FROM team_creation_requests WHERE actor_id=$1`, actor)
			}
			for _, statement := range []string{
				`UPDATE team_creation_requests SET name='Changed' WHERE actor_id=$1`,
				`DELETE FROM team_creation_requests WHERE actor_id=$1`,
			} {
				localIdentityError(t, tx, "42501", statement, actor)
			}
			localIdentityError(t, tx, "42501", `TRUNCATE team_creation_requests`)
		})
	}
}

func TestIntegration_TeamCreationServiceRoleCreateAndRecover(t *testing.T) {
	pool := teamCreationDatabase(t, func(pool *pgxpool.Pool) {
		// Supabase supplies these defaults before migrations narrow individual ACLs.
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO service_role`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO service_role`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO service_role`)
	})
	servicePool := teamCreationServiceRolePool(t, pool)
	client := newTeamCreationClient(t, servicePool)
	ctx := context.Background()
	actor := uuid.New()
	claims := teamCreationClaims(actor, uuid.NewString(), "Service role team")

	var currentRole string
	if err := servicePool.QueryRow(ctx, `SELECT current_user`).Scan(&currentRole); err != nil || currentRole != "service_role" {
		t.Fatalf("provisioning pool role=%q want=service_role err=%v", currentRole, err)
	}
	created := teamCreationSnapshot(t, client.call(claims, nil))
	id := uuid.MustParse(created["id"])
	teamCreationOutcome(t, pool, id, "granted")

	for _, check := range []struct {
		name  string
		query string
		args  []any
	}{
		{"profile", `SELECT count(*) FROM profile WHERE id=$1`, []any{actor}},
		{"promotion evidence", `SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`, []any{actor}},
		{"owner membership", `SELECT count(*) FROM team_member WHERE team_id=$1 AND profile_id=$2 AND role='owner'`, []any{id, actor}},
		{"active membership", `SELECT count(*) FROM team_memberships WHERE team_id=$1 AND user_id=$2 AND status='active'`, []any{id, actor}},
		{"owner RBAC", `SELECT count(*) FROM user_role_assignments a JOIN roles r ON r.id=a.role_id WHERE a.team_id=$1 AND a.user_id=$2 AND a.revoked_at IS NULL AND r.name='team_owner'`, []any{id, actor}},
		{"durable result", `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1 AND cell=$2 AND request_id=$3 AND team_id=$4`, []any{actor, claims["region"], claims["request_id"], id}},
	} {
		if n := teamCreationCount(t, pool, check.query, check.args...); n != 1 {
			t.Fatalf("%s count=%d want=1", check.name, n)
		}
	}

	recovered := teamCreationSnapshot(t, client.call(teamCreationRecover(claims), nil))
	if recovered["id"] != created["id"] || recovered["name"] != created["name"] || recovered["region"] != created["region"] {
		t.Fatalf("recovery changed committed result: create=%v recover=%v", created, recovered)
	}
}

func TestIntegration_TeamCreationAdditionalPolicyUsesPromotionAuthority(t *testing.T) {
	pool := teamCreationDatabase(t)
	client := newTeamCreationClient(t, pool)
	ctx := context.Background()
	for _, canonical := range []bool{false, true} {
		t.Run(fmt.Sprintf("canonical=%t", canonical), func(t *testing.T) {
			if canonical {
				rolloutExec(t, pool, `SELECT enable_canonical_promotion_identity('{"reference":"isolated additional team test","all_writers_ready":true,"rollback_ready":true}')`)
			}
			// A fresh actor models a creator whose existing-team authorization is
			// valid, but whose canonical promotion identity has not been claimed.
			actor := uuid.New()
			claims := teamCreationClaims(actor, uuid.NewString(), fmt.Sprintf("Regional additional team %t", canonical))
			firstTeamPolicy := claims["policy"]
			claims["policy"] = map[string]any{"version": 1, "mode": "additional_team", "session": "passed", "captcha": "not_applicable", "preauth": "not_applicable", "google_onboarding": "not_applicable", "additional_team": "passed"}
			denialsBefore := teamCreationCount(t, pool, `SELECT count(*) FROM team_signup_trial_denial`)
			rolloutExec(t, pool, `CREATE FUNCTION fail_additional_team_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected result failure'; END $$`)
			rolloutExec(t, pool, `CREATE TRIGGER fail_additional_team_result BEFORE INSERT ON team_creation_requests FOR EACH ROW EXECUTE FUNCTION fail_additional_team_result()`)
			failed := client.call(claims, nil)
			rolloutExec(t, pool, `DROP TRIGGER fail_additional_team_result ON team_creation_requests`)
			rolloutExec(t, pool, `DROP FUNCTION fail_additional_team_result()`)
			teamCreationStatus(t, failed, http.StatusInternalServerError, "internal_error")
			if n := teamCreationCount(t, pool, `SELECT count(*) FROM team WHERE name=$1`, claims["name"]); n != 0 {
				t.Fatal("failed additional creation left a team")
			}
			if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_signup_trial_denial`); n != denialsBefore {
				t.Fatal("failed additional creation left a denial")
			}
			for _, query := range []string{
				`SELECT count(*) FROM profile WHERE id=$1`,
				`SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`,
				`SELECT count(*) FROM team_signup_promotion_outcome WHERE user_id=$1`,
				`SELECT count(*) FROM team_member WHERE profile_id=$1`,
				`SELECT count(*) FROM team_memberships WHERE user_id=$1`,
				`SELECT count(*) FROM user_role_assignments WHERE user_id=$1`,
				`SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`,
			} {
				if n := teamCreationCount(t, pool, query, actor); n != 0 {
					t.Fatalf("failed additional creation left state: %s count=%d", query, n)
				}
			}
			teamCreationStatus(t, client.call(teamCreationRecover(claims), nil), http.StatusNotFound, "result_not_found")
			created := client.call(claims, nil)
			id := teamCreationID(t, created)
			teamCreationOutcome(t, pool, id, "granted")
			for _, query := range []string{
				`SELECT count(*) FROM team_signup_trial_denial WHERE team_id=$1`,
				`SELECT count(*) FROM team_signup_promotion_outcome WHERE team_id=$1 AND reason='additional_team'`,
				`SELECT count(*) FROM team_member WHERE team_id=$1 AND role='owner'`,
				`SELECT count(*) FROM team_memberships WHERE team_id=$1 AND status='active'`,
				`SELECT count(*) FROM user_role_assignments a JOIN roles r ON r.id=a.role_id WHERE a.team_id=$1 AND a.revoked_at IS NULL AND r.name='team_owner'`,
				`SELECT count(*) FROM team_creation_requests WHERE team_id=$1`,
			} {
				want := 1
				if strings.Contains(query, "team_signup_trial_denial") || strings.Contains(query, "reason='additional_team'") {
					want = 0
				}
				if n := teamCreationCount(t, pool, query, id); n != want {
					t.Fatalf("incomplete additional creation: %s count=%d want=%d", query, n, want)
				}
			}
			var eligible bool
			if err := pool.QueryRow(ctx, `SELECT team_sandbox_billing_eligible($1)`, id).Scan(&eligible); err != nil || !eligible {
				t.Fatalf("additional team billing eligible=%t err=%v", eligible, err)
			}
			// Legacy claim re-entry must preserve the authority-owned outcome.
			var outcome string
			if err := pool.QueryRow(ctx, `SELECT outcome FROM claim_team_signup_trial($1,$2)`, id, actor).Scan(&outcome); err != nil || outcome != "granted" {
				t.Fatalf("legacy re-entry outcome=%q err=%v", outcome, err)
			}
			readClient := newTeamCreationClient(t, teamCreationReadOnlyPool(t, pool))
			// A renewed first-team assertion cannot change a completed result.
			claims["policy"] = firstTeamPolicy
			for _, replay := range []map[string]any{claims, teamCreationRecover(claims)} {
				response := readClient.call(replay, nil)
				teamCreationStatus(t, response, http.StatusOK, "")
				if response.Body.String() != created.Body.String() {
					t.Fatal("additional team replay changed committed result")
				}
			}
			teamCreationOutcome(t, pool, id, "granted")
			for _, query := range []string{
				`SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$1`,
				`SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$1 AND signup_trial_claimed_at IS NOT NULL`,
				`SELECT count(*) FROM promotion_identity_history WHERE user_id=$1 AND promotion='signup'`,
			} {
				if n := teamCreationCount(t, pool, query, actor); n != 1 {
					t.Fatalf("additional creation did not retain its signup claim: %s count=%d", query, n)
				}
			}
		})
	}
}

func TestIntegration_TeamCreationDeviceAuthority(t *testing.T) {
	pool := teamCreationDatabase(t)
	client := newTeamCreationClient(t, pool)
	ctx := context.Background()
	register := func(t *testing.T, actor uuid.UUID, fingerprint, want string) {
		t.Helper()
		var result string
		if err := pool.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			actor, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&result); err != nil || result != want {
			t.Fatalf("device registration=%q want=%q err=%v", result, want, err)
		}
	}
	owner, prior := uuid.New(), uuid.New()
	fingerprint := "device-" + uuid.NewString()
	register(t, owner, fingerprint, "owner")
	register(t, prior, fingerprint, "owner_conflict")
	// Expansion records device consumption without enforcing device eligibility.
	priorID := teamCreationID(t, client.call(teamCreationClaims(prior, uuid.NewString(), "Expansion device team"), nil))
	teamCreationOutcome(t, pool, priorID, "granted")
	if n := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND user_id=$1 AND team_id=$2 AND fingerprint=$3`, prior, priorID, fingerprint); n != 1 {
		t.Fatalf("expansion device grants=%d", n)
	}
	// Both gates are enabled only in this disposable database.
	rolloutExec(t, pool, `SELECT enable_canonical_promotion_identity('{"reference":"isolated device provisioning test","all_writers_ready":true,"rollback_ready":true}')`)
	rolloutExec(t, pool, `SELECT set_promotion_device_policy(true,true)`)
	readClient := newTeamCreationClient(t, teamCreationReadOnlyPool(t, pool))
	for _, tc := range []struct {
		reason  string
		actor   uuid.UUID
		outcome string
	}{
		{"evidence_missing", uuid.New(), "promotion_ineligible"},
		{"owner_conflict", uuid.New(), "promotion_ineligible"},
		{"device_already_redeemed", owner, "promotion_ineligible"},
		{"first_identity_claim", uuid.New(), "granted"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			device := "device-" + uuid.NewString()
			switch tc.reason {
			case "owner_conflict":
				register(t, tc.actor, fingerprint, "owner_conflict")
			case "first_identity_claim":
				register(t, tc.actor, device, "owner")
			}
			claims := teamCreationClaims(tc.actor, uuid.NewString(), "Device team "+tc.reason)
			created := client.call(claims, nil)
			id := teamCreationID(t, created)
			teamCreationOutcome(t, pool, id, tc.outcome)
			var reason string
			if err := pool.QueryRow(ctx, `SELECT reason FROM team_signup_promotion_outcome WHERE team_id=$1`, id).Scan(&reason); err != nil || reason != tc.reason {
				t.Fatalf("reason=%q want=%q err=%v", reason, tc.reason, err)
			}
			for _, query := range []string{
				`SELECT count(*) FROM team_member WHERE team_id=$1 AND role='owner'`,
				`SELECT count(*) FROM team_memberships WHERE team_id=$1 AND status='active'`,
				`SELECT count(*) FROM user_role_assignments a JOIN roles r ON r.id=a.role_id WHERE a.team_id=$1 AND a.revoked_at IS NULL AND r.name='team_owner'`,
				`SELECT count(*) FROM team_creation_requests WHERE team_id=$1`,
			} {
				if n := teamCreationCount(t, pool, query, id); n != 1 {
					t.Fatalf("incomplete device-checked creation: %s count=%d", query, n)
				}
			}
			if tc.reason == "evidence_missing" {
				// Later evidence cannot upgrade the completed no-grant intent.
				register(t, tc.actor, device, "owner")
			}
			for _, replay := range []map[string]any{claims, teamCreationRecover(claims)} {
				response := readClient.call(replay, nil)
				teamCreationStatus(t, response, http.StatusOK, "")
				if response.Body.String() != created.Body.String() {
					t.Fatal("device-checked replay changed committed result")
				}
			}
			teamCreationOutcome(t, pool, id, tc.outcome)
			wantGrants := 0
			if tc.outcome == "granted" {
				wantGrants = 1
				if n := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND team_id=$1 AND user_id=$2 AND fingerprint=$3`, id, tc.actor, device); n != 1 {
					t.Fatalf("eligible device grants=%d", n)
				}
			}
			for _, query := range []string{
				`SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND user_id=$1`,
				`SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$1`,
			} {
				if n := teamCreationCount(t, pool, query, tc.actor); n != wantGrants {
					t.Fatalf("device consumption: %s count=%d want=%d", query, n, wantGrants)
				}
			}
		})
	}
}

func TestIntegration_TeamCreationProductionAuthority(t *testing.T) {
	pool := teamCreationDatabase(t)
	client := newTeamCreationClient(t, pool)
	ctx := context.Background()
	t.Run("expansion gate off", func(t *testing.T) {
		actor := uuid.New()
		claims := teamCreationClaims(actor, uuid.NewString(), "Expansion team")
		id := teamCreationID(t, client.call(claims, nil))
		teamCreationOutcome(t, pool, id, "granted")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`, actor); n != 1 {
			t.Fatalf("identity evidence=%d", n)
		}
		var enabled bool
		if err := pool.QueryRow(ctx, `SELECT canonical_promotion_identity_enabled()`).Scan(&enabled); err != nil || enabled {
			t.Fatalf("creation changed gate: %t %v", enabled, err)
		}
	})
	t.Run("successful non-default cell creation and recovery", func(t *testing.T) {
		uswClient := newTeamCreationClientForRegion(t, pool, "usw")
		actor := uuid.New()
		const name = "Cafe\u0301  ☃"
		claims := teamCreationClaimsForRegion(actor, uuid.NewString(), name, "usw")
		// Keep the Auth source revision and retrieval observation distinct so
		// the transaction's argument order cannot be masked by equal values.
		authUpdatedAt := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
		observedAt := authUpdatedAt.Add(45 * time.Second)
		identity := claims["identity"].(map[string]any)
		identity["auth_updated_at"] = authUpdatedAt.Format("2006-01-02T15:04:05.000000Z")
		identity["observed_at"] = observedAt.Format("2006-01-02T15:04:05.000000Z")
		snapshot := teamCreationSnapshot(t, uswClient.call(claims, nil))
		id := uuid.MustParse(snapshot["id"])
		if snapshot["name"] != name || snapshot["region"] != "usw" {
			t.Fatalf("unexpected non-default response: %v", snapshot)
		}
		var homeRegion, cell, durableRegion, teamName, durableName string
		if err := pool.QueryRow(ctx, `SELECT home_region, name FROM team WHERE id=$1`, id).Scan(&homeRegion, &teamName); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT cell, region, name FROM team_creation_requests WHERE actor_id=$1 AND request_id=$2`, actor, claims["request_id"]).Scan(&cell, &durableRegion, &durableName); err != nil {
			t.Fatal(err)
		}
		if teamName != name || durableName != name {
			t.Fatalf("name bytes changed: team=%q durable=%q want=%q", teamName, durableName, name)
		}
		if homeRegion != "usw" || cell != "usw" || durableRegion != "usw" {
			t.Fatalf("non-default routing home=%q cell=%q durable_region=%q", homeRegion, cell, durableRegion)
		}
		var evidenceEmail string
		var evidenceVerified bool
		var evidenceAuthUpdatedAt, evidenceObservedAt time.Time
		if err := pool.QueryRow(ctx, `SELECT email, email_verified, auth_updated_at, observed_at
			FROM promotion_identity_evidence WHERE user_id=$1`, actor).
			Scan(&evidenceEmail, &evidenceVerified, &evidenceAuthUpdatedAt, &evidenceObservedAt); err != nil {
			t.Fatal(err)
		}
		if evidenceEmail != actor.String()+"@example.com" || !evidenceVerified ||
			!evidenceAuthUpdatedAt.Equal(authUpdatedAt) || !evidenceObservedAt.Equal(observedAt) {
			t.Fatalf("identity evidence=(%q,%t,%v,%v), want (%q,true,%v,%v)", evidenceEmail, evidenceVerified,
				evidenceAuthUpdatedAt, evidenceObservedAt, actor.String()+"@example.com", authUpdatedAt, observedAt)
		}
		recovered := teamCreationSnapshot(t, uswClient.call(teamCreationRecover(claims), nil))
		if recovered["id"] != snapshot["id"] || recovered["name"] != name || recovered["region"] != "usw" {
			t.Fatalf("recovery changed non-default snapshot: create=%v recover=%v", snapshot, recovered)
		}
		// A replay with changed identity metadata must return the durable result
		// without rewriting the authority-owned evidence row.
		identity["email"] = "replacement@example.com"
		identity["auth_updated_at"] = authUpdatedAt.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
		identity["observed_at"] = observedAt.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
		if replay := teamCreationSnapshot(t, uswClient.call(claims, nil)); replay["id"] != snapshot["id"] {
			t.Fatalf("replay changed committed snapshot: create=%v replay=%v", snapshot, replay)
		}
		var replayEmail string
		var replayVerified bool
		var replayAuthUpdatedAt, replayObservedAt time.Time
		if err := pool.QueryRow(ctx, `SELECT email, email_verified, auth_updated_at, observed_at
			FROM promotion_identity_evidence WHERE user_id=$1`, actor).
			Scan(&replayEmail, &replayVerified, &replayAuthUpdatedAt, &replayObservedAt); err != nil {
			t.Fatal(err)
		}
		if replayEmail != evidenceEmail || replayVerified != evidenceVerified ||
			!replayAuthUpdatedAt.Equal(evidenceAuthUpdatedAt) || !replayObservedAt.Equal(evidenceObservedAt) {
			t.Fatalf("replay rewrote identity evidence=(%q,%t,%v,%v), original=(%q,%t,%v,%v)", replayEmail, replayVerified,
				replayAuthUpdatedAt, replayObservedAt, evidenceEmail, evidenceVerified, evidenceAuthUpdatedAt, evidenceObservedAt)
		}
	})
	// This activation is confined to the disposable test database.
	rolloutExec(t, pool, `SELECT enable_canonical_promotion_identity('{"reference":"isolated provisioning test","all_writers_ready":true,"rollback_ready":true}')`)
	t.Run("response loss replay isolation and tombstone", func(t *testing.T) {
		actor := uuid.New()
		claims := teamCreationClaims(actor, uuid.NewString(), "Café ☃")
		teamCreationStatus(t, client.call(teamCreationRecover(claims), nil), 404, "result_not_found")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM profile WHERE id=$1`, actor); n != 0 {
			t.Fatal("recovery created profile")
		}
		var results [2]*httptest.ResponseRecorder
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = client.call(claims, nil) }(i)
		}
		wg.Wait()
		id := teamCreationID(t, results[0])
		teamCreationID(t, results[1])
		if results[0].Body.String() != results[1].Body.String() {
			t.Fatal("concurrent requests diverged")
		}
		teamCreationOutcome(t, pool, id, "granted")
		// Simulate a dropped response: the caller has no create response and
		// recovers using the same logical request identity. Recovery must return
		// the committed snapshot without fresh create evidence or writes.
		lostActor := uuid.New()
		lostClaims := teamCreationClaims(lostActor, uuid.NewString(), "Dropped response Café ☃")
		_ = client.call(lostClaims, nil)
		var committedID uuid.UUID
		var committedName, committedRegion string
		if err := pool.QueryRow(ctx, `SELECT team_id, name, region FROM team_creation_requests WHERE actor_id=$1 AND cell=$2 AND request_id=$3`, lostActor, lostClaims["region"], lostClaims["request_id"]).Scan(&committedID, &committedName, &committedRegion); err != nil {
			t.Fatal(err)
		}
		readPool := teamCreationReadOnlyPool(t, pool)
		lostClient := newTeamCreationClient(t, readPool)
		// Advance beyond expiry plus skew without changing the original assertion.
		recoveryTime := time.Unix(lostClaims["exp"].(int64)+31, 0)
		lostClient.handler.Now = func() time.Time { return recoveryTime }
		teamCreationStatus(t, lostClient.call(lostClaims, nil), http.StatusUnauthorized, "assertion_expired")
		freshRecovery := teamCreationRecover(lostClaims)
		freshRecovery["iat"], freshRecovery["exp"] = recoveryTime.Unix(), recoveryTime.Unix()+120
		recoveredLost := teamCreationSnapshot(t, lostClient.call(freshRecovery, nil))
		if recoveredLost["id"] != committedID.String() || recoveredLost["name"] != committedName || recoveredLost["region"] != committedRegion {
			t.Fatalf("lost-response recovery changed committed result: %v", recoveredLost)
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, lostActor); n != 1 {
			t.Fatalf("lost-response recovery changed request count: %d", n)
		}
		for _, query := range []string{
			`SELECT count(*) FROM team_member WHERE team_id=$1 AND profile_id=$2 AND role='owner'`,
			`SELECT count(*) FROM team_memberships WHERE team_id=$1 AND user_id=$2 AND status='active'`,
			`SELECT count(*) FROM user_role_assignments a JOIN roles r ON r.id=a.role_id WHERE a.team_id=$1 AND a.user_id=$2 AND a.revoked_at IS NULL AND r.name='team_owner'`,
			`SELECT count(*) FROM team_creation_requests WHERE team_id=$1 AND actor_id=$2`,
		} {
			if n := teamCreationCount(t, pool, query, id, actor); n != 1 {
				t.Fatalf("incomplete creation: %s count=%d", query, n)
			}
		}
		rolloutExec(t, pool, `UPDATE team SET name='Renamed by administrator' WHERE id=$1`, id)
		// Fresh proof with stale evidence must replay without calling the writer.
		identity := claims["identity"].(map[string]any)
		identity["observed_at"] = "2000-01-01T00:00:00.000000Z"
		identity["auth_updated_at"] = "2000-01-01T00:00:00.000000Z"
		evidenceBefore := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`, actor)
		// A transaction configured read-only proves recover and completed create do not write.
		readClient := newTeamCreationClient(t, readPool)
		for _, authorization := range []map[string]any{claims, teamCreationRecover(claims)} {
			response := readClient.call(authorization, func(r *http.Request) {
				parts := strings.Split(r.Header.Get("X-Team-Creation-Assertion"), ".")
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"team-creation+jwt","kid":"next"}`))
				message := header + "." + parts[1]
				next := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", ed25519.SeedSize)))
				r.Header.Set("X-Team-Creation-Assertion", message+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(next, []byte(message))))
			})
			teamCreationStatus(t, response, 200, "")
			if response.Body.String() != results[0].Body.String() {
				t.Fatal("replay changed original snapshot")
			}
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`, actor); n != evidenceBefore {
			t.Fatal("replay refreshed evidence")
		}
		other := teamCreationRecover(claims)
		other["sub"] = uuid.NewString()
		teamCreationStatus(t, client.call(other, nil), 404, "result_not_found")
		changed := teamCreationRecover(claims)
		changed["name"] = "Changed"
		teamCreationStatus(t, client.call(changed, nil), 409, "idempotency_conflict")
		// Emulate administrative deletion through the real tombstone trigger.
		rolloutExec(t, pool, `DELETE FROM user_role_assignments WHERE team_id=$1`, id)
		rolloutExec(t, pool, `DELETE FROM team_memberships WHERE team_id=$1`, id)
		rolloutExec(t, pool, `DELETE FROM team_member WHERE team_id=$1`, id)
		rolloutExec(t, pool, `DELETE FROM team_credit_grant WHERE team_id=$1`, id)
		rolloutExec(t, pool, `DELETE FROM team WHERE id=$1`, id)
		for _, c := range []map[string]any{claims, teamCreationRecover(claims)} {
			teamCreationStatus(t, client.call(c, nil), 410, "team_deleted")
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE team_id=$1 AND deleted_at IS NOT NULL`, id); n != 1 {
			t.Fatal("missing durable tombstone")
		}
		// Reusing the deleted UUID cannot make a tombstoned intent live again.
		rolloutExec(t, pool, `INSERT INTO team(id,name,home_region) VALUES($1,'Replacement team','use')`, id)
		teamCreationStatus(t, client.call(teamCreationRecover(claims), nil), 410, "team_deleted")
	})
	t.Run("atomic failures retry every write stage", func(t *testing.T) {
		for _, table := range []string{"team", "team_member", "team_memberships", "user_role_assignments", "team_creation_requests"} {
			t.Run(table, func(t *testing.T) {
				actor := uuid.New()
				claims := teamCreationClaims(actor, uuid.NewString(), "Rollback "+table)
				if table == "team" {
					other := teamCreationClaims(uuid.New(), uuid.NewString(), claims["name"].(string))
					otherID := teamCreationID(t, client.call(other, nil))
					for attempt := 0; attempt < 2; attempt++ {
						teamCreationStatus(t, client.call(claims, nil), 409, "team_name_conflict")
					}
					if n := teamCreationCount(t, pool, `SELECT count(*) FROM team WHERE id=$1 AND name=$2`, otherID, claims["name"]); n != 1 {
						t.Fatal("name conflict changed the existing team")
					}
					rolloutExec(t, pool, `UPDATE team SET name=$2 WHERE id=$1`, otherID, "Renamed "+otherID.String())
				} else {
					rolloutExec(t, pool, `CREATE FUNCTION fail_team_creation_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$`)
					rolloutExec(t, pool, fmt.Sprintf(`CREATE TRIGGER fail_team_creation_write BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION fail_team_creation_write()`, pgx.Identifier{table}.Sanitize()))
					response := client.call(claims, nil)
					rolloutExec(t, pool, fmt.Sprintf(`DROP TRIGGER fail_team_creation_write ON %s`, pgx.Identifier{table}.Sanitize()))
					rolloutExec(t, pool, `DROP FUNCTION fail_team_creation_write()`)
					teamCreationStatus(t, response, 500, "internal_error")
				}
				for _, check := range []struct {
					query string
					arg   any
				}{
					{`SELECT count(*) FROM team WHERE name=$1`, claims["name"]},
					{`SELECT count(*) FROM profile WHERE id=$1`, actor},
					{`SELECT count(*) FROM promotion_identity_evidence WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM promotion_identity_current WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM promotion_identity_binding WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM promotion_identity_history WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM team_credit_grant WHERE created_by=$1`, actor},
					{`SELECT count(*) FROM team_signup_promotion_outcome WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM promotion_device_grant WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM team_member WHERE profile_id=$1`, actor},
					{`SELECT count(*) FROM team_memberships WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM user_role_assignments WHERE user_id=$1`, actor},
					{`SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, actor},
				} {
					if n := teamCreationCount(t, pool, check.query, check.arg); n != 0 {
						t.Fatalf("partial state survived: %s count=%d", check.query, n)
					}
				}
				teamCreationStatus(t, client.call(teamCreationRecover(claims), nil), 404, "result_not_found")
				id := teamCreationID(t, client.call(claims, nil))
				teamCreationOutcome(t, pool, id, "granted")
				if n := teamCreationCount(t, pool, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND user_id=$1 AND team_id=$2`, actor, id); n != 1 {
					t.Fatalf("retry device grants=%d", n)
				}
			})
		}
	})
	t.Run("canonical aliases and no grant", func(t *testing.T) {
		alias := strings.ReplaceAll(uuid.NewString(), "-", "")
		var claims [2]map[string]any
		for i := range claims {
			claims[i] = teamCreationClaims(uuid.New(), uuid.NewString(), fmt.Sprintf("Alias %d", i))
		}
		promotionExampleProviderDomains(t, pool)
		claims[0]["identity"].(map[string]any)["email"] = alias + "@mail.example.com"
		claims[1]["identity"].(map[string]any)["email"] = alias[:5] + "." + alias[5:] + "+tag@alias.example.com"
		var results [2]*httptest.ResponseRecorder
		var wg sync.WaitGroup
		for i := range claims {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = client.call(claims[i], nil) }(i)
		}
		wg.Wait()
		ids := []uuid.UUID{teamCreationID(t, results[0]), teamCreationID(t, results[1])}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_credit_grant WHERE team_id=ANY($1::uuid[]) AND reason='signup trial credit'`, ids); n != 1 {
			t.Fatalf("alias grants=%d", n)
		}
		for i, email := range []any{nil, "unverified@example.com"} {
			c := teamCreationClaims(uuid.New(), uuid.NewString(), fmt.Sprintf("Ineligible team %d", i))
			identity := c["identity"].(map[string]any)
			identity["email"] = email
			identity["email_verified"] = false
			id := teamCreationID(t, client.call(c, nil))
			teamCreationOutcome(t, pool, id, "promotion_ineligible")
		}
		claims[0]["request_id"] = uuid.NewString()
		claims[0]["name"] = "Additional team"
		claims[0]["policy"] = map[string]any{"version": 1, "mode": "additional_team", "session": "passed", "captcha": "not_applicable", "preauth": "not_applicable", "google_onboarding": "not_applicable", "additional_team": "passed"}
		additionalID := teamCreationID(t, client.call(claims[0], nil))
		teamCreationOutcome(t, pool, additionalID, "already_claimed")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, additionalID); n != 0 {
			t.Fatalf("additional team signup grants=%d", n)
		}
	})
	t.Run("revision conflict and changed verification", func(t *testing.T) {
		actor := uuid.New()
		claims := teamCreationClaims(actor, uuid.NewString(), "Evidence team")
		identity := claims["identity"].(map[string]any)
		revision := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
		stamp := revision.Format("2006-01-02T15:04:05.000000Z")
		rolloutExec(t, pool, `SELECT upsert_profile_with_promotion_identity($1,$2,true,$3,clock_timestamp())`, actor, "original@example.com", revision)
		identity["auth_updated_at"] = stamp
		teamCreationStatus(t, client.call(claims, nil), 503, "provisioning_unavailable")
		identity["auth_updated_at"] = revision.Add(-time.Second).Format("2006-01-02T15:04:05.000000Z")
		identity["email"] = "original@example.com"
		teamCreationStatus(t, client.call(claims, nil), 503, "provisioning_unavailable")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, actor); n != 0 {
			t.Fatal("conflicting evidence created result")
		}
		identity["auth_updated_at"] = revision.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
		identity["email_verified"] = false
		teamCreationOutcome(t, pool, teamCreationID(t, client.call(claims, nil)), "promotion_ineligible")
	})
	t.Run("stale observation rolls back new actor", func(t *testing.T) {
		actor := uuid.New()
		claims := teamCreationClaims(actor, uuid.NewString(), "Stale observation")
		identity := claims["identity"].(map[string]any)
		identity["auth_updated_at"] = time.Now().UTC().Add(-7 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
		identity["observed_at"] = time.Now().UTC().Add(-6 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
		teamCreationStatus(t, client.call(claims, nil), 503, "provisioning_unavailable")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM profile WHERE id=$1`, actor); n != 0 {
			t.Fatal("stale observation wrote profile")
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, actor); n != 0 {
			t.Fatal("stale observation persisted result")
		}
	})

	t.Run("join before create", func(t *testing.T) {
		owner := teamCreationClaims(uuid.New(), uuid.NewString(), "Existing team")
		existing := teamCreationID(t, client.call(owner, nil))
		actor := uuid.New()
		rolloutExec(t, pool, `SELECT upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp()-interval '1 minute',clock_timestamp())`, actor, actor.String()+"@example.com")
		rolloutExec(t, pool, `INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'member')`, existing, actor)
		rolloutExec(t, pool, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, existing, actor)
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$1`, actor); n != 0 {
			t.Fatal("joining consumed trial")
		}
		joinedClaims := teamCreationClaims(actor, uuid.NewString(), "Joined actor team")
		joinedClaims["policy"] = map[string]any{
			"version": 1, "mode": "additional_team", "session": "passed",
			"captcha": "not_applicable", "preauth": "not_applicable",
			"google_onboarding": "not_applicable", "additional_team": "passed",
		}
		// Existing-team authorization is not a promotion decision: a joined,
		// never-claimed actor remains eligible for the canonical first grant.
		teamCreationOutcome(t, pool, teamCreationID(t, client.call(joinedClaims, nil)), "granted")
	})
	t.Run("recovery during in-flight creation is read-only", func(t *testing.T) {
		const lockName = "team-creation-inflight-test"
		rolloutExec(t, pool, `CREATE FUNCTION hold_team_creation_request() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('team-creation-inflight-test', 0)); RETURN NEW; END $$`)
		rolloutExec(t, pool, `CREATE TRIGGER hold_team_creation_request BEFORE INSERT ON team_creation_requests FOR EACH ROW EXECUTE FUNCTION hold_team_creation_request()`)
		defer func() {
			rolloutExec(t, pool, `DROP TRIGGER hold_team_creation_request ON team_creation_requests`)
			rolloutExec(t, pool, `DROP FUNCTION hold_team_creation_request()`)
		}()
		hold, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Rollback releases the lock before the earlier trigger-cleanup defer,
		// including when an assertion aborts this subtest.
		defer hold.Rollback(ctx)
		if _, err := hold.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockName); err != nil {
			t.Fatal(err)
		}
		readClient := newTeamCreationClient(t, teamCreationReadOnlyPool(t, pool))
		actor := uuid.New()
		claims := teamCreationClaims(actor, uuid.NewString(), "In-flight creation")
		created := make(chan *httptest.ResponseRecorder, 1)
		finished := make(chan struct{})
		createCtx, cancelCreate := context.WithCancel(ctx)
		defer func() {
			cancelCreate()
			_ = hold.Rollback(ctx)
			<-finished
		}()
		go func() {
			defer close(finished)
			created <- client.call(claims, func(r *http.Request) { *r = *r.WithContext(createCtx) })
		}()
		waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
		defer cancelWait()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var waiting bool
			if err := pool.QueryRow(waitCtx, `SELECT EXISTS (
				SELECT 1 FROM pg_locks held JOIN pg_locks blocked
				ON blocked.locktype=held.locktype AND blocked.database=held.database
				AND blocked.classid=held.classid AND blocked.objid=held.objid AND blocked.objsubid=held.objsubid
				JOIN pg_stat_activity a ON a.pid=blocked.pid
				WHERE held.pid=$1 AND held.locktype='advisory' AND held.granted AND NOT blocked.granted
				AND a.wait_event_type='Lock' AND a.wait_event='advisory'
				AND a.query LIKE 'INSERT INTO team_creation_requests%'
			)`, hold.Conn().PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatalf("observe creation at blocking trigger: %v", err)
			}
			if waiting {
				break
			}
			select {
			case <-finished:
				t.Fatal("creation finished before reaching the blocking trigger")
			case <-waitCtx.Done():
				t.Fatal("creation did not reach the blocking trigger")
			case <-ticker.C:
			}
		}
		teamCreationStatus(t, readClient.call(teamCreationRecover(claims), nil), http.StatusNotFound, "result_not_found")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, actor); n != 0 {
			t.Fatalf("in-flight recovery observed or created a durable result: %d", n)
		}
		if err := hold.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		createdResponse := <-created
		createdSnapshot := teamCreationSnapshot(t, createdResponse)
		recovered := teamCreationSnapshot(t, readClient.call(teamCreationRecover(claims), nil))
		if recovered["id"] != createdSnapshot["id"] || recovered["name"] != createdSnapshot["name"] || recovered["region"] != createdSnapshot["region"] {
			t.Fatalf("post-commit recovery changed result: create=%v recover=%v", createdSnapshot, recovered)
		}
	})
	t.Run("legacy and API creation coexist without duplicate grants", func(t *testing.T) {
		actor := uuid.New()
		revision := time.Now().UTC().Truncate(time.Microsecond)
		claims := teamCreationClaims(actor, uuid.NewString(), "Concurrent API team")
		claims["identity"].(map[string]any)["auth_updated_at"] = revision.Format("2006-01-02T15:04:05.000000Z")
		rolloutExec(t, pool, `SELECT upsert_profile_with_promotion_identity($1,$2,true,$3,$3)`, actor, actor.String()+"@example.com", revision)
		legacyDone := make(chan error, 1)
		var legacyID uuid.UUID
		go func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				legacyDone <- err
				return
			}
			defer tx.Rollback(ctx)
			if err = tx.QueryRow(ctx, `INSERT INTO team(name, home_region) VALUES($1,'use') RETURNING id`, "Legacy concurrent team").Scan(&legacyID); err != nil {
				legacyDone <- err
				return
			}
			if _, err = tx.Exec(ctx, `INSERT INTO team_member(team_id, profile_id, role) VALUES($1,$2,'owner')`, legacyID, actor); err != nil {
				legacyDone <- err
				return
			}
			if _, err = tx.Exec(ctx, `INSERT INTO team_memberships(team_id, user_id, status) VALUES($1,$2,'active')`, legacyID, actor); err != nil {
				legacyDone <- err
				return
			}
			if _, err = tx.Exec(ctx, `INSERT INTO user_role_assignments(user_id, role_id, scope_type, team_id, granted_by)
				SELECT $1, id, 'team', $2, $1 FROM roles WHERE name='team_owner' AND scope_type='team'`, actor, legacyID); err != nil {
				legacyDone <- err
				return
			}
			legacyDone <- tx.Commit(ctx)
		}()
		apiDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { apiDone <- client.call(claims, nil) }()
		if err := <-legacyDone; err != nil {
			t.Fatal(err)
		}
		apiID := teamCreationID(t, <-apiDone)
		if apiID == legacyID {
			t.Fatal("legacy and API unexpectedly reused one team")
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_credit_grant WHERE reason='signup trial credit' AND created_by=$1`, actor); n != 1 {
			t.Fatalf("legacy/API coexistence issued %d grants", n)
		}
	})
	t.Run("registered route rejects before writes", func(t *testing.T) {
		actor := uuid.New()
		for _, tc := range []struct {
			name   string
			change func(map[string]any)
		}{
			{"failed session", func(c map[string]any) {
				c["policy"].(map[string]any)["session"] = "failed"
			}},
			{"failed captcha", func(c map[string]any) {
				c["policy"].(map[string]any)["captcha"] = "failed"
			}},
			{"failed Google onboarding", func(c map[string]any) {
				c["policy"].(map[string]any)["google_onboarding"] = "failed"
			}},
			{"additional mode retains first-team checks", func(c map[string]any) {
				p := c["policy"].(map[string]any)
				p["mode"], p["additional_team"] = "additional_team", "passed"
			}},
			{"additional mode missing authorization", func(c map[string]any) {
				p := c["policy"].(map[string]any)
				p["mode"], p["additional_team"] = "additional_team", "not_applicable"
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				claims := teamCreationClaims(actor, uuid.NewString(), "Rejected policy team")
				tc.change(claims)
				teamCreationStatus(t, client.call(claims, nil), http.StatusForbidden, "policy_not_satisfied")
			})
		}
		claims := teamCreationClaims(actor, uuid.NewString(), "Rejected team")
		for _, tc := range []struct {
			name   string
			mutate func(*http.Request)
			status int
			code   string
		}{
			{"missing internal", func(r *http.Request) { r.Header.Del("Authorization") }, 401, "invalid_assertion"},
			{"invalid internal", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, 401, "invalid_assertion"},
			{"actor only", func(r *http.Request) {
				r.Header.Del("X-Team-Creation-Assertion")
				r.Header.Set("X-Actor-User-Id", actor.String())
			}, 401, "invalid_assertion"},
			{"body substitution", func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 }, 400, "invalid_request"},
			{"large body", func(r *http.Request) { r.ContentLength = 16385 }, 413, "request_too_large"},
			{"large assertion", func(r *http.Request) { r.Header.Set("X-Team-Creation-Assertion", strings.Repeat("x", 8193)) }, 413, "request_too_large"},
		} {
			t.Run(tc.name, func(t *testing.T) { teamCreationStatus(t, client.call(claims, tc.mutate), tc.status, tc.code) })
		}
		claims["region"] = "usw"
		teamCreationStatus(t, client.call(claims, nil), 409, "wrong_region")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM profile WHERE id=$1`, actor); n != 0 {
			t.Fatal("rejection wrote profile")
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_creation_requests WHERE actor_id=$1`, actor); n != 0 {
			t.Fatal("rejection persisted request")
		}
	})
	t.Run("authority unavailable preserves replay", func(t *testing.T) {
		claims := teamCreationClaims(uuid.New(), uuid.NewString(), "Durable result")
		created := client.call(claims, nil)
		teamCreationID(t, created)
		rolloutExec(t, pool, `ALTER FUNCTION upsert_profile_with_promotion_identity(uuid,text,boolean,timestamptz,timestamptz) RENAME TO unavailable_identity_writer`)
		defer rolloutExec(t, pool, `ALTER FUNCTION unavailable_identity_writer(uuid,text,boolean,timestamptz,timestamptz) RENAME TO upsert_profile_with_promotion_identity`)
		for _, c := range []map[string]any{claims, teamCreationRecover(claims)} {
			response := client.call(c, nil)
			teamCreationStatus(t, response, 200, "")
			if response.Body.String() != created.Body.String() {
				t.Fatal("authority outage changed completed result")
			}
		}
		actor := uuid.New()
		teamCreationStatus(t, client.call(teamCreationClaims(actor, uuid.NewString(), "Unavailable creation"), nil), 503, "provisioning_unavailable")
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM profile WHERE id=$1`, actor); n != 0 {
			t.Fatal("unavailable authority wrote profile")
		}
	})
}
