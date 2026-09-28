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
func teamCreationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
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
	if err := applyMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

type teamCreationClient struct {
	t       *testing.T
	router  *gin.Engine
	private ed25519.PrivateKey
}

func newTeamCreationClient(t *testing.T, pool *pgxpool.Pool) *teamCreationClient {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", "team-creation-test-token")
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	next := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", ed25519.SeedSize)))
	h := &api.Handlers{Pool: pool, Config: &config.Config{TeamCreationRegion: "use", TeamCreationKeys: map[string]ed25519.PublicKey{"test": public, "next": next.Public().(ed25519.PublicKey)}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &teamCreationClient{t: t, router: api.SetupRouter(ctx, h, pool), private: private}
}
func teamCreationClaims(actor uuid.UUID, requestID, name string) map[string]any {
	now := time.Now().UTC()
	stamp := now.Format("2006-01-02T15:04:05.000000Z")
	return map[string]any{
		"v": 1, "iss": "superserve-console", "aud": "superserve-team-creation", "purpose": "team-creation", "sub": actor.String(), "iat": now.Unix(), "exp": now.Unix() + 120,
		"request_id": requestID, "name": name, "region": "use", "authorization": "create",
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
		readConfig := pool.Config().Copy()
		readConfig.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
		readPool, err := pgxpool.NewWithConfig(ctx, readConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer readPool.Close()
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
		for _, table := range []string{"team_member", "team_memberships", "user_role_assignments", "team_creation_requests"} {
			t.Run(table, func(t *testing.T) {
				actor := uuid.New()
				claims := teamCreationClaims(actor, uuid.NewString(), "Rollback "+table)
				rolloutExec(t, pool, `CREATE FUNCTION fail_team_creation_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$`)
				rolloutExec(t, pool, fmt.Sprintf(`CREATE TRIGGER fail_team_creation_write BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION fail_team_creation_write()`, pgx.Identifier{table}.Sanitize()))
				response := client.call(claims, nil)
				rolloutExec(t, pool, fmt.Sprintf(`DROP TRIGGER fail_team_creation_write ON %s`, pgx.Identifier{table}.Sanitize()))
				rolloutExec(t, pool, `DROP FUNCTION fail_team_creation_write()`)
				teamCreationStatus(t, response, 500, "internal_error")
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
			})
		}
	})
	t.Run("canonical aliases and no grant", func(t *testing.T) {
		alias := strings.ReplaceAll(uuid.NewString(), "-", "")
		var claims [2]map[string]any
		for i := range claims {
			claims[i] = teamCreationClaims(uuid.New(), uuid.NewString(), fmt.Sprintf("Alias %d", i))
		}
		claims[0]["identity"].(map[string]any)["email"] = alias + "@gmail.com"
		claims[1]["identity"].(map[string]any)["email"] = alias[:5] + "." + alias[5:] + "+tag@googlemail.com"
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
		teamCreationOutcome(t, pool, teamCreationID(t, client.call(claims[0], nil)), "already_claimed")
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
		teamCreationOutcome(t, pool, teamCreationID(t, client.call(teamCreationClaims(actor, uuid.NewString(), "Joined actor team"), nil)), "granted")
	})
	t.Run("registered route rejects before writes", func(t *testing.T) {
		actor := uuid.New()
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
