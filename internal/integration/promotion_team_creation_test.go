//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
)

func promotionAssertionSigner(t *testing.T) func(string, uuid.UUID, map[string]any) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(public))
	return func(operation string, user uuid.UUID, extra map[string]any) string {
		t.Helper()
		claims := jwt.MapClaims{"iss": "promotion-auth-adapter", "aud": "promotion-account",
			"sub": user.String(), "iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Minute).Unix(), "operation": operation}
		for k, v := range extra {
			claims[k] = v
		}
		signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
}

func TestIntegration_TrustedTeamPromotionAttempt(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	auth := promotionIsolatedDatabase(t, false)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	t.Setenv("SANDBOX_ID_REGION", "use")
	sign := promotionAssertionSigner(t)
	handlers := &api.Handlers{Pool: region, PromotionAuthPool: auth}
	router := api.SetupRouter(t.Context(), handlers, nil)
	request := func(operation string, user uuid.UUID, body map[string]any, assertion string) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/"+operation, strings.NewReader(string(payload)))
		req.Header.Set("Authorization", "Bearer account-example-token")
		req.Header.Set("X-Actor-User-Id", user.String())
		req.Header.Set("X-Promotion-Account-Assertion", assertion)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	for _, unavailable := range []bool{true, false} {
		t.Run(map[bool]string{true: "registration failure with prior evidence", false: "successful registration"}[unavailable], func(t *testing.T) {
			user, team, attempt := uuid.New(), uuid.New(), uuid.New()
			rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
			evidence := promotionVerifiedSignup(t, auth, user, "visitor-"+uuid.NewString())
			rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, evidence.attempt, evidence.event, evidence.fingerprint)
			if unavailable {
				handlers.PromotionAuthPool = nil
			} else {
				handlers.PromotionAuthPool = auth
			}
			registration := request("register", user, map[string]any{"user_id": user}, sign("register", user, nil))
			wantStatus := http.StatusOK
			if unavailable {
				wantStatus = http.StatusServiceUnavailable
			}
			if registration.Code != wantStatus {
				t.Fatalf("registration: %d %s", registration.Code, registration.Body.String())
			}
			body := map[string]any{"user_id": user, "team_id": team, "attempt_id": attempt, "name": "example-team-" + team.String(), "home_region": "use", "authority_unavailable": unavailable}
			binding := map[string]any{"team_id": team, "attempt_id": attempt, "home_region": "use", "authority_unavailable": unavailable}
			assertion := sign("create-team", user, binding)
			for _, field := range []string{"user_id", "team_id", "attempt_id", "home_region", "authority_unavailable"} {
				original := body[field]
				actor := user
				switch field {
				case "home_region":
					body[field] = "usw"
				case "authority_unavailable":
					body[field] = !unavailable
				default:
					body[field] = uuid.New()
				}
				if field == "user_id" {
					actor = body[field].(uuid.UUID)
				}
				w := request("create-team", actor, body, assertion)
				if w.Code != http.StatusForbidden {
					t.Fatalf("mismatched %s: %d %s", field, w.Code, w.Body.String())
				}
				body[field] = original
			}
			if w := request("create-team", user, body, ""); w.Code != http.StatusForbidden {
				t.Fatalf("unsigned request: %d", w.Code)
			}
			var first string
			for i := 0; i < 2; i++ {
				// Restored registration must not change the pinned no-credit attempt.
				handlers.PromotionAuthPool = auth
				if i == 1 {
					w := request("register", user, map[string]any{"user_id": user}, sign("register", user, nil))
					if w.Code != http.StatusOK {
						t.Fatalf("registration retry: %d %s", w.Code, w.Body.String())
					}
				}
				w := request("create-team", user, body, assertion)
				if w.Code != http.StatusOK {
					t.Fatalf("creation %d: %d %s", i, w.Code, w.Body.String())
				}
				var result struct {
					TeamID  uuid.UUID `json:"team_id"`
					Outcome string    `json:"outcome"`
					Reason  string    `json:"reason"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				want := "granted"
				if unavailable {
					want = "promotion_ineligible"
				}
				if result.TeamID != team || result.Outcome != want || (unavailable && result.Reason != "authority_unavailable") {
					t.Fatalf("result: %+v", result)
				}
				if i == 0 {
					first = w.Body.String()
				} else if first != w.Body.String() {
					t.Fatalf("replay changed: %s / %s", first, w.Body.String())
				}
			}
			// Even a fresh valid assertion cannot change an accepted binding.
			for _, field := range []string{"user_id", "team_id", "attempt_id", "authority_unavailable", "name"} {
				original := body[field]
				actor := user
				wantStatus := http.StatusBadRequest
				if field == "authority_unavailable" {
					body[field] = !unavailable
				} else if field == "name" {
					body[field] = "changed-example-team"
				} else {
					body[field] = uuid.New()
				}
				if field == "user_id" {
					actor = body[field].(uuid.UUID)
				} else if field != "name" {
					binding[field] = body[field]
				}
				if field == "attempt_id" {
					wantStatus = http.StatusConflict
				}
				if w := request("create-team", actor, body, sign("create-team", actor, binding)); w.Code != wantStatus {
					t.Fatalf("changed durable %s: %d %s", field, w.Code, w.Body.String())
				}
				body[field] = original
				if field != "user_id" && field != "name" {
					binding[field] = original
				}
			}
			var credits, devices, claims, consumption, teams int
			err := region.QueryRow(t.Context(), `SELECT
                (SELECT count(*) FROM team_credit_grant WHERE team_id=$1),
                (SELECT count(*) FROM promotion_device_grant WHERE team_id=$1),
                (SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$2),
                (SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$2 AND signup_trial_claimed_at IS NOT NULL),
                (SELECT count(*) FROM team WHERE id=$1)`, team, user).Scan(&credits, &devices, &claims, &consumption, &teams)
			want := 1
			if unavailable {
				want = 0
			}
			if err != nil || teams != 1 || credits != want || devices != want || claims != want || consumption != want {
				t.Fatalf("persisted: teams=%d credits=%d devices=%d claims=%d consumption=%d err=%v", teams, credits, devices, claims, consumption, err)
			}
			var outcome, reason string
			if err := region.QueryRow(t.Context(), `SELECT * FROM claim_team_signup_trial($1,$2)`, team, user).Scan(&outcome, &reason); err != nil || (unavailable && (outcome != "promotion_ineligible" || reason != "authority_unavailable")) {
				t.Fatalf("direct claim replay: %s/%s %v", outcome, reason, err)
			}
			// Deletion must not reopen an accepted attempt or recreate its team.
			rolloutExec(t, region, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
			rolloutExec(t, region, `DELETE FROM team WHERE id=$1`, team)
			rolloutExec(t, region, `DELETE FROM profile WHERE id=$1`, user)
			w := request("create-team", user, body, sign("create-team", user, binding))
			if w.Code != http.StatusOK || w.Body.String() != first {
				t.Fatalf("deleted team replay: %d %s, want %s", w.Code, w.Body.String(), first)
			}
			var retainedAttempts, retainedOwners int
			err = region.QueryRow(t.Context(), `SELECT
                (SELECT count(*) FROM team WHERE id=$1),
                (SELECT count(*) FROM team_credit_grant WHERE team_id=$1),
                (SELECT count(*) FROM team_promotion_creation_attempt WHERE attempt_id=$2),
                (SELECT count(*) FROM promotion_device_owner WHERE user_id=$3)`, team, attempt, user).
				Scan(&teams, &credits, &retainedAttempts, &retainedOwners)
			if err != nil || teams != 0 || credits != 0 || retainedAttempts != 1 || retainedOwners != 1 {
				t.Fatalf("deleted replay state: teams=%d credits=%d attempts=%d owners=%d err=%v", teams, credits, retainedAttempts, retainedOwners, err)
			}
		})
	}
}

func TestIntegration_PromotionPolicyContentionPreservesProvisioning(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit team", true: "legacy owner"}[legacy], func(t *testing.T) {
			user, team := uuid.New(), uuid.New()
			rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
			rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
			if legacy {
				rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "example-team-"+team.String())
				rolloutExec(t, region, `INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'owner')`, team, user)
				rolloutExec(t, region, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, user)
			}
			holder, err := region.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(t.Context())
			rolloutExec(t, holder, `SELECT 1 FROM promotion_device_policy WHERE singleton FOR UPDATE`)
			if legacy {
				rolloutExec(t, region, `INSERT INTO user_role_assignments(team_id,user_id,scope_type,role_id)
                    SELECT $1,$2,'team',id FROM roles WHERE name='team_owner' AND scope_type='team'`, team, user)
			} else if err := region.QueryRow(t.Context(), `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`, "example-team-"+team.String(), user).Scan(&team); err != nil {
				t.Fatalf("contended provisioning: %v", err)
			}
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			var outcome, reason string
			if err := region.QueryRow(t.Context(), `SELECT * FROM claim_team_signup_trial($1,$2)`, team, user).Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "authority_unavailable" {
				t.Fatalf("contended outcome: %s/%s %v", outcome, reason, err)
			}
			var teams, credits, devices, claims, consumption, owners int
			err = region.QueryRow(t.Context(), `SELECT
                (SELECT count(*) FROM team WHERE id=$1),
                (SELECT count(*) FROM team_credit_grant WHERE team_id=$1),
                (SELECT count(*) FROM promotion_device_grant WHERE team_id=$1),
                (SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$2),
                (SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$2 AND signup_trial_claimed_at IS NOT NULL),
                (SELECT count(*) FROM user_role_assignments WHERE team_id=$1 AND user_id=$2)`, team, user).Scan(&teams, &credits, &devices, &claims, &consumption, &owners)
			if err != nil || teams != 1 || credits != 0 || devices != 0 || claims != 0 || consumption != 0 || (legacy && owners != 1) {
				t.Fatalf("provisioning: teams=%d credits=%d devices=%d claims=%d consumption=%d owners=%d err=%v", teams, credits, devices, claims, consumption, owners, err)
			}
		})
	}
}

func TestIntegration_TrustedTeamPromotionAttemptPrivilegesAndGrantFailure(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		var execute, write bool
		err := region.QueryRow(t.Context(), `SELECT
            has_function_privilege($1,'create_team_with_promotion_attempt(uuid,uuid,uuid,text,text,boolean)','EXECUTE'),
            has_table_privilege($1,'team_promotion_creation_attempt','INSERT,UPDATE,DELETE,TRUNCATE')`, role).Scan(&execute, &write)
		if err != nil || execute != (role == "service_role") || write {
			t.Fatalf("%s: execute=%t write=%t err=%v", role, execute, write, err)
		}
	}
	user, team, attempt := uuid.New(), uuid.New(), uuid.New()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	rolloutExec(t, region, `CREATE FUNCTION fail_test_credit_grant() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'test grant contention' USING ERRCODE='55P03'; END $$;
        CREATE TRIGGER fail_test_credit_grant BEFORE INSERT ON team_credit_grant FOR EACH ROW EXECUTE FUNCTION fail_test_credit_grant()`)
	_, err := region.Exec(t.Context(), `SELECT * FROM create_team_with_promotion_attempt($1,$2,$3,$4,'use',false)`, attempt, team, user, "example-team-"+team.String())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || pgErr.Message != "test grant contention" {
		t.Fatalf("expected injected grant contention, got %v", err)
	}
	var attempts, teams int
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team_promotion_creation_attempt WHERE attempt_id=$1),
        (SELECT count(*) FROM team WHERE id=$2)`, attempt, team).Scan(&attempts, &teams); err != nil || attempts != 0 || teams != 0 {
		t.Fatalf("failed grant persisted: attempts=%d teams=%d err=%v", attempts, teams, err)
	}
	rolloutExec(t, region, `DROP TRIGGER fail_test_credit_grant ON team_credit_grant`)
	var resultTeam uuid.UUID
	var outcome, reason string
	if err := region.QueryRow(t.Context(), `SELECT * FROM create_team_with_promotion_attempt($1,$2,$3,$4,'use',false)`, attempt, team, user, "example-team-"+team.String()).Scan(&resultTeam, &outcome, &reason); err != nil || resultTeam != team || outcome != "granted" {
		t.Fatalf("grant retry: %s/%s %v", outcome, reason, err)
	}
}

func TestIntegration_DurableTeamCreationRecovery(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	t.Setenv("INTERNAL_API_TOKEN", "internal-example-token")
	t.Setenv("SANDBOX_ID_REGION", "use")
	sign := promotionAssertionSigner(t)
	user, otherUser := uuid.New(), uuid.New()
	for _, actor := range []uuid.UUID{user, otherUser} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, actor, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	}
	var previousPool *pgxpool.Pool
	t.Cleanup(func() {
		if previousPool != nil {
			previousPool.Close()
		}
	})
	newRouter := func() http.Handler {
		// Discard the previous connection lifetime along with its handlers.
		if previousPool != nil {
			previousPool.Close()
		}
		pool, err := pgxpool.NewWithConfig(t.Context(), region.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		previousPool = pool
		return api.SetupRouter(t.Context(), &api.Handlers{Pool: pool}, nil)
	}
	request := func(router http.Handler, operation string, actor uuid.UUID, body map[string]any, status int) map[string]any {
		t.Helper()
		body["user_id"] = actor
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/"+operation, strings.NewReader(string(payload)))
		req.Header.Set("Authorization", "Bearer account-example-token")
		req.Header.Set("X-Actor-User-Id", actor.String())
		req.Header.Set("X-Promotion-Account-Assertion", sign(operation, actor, body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: %d %s", operation, w.Code, w.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	locator := uuid.New()
	prepare := map[string]any{"operation_id": locator, "name": "example-team", "home_region": "use", "authority_unavailable": true}
	recoverBody := map[string]any{"operation_id": locator, "home_region": "use"}
	request(newRouter(), "recover-team", user, recoverBody, http.StatusNotFound)
	// Discard the preparation response completely; the locator predates dispatch.
	request(newRouter(), "prepare-team", user, prepare, http.StatusOK)
	recovered := request(newRouter(), "recover-team", user, recoverBody, http.StatusOK)
	if recovered["state"] != "prepared" || recovered["authority_unavailable"] != true || recovered["name"] != "example-team" {
		t.Fatalf("recovered: %v", recovered)
	}
	replayed := request(newRouter(), "prepare-team", user, prepare, http.StatusOK)
	if !reflect.DeepEqual(recovered, replayed) {
		t.Fatalf("prepare replay changed: %v / %v", recovered, replayed)
	}
	var teams, credits int
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team WHERE id=$1),
        (SELECT count(*) FROM team_credit_grant WHERE team_id=$1)`, recovered["team_id"]).Scan(&teams, &credits); err != nil || teams != 0 || credits != 0 {
		t.Fatalf("prepare dispatched value: teams=%d credits=%d err=%v", teams, credits, err)
	}
	request(newRouter(), "recover-team", otherUser, recoverBody, http.StatusConflict)
	request(newRouter(), "prepare-team", otherUser, prepare, http.StatusConflict)
	for _, field := range []string{"name", "authority_unavailable"} {
		original := prepare[field]
		if field == "name" {
			prepare[field] = "changed-team"
		} else {
			prepare[field] = false
		}
		request(newRouter(), "prepare-team", user, prepare, http.StatusConflict)
		prepare[field] = original
	}
	recoverBody["home_region"] = "usw"
	request(newRouter(), "recover-team", user, recoverBody, http.StatusForbidden)
	// A correctly signed request at another local region still cannot adopt the row.
	t.Setenv("SANDBOX_ID_REGION", "usw")
	request(newRouter(), "recover-team", user, recoverBody, http.StatusConflict)
	t.Setenv("SANDBOX_ID_REGION", "use")
	recoverBody["home_region"] = "use"
	complete := map[string]any{}
	for _, field := range []string{"operation_id", "attempt_id", "team_id", "name", "home_region", "authority_unavailable"} {
		complete[field] = recovered[field]
	}
	for _, field := range []string{"attempt_id", "team_id", "name", "authority_unavailable"} {
		original := complete[field]
		switch field {
		case "name":
			complete[field] = "changed-team"
		case "authority_unavailable":
			complete[field] = false
		default:
			complete[field] = uuid.New()
		}
		request(newRouter(), "complete-team", user, complete, http.StatusConflict)
		complete[field] = original
	}
	request(newRouter(), "complete-team", otherUser, complete, http.StatusConflict)
	// Previously accepted evidence is present, and publication has recovered.
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,source_attempt_id,source_event_id,fingerprint)
        FROM promotion_signup_device_evidence WHERE user_id=$1`, user)
	request(newRouter(), "complete-team", user, complete, http.StatusOK) // lose committed response
	completed := request(newRouter(), "recover-team", user, recoverBody, http.StatusOK)
	if completed["state"] != "completed" || completed["outcome"] != "promotion_ineligible" || completed["reason"] != "authority_unavailable" {
		t.Fatalf("completed: %v", completed)
	}
	if got := request(newRouter(), "complete-team", user, complete, http.StatusOK); !reflect.DeepEqual(got, completed) {
		t.Fatalf("completion replay: %v", got)
	}
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team WHERE id=$1),
        (SELECT count(*) FROM team_credit_grant WHERE team_id=$1)`, recovered["team_id"]).Scan(&teams, &credits); err != nil || teams != 1 || credits != 0 {
		t.Fatalf("no-credit creation: teams=%d credits=%d err=%v", teams, credits, err)
	}
	// No locator or cookie is needed to discover candidates; selection is explicit.
	list := request(newRouter(), "discover-team-creations", user, map[string]any{"home_region": "use"}, http.StatusOK)
	if list["state"] != "selection_required" || len(list["operations"].([]any)) != 1 || list["operations"].([]any)[0].(map[string]any)["operation_id"] != locator.String() {
		t.Fatalf("discovery: %v", list)
	}
	list = request(newRouter(), "discover-team-creations", otherUser, map[string]any{"home_region": "use"}, http.StatusOK)
	if len(list["operations"].([]any)) != 0 {
		t.Fatalf("cross-actor discovery: %v", list)
	}
	rolloutExec(t, region, `DELETE FROM team WHERE id=$1`, recovered["team_id"])
	rolloutExec(t, region, `DELETE FROM profile WHERE id=$1`, user)
	deleted := request(newRouter(), "complete-team", user, complete, http.StatusOK)
	if deleted["state"] != "deleted" || deleted["outcome"] != completed["outcome"] || deleted["team_id"] != recovered["team_id"] {
		t.Fatalf("deleted replay: %v", deleted)
	}
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team WHERE id=$1),
        (SELECT count(*) FROM team_credit_grant WHERE team_id=$1)`, recovered["team_id"]).Scan(&teams, &credits); err != nil || teams != 0 || credits != 0 {
		t.Fatalf("deletion recreated value: %d/%d %v", teams, credits, err)
	}
}

func TestIntegration_DurableTeamCreationConcurrency(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	user := uuid.New()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	type operation struct {
		OperationID uuid.UUID `json:"operation_id"`
		AttemptID   uuid.UUID `json:"attempt_id"`
		TeamID      uuid.UUID `json:"team_id"`
		State       string    `json:"state"`
		Outcome     string    `json:"outcome"`
	}
	locators := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	results := make([]operation, 9)
	errs := make([]error, len(results))
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var raw []byte
			errs[i] = region.QueryRow(t.Context(), `SELECT prepare_team_promotion_creation($1,$2,'example-team','use',false)`, locators[i%3], user).Scan(&raw)
			if errs[i] == nil {
				errs[i] = json.Unmarshal(raw, &results[i])
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil || results[i].State != "prepared" || results[i].AttemptID == uuid.Nil || results[i].TeamID == uuid.Nil {
			t.Fatalf("prepare %d: %+v %v", i, results[i], err)
		}
		if results[i] != results[i%3] {
			t.Fatalf("duplicate prepare changed: %+v / %+v", results[i], results[i%3])
		}
	}
	if results[0].TeamID == results[1].TeamID || results[1].TeamID == results[2].TeamID || results[0].TeamID == results[2].TeamID {
		t.Fatal("distinct same-name operations coalesced")
	}
	// Concurrent retries for one operation must dispatch value only once.
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op := results[0]
			_, errs[i] = region.Exec(t.Context(), `SELECT complete_team_promotion_creation($1,$2,$3,$4,'example-team','use',false)`, op.OperationID, op.AttemptID, op.TeamID, user)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, op := range results[1:3] {
		_, err := region.Exec(t.Context(), `SELECT complete_team_promotion_creation($1,$2,$3,$4,'example-team','use',false)`, op.OperationID, op.AttemptID, op.TeamID, user)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "team_name_key" {
			t.Fatalf("expected team name conflict: %v", err)
		}
		var raw []byte
		if err := region.QueryRow(t.Context(), `SELECT recover_team_promotion_creation($1,$2,'use')`, op.OperationID, user).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var recovered operation
		if err := json.Unmarshal(raw, &recovered); err != nil || recovered != op {
			t.Fatalf("name conflict changed prepared operation: %+v / %+v %v", recovered, op, err)
		}
		// Free the unique team name without changing the prepared operation's tuple.
		rolloutExec(t, region, `UPDATE team SET name=$2 WHERE id=$1`, results[i].TeamID, "example-team-"+results[i].TeamID.String())
		rolloutExec(t, region, `SELECT complete_team_promotion_creation($1,$2,$3,$4,'example-team','use',false)`, op.OperationID, op.AttemptID, op.TeamID, user)
	}
	var attempts, teams, credits, devices, consumption int
	err := region.QueryRow(t.Context(), `SELECT
        (SELECT count(*) FROM team_promotion_creation_attempt WHERE user_id=$1),
        (SELECT count(*) FROM team WHERE id IN (SELECT team_id FROM team_promotion_creation_attempt WHERE user_id=$1)),
        (SELECT count(*) FROM team_credit_grant WHERE created_by=$1),
        (SELECT count(*) FROM promotion_device_grant WHERE user_id=$1),
        (SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$1 AND signup_trial_claimed_at IS NOT NULL)`, user).
		Scan(&attempts, &teams, &credits, &devices, &consumption)
	if err != nil || attempts != 3 || teams != 3 || credits != 1 || devices != 1 || consumption != 1 {
		t.Fatalf("conservation: %d/%d/%d/%d/%d %v", attempts, teams, credits, devices, consumption, err)
	}
	op := results[0]
	rolloutExec(t, region, `DELETE FROM team_credit_grant WHERE team_id=$1`, op.TeamID)
	rolloutExec(t, region, `DELETE FROM team WHERE id=$1`, op.TeamID)
	var raw []byte
	if err := region.QueryRow(t.Context(), `SELECT complete_team_promotion_creation($1,$2,$3,$4,'example-team','use',false)`, op.OperationID, op.AttemptID, op.TeamID, user).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var deleted operation
	if err := json.Unmarshal(raw, &deleted); err != nil || deleted.State != "deleted" || deleted.Outcome != "granted" {
		t.Fatalf("granted tombstone: %+v %v", deleted, err)
	}
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team WHERE id=$1),
        (SELECT count(*) FROM team_credit_grant WHERE team_id=$1)`, op.TeamID).Scan(&teams, &credits); err != nil || teams != 0 || credits != 0 {
		t.Fatalf("granted replay recreated value: %d/%d %v", teams, credits, err)
	}
}

func TestIntegration_DurableTeamCreationRollbackAndPrivileges(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		for _, function := range []string{
			"prepare_team_promotion_creation(uuid,uuid,text,text,boolean)",
			"recover_team_promotion_creation(uuid,uuid,text)",
			"complete_team_promotion_creation(uuid,uuid,uuid,uuid,text,text,boolean)",
			"discover_team_promotion_creations(uuid,text,uuid)",
		} {
			var execute, tableAccess bool
			err := region.QueryRow(t.Context(), `SELECT has_function_privilege($1,$2,'EXECUTE'),
                has_table_privilege($1,'team_promotion_creation_attempt','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role, function).Scan(&execute, &tableAccess)
			if err != nil || execute != (role == "service_role") || tableAccess {
				t.Fatalf("privileges %s %s: %t/%t %v", role, function, execute, tableAccess, err)
			}
		}
	}
	user, locator := uuid.New(), uuid.New()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
	var raw []byte
	if err := region.QueryRow(t.Context(), `SELECT prepare_team_promotion_creation($1,$2,'example-team','use',false)`, locator, user).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		AttemptID uuid.UUID `json:"attempt_id"`
		TeamID    uuid.UUID `json:"team_id"`
	}
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, region, `CREATE FUNCTION fail_prepared_credit_grant() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'test grant contention' USING ERRCODE='55P03'; END $$;
        CREATE TRIGGER fail_prepared_credit_grant BEFORE INSERT ON team_credit_grant FOR EACH ROW EXECUTE FUNCTION fail_prepared_credit_grant()`)
	_, err := region.Exec(t.Context(), `SELECT complete_team_promotion_creation($1,$2,$3,$4,'example-team','use',false)`, locator, prepared.AttemptID, prepared.TeamID, user)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("expected grant failure: %v", err)
	}
	var attempts, teams int
	if err := region.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team_promotion_creation_attempt WHERE operation_id=$1 AND outcome IS NULL),
        (SELECT count(*) FROM team WHERE id=$2)`, locator, prepared.TeamID).Scan(&attempts, &teams); err != nil || attempts != 1 || teams != 0 {
		t.Fatalf("prepare lost on rollback: %d/%d %v", attempts, teams, err)
	}
	rolloutExec(t, region, `DROP TRIGGER fail_prepared_credit_grant ON team_credit_grant`)
	// An old API process can safely dispatch an already prepared tuple.
	var team uuid.UUID
	var outcome, reason string
	if err := region.QueryRow(t.Context(), `SELECT * FROM create_team_with_promotion_attempt($1,$2,$3,'example-team','use',false)`, prepared.AttemptID, prepared.TeamID, user).Scan(&team, &outcome, &reason); err != nil || team != prepared.TeamID || outcome != "granted" {
		t.Fatalf("legacy dispatch: %s/%s %v", outcome, reason, err)
	}
	if err := region.QueryRow(t.Context(), `SELECT recover_team_promotion_creation($1,$2,'use')->>'outcome'`, locator, user).Scan(&outcome); err != nil || outcome != "granted" {
		t.Fatalf("legacy result recovery: %s %v", outcome, err)
	}
	// Discovery is bounded and cursor-based even if all names are identical.
	rolloutExec(t, region, `SELECT prepare_team_promotion_creation(gen_random_uuid(),$1,'example-team','use',true) FROM generate_series(1,54)`, user)
	seen := map[string]bool{}
	var cursor any
	for page := 0; page < 2; page++ {
		if err := region.QueryRow(t.Context(), `SELECT discover_team_promotion_creations($1,'use',$2)`, user, cursor).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result struct {
			State      string `json:"state"`
			Operations []struct {
				ID string `json:"operation_id"`
			} `json:"operations"`
			Next *string `json:"next_cursor"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		want := 50
		if page == 1 {
			want = 5
		}
		if result.State != "selection_required" || len(result.Operations) != want || (result.Next == nil) != (page == 1) {
			t.Fatalf("page %d: %+v", page, result)
		}
		for _, op := range result.Operations {
			if seen[op.ID] {
				t.Fatalf("duplicate page entry: %s", op.ID)
			}
			seen[op.ID] = true
		}
		if result.Next != nil {
			cursor = *result.Next
		}
	}
	if len(seen) != 55 {
		t.Fatalf("discovered %d operations", len(seen))
	}
}
