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
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
