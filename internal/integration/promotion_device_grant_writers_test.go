//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
)

func TestIntegration_SignupPromotionEligibilityHTTP(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	owner, other, missing := uuid.New(), uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other, missing} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	}
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	}

	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	router := api.SetupRouter(t.Context(), &api.Handlers{Pool: region}, nil)
	request := func(token, actor, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/promotion/account/signup-eligibility", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("X-Actor-User-Id", actor)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	otherBody := `{"user_id":"` + other.String() + `"}`
	for _, token := range []string{"", "capture-example-token", "wrong-token"} {
		if w := request(token, other.String(), otherBody); w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, body %s", token, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		name, actor, body string
		status            int
	}{
		{"actor mismatch", owner.String(), otherBody, http.StatusForbidden},
		{"actor missing", "", otherBody, http.StatusForbidden},
		{"malformed user", other.String(), `{"user_id":"invalid"}`, http.StatusBadRequest},
		{"unknown field", other.String(), `{"user_id":"` + other.String() + `","fingerprint":"` + fingerprint + `"}`, http.StatusBadRequest},
		{"attempt rejected", other.String(), `{"user_id":"` + other.String() + `","attempt_id":"` + uuid.NewString() + `"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request("account-example-token", tc.actor, tc.body)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if strings.Contains(w.Body.String(), fingerprint) || strings.Contains(w.Body.String(), owner.String()) {
				t.Fatalf("identifier leaked: %s", w.Body.String())
			}
		})
	}
	for _, tc := range []struct {
		user uuid.UUID
		want map[string]string
	}{
		{other, map[string]string{"ownership": "another_owner", "device_decision": "owner_conflict", "eligibility": "ineligible", "reason": "owner_conflict"}},
		{missing, map[string]string{"ownership": "evidence_missing", "device_decision": "evidence_missing", "eligibility": "ineligible", "reason": "evidence_missing"}},
	} {
		w := request("account-example-token", tc.user.String(), `{"user_id":"`+tc.user.String()+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("user %s: status %d: %s", tc.user, w.Code, w.Body.String())
		}
		var got map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("user %s: response %v, want %v: %v", tc.user, got, tc.want, err)
		}
		if strings.Contains(w.Body.String(), fingerprint) || strings.Contains(w.Body.String(), owner.String()) || strings.Contains(w.Body.String(), tc.user.String()) {
			t.Fatalf("identifier leaked: %s", w.Body.String())
		}
	}
	var deviceGrants, creditGrants, claims int
	if err := region.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM promotion_device_grant),
		(SELECT count(*) FROM team_credit_grant),
		(SELECT count(*) FROM user_signup_trial_claim)`).Scan(&deviceGrants, &creditGrants, &claims); err != nil ||
		deviceGrants != 0 || creditGrants != 0 || claims != 0 {
		t.Fatalf("eligibility request issued value: device=%d credit=%d claims=%d: %v",
			deviceGrants, creditGrants, claims, err)
	}
}

func TestIntegration_PromotionDeviceLiveSignupWriterAndSnapshot(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	missing := uuid.New()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, missing, missing.String()+"@example.com")
	var team uuid.UUID
	if err := region.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`,
		"example-no-device-"+uuid.NewString(), missing).Scan(&team); err != nil {
		t.Fatalf("team creation with missing device: %v", err)
	}
	var outcome, reason string
	if err := region.QueryRow(ctx, `SELECT outcome,reason FROM team_signup_promotion_outcome WHERE team_id=$1`, team).
		Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "evidence_missing" {
		t.Fatalf("missing-evidence result = %q/%q: %v", outcome, reason, err)
	}
	var grants, claims int
	if err := region.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM team_credit_grant WHERE team_id=$1),
		(SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$2)`, team, missing).
		Scan(&grants, &claims); err != nil || grants != 0 || claims != 0 {
		t.Fatalf("missing evidence consumed grant or claim: %d/%d: %v", grants, claims, err)
	}
	var ownership, decision, eligibility, snapshotReason string
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, missing).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "evidence_missing" || decision != "evidence_missing" || eligibility != "ineligible" {
		t.Fatalf("missing snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	var state string
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
		team, missing, "evt-"+uuid.NewString()).Scan(&state); err != nil || state != "evidence_missing" {
		t.Fatalf("missing-evidence Stripe reservation = %q: %v", state, err)
	}

	owner, other := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	}
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, other).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "another_owner" || decision != "owner_conflict" || eligibility != "ineligible" {
		t.Fatalf("conflict snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(false,true)`)
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, other).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "another_owner" || decision != "eligible" || eligibility != "unknown" || snapshotReason != "team_checks_pending" {
		t.Fatalf("disabled device check snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant WHERE user_id=$1`, other).
		Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("snapshot issued a grant: %d: %v", grants, err)
	}
	if err := region.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`,
		"example-device-off-"+uuid.NewString(), other).Scan(&team); err != nil {
		t.Fatalf("team creation while device check is off: %v", err)
	}
	if err := region.QueryRow(ctx, `SELECT outcome,reason FROM team_signup_promotion_outcome WHERE team_id=$1`, team).
		Scan(&outcome, &reason); err != nil || outcome != "granted" {
		t.Fatalf("device-off grant = %q/%q: %v", outcome, reason, err)
	}
	rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	event := "evt-" + uuid.NewString()
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
		team, other, event).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("Stripe compatibility reservation = %q: %v", state, err)
	}
	rolloutExec(t, region, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, other, "grant-"+uuid.NewString())
	var stripeGrants int
	if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant
		WHERE promotion='stripe' AND team_id=$1 AND user_id=$2 AND fingerprint=$3`,
		team, other, fingerprint).Scan(&stripeGrants); err != nil || stripeGrants != 1 {
		t.Fatalf("Stripe finalization did not record device grant: %d: %v", stripeGrants, err)
	}
}

func TestIntegration_PromotionDeviceConcurrentGrantWriters(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	users := [2]uuid.UUID{uuid.New(), uuid.New()}
	fingerprint := "visitor-" + uuid.NewString()
	for i, user := range users {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		var registration string
		if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&registration); err != nil {
			t.Fatal(err)
		}
		want := "owner"
		if i == 1 {
			want = "owner_conflict"
		}
		if registration != want {
			t.Fatalf("registration %d = %q, want %q", i, registration, want)
		}
	}

	type result struct {
		state string
		err   error
	}
	race := func(fn func(int) (string, error)) [2]result {
		t.Helper()
		var results [2]result
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range users {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i].state, results[i].err = fn(i)
			}(i)
		}
		close(start)
		wg.Wait()
		return results
	}

	var signupTeams [2]uuid.UUID
	signups := race(func(i int) (string, error) {
		var team uuid.UUID
		err := region.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`,
			"concurrent-signup-"+uuid.NewString(), users[i]).Scan(&team)
		if err != nil {
			return "", err
		}
		signupTeams[i] = team
		var outcome string
		err = region.QueryRow(ctx, `SELECT outcome FROM team_signup_promotion_outcome WHERE team_id=$1`, team).Scan(&outcome)
		return outcome, err
	})
	for i, got := range signups {
		want := "granted"
		if i == 1 {
			want = "promotion_ineligible"
		}
		if got.err != nil || got.state != want {
			t.Fatalf("signup %d = %q, err=%v, want %q", i, got.state, got.err, want)
		}
	}

	var billingTeams [2]uuid.UUID
	var events [2]string
	for i := range users {
		billingTeams[i] = uuid.New()
		events[i] = "evt-" + uuid.NewString()
		rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, billingTeams[i], "concurrent-billing-"+billingTeams[i].String())
		rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, billingTeams[i])
	}
	reservations := race(func(i int) (string, error) {
		var state string
		err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
			billingTeams[i], users[i], events[i]).Scan(&state)
		return state, err
	})
	for i, got := range reservations {
		want := "acquired"
		if i == 1 {
			want = "owner_conflict"
		}
		if got.err != nil || got.state != want {
			t.Fatalf("Stripe reservation %d = %q, err=%v, want %q", i, got.state, got.err, want)
		}
	}

	finalizations := race(func(i int) (string, error) {
		_, err := region.Exec(ctx, `SELECT finalize_stripe_promotion($1,$2,$3)`,
			billingTeams[i], users[i], "grant-"+uuid.NewString())
		return "", err
	})
	if finalizations[0].err != nil || finalizations[1].err == nil {
		t.Fatalf("Stripe finalization errors = [%v, %v], want winner success and loser rejection",
			finalizations[0].err, finalizations[1].err)
	}

	for _, promotion := range []string{"signup", "stripe"} {
		var grants, winnerGrants, loserGrants, creditGrants, winnerConsumption, loserConsumption int
		err := region.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM promotion_device_grant WHERE fingerprint=$1 AND promotion=$2),
			(SELECT count(*) FROM promotion_device_grant WHERE user_id=$3 AND promotion=$2),
			(SELECT count(*) FROM promotion_device_grant WHERE user_id=$4 AND promotion=$2),
			(SELECT count(*) FROM team_credit_grant WHERE team_id=ANY($5::uuid[]) AND reason=$6),
			(SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$3 AND
				CASE WHEN $2='signup' THEN signup_trial_claimed_at IS NOT NULL ELSE stripe_redemption_at IS NOT NULL END),
			(SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$4 AND
				CASE WHEN $2='signup' THEN signup_trial_claimed_at IS NOT NULL OR signup_trial_team_id IS NOT NULL
				ELSE stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL END)`,
			fingerprint, promotion, users[0], users[1],
			[]uuid.UUID{signupTeams[0], signupTeams[1], billingTeams[0], billingTeams[1]},
			map[string]string{"signup": "signup trial credit", "stripe": "stripe promotional credit"}[promotion]).
			Scan(&grants, &winnerGrants, &loserGrants, &creditGrants, &winnerConsumption, &loserConsumption)
		if err != nil || grants != 1 || winnerGrants != 1 || loserGrants != 0 ||
			creditGrants != 1 || winnerConsumption != 1 || loserConsumption != 0 {
			t.Fatalf("%s split or extra grant: device=%d winner=%d loser=%d credit=%d consumption=%d/%d err=%v",
				promotion, grants, winnerGrants, loserGrants, creditGrants, winnerConsumption, loserConsumption, err)
		}
	}
}
