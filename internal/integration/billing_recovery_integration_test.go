//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recoveryStripeFixture struct {
	mu           sync.Mutex
	server       *httptest.Server
	subCalls     map[string]int
	grantCalls   map[string]int
	grants       map[string][]map[string]any
	cancelOnCall map[string]int
	checkouts    map[string]map[string]any
	onFirstRead  map[string]func() error
}

func (f *recoveryStripeFixture) setCancelOnCall(subscriptionID string, call int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelOnCall[subscriptionID] = call
}

func (f *recoveryStripeFixture) beforeFirstSubscriptionRead(subscriptionID string, hook func() error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onFirstRead[subscriptionID] = hook
}

func (f *recoveryStripeFixture) setExistingGrant(teamID uuid.UUID, subscriptionID string) {
	f.setExistingGrantAmount(teamID, subscriptionID, 9500)
}

func (f *recoveryStripeFixture) setExistingGrantAmount(teamID uuid.UUID, subscriptionID string, amount int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	customerID := "cus_" + strings.TrimPrefix(subscriptionID, "sub_")
	f.grants[customerID] = []map[string]any{{
		"id":                   "grant_" + teamID.String(),
		"category":             "promotional",
		"amount":               map[string]any{"monetary": map[string]any{"value": amount, "currency": "usd"}},
		"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
		"metadata":             map[string]string{"activation_identity": "stripe-activation-credit-" + teamID.String()},
	}}
}

func (f *recoveryStripeFixture) grantCallCount(customerID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grantCalls[customerID]
}

func (f *recoveryStripeFixture) subscriptionCallCount(subscriptionID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subCalls[subscriptionID]
}

func newRecoveryStripeFixture(t *testing.T) *recoveryStripeFixture {
	t.Helper()
	f := &recoveryStripeFixture{
		subCalls:     make(map[string]int),
		grantCalls:   make(map[string]int),
		grants:       make(map[string][]map[string]any),
		cancelOnCall: make(map[string]int),
		checkouts:    make(map[string]map[string]any),
		onFirstRead:  make(map[string]func() error),
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/checkout/sessions/") {
			_ = json.NewEncoder(w).Encode(f.checkouts[strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/")])
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/subscriptions/") {
			subscriptionID := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
			f.subCalls[subscriptionID]++
			if hook := f.onFirstRead[subscriptionID]; hook != nil && f.subCalls[subscriptionID] == 1 {
				if err := hook(); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			status := "active"
			if cutoff := f.cancelOnCall[subscriptionID]; cutoff > 0 && f.subCalls[subscriptionID] >= cutoff {
				status = "canceled"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": subscriptionID, "customer": "cus_" + strings.TrimPrefix(subscriptionID, "sub_"),
				"status": status, "current_period_start": time.Now().Add(-time.Hour).Unix(),
				"current_period_end": time.Now().Add(30 * 24 * time.Hour).Unix(),
			})
			return
		}
		if r.URL.Path == "/v1/billing/credit_grants" && r.Method == http.MethodGet {
			customer := r.URL.Query().Get("customer")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": f.grants[customer], "has_more": false})
			return
		}
		if r.URL.Path == "/v1/billing/credit_grants" && r.Method == http.MethodPost {
			customer := r.FormValue("customer")
			f.grantCalls[customer]++
			amount, err := strconv.ParseInt(r.FormValue("amount[monetary][value]"), 10, 64)
			if err != nil {
				t.Errorf("invalid grant amount: %v", err)
			}
			grant := map[string]any{
				"id":                   "grant_" + strings.TrimPrefix(customer, "cus_"),
				"category":             "promotional",
				"amount":               map[string]any{"monetary": map[string]any{"value": amount, "currency": "usd"}},
				"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
				"metadata":             map[string]string{"activation_identity": r.FormValue("metadata[activation_identity]")},
			}
			f.grants[customer] = append(f.grants[customer], grant)
			_ = json.NewEncoder(w).Encode(grant)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func seedRecoveryBillingAccount(t *testing.T, subscriptionID string) uuid.UUID {
	t.Helper()
	teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + strings.TrimPrefix(subscriptionID, "sub_")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')
	`, teamID, customerID, subscriptionID); err != nil {
		t.Fatalf("seed recovery billing account: %v", err)
	}
	return teamID
}

func runBillingRecoveryCommand(t *testing.T, stripeBaseURL string, args ...string) map[string]any {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "../..")
	commandArgs := append([]string{"run", "./cmd/billing-recovery", "-stripe-api-base-url", stripeBaseURL}, args...)
	cmd := exec.Command("go", commandArgs...)
	cmd.Dir = root
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://postgres:postgres@localhost:5432/sandbox_test?sslmode=disable"
	}
	env := os.Environ()
	setEnv := func(key, value string) {
		prefix := key + "="
		for i, entry := range env {
			if strings.HasPrefix(entry, prefix) {
				env[i] = prefix + value
				return
			}
		}
		env = append(env, prefix+value)
	}
	setEnv("DATABASE_URL", databaseURL)
	setEnv("STRIPE_SECRET_KEY", "test_secret")
	setEnv("STRIPE_API_VERSION", "2025-06-30")
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("billing-recovery %v: %v\n%s", args, err, output)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output))), &result); err != nil {
		t.Fatalf("decode billing-recovery output %q: %v", output, err)
	}
	return result
}

func TestIntegration_BillingRecoveryDryRunApplyRevalidatesAndExcludes(t *testing.T) {
	ctx := context.Background()
	stripe := newRecoveryStripeFixture(t)
	goodTeam := seedRecoveryBillingAccount(t, "sub_"+uuid.NewString())
	raceTeam := seedRecoveryBillingAccount(t, "sub_"+uuid.NewString())
	postGrantRaceTeam := seedRecoveryBillingAccount(t, "sub_"+uuid.NewString())
	var goodSubscription, raceSubscription string
	if err := testPool.QueryRow(ctx, `SELECT stripe_subscription_id FROM team_billing_account WHERE team_id=$1`, goodTeam).Scan(&goodSubscription); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT stripe_subscription_id FROM team_billing_account WHERE team_id=$1`, raceTeam).Scan(&raceSubscription); err != nil {
		t.Fatal(err)
	}
	var postGrantRaceSubscription string
	if err := testPool.QueryRow(ctx, `SELECT stripe_subscription_id FROM team_billing_account WHERE team_id=$1`, postGrantRaceTeam).Scan(&postGrantRaceSubscription); err != nil {
		t.Fatal(err)
	}
	stripe.setCancelOnCall(raceSubscription, 2)
	// The subscription changes after the locked evidence read but before the
	// final revalidation. Recovery must leave local activation uncommitted.
	stripe.setCancelOnCall(postGrantRaceSubscription, 3)
	stripe.setExistingGrant(goodTeam, goodSubscription)
	stripe.setExistingGrant(raceTeam, raceSubscription)
	stripe.setExistingGrant(postGrantRaceTeam, postGrantRaceSubscription)

	dryRun := runBillingRecoveryCommand(t, stripe.server.URL, "-team", goodTeam.String())
	if dryRun["outcome"] != "candidate" || dryRun["reason"] != "existing_stripe_grant_reconcile" {
		t.Fatalf("dry-run result = %#v, want existing grant candidate", dryRun)
	}
	var beforeGrant *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_grant_id FROM team_billing_account WHERE team_id=$1`, goodTeam).Scan(&beforeGrant); err != nil {
		t.Fatal(err)
	}
	if beforeGrant != nil {
		t.Fatalf("dry-run mutated local grant id to %q", *beforeGrant)
	}

	applied := runBillingRecoveryCommand(t, stripe.server.URL, "-team", goodTeam.String(), "-apply")
	if applied["outcome"] != "repaired" {
		t.Fatalf("apply result = %#v, want repaired", applied)
	}
	var trialEndedAt *time.Time
	var eventAt *time.Time
	var grantID *string
	if err := testPool.QueryRow(ctx, `SELECT trial_ended_at, stripe_subscription_event_at, stripe_activation_credit_grant_id FROM team_billing_account WHERE team_id=$1`, goodTeam).Scan(&trialEndedAt, &eventAt, &grantID); err != nil {
		t.Fatal(err)
	}
	if trialEndedAt == nil || eventAt == nil || grantID == nil {
		t.Fatalf("apply did not persist activation watermark: trial_ended_at=%v event_at=%v grant_id=%q", trialEndedAt, eventAt, derefString(grantID))
	}
	// A delayed older subscription delivery must be acknowledged without
	// regressing the state repaired by the command.
	webhookStripe := &fakeStripeClient{}
	router := newBillingRouter(t, webhookStripe)
	oldCreatedAt := eventAt.Add(-time.Minute)
	oldPayload := stripeSubscriptionWebhookPayload(t, "evt_recovery_watermark_guard", "customer.subscription.updated", goodSubscription, "cus_"+strings.TrimPrefix(goodSubscription, "sub_"), "past_due", oldCreatedAt, oldCreatedAt, oldCreatedAt.AddDate(0, 1, 0))
	request := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(oldPayload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Stripe-Signature", stripeSignature(t, oldPayload, oldCreatedAt))
	if response := doRequest(router, request); response.Code != http.StatusOK {
		t.Fatalf("delayed post-recovery webhook: expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var status string
	if err := testPool.QueryRow(ctx, `SELECT stripe_subscription_status FROM team_billing_account WHERE team_id=$1`, goodTeam).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("delayed webhook regressed repaired status to %q", status)
	}

	repeated := runBillingRecoveryCommand(t, stripe.server.URL, "-team", goodTeam.String(), "-apply")
	goodGrantCalls := stripe.grantCallCount("cus_" + strings.TrimPrefix(goodSubscription, "sub_"))
	if repeated["outcome"] != "repaired" || goodGrantCalls != 0 {
		t.Fatalf("repeat apply = %#v, grant calls = %v; want no external grant creation", repeated, goodGrantCalls)
	}
	goodSubCalls := stripe.subscriptionCallCount(goodSubscription)
	if goodSubCalls < 4 {
		t.Fatalf("subscription lookups = %d, want audit plus apply revalidation on both runs", goodSubCalls)
	}

	race := runBillingRecoveryCommand(t, stripe.server.URL, "-team", raceTeam.String(), "-apply")
	if race["outcome"] != "unresolved" || race["reason"] != "local_activation_failed" {
		t.Fatalf("race revalidation result = %#v, want unresolved local activation", race)
	}
	var raceGrant *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_grant_id FROM team_billing_account WHERE team_id=$1`, raceTeam).Scan(&raceGrant); err != nil {
		t.Fatal(err)
	}
	if raceGrant != nil {
		t.Fatalf("stale revalidation mutated race target grant to %q", *raceGrant)
	}

	postGrantRace := runBillingRecoveryCommand(t, stripe.server.URL, "-team", postGrantRaceTeam.String(), "-apply")
	if postGrantRace["outcome"] != "unresolved" || postGrantRace["reason"] != "local_activation_failed" {
		t.Fatalf("post-grant race result = %#v, want unresolved local activation", postGrantRace)
	}
	var postGrantRaceLocalGrant *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_grant_id FROM team_billing_account WHERE team_id=$1`, postGrantRaceTeam).Scan(&postGrantRaceLocalGrant); err != nil {
		t.Fatal(err)
	}
	if postGrantRaceLocalGrant != nil {
		t.Fatalf("post-grant race mutated local grant to %q", *postGrantRaceLocalGrant)
	}
	grantCalls := stripe.grantCallCount("cus_" + strings.TrimPrefix(postGrantRaceSubscription, "sub_"))
	if grantCalls != 0 {
		t.Fatalf("final revalidation race made %d grant calls, want none", grantCalls)
	}

	beforeExcludedCalls := stripe.subscriptionCallCount(raceSubscription)
	excluded := runBillingRecoveryCommand(t, stripe.server.URL, "-team", raceTeam.String(), "-exclude-team", raceTeam.String())
	if excluded["outcome"] != "skipped" || excluded["reason"] != "operationally_excluded" {
		t.Fatalf("excluded result = %#v, want operational exclusion", excluded)
	}
	if stripe.subscriptionCallCount(raceSubscription) != beforeExcludedCalls {
		t.Fatal("excluded recovery target unexpectedly called Stripe")
	}
}

func TestIntegration_BillingRecoveryCompletedCheckout(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		amount       int
		mismatch     bool
		missingGrant bool
		want         string
	}{
		{"standard", "complete", 9500, false, false, "repaired"},
		{"custom", "complete", 100000, false, false, "repaired"},
		{"open", "open", 9500, false, false, "skipped"},
		{"wrong_owner", "complete", 9500, true, false, "skipped"},
		{"missing_standard_grant", "complete", 9500, false, true, "unresolved"},
		{"missing_custom_grant", "complete", 100000, false, true, "unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			stripe := newRecoveryStripeFixture(t)
			subscription := "sub_" + uuid.NewString()
			customer := "cus_" + strings.TrimPrefix(subscription, "sub_")
			session := "cs_" + uuid.NewString()
			team := seedRecoveryBillingAccount(t, subscription)
			if !tc.missingGrant {
				stripe.setExistingGrantAmount(team, subscription, int64(tc.amount))
			}
			_, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status=NULL,checkout_initializing_at=now(),checkout_anchor_snapshot=now(),checkout_session_id=$2 WHERE team_id=$1`, team, session)
			if err != nil {
				t.Fatal(err)
			}
			owner := team.String()
			if tc.mismatch {
				owner = uuid.NewString()
			}
			stripe.mu.Lock()
			stripe.checkouts[session] = map[string]any{"id": session, "status": tc.status, "customer": customer, "subscription": subscription, "client_reference_id": owner}
			stripe.mu.Unlock()
			args := []string{"-team", team.String(), "-activation-credit-cents", strconv.Itoa(tc.amount)}
			dry := runBillingRecoveryCommand(t, stripe.server.URL, args...)
			if tc.want == "repaired" && dry["outcome"] != "candidate" {
				t.Fatalf("dry-run: %v", dry)
			}
			if tc.missingGrant && (dry["outcome"] != "unresolved" || dry["reason"] != "activation_grant_requires_webhook_reconciliation") {
				t.Fatalf("missing grant dry-run: %v", dry)
			}
			if stripe.grantCallCount(customer) != 0 {
				t.Fatal("dry-run created credit")
			}
			result := runBillingRecoveryCommand(t, stripe.server.URL, append(args, "-apply")...)
			if result["outcome"] != tc.want {
				t.Fatalf("apply=%v, want %s", result, tc.want)
			}
			if tc.missingGrant && result["reason"] != "activation_grant_requires_webhook_reconciliation" {
				t.Fatalf("missing grant apply: %v", result)
			}
			var complete, checkoutCleared, anchorCleared bool
			err = testPool.QueryRow(ctx, `SELECT trial_ended_at IS NOT NULL AND stripe_activation_credit_grant_id IS NOT NULL,checkout_initializing_at IS NULL AND checkout_session_id IS NULL,checkout_anchor_snapshot IS NULL FROM team_billing_account WHERE team_id=$1`, team).Scan(&complete, &checkoutCleared, &anchorCleared)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "repaired" {
				if complete || checkoutCleared || anchorCleared || stripe.grantCallCount(customer) != 0 {
					t.Fatal("unsafe checkout mutated")
				}
				return
			}
			if !complete || !checkoutCleared || !anchorCleared {
				t.Fatal("activation or checkout cleanup missing")
			}
			repeat := runBillingRecoveryCommand(t, stripe.server.URL, append(args, "-apply")...)
			if repeat["outcome"] != "repaired" || stripe.grantCallCount(customer) != 0 {
				t.Fatalf("retry=%v creates=%d", repeat, stripe.grantCallCount(customer))
			}
			stripe.mu.Lock()
			amount := stripe.grants[customer][0]["amount"].(map[string]any)["monetary"].(map[string]any)["value"].(int64)
			stripe.mu.Unlock()
			if amount != int64(tc.amount) {
				t.Fatalf("amount=%d, want %d", amount, tc.amount)
			}
			if tc.amount != 9500 {
				wrong := runBillingRecoveryCommand(t, stripe.server.URL, "-team", team.String(), "-apply")
				if wrong["outcome"] != "unresolved" || stripe.grantCallCount(customer) != 0 {
					t.Fatalf("wrong amount must not issue credit: %v", wrong)
				}
			}
		})
	}
}

func TestIntegration_BillingRecoveryExpiredReservationAndMissingAssociation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "expired_reservation"
		if missing {
			name = "missing_association"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			stripe := newRecoveryStripeFixture(t)
			subscription := "sub_" + uuid.NewString()
			customer := "cus_" + strings.TrimPrefix(subscription, "sub_")
			session := "cs_" + uuid.NewString()
			team := seedRecoveryBillingAccount(t, subscription)
			stripe.setExistingGrant(team, subscription)
			var reservation *time.Time
			status := "expired"
			if missing {
				now := time.Now()
				reservation = &now
				status = "complete"
			}
			_, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=$2,checkout_session_id=$3,stripe_subscription_id=CASE WHEN $4 THEN NULL ELSE stripe_subscription_id END WHERE team_id=$1`, team, reservation, session, missing)
			if err != nil {
				t.Fatal(err)
			}
			stripe.mu.Lock()
			stripe.checkouts[session] = map[string]any{"id": session, "status": status, "customer": customer, "subscription": subscription, "client_reference_id": team.String()}
			stripe.mu.Unlock()
			result := runBillingRecoveryCommand(t, stripe.server.URL, "-team", team.String(), "-apply")
			expected := "repaired"
			if missing {
				expected = "skipped"
			}
			if result["outcome"] != expected {
				t.Fatalf("outcome=%v, want %s", result, expected)
			}
			var retained string
			var activated bool
			var storedSub *string
			err = testPool.QueryRow(ctx, `SELECT checkout_session_id,trial_ended_at IS NOT NULL,stripe_subscription_id FROM team_billing_account WHERE team_id=$1`, team).Scan(&retained, &activated, &storedSub)
			if err != nil {
				t.Fatal(err)
			}
			if retained != session {
				t.Fatal("retained session identity lost")
			}
			if missing {
				if activated || storedSub != nil || stripe.grantCallCount(customer) != 0 {
					t.Fatal("missing association mutated")
				}
			} else if !activated || stripe.grantCallCount(customer) != 0 {
				t.Fatal("existing subscription not recovered")
			}
		})
	}
}

func TestIntegration_BillingRecoveryMissingGrantDoesNotCreateCredit(t *testing.T) {
	stripe := newRecoveryStripeFixture(t)
	subscriptionID := "sub_" + uuid.NewString()
	teamID := seedRecoveryBillingAccount(t, subscriptionID)
	for _, mode := range [][]string{nil, {"-apply"}} {
		args := append([]string{"-team", teamID.String()}, mode...)
		result := runBillingRecoveryCommand(t, stripe.server.URL, args...)
		if result["outcome"] != "unresolved" || result["reason"] != "activation_grant_requires_webhook_reconciliation" {
			t.Fatalf("missing grant result = %#v, want unresolved promotion", result)
		}
	}
	if calls := stripe.grantCallCount("cus_" + strings.TrimPrefix(subscriptionID, "sub_")); calls != 0 {
		t.Fatalf("missing grant made %d creation calls", calls)
	}
	var changed bool
	if err := testPool.QueryRow(t.Context(), `SELECT trial_ended_at IS NOT NULL
		OR stripe_activation_credit_grant_id IS NOT NULL OR stripe_activation_credit_granted_at IS NOT NULL
		FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&changed); err != nil || changed {
		t.Fatalf("missing grant changed local activation: changed=%v err=%v", changed, err)
	}
}

func TestIntegration_BillingRecoveryPreservesUserPromotionState(t *testing.T) {
	for _, state := range []string{"pending", "pending_without_team_actor", "redeemed_without_team_actor", "checkout_actor", "deleted_checkout_actor", "completed_checkout_actor"} {
		t.Run(state, func(t *testing.T) {
			ctx := t.Context()
			stripe := newRecoveryStripeFixture(t)
			subscriptionID := "sub_" + uuid.NewString()
			teamID := seedRecoveryBillingAccount(t, subscriptionID)
			var userID uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT user_id FROM team_memberships WHERE team_id=$1 LIMIT 1`, teamID).Scan(&userID); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "checkout_actor", "deleted_checkout_actor", "completed_checkout_actor":
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET
					stripe_checkout_actor_id=CASE WHEN $3 THEN $2::uuid ELSE NULL END,
					stripe_checkout_actor_claimed_at=now() WHERE team_id=$1`, teamID, userID, state != "deleted_checkout_actor"); err != nil {
					t.Fatal(err)
				}
				if _, err := testPool.Exec(ctx, `INSERT INTO user_promotion_entitlement(user_id) VALUES($1) ON CONFLICT DO NOTHING`, userID); err != nil {
					t.Fatal(err)
				}
				if state == "completed_checkout_actor" {
					sessionID := "cs_" + uuid.NewString()
					if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=now(),
						checkout_anchor_snapshot=now(),checkout_session_id=$2 WHERE team_id=$1`, teamID, sessionID); err != nil {
						t.Fatal(err)
					}
					stripe.mu.Lock()
					stripe.checkouts[sessionID] = map[string]any{"id": sessionID, "status": "complete",
						"customer":     "cus_" + strings.TrimPrefix(subscriptionID, "sub_"),
						"subscription": subscriptionID, "client_reference_id": teamID.String()}
					stripe.mu.Unlock()
				}
			case "redeemed_without_team_actor":
				if _, err := testPool.Exec(ctx, `INSERT INTO user_promotion_entitlement
					(user_id,stripe_redemption_at,stripe_redemption_team_id) VALUES($1,now(),$2)
					ON CONFLICT(user_id) DO UPDATE SET stripe_redemption_at=now(),stripe_redemption_team_id=$2`, userID, teamID); err != nil {
					t.Fatal(err)
				}
			default:
				var reserved bool
				if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event($1,$2,$3)`, teamID, userID, "evt_recovery_"+teamID.String()).Scan(&reserved); err != nil || !reserved {
					t.Fatalf("reserve promotion: reserved=%v err=%v", reserved, err)
				}
				if _, err := testPool.Exec(ctx, `UPDATE user_promotion_entitlement SET stripe_redemption_attempted_at=now() WHERE user_id=$1`, userID); err != nil {
					t.Fatal(err)
				}
				if state == "pending_without_team_actor" {
					if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_activation_user_id=NULL,
						stripe_activation_credit_reserved_at=NULL,stripe_activation_credit_reservation_event_id=NULL
						WHERE team_id=$1`, teamID); err != nil {
						t.Fatal(err)
					}
				}
			}
			stripe.setExistingGrant(teamID, subscriptionID)
			var beforeTeam, beforeUser string
			readState := func(team, user *string) {
				t.Helper()
				if err := testPool.QueryRow(ctx, `SELECT row_to_json(a)::text,row_to_json(u)::text
					FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=$2
					WHERE a.team_id=$1`, teamID, userID).Scan(team, user); err != nil {
					t.Fatal(err)
				}
			}
			readState(&beforeTeam, &beforeUser)
			result := runBillingRecoveryCommand(t, stripe.server.URL, "-team", teamID.String(), "-apply")
			if result["outcome"] != "unresolved" || result["reason"] != "user_promotion_requires_webhook_reconciliation" {
				t.Fatalf("user promotion result = %#v, want unresolved user promotion", result)
			}
			var afterTeam, afterUser string
			readState(&afterTeam, &afterUser)
			if afterTeam != beforeTeam || afterUser != beforeUser {
				t.Fatalf("recovery mutated user promotion state: team changed=%v user changed=%v", afterTeam != beforeTeam, afterUser != beforeUser)
			}
			if calls := stripe.grantCallCount("cus_" + strings.TrimPrefix(subscriptionID, "sub_")); calls != 0 {
				t.Fatalf("user promotion recovery made %d grant creation calls", calls)
			}
		})
	}
}

func TestIntegration_BillingRecoveryRechecksPromotionAfterAudit(t *testing.T) {
	ctx := t.Context()
	stripe := newRecoveryStripeFixture(t)
	subscriptionID := "sub_" + uuid.NewString()
	teamID := seedRecoveryBillingAccount(t, subscriptionID)
	stripe.setExistingGrant(teamID, subscriptionID)
	stripe.beforeFirstSubscriptionRead(subscriptionID, func() error {
		_, err := testPool.Exec(ctx, `SELECT reserve_stripe_promotion_for_event($1,user_id,$2)
			FROM team_memberships WHERE team_id=$1`, teamID, "evt_racing_"+teamID.String())
		return err
	})
	result := runBillingRecoveryCommand(t, stripe.server.URL, "-team", teamID.String(), "-apply")
	if result["outcome"] != "unresolved" || result["reason"] != "local_activation_failed" {
		t.Fatalf("racing promotion result = %#v, want unresolved local activation", result)
	}
	var pending, changed bool
	if err := testPool.QueryRow(ctx, `SELECT
		a.stripe_activation_user_id IS NOT NULL AND a.stripe_activation_credit_reserved_at IS NOT NULL
		AND u.stripe_redemption_reserved_team_id=$1,
		a.trial_ended_at IS NOT NULL OR a.stripe_activation_credit_grant_id IS NOT NULL
		OR a.stripe_activation_credit_granted_at IS NOT NULL OR u.stripe_redemption_at IS NOT NULL
		FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=a.stripe_activation_user_id
		WHERE a.team_id=$1`, teamID).Scan(&pending, &changed); err != nil || !pending || changed {
		t.Fatalf("racing promotion fence: pending=%v changed=%v err=%v", pending, changed, err)
	}
	if calls := stripe.grantCallCount("cus_" + strings.TrimPrefix(subscriptionID, "sub_")); calls != 0 {
		t.Fatalf("racing promotion made %d grant creation calls", calls)
	}
}
