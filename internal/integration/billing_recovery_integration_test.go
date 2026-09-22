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
}

func (f *recoveryStripeFixture) setCancelOnCall(subscriptionID string, call int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelOnCall[subscriptionID] = call
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
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/subscriptions/") {
			subscriptionID := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
			f.subCalls[subscriptionID]++
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
			grant := map[string]any{
				"id":                   "grant_" + strings.TrimPrefix(customer, "cus_"),
				"category":             "promotional",
				"amount":               map[string]any{"monetary": map[string]any{"value": 9500, "currency": "usd"}},
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
	// The subscription changes after the grant POST but before the final
	// post-mutation revalidation. Recovery must report the race and leave local
	// activation uncommitted.
	stripe.setCancelOnCall(postGrantRaceSubscription, 3)

	dryRun := runBillingRecoveryCommand(t, stripe.server.URL, "-team", goodTeam.String())
	if dryRun["outcome"] != "candidate" || dryRun["reason"] != "active_subscription_without_activation_grant" {
		t.Fatalf("dry-run result = %#v, want active candidate", dryRun)
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
	if repeated["outcome"] != "repaired" || goodGrantCalls != 1 {
		t.Fatalf("repeat apply = %#v, grant calls = %v; want one external grant", repeated, goodGrantCalls)
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
	if grantCalls != 1 {
		t.Fatalf("post-grant race made %d grant calls, want one idempotent external attempt", grantCalls)
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
