//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func seedPendingBillingAccount(t *testing.T, teamID uuid.UUID, customerID, subscriptionID string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (
			team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status
		)
		VALUES ($1, $2, $3, 'incomplete')
	`, teamID, customerID, subscriptionID); err != nil {
		t.Fatalf("seed billing account: %v", err)
	}
}

func pausePreviewSandbox(t *testing.T, r *gin.Engine, sandboxID uuid.UUID, apiKey string) {
	t.Helper()
	if response := do(r, http.MethodPost, "/sandboxes/"+sandboxID.String()+"/pause", apiKey, ""); response.Code != http.StatusNoContent {
		t.Fatalf("pause sandbox = %d %s", response.Code, response.Body.String())
	}
}

func TestIntegration_ActivatedBillingAllowsResumeSandbox(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + teamID.String()
	subscriptionID := "sub_" + teamID.String()
	owner := seedActivePreviewHost(t,
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPortBrowserAuth,
	)
	sandboxID := seedPrivatePreviewSandbox(t, teamID, owner, "activated-billing-resume")
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)
	pausePreviewSandbox(t, r, sandboxID, apiKey)
	seedPendingBillingAccount(t, teamID, customerID, subscriptionID)

	createdAt := time.Now().UTC().Truncate(time.Second)
	payload := stripeSubscriptionWebhookPayload(t, "evt_activation_resume", "customer.subscription.updated", subscriptionID, customerID, "active", createdAt, createdAt, createdAt.AddDate(0, 1, 0))
	req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, createdAt))
	if response := doRequest(r, req); response.Code != http.StatusOK {
		t.Fatalf("activation webhook = %d %s", response.Code, response.Body.String())
	}
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("activation Stripe grant calls = %d, want 1", got)
	}
	eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, teamID)
	if err != nil {
		t.Fatalf("check activated billing eligibility: %v", err)
	}
	if !eligible {
		t.Fatal("legitimate activation must make the team billing eligible")
	}
	if response := do(r, http.MethodPost, "/sandboxes/"+sandboxID.String()+"/resume", apiKey, ""); response.Code != http.StatusOK {
		t.Fatalf("billing-eligible resume = %d %s, want 200", response.Code, response.Body.String())
	}
}

func TestIntegration_ActivatedBillingResumeRemainsBlockedByAbuse(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	owner := seedActivePreviewHost(t,
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPortBrowserAuth,
	)
	sandboxID := seedPrivatePreviewSandbox(t, teamID, owner, "abuse-blocked-resume")
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)
	pausePreviewSandbox(t, r, sandboxID, apiKey)
	now := time.Now().UTC()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (
			team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status,
			trial_ended_at, stripe_activation_credit_granted_at, stripe_activation_credit_grant_id
		)
		VALUES ($1, $2, $3, 'active', $4, $4, $5)
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String(), now, "grant_"+teamID.String()); err != nil {
		t.Fatalf("seed activated billing account: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "compute.json")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`{"mode":"enforce","restrictions":[{"subject_type":"team","subject_id":%q,"actions":["resume"]}]}`, teamID)), 0600); err != nil {
		t.Fatal(err)
	}
	source := abuse.NewConfigComputeSource(configPath, nil, nil)
	source.Refresh(ctx)
	restricted := api.NewHandlers(&stubVMD{}, testQueries, &config.Config{
		Port: "0", VMDAddress: "localhost:0", SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID,
	})
	restricted.Pool = testPool
	restricted.ComputeRestrictions = &abuse.ComputeEvaluator{Source: source}
	registerTestHandlers(restricted)
	restrictedRouter := api.SetupRouter(t.Context(), restricted, testPool)
	if response := do(restrictedRouter, http.MethodPost, "/sandboxes/"+sandboxID.String()+"/resume", apiKey, ""); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"abuse_denied"`) {
		t.Fatalf("abuse-restricted resume = %d %s, want independent abuse denial", response.Code, response.Body.String())
	}
	eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, teamID)
	if err != nil {
		t.Fatalf("recheck activated billing eligibility: %v", err)
	}
	if !eligible {
		t.Fatal("abuse enforcement must not revoke legitimate billing eligibility")
	}
}
