//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const testStripeWebhookSecret = "whsec_test_secret"
const testStripeMeterErrorWebhookSecret = "whsec_test_meter_error_secret"

type fakeStripeClient struct {
	mu                        sync.Mutex
	reportCalls               []api.StripeReportMeterEventParams
	checkoutCalls             []api.StripeCreateCheckoutSessionParams
	portalCalls               []api.StripeCreateCustomerPortalSessionParams
	customerCalls             []api.StripeCreateCustomerParams
	creditGrantCalls          []api.StripeCreateBillingCreditGrantParams
	creditGrantErr            error
	creditGrantErrAt          int
	creditGrantAmbiguousErr   error
	creditGrantAmbiguousErrAt int
	creditGrantExternalIDs    map[string]string
	creditGrantExternalCalls  int
	creditBalance             api.StripeCreditBalance
	creditBalanceErr          error
	reportErr                 error
	reportErrAt               int
	checkoutErr               error
	nextCustomerID            string
	nextCheckoutURL           string
	nextPortalURL             string
}

func (f *fakeStripeClient) GetCustomerCreditBalance(_ context.Context, _ string) (api.StripeCreditBalance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creditBalanceErr != nil {
		return api.StripeCreditBalance{}, f.creditBalanceErr
	}
	return f.creditBalance, nil
}

type thinEventStripeClient struct {
	*fakeStripeClient
	retrieved         json.RawMessage
	retrieveCalls     int
	retrieveErrOnCall int
	retrieveErr       error
}

type summaryStripeClient struct {
	*fakeStripeClient
	countedUsage func(string, string, time.Time, time.Time) (string, error)
}

func (f *summaryStripeClient) CountedMeterUsage(_ context.Context, eventName, customer string, start, end time.Time) (string, error) {
	return f.countedUsage(eventName, customer, start, end)
}

func (f *thinEventStripeClient) RetrieveEvent(context.Context, string) (json.RawMessage, error) {
	f.retrieveCalls++
	if f.retrieveErrOnCall > 0 && f.retrieveCalls >= f.retrieveErrOnCall {
		if f.retrieveErr != nil {
			return nil, f.retrieveErr
		}
		return nil, errors.New("Stripe event retrieval failed")
	}
	return f.retrieved, nil
}

func (f *fakeStripeClient) CreateCustomer(_ context.Context, params api.StripeCreateCustomerParams) (api.StripeCustomer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.customerCalls = append(f.customerCalls, params)
	id := f.nextCustomerID
	if id == "" {
		id = "cus_test_default"
	}
	return api.StripeCustomer{ID: id}, nil
}

func (f *fakeStripeClient) CreateBillingCreditGrant(_ context.Context, params api.StripeCreateBillingCreditGrantParams) (api.StripeBillingCreditGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creditGrantCalls = append(f.creditGrantCalls, params)
	if f.creditGrantAmbiguousErr != nil && len(f.creditGrantCalls) == f.creditGrantAmbiguousErrAt {
		return api.StripeBillingCreditGrant{}, f.creditGrantAmbiguousErr
	}
	return api.StripeBillingCreditGrant{ID: "credgrant_test_123"}, nil
}

func (f *fakeStripeClient) RevokeActivationCredit(_ context.Context, _ uuid.UUID, _ string, grantID string) (string, error) {
	if grantID == "" {
		grantID = "credgrant_test_123"
	}
	return grantID, nil
}

func (f *fakeStripeClient) CreateCheckoutSession(_ context.Context, params api.StripeCreateCheckoutSessionParams) (api.StripeCheckoutSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkoutCalls = append(f.checkoutCalls, params)
	if f.checkoutErr != nil {
		return api.StripeCheckoutSession{}, f.checkoutErr
	}
	url := f.nextCheckoutURL
	if url == "" {
		url = "https://checkout.stripe.test/session"
	}
	return api.StripeCheckoutSession{ID: "cs_test_123", URL: url}, nil
}

func (f *fakeStripeClient) CreateCustomerPortalSession(_ context.Context, params api.StripeCreateCustomerPortalSessionParams) (api.StripePortalSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.portalCalls = append(f.portalCalls, params)
	url := f.nextPortalURL
	if url == "" {
		url = "https://billing.stripe.test/portal"
	}
	return api.StripePortalSession{URL: url}, nil
}

func (f *fakeStripeClient) ReportMeterEvent(_ context.Context, params api.StripeReportMeterEventParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reportCalls = append(f.reportCalls, params)
	if f.reportErr != nil && (f.reportErrAt == 0 || len(f.reportCalls) == f.reportErrAt) {
		return f.reportErr
	}
	return nil
}

func newBillingRouter(t *testing.T, stripe api.StripeBillingClient) *gin.Engine {
	t.Helper()
	return newBillingRouterWithPool(t, stripe, testPool)
}

func newBillingRouterWithPool(t *testing.T, stripe api.StripeBillingClient, pool *pgxpool.Pool, resources ...config.BillingResourceConfig) *gin.Engine {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	cfg := &config.Config{
		BillingResources:              resources,
		Port:                          "0",
		VMDAddress:                    "localhost:0",
		SystemTeamID:                  testSystemTeamID.String(),
		StripeWebhookSecret:           testStripeWebhookSecret,
		StripeMeterErrorWebhookSecret: testStripeMeterErrorWebhookSecret,
		StripeAPIVersion:              "2025-06-30",
		StripeCheckoutPriceIDs:        []string{"price_cpu", "price_memory", "price_storage"},
		AppAllowedOrigins:             []string{"https://app.superserve.test"},
	}
	h := api.NewHandlers(&stubVMD{}, db.New(pool), cfg)
	h.Pool = pool
	h.Stripe = stripe
	return api.SetupRouter(t.Context(), h, pool)
}

func seedBillingPeriodForStripe(t *testing.T, approved bool, exportEnabled bool) (uuid.UUID, string, time.Time, time.Time) {
	t.Helper()
	ctx := context.Background()
	teamID, _, _ := seedTeamAndKeyWithRole(t, "viewer")
	periodStart := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	status := "validating"
	if approved {
		status = "approved"
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export default row: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team_feature_flag
		SET enabled = $2
		WHERE team_id = $1
		  AND key = 'billing_export_enabled'
	`, teamID, exportEnabled); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage (
			team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 7200, 7372800, 3686400)
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed billing usage: %v", err)
	}
	sandboxID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id)
		VALUES ($1, $2, 'stripe-billing-fixture', 'deleted', 1, 1024, 'default')
	`, sandboxID, teamID); err != nil {
		t.Fatalf("seed billing sandbox: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 1, 1024, $3, $4, 'deleted')
	`, sandboxID, teamID, periodStart, periodStart.Add(2*time.Hour)); err != nil {
		t.Fatalf("seed billing compute interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (
			sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 1024, $3, $4, 'deleted')
	`, sandboxID, teamID, periodStart, periodStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed billing storage interval: %v", err)
	}
	if _, err := testQueries.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Status:      status,
	}); err != nil {
		t.Fatalf("seed billing period: %v", err)
	}
	if exportEnabled {
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
			VALUES ($1, $2, $3, 'active')
		`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
			t.Fatalf("seed billing account: %v", err)
		}
	}
	return teamID, apiPeriodID(periodStart, periodEnd), periodStart, periodEnd
}

func apiPeriodID(start, end time.Time) string {
	return start.Format(time.RFC3339) + "," + end.Format(time.RFC3339)
}

// TestIntegration_GetBillingSummaryStripeCredits exercises the Stripe-authoritative
// branch with aggregate balances that differ from any local audit grant.
func TestIntegration_GetBillingSummaryStripeCredits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stripe float64
		local  float64
	}{
		{name: "zero", stripe: 0, local: 95},
		{name: "partial", stripe: 20.5, local: 95},
		{name: "full", stripe: 95, local: 1},
		{name: "multiple grants aggregate", stripe: 145, local: 95},
		{name: "large grant", stripe: 12000, local: 95},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
			viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
			if _, err := testPool.Exec(ctx, `
				INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason)
				VALUES ($1, $2, $2, 'audit-only local fixture')`, teamID, tc.local); err != nil {
				t.Fatalf("seed local audit credit: %v", err)
			}
			stripe := &fakeStripeClient{creditBalance: api.StripeCreditBalance{AvailableUSD: tc.stripe, ObservedAt: time.Now().UTC(), IncludesCurrentPeriodUsage: false}}
			w := do(newBillingRouter(t, stripe), "GET", "/billing/summary", viewerKey, "")
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			body := mustJSON(t, w)
			if body["credit_source"] != "stripe" || body["credit_status"] != "available" {
				t.Fatalf("credit state = %v/%v, want stripe/available", body["credit_source"], body["credit_status"])
			}
			if got := body["stripe_credit_balance_usd"].(float64); math.Abs(got-tc.stripe) > 1e-9 {
				t.Fatalf("stripe balance = %v, want %v", got, tc.stripe)
			}
			charges := body["current_charges_usd"].(float64)
			wantApplied := math.Min(math.Max(charges, 0), math.Max(tc.stripe, 0))
			wantRemaining := math.Max(tc.stripe-wantApplied, 0)
			if got := body["stripe_credits_applied_usd"].(float64); math.Abs(got-wantApplied) > 1e-9 {
				t.Fatalf("stripe applied = %v, want %v", got, wantApplied)
			}
			if got := body["stripe_remaining_credit_usd"].(float64); math.Abs(got-wantRemaining) > 1e-9 {
				t.Fatalf("stripe remaining = %v, want %v", got, wantRemaining)
			}
			if _, ok := body["credits_remaining_usd"]; ok && body["credits_remaining_usd"] != nil {
				t.Fatalf("post-activation local estimate should remain unavailable: %v", body["credits_remaining_usd"])
			}
		})
	}
}

func TestIntegration_GetBillingSummaryStripeCreditReaderFailureDegrades(t *testing.T) {
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	stripe := &fakeStripeClient{creditBalanceErr: errors.New("credit balance unavailable")}
	w := do(newBillingRouter(t, stripe), "GET", "/billing/summary", viewerKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := mustJSON(t, w)
	if body["current_charges_usd"] == nil {
		t.Fatal("expected non-Stripe charges when Stripe credit read fails")
	}
	for _, field := range []string{"stripe_credit_balance_usd", "credits_applied_usd", "credits_remaining_usd", "expected_invoice_amount_usd"} {
		if value, ok := body[field]; ok && value != nil {
			t.Fatalf("%s = %v, want null when Stripe credit is unavailable", field, value)
		}
	}
	if body["credit_status"] != "unavailable" {
		t.Fatalf("credit_status = %v, want unavailable", body["credit_status"])
	}
}

func TestIntegration_GetBillingSummaryStripeCreditAlreadyReflectsCurrentPeriod(t *testing.T) {
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	stripe := &fakeStripeClient{creditBalance: api.StripeCreditBalance{AvailableUSD: 20, ObservedAt: time.Now().UTC(), IncludesCurrentPeriodUsage: true}}
	w := do(newBillingRouter(t, stripe), "GET", "/billing/summary", viewerKey, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := mustJSON(t, w)
	if body["stripe_credit_balance_usd"] != float64(20) {
		t.Fatalf("stripe balance = %v, want 20", body["stripe_credit_balance_usd"])
	}
	if got := body["stripe_credits_applied_usd"].(float64); got != 0 {
		t.Fatalf("stripe applied = %v, want 0", got)
	}
	if got := body["stripe_remaining_credit_usd"].(float64); got != 20 {
		t.Fatalf("stripe remaining = %v, want 20", got)
	}
	// Stripe's available balance already reflects current-period usage; do not
	// subtract it again in a local payable estimate.
	for _, field := range []string{"credits_applied_usd", "credits_remaining_usd", "expected_invoice_amount_usd"} {
		if value, ok := body[field]; ok && value != nil {
			t.Fatalf("%s = %v, want null for Stripe-authoritative accounting", field, value)
		}
	}
}

func stripeSignature(t *testing.T, payload []byte, ts time.Time, secret ...string) string {
	t.Helper()
	signingSecret := testStripeWebhookSecret
	if len(secret) > 0 {
		signingSecret = secret[0]
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(fmt.Sprintf("%d.", ts.Unix())))
	mac.Write(payload)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func stripeSubscriptionWebhookPayload(t *testing.T, eventID, eventType, subscriptionID, customerID, status string, created, periodStart, periodEnd time.Time) []byte {
	return stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, eventType, subscriptionID, customerID, status, created, periodStart, periodEnd, nil)
}

func stripeSubscriptionWebhookPayloadWithMetadata(t *testing.T, eventID, eventType, subscriptionID, customerID, status string, created, periodStart, periodEnd time.Time, metadata map[string]string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":      eventID,
		"type":    eventType,
		"created": created.Unix(),
		"data": map[string]any{
			"object": map[string]any{
				"id":       subscriptionID,
				"customer": customerID,
				"status":   status,
				"metadata": metadata,
				"items": map[string]any{
					"data": []map[string]any{
						{
							"current_period_start": periodStart.Unix(),
							"current_period_end":   periodEnd.Unix(),
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal subscription webhook payload: %v", err)
	}
	return payload
}

func stripeCheckoutWebhookPayload(t *testing.T, eventID, clientReferenceID, customerID, subscriptionID string, created time.Time) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":      eventID,
		"type":    "checkout.session.completed",
		"created": created.Unix(),
		"data": map[string]any{
			"object": map[string]any{
				"id":                  "cs_" + eventID,
				"customer":            customerID,
				"subscription":        subscriptionID,
				"client_reference_id": clientReferenceID,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal checkout webhook payload: %v", err)
	}
	return payload
}

func stripeInvoiceWebhookPayload(t *testing.T, eventID, eventType, customerID, subscriptionID, status string, created time.Time) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":      eventID,
		"type":    eventType,
		"created": created.Unix(),
		"data": map[string]any{
			"object": map[string]any{
				"id":           "in_" + eventID,
				"customer":     customerID,
				"subscription": subscriptionID,
				"status":       status,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal invoice webhook payload: %v", err)
	}
	return payload
}

func sendStripeActivationWebhook(t *testing.T, r *gin.Engine, eventID string, teamID, userID uuid.UUID, created time.Time) *httptest.ResponseRecorder {
	t.Helper()
	periodStart := created
	periodEnd := created.AddDate(0, 1, 0)
	customerID := "cus_" + teamID.String()
	payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, "customer.subscription.updated", "sub_"+teamID.String(), customerID, "active", created, periodStart, periodEnd, map[string]string{
		"activation_user_id": userID.String(),
	})
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, created))
	return doRequest(r, req)
}

func doRequest(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func exportAttemptCount(t *testing.T, teamID uuid.UUID, status string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM billing_usage_export
		WHERE team_id = $1
		  AND status = $2
	`, teamID, status).Scan(&n); err != nil {
		t.Fatalf("count billing export attempts: %v", err)
	}
	return n
}

func billingUsageExportRowCount(t *testing.T, teamID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM billing_usage_export
		WHERE team_id = $1
	`, teamID).Scan(&n); err != nil {
		t.Fatalf("count billing usage export rows: %v", err)
	}
	return n
}

func teamBillingAccountRowCount(t *testing.T, teamID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM team_billing_account
		WHERE team_id = $1
	`, teamID).Scan(&n); err != nil {
		t.Fatalf("count billing account rows: %v", err)
	}
	return n
}

func billingPeriodStatus(t *testing.T, teamID uuid.UUID, periodStart, periodEnd time.Time) string {
	t.Helper()
	var status string
	if err := testPool.QueryRow(context.Background(), `
		SELECT status
		FROM team_billing_period
		WHERE team_id = $1 AND period_start = $2 AND period_end = $3
	`, teamID, periodStart, periodEnd).Scan(&status); err != nil {
		t.Fatalf("read billing period status: %v", err)
	}
	return status
}

func billingPeriodRowCount(t *testing.T, teamID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM team_billing_period
		WHERE team_id = $1
	`, teamID).Scan(&n); err != nil {
		t.Fatalf("count billing period rows: %v", err)
	}
	return n
}

func teamCreditGrantRowCount(t *testing.T, teamID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM team_credit_grant
		WHERE team_id = $1
	`, teamID).Scan(&n); err != nil {
		t.Fatalf("count credit grant rows: %v", err)
	}
	return n
}

func teamBillingUsageExportedAtValid(t *testing.T, teamID uuid.UUID, periodStart, periodEnd time.Time) bool {
	t.Helper()
	var exportedAt pgtype.Timestamptz
	if err := testPool.QueryRow(context.Background(), `
		SELECT exported_at
		FROM team_billing_usage
		WHERE team_id = $1 AND period_start = $2 AND period_end = $3
	`, teamID, periodStart, periodEnd).Scan(&exportedAt); err != nil {
		t.Fatalf("read team billing usage exported_at: %v", err)
	}
	return exportedAt.Valid
}

func TestIntegration_ShadowBillingSkipsStripeCalls(t *testing.T) {
	teamID, periodID, _, _ := seedBillingPeriodForStripe(t, true, false)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)

	w := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("shadow export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.reportCalls); got != 0 {
		t.Fatalf("stripe report calls = %d, want 0 in shadow mode", got)
	}
	if got := exportAttemptCount(t, teamID, "skipped_shadow"); got != 2 {
		t.Fatalf("skipped shadow attempts = %d, want 2", got)
	}

	replay := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if replay.Code != http.StatusOK {
		t.Fatalf("shadow export replay: expected 200, got %d: %s", replay.Code, replay.Body.String())
	}
	if got := exportAttemptCount(t, teamID, "skipped_shadow"); got != 2 {
		t.Fatalf("shadow replay changed skipped shadow attempts to %d, want still 2", got)
	}
}

func TestIntegration_LiveBillingSendsStripeEventsAndIsIdempotent(t *testing.T) {
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	const (
		wantCPUHours     = 1.0
		wantMemoryHours  = 1.0
		wantStorageHours = 1.0
	)
	result, err := testPool.Exec(context.Background(), `
		UPDATE sandbox_compute_billing_interval
		SET ended_at = $2
		WHERE team_id = $1
	`, teamID, periodStart.Add(time.Hour))
	if err != nil {
		t.Fatalf("update compute billing interval: %v", err)
	}
	if rows := result.RowsAffected(); rows != 1 {
		t.Fatalf("updated compute billing intervals = %d, want 1", rows)
	}
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_storage_billing_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable storage billing: %v", err)
	}

	previewResp := do(r, "GET", "/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export-preview", viewerKey, "")
	if previewResp.Code != http.StatusOK {
		t.Fatalf("export preview: expected 200, got %d: %s", previewResp.Code, previewResp.Body.String())
	}
	var preview struct {
		Items []struct {
			EventName string  `json:"stripe_event_name"`
			Value     float64 `json:"value"`
		} `json:"items"`
	}
	if err := json.Unmarshal(previewResp.Body.Bytes(), &preview); err != nil {
		t.Fatalf("decode export preview: %v", err)
	}
	if got := len(preview.Items); got != 3 {
		t.Fatalf("preview item count = %d, want 3", got)
	}
	wantPreview := map[string]float64{}
	for _, item := range preview.Items {
		wantPreview[item.EventName] = item.Value
	}
	if got := len(wantPreview); got != 3 {
		t.Fatalf("preview item count = %d, want 3", got)
	}
	for eventName, wantValue := range map[string]float64{
		"cpu_vcpu_hours":    wantCPUHours,
		"memory_gib_hours":  wantMemoryHours,
		"storage_gib_hours": wantStorageHours,
	} {
		if got, ok := wantPreview[eventName]; !ok || math.Abs(got-wantValue) > 1e-9 {
			t.Fatalf("preview %s quantity = %v, want %v", eventName, got, wantValue)
		}
	}

	first := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if first.Code != http.StatusOK {
		t.Fatalf("live export: expected 200, got %d: %s", first.Code, first.Body.String())
	}
	if got := len(stripe.reportCalls); got != 3 {
		t.Fatalf("first export stripe calls = %d, want 3", got)
	}
	stripeEventCounts := map[string]int{}
	for i, call := range stripe.reportCalls {
		stripeEventCounts[call.EventName]++
		if got := len(call.Identifier); got > 100 {
			t.Fatalf("stripe identifier %d length = %d, want <= 100", i, got)
		}
		wantValue, ok := wantPreview[call.EventName]
		if !ok {
			t.Fatalf("unexpected stripe event name %q", call.EventName)
		}
		gotValue, err := strconv.ParseFloat(call.Value, 64)
		if err != nil {
			t.Fatalf("parse stripe call %d quantity %q: %v", i, call.Value, err)
		}
		if call.Value != "1.000000000000" {
			t.Fatalf("stripe call %d serialized quantity = %q, want 1.000000000000", i, call.Value)
		}
		if math.Abs(gotValue-wantValue) > 1e-6 {
			t.Fatalf("stripe call %d quantity = %v, want %v from preview", i, gotValue, wantValue)
		}
		wantTimestamp := periodEnd.UTC().Add(-time.Second).Unix()
		if call.Timestamp != wantTimestamp {
			t.Fatalf("stripe call %d timestamp = %d, want %d", i, call.Timestamp, wantTimestamp)
		}
	}
	for eventName := range wantPreview {
		if got := stripeEventCounts[eventName]; got != 1 {
			t.Fatalf("stripe %s event count = %d, want 1", eventName, got)
		}
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after export = %q, want exported", got)
	}
	if !teamBillingUsageExportedAtValid(t, teamID, periodStart, periodEnd) {
		t.Fatal("team billing usage was not marked exported after live export")
	}

	second := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if second.Code != http.StatusOK {
		t.Fatalf("idempotent export replay: expected 200, got %d: %s", second.Code, second.Body.String())
	}
	if got := len(stripe.reportCalls); got != 3 {
		t.Fatalf("second export changed stripe call count to %d, want still 3", got)
	}
}

func TestIntegration_CreateStripeCheckoutSessionUsesConfiguredPrice(t *testing.T) {
	teamID, apiKey, userID := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	stripe := &fakeStripeClient{
		nextCustomerID:  "cus_" + teamID.String(),
		nextCheckoutURL: "https://checkout.stripe.test/session",
	}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/checkout-session", apiKey, `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("checkout session: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.customerCalls); got != 1 {
		t.Fatalf("customer calls = %d, want 1", got)
	}
	if got := stripe.customerCalls[0].IdempotencyKey; got == "" {
		t.Fatal("customer creation idempotency key was not set")
	}
	if got := len(stripe.checkoutCalls); got != 1 {
		t.Fatalf("checkout calls = %d, want 1", got)
	}
	if got := stripe.checkoutCalls[0].PriceIDs; len(got) != 2 || got[0] != "price_cpu" || got[1] != "price_memory" {
		t.Fatalf("checkout price IDs = %v, want configured metered prices", got)
	}
	if got := stripe.checkoutCalls[0].ClientReferenceID; got != teamID.String() {
		t.Fatalf("client reference id = %q, want team id %q", got, teamID.String())
	}
	if got := stripe.checkoutCalls[0].Metadata["activation_user_id"]; got != userID.String() {
		t.Fatalf("activation user metadata = %q, want authenticated user %q", got, userID)
	}
	if got := stripe.checkoutCalls[0].IdempotencyKey; got == "" {
		t.Fatal("checkout idempotency key was not set")
	}
}

func TestIntegration_StripeCheckoutRetryKeepsSuccessfulActivationActor(t *testing.T) {
	teamID, firstKey, firstUserID := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	stripe := &fakeStripeClient{
		nextCustomerID:  "cus_" + teamID.String(),
		nextCheckoutURL: "https://checkout.stripe.test/session",
	}
	r := newBillingRouter(t, stripe)
	body := `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`
	if w := do(r, "POST", "/stripe/checkout-session", firstKey, body); w.Code != http.StatusOK {
		t.Fatalf("first checkout session: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(r, "POST", "/stripe/checkout-session", secondKey, body); w.Code != http.StatusConflict {
		t.Fatalf("retry checkout session: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if len(stripe.checkoutCalls) != 1 {
		t.Fatalf("checkout calls = %d, want 1", len(stripe.checkoutCalls))
	}
	if stripe.checkoutCalls[0].Metadata["activation_user_id"] != firstUserID.String() {
		t.Fatalf("first checkout actor metadata = %q, want %q", stripe.checkoutCalls[0].Metadata["activation_user_id"], firstUserID)
	}
	created := time.Now().UTC()
	payload := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_retry_activation", "customer.subscription.updated", "sub_"+teamID.String(), stripe.nextCustomerID, "active", created, created, created.AddDate(0, 1, 0), stripe.checkoutCalls[0].Metadata)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, created))
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("activation webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var redeemedUser uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		SELECT stripe_activation_user_id
		FROM team_billing_account
		WHERE team_id = $1
	`, teamID).Scan(&redeemedUser); err != nil {
		t.Fatalf("load activation actor: %v", err)
	}
	if redeemedUser != firstUserID {
		t.Fatalf("activation actor = %s, want successful checkout actor %s", redeemedUser, firstUserID)
	}
}

func TestIntegration_FailedCheckoutDoesNotRecordActivationUser(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	stripe := &fakeStripeClient{
		nextCustomerID: "cus_" + teamID.String(),
		checkoutErr:    errors.New("checkout unavailable"),
	}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/checkout-session", apiKey, `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("failed checkout: expected 502, got %d: %s", w.Code, w.Body.String())
	}
	var activationUser *uuid.UUID
	if err := testPool.QueryRow(context.Background(), `
		SELECT stripe_activation_user_id
		FROM team_billing_account
		WHERE team_id = $1
	`, teamID).Scan(&activationUser); err != nil {
		t.Fatalf("load activation user after failed checkout: %v", err)
	}
	if activationUser != nil {
		t.Fatalf("failed checkout recorded activation user %s", activationUser)
	}
}

func TestIntegration_StripeActivationEndsTrialAndGrantsPromoCreditOnce(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + teamID.String()
	subscriptionID := "sub_" + teamID.String()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'incomplete')
	`, teamID, customerID, subscriptionID); err != nil {
		t.Fatalf("seed incomplete billing account: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason)
		VALUES ($1, 5.000000, 5.000000, 'signup trial credit')
	`, teamID); err != nil {
		t.Fatalf("seed signup trial credit: %v", err)
	}

	created := time.Now().UTC().Truncate(time.Second)
	periodStart := created
	periodEnd := created.AddDate(0, 1, 0)
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)
	for i, eventID := range []string{"evt_trial_activation", "evt_trial_activation_replay"} {
		eventCreated := created.Add(time.Duration(i) * time.Second)
		payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, "customer.subscription.updated", subscriptionID, customerID, "active", eventCreated, periodStart, periodEnd, map[string]string{
			"activation_user_id": userID.String(),
		})
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, eventCreated))
		w := doRequest(r, req)
		if w.Code != http.StatusOK {
			t.Fatalf("activation webhook %s: expected 200, got %d: %s", eventID, w.Code, w.Body.String())
		}
	}

	var trialRemaining float64
	if err := testPool.QueryRow(ctx, `
		SELECT remaining_usd
		FROM team_credit_grant
		WHERE team_id = $1 AND reason = 'signup trial credit'
	`, teamID).Scan(&trialRemaining); err != nil {
		t.Fatalf("load trial credit after activation: %v", err)
	}
	if trialRemaining != 0 {
		t.Fatalf("trial credit remaining = %v, want 0", trialRemaining)
	}
	var promoCount int
	if err := testPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM team_credit_grant
		WHERE team_id = $1 AND reason = 'stripe promotional credit' AND amount_usd = 95
	`, teamID).Scan(&promoCount); err != nil {
		t.Fatalf("count promotional grants: %v", err)
	}
	if promoCount != 0 {
		t.Fatalf("local promotional grant count = %d, want 0", promoCount)
	}
	var trialEndedAt, promoGrantedAt *time.Time
	var stripeGrantID *string
	if err := testPool.QueryRow(ctx, `
		SELECT trial_ended_at, stripe_activation_credit_granted_at, stripe_activation_credit_grant_id
		FROM team_billing_account WHERE team_id = $1
	`, teamID).Scan(&trialEndedAt, &promoGrantedAt, &stripeGrantID); err != nil {
		t.Fatalf("load billing transition state: %v", err)
	}
	if trialEndedAt == nil || promoGrantedAt == nil || stripeGrantID == nil || *stripeGrantID != "credgrant_test_123" {
		t.Fatal("billing activation state was not persisted")
	}
	var creatorRedemptions int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM user_promotion_entitlement
		WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL AND stripe_redemption_team_id = $2
	`, userID, teamID).Scan(&creatorRedemptions); err != nil {
		t.Fatalf("count creator-user redemptions: %v", err)
	}
	if creatorRedemptions != 1 {
		t.Fatalf("creator-user redemptions = %d, want 1", creatorRedemptions)
	}
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("Stripe credit grant calls = %d, want 1", got)
	}
	if got := stripe.creditGrantCalls[0].AmountCents; got != 9500 {
		t.Fatalf("Stripe credit grant amount = %d, want 9500 cents", got)
	}
}

func TestIntegration_StripeSubscriptionCreatedAfterCheckoutExpiration(t *testing.T) {
	created := time.Now().UTC().Truncate(time.Second)
	expiredGeneration := created.Add(-time.Hour)
	for _, tc := range []struct {
		name, generation    string
		ignored             bool
		reservationBlocked  bool
		replacementCheckout bool
		unsavedSession      bool
	}{
		{name: "matching generation", generation: expiredGeneration.Format(time.RFC3339Nano), ignored: true},
		{name: "different generation", generation: created.Format(time.RFC3339Nano), reservationBlocked: true},
		{name: "missing generation"},
		{name: "malformed generation", generation: "invalid", reservationBlocked: true},
		{name: "replacement checkout matching generation", generation: expiredGeneration.Format(time.RFC3339Nano), ignored: true, replacementCheckout: true},
		{name: "initializing replacement matching generation", generation: expiredGeneration.Format(time.RFC3339Nano), ignored: true, replacementCheckout: true, unsavedSession: true},
		{name: "replacement checkout different generation", generation: created.Format(time.RFC3339Nano), replacementCheckout: true},
		{name: "replacement checkout missing generation", replacementCheckout: true},
		{name: "replacement checkout malformed generation", generation: "invalid", replacementCheckout: true},
	} {
		for _, status := range []string{"active", "paused"} {
			t.Run(tc.name+"/"+status, func(t *testing.T) {
				ctx := context.Background()
				teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
				customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
				if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id)
					VALUES ($1, $2)`, teamID, customerID); err != nil {
					t.Fatal(err)
				}
				if err := testQueries.RecordStripeCheckoutExpiration(ctx, db.RecordStripeCheckoutExpirationParams{
					TeamID: teamID, StripeCustomerID: customerID,
					CheckoutGeneration: expiredGeneration, CheckoutSessionID: "cs_" + teamID.String(),
				}); err != nil {
					t.Fatal(err)
				}
				if tc.replacementCheckout {
					var sessionID *string
					if !tc.unsavedSession {
						savedSessionID := "cs_replacement_" + teamID.String()
						sessionID = &savedSessionID
					}
					if _, err := testPool.Exec(ctx, `UPDATE team_billing_account
						SET checkout_initializing_at = $2, checkout_session_id = $3, stripe_checkout_actor_id = $4
						WHERE team_id = $1`, teamID, created, sessionID, userID); err != nil {
						t.Fatal(err)
					}
				}
				beforeAccount, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				metadata := map[string]string{"activation_user_id": userID.String()}
				if tc.generation != "" {
					metadata["checkout_generation"] = tc.generation
				}
				eventID := "evt_" + uuid.NewString()
				payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, "customer.subscription.created",
					subscriptionID, customerID, status, created, created, created.AddDate(0, 1, 0), metadata)
				if tc.replacementCheckout {
					if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event (event_id, event_type, payload, last_error)
						VALUES ($1, 'customer.subscription.created', $2, $3)`, eventID, payload, db.StripeCheckoutAssociationPendingError); err != nil {
						t.Fatal(err)
					}
				}
				stripe := &fakeStripeClient{}
				router := newBillingRouter(t, stripe)
				// A supplied generation needs its captured checkout identity to
				// reserve credit; unrelated expiration does not bypass that fence.
				blocked := tc.reservationBlocked && status == "active"
				pending := tc.replacementCheckout && !tc.ignored
				wantStatus := http.StatusOK
				if blocked || pending {
					wantStatus = http.StatusInternalServerError
				}
				for delivery := 0; delivery < 2; delivery++ {
					req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
					if response := doRequest(router, req); response.Code != wantStatus {
						t.Fatalf("delivery %d: status=%d body=%s", delivery, response.Code, response.Body.String())
					}
				}
				event, err := testQueries.GetStripeWebhookEvent(ctx, eventID)
				if err != nil {
					t.Fatal(err)
				}
				if pending {
					if event.ProcessedAt.Valid || derefString(event.LastError) != db.StripeCheckoutAssociationPendingError {
						t.Fatalf("association-pending event: %+v", event)
					}
				} else if blocked {
					if event.ProcessedAt.Valid || derefString(event.LastError) != "Stripe promotion reservation is contended; retry webhook" {
						t.Fatalf("reservation-blocked event: %+v", event)
					}
				} else if !event.ProcessedAt.Valid || event.LastError != nil {
					t.Fatalf("processed event: %+v", event)
				}
				account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				if tc.replacementCheckout && !reflect.DeepEqual(account, beforeAccount) {
					t.Fatalf("redelivery changed replacement checkout: before=%+v after=%+v", beforeAccount, account)
				}
				if tc.ignored || blocked || pending {
					if account.StripeSubscriptionID != nil || account.StripeSubscriptionEventAt.Valid {
						t.Fatalf("ignored or blocked subscription changed billing state: %+v", account)
					}
				} else if derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != status || !account.StripeSubscriptionEventAt.Valid {
					t.Fatalf("unrelated expiration suppressed subscription: %+v", account)
				}
				wantGrants := 0
				if !tc.ignored && !blocked && !pending && status == "active" {
					wantGrants = 1
				}
				if len(stripe.creditGrantCalls) != wantGrants || account.StripeActivationCreditGrantedAt.Valid != (wantGrants == 1) {
					t.Fatalf("activation: grants=%d granted_at=%v, want %d grants", len(stripe.creditGrantCalls), account.StripeActivationCreditGrantedAt, wantGrants)
				}
			})
		}
	}
}

func TestIntegration_StripePromotionReservationTimeoutRetriesWebhook(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + teamID.String()
	subscriptionID := "sub_" + teamID.String()
	eventID := "evt_reservation_retry_" + teamID.String()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'incomplete')
	`, teamID, customerID, subscriptionID); err != nil {
		t.Fatalf("seed billing account: %v", err)
	}
	created := time.Now().UTC().Truncate(time.Second)
	payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, "customer.subscription.updated",
		subscriptionID, customerID, "active", created, created, created.AddDate(0, 1, 0),
		map[string]string{"activation_user_id": userID.String()})
	stripe := &fakeStripeClient{creditGrantAmbiguousErr: errors.New("Stripe response lost after grant creation"), creditGrantAmbiguousErrAt: 1}
	router := newBillingRouter(t, stripe)
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, created))
		return doRequest(router, req)
	}
	if w := send(); w.Code != http.StatusInternalServerError {
		t.Fatalf("ambiguous grant response: expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var attemptedAt, reservedAt *time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT u.stripe_redemption_attempted_at, a.stripe_activation_credit_reserved_at
		FROM user_promotion_entitlement u JOIN team_billing_account a ON a.team_id = $1
		WHERE u.user_id = $2`, teamID, userID).Scan(&attemptedAt, &reservedAt); err != nil || attemptedAt == nil || reservedAt == nil {
		t.Fatalf("ambiguous grant lost reservation: attempted_at=%v reserved_at=%v err=%v", attemptedAt, reservedAt, err)
	}

	lockConn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('stripe-promo-user:' || $1::text)::bigint)`, userID); err != nil {
		t.Fatalf("lock promotion user: %v", err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('stripe-promo-user:' || $1::text)::bigint)`, userID)
		}
	}()

	if w := send(); w.Code != http.StatusInternalServerError {
		t.Fatalf("contended replay: expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var processedAt *time.Time
	if err := testPool.QueryRow(ctx, `SELECT processed_at FROM stripe_webhook_event WHERE event_id=$1`, eventID).Scan(&processedAt); err != nil || processedAt != nil {
		t.Fatalf("contended event processed: processed_at=%v err=%v", processedAt, err)
	}
	if len(stripe.creditGrantCalls) != 1 {
		t.Fatal("contended reservation reached Stripe")
	}
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext('stripe-promo-user:' || $1::text)::bigint)`, userID); err != nil {
		t.Fatalf("unlock promotion user: %v", err)
	}
	locked = false
	if w := send(); w.Code != http.StatusOK {
		t.Fatalf("reservation replay: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(stripe.creditGrantCalls) != 2 || stripe.creditGrantCalls[0].IdempotencyKey != stripe.creditGrantCalls[1].IdempotencyKey {
		t.Fatalf("Stripe grant replay did not reuse the original idempotency key: calls=%v", stripe.creditGrantCalls)
	}
	var grantID *string
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_credit_grant_id FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&grantID); err != nil || grantID == nil || *grantID != "credgrant_test_123" {
		t.Fatalf("replayed grant was not finalized: grant_id=%v err=%v", grantID, err)
	}
}

func removeCanonicalPromotionAuthority(t *testing.T) func() error {
	t.Helper()
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible`); err != nil {
		t.Fatal(err)
	}
	var canonicalEnabled bool
	var enabledAt *time.Time
	var readinessReference *string
	if err := tx.QueryRow(ctx, `
		DELETE FROM promotion_identity_enforcement WHERE singleton
		RETURNING enabled, enabled_at, readiness_reference
	`).Scan(&canonicalEnabled, &enabledAt, &readinessReference); err != nil {
		t.Fatalf("remove canonical promotion authority: %v", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	authorityRestored := false
	restoreAuthority := func() error {
		_, err := testPool.Exec(context.Background(), `
			INSERT INTO promotion_identity_enforcement (singleton, enabled, enabled_at, readiness_reference)
			VALUES (true, $1, $2, $3)
		`, canonicalEnabled, enabledAt, readinessReference)
		if err == nil {
			authorityRestored = true
		}
		return err
	}
	t.Cleanup(func() {
		if authorityRestored {
			return
		}
		if err := restoreAuthority(); err != nil {
			t.Errorf("restore canonical promotion authority: %v", err)
		}
	})
	return restoreAuthority
}

func TestIntegration_StripeSettledPromotionAuthorityFailureAllowsPaidResume(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'incomplete')
	`, teamID, customerID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	created := time.Now().UTC().Truncate(time.Second)
	response := sendStripeActivationWebhook(t, router, "evt_settled_"+uuid.NewString(), teamID, userID, created)
	if response.Code != http.StatusOK {
		t.Fatalf("initial activation: got %d: %s", response.Code, response.Body.String())
	}
	before, err := testQueries.GetTeamBillingAccountByStripeCustomerID(ctx, &customerID)
	if err != nil || before.StripeActivationCreditGrantID == nil || !before.StripeActivationCreditGrantedAt.Valid ||
		before.StripeActivationCreditReservedAt.Valid || len(stripe.creditGrantCalls) != 1 {
		t.Fatalf("initial promotion did not settle: account=%+v Stripe=%d err=%v", before, len(stripe.creditGrantCalls), err)
	}
	beforeGrants := teamCreditGrantRowCount(t, teamID)
	removeCanonicalPromotionAuthority(t)

	for i, transition := range []struct{ eventType, status string }{
		{"customer.subscription.paused", "paused"},
		{"customer.subscription.resumed", "active"},
	} {
		eventID := "evt_settled_transition_" + uuid.NewString()
		eventAt := created.Add(time.Duration(i+1) * time.Second)
		payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, transition.eventType,
			subscriptionID, customerID, transition.status, eventAt, created, created.AddDate(0, 1, 0),
			map[string]string{"activation_user_id": userID.String()})
		for replay := 0; replay < 2; replay++ {
			req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Stripe-Signature", stripeSignature(t, payload, eventAt))
			response = doRequest(router, req)
			if response.Code != http.StatusOK {
				t.Fatalf("%s replay=%d: got %d: %s", transition.eventType, replay, response.Code, response.Body.String())
			}
		}
		var processed bool
		if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id=$1`, eventID).Scan(&processed); err != nil || !processed {
			t.Fatalf("transition not processed: processed=%v err=%v", processed, err)
		}
		after, err := testQueries.GetTeamBillingAccountByStripeCustomerID(ctx, &customerID)
		if err != nil {
			t.Fatal(err)
		}
		if after.StripeSubscriptionStatus == nil || *after.StripeSubscriptionStatus != transition.status || !after.TrialEndedAt.Valid {
			t.Fatalf("paid transition not applied: status=%v trial_ended_at=%v", after.StripeSubscriptionStatus, after.TrialEndedAt)
		}
		if !reflect.DeepEqual(after.StripeActivationCreditGrantID, before.StripeActivationCreditGrantID) ||
			after.StripeActivationCreditGrantedAt != before.StripeActivationCreditGrantedAt ||
			after.StripeActivationCreditReservedAt.Valid || after.StripeActivationUserID != before.StripeActivationUserID ||
			teamCreditGrantRowCount(t, teamID) != beforeGrants || len(stripe.creditGrantCalls) != 1 {
			t.Fatal("paid transition changed the settled promotion or issued another grant")
		}
	}
	var redeemed, pending bool
	if err := testPool.QueryRow(ctx, `
		SELECT stripe_redemption_at IS NOT NULL AND stripe_redemption_team_id=$2,
			stripe_redemption_reserved_team_id IS NOT NULL OR stripe_redemption_attempted_at IS NOT NULL
		FROM user_promotion_entitlement WHERE user_id=$1
	`, userID, teamID).Scan(&redeemed, &pending); err != nil || !redeemed || pending {
		t.Fatalf("settled entitlement changed: redeemed=%v pending=%v err=%v", redeemed, pending, err)
	}
}

func TestIntegration_StripePromotionAuthorityFailureAllowsPaidActivation(t *testing.T) {
	testStripePromotionAuthorityFailureAllowsPaidActivation(t, false, false, false)
}

func TestIntegration_StripePromotionAuthorityFailureWithReservationAllowsPaidActivation(t *testing.T) {
	testStripePromotionAuthorityFailureAllowsPaidActivation(t, true, false, false)
}

func TestIntegration_StripePromotionAuthorityFailurePreservesAttemptedReservation(t *testing.T) {
	testStripePromotionAuthorityFailureAllowsPaidActivation(t, true, true, false)
}

func TestIntegration_StripePromotionAuthorityFailurePreservesOwningEvent(t *testing.T) {
	testStripePromotionAuthorityFailureAllowsPaidActivation(t, true, false, true)
}

func testStripePromotionAuthorityFailureAllowsPaidActivation(t *testing.T, reserved, attempted, owningEvent bool) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	eventID := "evt_authority_unavailable_" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'incomplete')
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	if reserved {
		identity := "legacy:" + userID.String()
		if _, err := testPool.Exec(ctx, `
			INSERT INTO promotion_identity(identity_key, stripe_reserved_team_id, stripe_reserved_user_id)
			VALUES($1, $2, $3)
			ON CONFLICT (identity_key) DO UPDATE SET
				stripe_reserved_team_id=EXCLUDED.stripe_reserved_team_id,
				stripe_reserved_user_id=EXCLUDED.stripe_reserved_user_id
		`, identity, teamID, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `
			INSERT INTO user_promotion_entitlement(user_id, stripe_redemption_reserved_team_id, stripe_redemption_reserved_at)
			VALUES($1, $2, now())
			ON CONFLICT (user_id) DO UPDATE SET
				stripe_redemption_reserved_team_id=EXCLUDED.stripe_redemption_reserved_team_id,
				stripe_redemption_reserved_at=EXCLUDED.stripe_redemption_reserved_at
		`, userID, teamID); err != nil {
			t.Fatal(err)
		}
		if attempted {
			if _, err := testPool.Exec(ctx, `
				UPDATE user_promotion_entitlement SET stripe_redemption_attempted_at=now() WHERE user_id=$1
			`, userID); err != nil {
				t.Fatal(err)
			}
		}
		reservationEventID := "evt_prior_reservation"
		if owningEvent {
			reservationEventID = eventID
		}
		if _, err := testPool.Exec(ctx, `
			UPDATE team_billing_account
			SET stripe_activation_user_id=$2, stripe_activation_identity_key=$3,
				stripe_activation_identity_evidence_version=capture_promotion_identity_evidence($2),
				stripe_activation_credit_reserved_at=now(), stripe_activation_credit_reservation_event_id=$4
			WHERE team_id=$1
		`, teamID, userID, identity, reservationEventID); err != nil {
			t.Fatal(err)
		}
	}
	restoreAuthority := removeCanonicalPromotionAuthority(t)

	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	created := time.Now().UTC().Truncate(time.Second)
	response := sendStripeActivationWebhook(t, router, eventID, teamID, userID, created)
	if attempted || owningEvent {
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("reserved promotion webhook: expected 500, got %d: %s", response.Code, response.Body.String())
		}
		var processedAt, reservedAt *time.Time
		var reservationEvent *string
		if err := testPool.QueryRow(ctx, `
			SELECT e.processed_at, a.stripe_activation_credit_reserved_at, a.stripe_activation_credit_reservation_event_id
			FROM stripe_webhook_event e JOIN team_billing_account a ON a.team_id=$2 WHERE e.event_id=$1
		`, eventID, teamID).Scan(&processedAt, &reservedAt, &reservationEvent); err != nil || processedAt != nil || reservedAt == nil {
			t.Fatalf("reserved promotion event state: processed_at=%v reserved_at=%v err=%v", processedAt, reservedAt, err)
		}
		if len(stripe.creditGrantCalls) != 0 {
			t.Fatal("reserved promotion was issued without authority")
		}
		if owningEvent {
			if reservationEvent == nil || *reservationEvent != eventID {
				t.Fatalf("owning reservation changed: %v", reservationEvent)
			}
			if err := restoreAuthority(); err != nil {
				t.Fatalf("restore canonical promotion authority: %v", err)
			}
			response = sendStripeActivationWebhook(t, router, eventID, teamID, userID, created)
			if response.Code != http.StatusOK {
				t.Fatalf("owning event recovery: expected 200, got %d: %s", response.Code, response.Body.String())
			}
			var grantID *string
			if err := testPool.QueryRow(ctx, `
				SELECT e.processed_at, a.stripe_activation_credit_grant_id
				FROM stripe_webhook_event e JOIN team_billing_account a ON a.team_id=$2 WHERE e.event_id=$1
			`, eventID, teamID).Scan(&processedAt, &grantID); err != nil || processedAt == nil || grantID == nil || len(stripe.creditGrantCalls) != 1 {
				t.Fatalf("owning event did not settle after recovery: processed_at=%v grant_id=%v Stripe=%d err=%v", processedAt, grantID, len(stripe.creditGrantCalls), err)
			}
			var historyReconciled bool
			if err := testPool.QueryRow(ctx, `
				SELECT EXISTS(SELECT 1 FROM promotion_identity_history
					WHERE team_id=$1 AND user_id=$2 AND promotion='stripe' AND status='reconciled')
			`, teamID, userID).Scan(&historyReconciled); err != nil || !historyReconciled {
				t.Fatalf("recovered legacy grant history was not reconciled: reconciled=%v err=%v", historyReconciled, err)
			}
		}
		return
	}
	if response.Code != http.StatusOK {
		t.Fatalf("paid activation webhook: expected 200, got %d: %s", response.Code, response.Body.String())
	}
	response = sendStripeActivationWebhook(t, router, eventID, teamID, userID, created)
	if response.Code != http.StatusOK {
		t.Fatalf("paid activation replay: expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var trialEndedAt *time.Time
	var status string
	var grantID *string
	if err := testPool.QueryRow(ctx, `
		SELECT trial_ended_at, stripe_subscription_status, stripe_activation_credit_grant_id
		FROM team_billing_account WHERE team_id = $1
	`, teamID).Scan(&trialEndedAt, &status, &grantID); err != nil {
		t.Fatal(err)
	}
	if trialEndedAt == nil || status != "active" || grantID != nil {
		t.Fatalf("paid activation state: trial_ended_at=%v status=%q grant_id=%v", trialEndedAt, status, grantID)
	}
	var processedAt *time.Time
	var reservedAt *time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT e.processed_at, a.stripe_activation_credit_reserved_at
		FROM stripe_webhook_event e JOIN team_billing_account a ON a.team_id = $2
		WHERE e.event_id = $1
	`, eventID, teamID).Scan(&processedAt, &reservedAt); err != nil || processedAt == nil || (reservedAt != nil) != reserved {
		t.Fatalf("authority failure webhook state: processed_at=%v reserved_at=%v err=%v", processedAt, reservedAt, err)
	}
	var outcome, denialReason string
	if err := testPool.QueryRow(ctx, `SELECT outcome, reason FROM stripe_promotion_outcome WHERE event_id=$1 AND team_id=$2 AND user_id=$3`,
		eventID, teamID, userID).Scan(&outcome, &denialReason); err != nil || outcome != "promotion_ineligible" || denialReason != "authority_unavailable" {
		t.Fatalf("authority failure outcome = %q/%q: %v", outcome, denialReason, err)
	}
	var grants, reservations int
	if err := testPool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM team_credit_grant WHERE team_id = $1 AND reason = 'stripe promotional credit'),
			(SELECT count(*) FROM user_promotion_entitlement WHERE user_id = $2
				AND (stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
	`, teamID, userID).Scan(&grants, &reservations); err != nil {
		t.Fatal(err)
	}
	wantReservations := 0
	if reserved {
		wantReservations = 1
	}
	if grants != 0 || reservations != wantReservations || len(stripe.creditGrantCalls) != 0 {
		t.Fatalf("promotion issued without authority: local=%d reservations=%d Stripe=%d", grants, reservations, len(stripe.creditGrantCalls))
	}
}

func TestIntegration_PendingDevicePromotionAllowsPaidActivation(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, other := uuid.New(), uuid.New()
	ownerTeam, otherTeam := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	}
	for _, team := range []uuid.UUID{ownerTeam, otherTeam} {
		rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
		rolloutExec(t, region, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
			VALUES($1,$2,$3,'incomplete')`, team, "cus_"+team.String(), "sub_"+team.String())
	}
	otherEvent := "evt_pending_" + uuid.NewString()
	var state string
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`,
		otherTeam, other, otherEvent, "sub_"+otherTeam.String()).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("device-off reservation = %q: %v", state, err)
	}
	attemptedAt, err := db.New(region).MarkStripePromotionAttempt(ctx, db.MarkStripePromotionAttemptParams{
		UserID: other, TeamID: pgtype.UUID{Bytes: otherTeam, Valid: true}, EventID: &otherEvent,
	})
	if err != nil || !attemptedAt.Valid {
		t.Fatalf("mark unresolved Stripe attempt: attempted_at=%v err=%v", attemptedAt, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	if err := region.QueryRow(ctx, `SELECT promotion_device_decision($1,'stripe')`, owner).Scan(&state); err != nil || state != "device_reservation_pending" {
		t.Fatalf("owner decision after policy change = %q: %v", state, err)
	}

	stripe := &fakeStripeClient{}
	eventID := "evt_paid_pending_" + uuid.NewString()
	router := newBillingRouterWithPool(t, stripe, region)
	created := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 2; i++ {
		response := sendStripeActivationWebhook(t, router, eventID, ownerTeam, owner, created)
		if response.Code != http.StatusOK {
			t.Fatalf("paid activation delivery %d: expected 200, got %d: %s", i, response.Code, response.Body.String())
		}
	}
	var trialEndedAt, processedAt *time.Time
	var status string
	var grantID *string
	if err := region.QueryRow(ctx, `SELECT trial_ended_at,stripe_subscription_status,stripe_activation_credit_grant_id
		FROM team_billing_account WHERE team_id=$1`, ownerTeam).Scan(&trialEndedAt, &status, &grantID); err != nil {
		t.Fatal(err)
	}
	if trialEndedAt == nil || status != "active" || grantID != nil {
		t.Fatalf("paid activation state: trial_ended_at=%v status=%q grant_id=%v", trialEndedAt, status, grantID)
	}
	if err := region.QueryRow(ctx, `SELECT processed_at FROM stripe_webhook_event WHERE event_id=$1`, eventID).Scan(&processedAt); err != nil || processedAt == nil {
		t.Fatalf("webhook not processed: processed_at=%v err=%v", processedAt, err)
	}
	var denialReason string
	if err := region.QueryRow(ctx, `SELECT reason FROM stripe_promotion_outcome WHERE event_id=$1 AND team_id=$2 AND user_id=$3`,
		eventID, ownerTeam, owner).Scan(&denialReason); err != nil || denialReason != "device_reservation_pending" {
		t.Fatalf("pending device outcome = %q: %v", denialReason, err)
	}
	var ownerReservations, ownerGrants, teamGrants int
	if err := region.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$1 AND (stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL)),
		(SELECT count(*) FROM promotion_device_grant WHERE user_id=$1 AND promotion='stripe'),
		(SELECT count(*) FROM team_credit_grant WHERE team_id=$2 AND reason='stripe promotional credit')`, owner, ownerTeam).
		Scan(&ownerReservations, &ownerGrants, &teamGrants); err != nil || ownerReservations != 0 || ownerGrants != 0 || teamGrants != 0 || len(stripe.creditGrantCalls) != 0 {
		t.Fatalf("pending device reservation issued promotion: reservations=%d device_grants=%d team_grants=%d Stripe=%d err=%v",
			ownerReservations, ownerGrants, teamGrants, len(stripe.creditGrantCalls), err)
	}
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,$4,NULL,false)`,
		otherTeam, other, otherEvent, "sub_"+otherTeam.String()).Scan(&state); err != nil || state != "existing" {
		t.Fatalf("original uncertain reservation after paid activation = %q: %v", state, err)
	}
	var pendingAttemptAt *time.Time
	if err := region.QueryRow(ctx, `SELECT stripe_redemption_attempted_at FROM user_promotion_entitlement WHERE user_id=$1`,
		other).Scan(&pendingAttemptAt); err != nil || pendingAttemptAt == nil || !pendingAttemptAt.Equal(attemptedAt.Time) {
		t.Fatalf("original Stripe attempt changed: attempted_at=%v err=%v", pendingAttemptAt, err)
	}
}

func TestIntegration_StripeDeviceDenialReasonsSurvivePaidActivation(t *testing.T) {
	ctx := context.Background()
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
	// A grant issued while device enforcement was off still fences the owner
	// after enforcement is enabled.
	rolloutExec(t, region, `INSERT INTO promotion_device_grant(promotion,user_id,team_id,fingerprint)
		VALUES('stripe',$1,$2,$3)`, other, uuid.New(), fingerprint)

	stripe := &fakeStripeClient{}
	router := newBillingRouterWithPool(t, stripe, region)
	for _, tc := range []struct {
		user   uuid.UUID
		reason string
	}{
		{other, "owner_conflict"},
		{owner, "device_already_redeemed"},
		{missing, "evidence_missing"},
	} {
		team, eventID := uuid.New(), "evt_device_denial_"+uuid.NewString()
		rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
		rolloutExec(t, region, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
			VALUES($1,$2,$3,'incomplete')`, team, "cus_"+team.String(), "sub_"+team.String())
		created := time.Now().UTC().Truncate(time.Second)
		for delivery := 0; delivery < 2; delivery++ {
			if response := sendStripeActivationWebhook(t, router, eventID, team, tc.user, created); response.Code != http.StatusOK {
				t.Fatalf("%s paid activation delivery %d: %d: %s", tc.reason, delivery, response.Code, response.Body.String())
			}
		}
		var reason, outcome string
		var processedAt, trialEndedAt *time.Time
		if err := region.QueryRow(ctx, `SELECT o.outcome,o.reason,e.processed_at,a.trial_ended_at
			FROM stripe_promotion_outcome o JOIN stripe_webhook_event e USING(event_id)
			JOIN team_billing_account a ON a.team_id=o.team_id
			WHERE o.event_id=$1 AND o.team_id=$2 AND o.user_id=$3`, eventID, team, tc.user).
			Scan(&outcome, &reason, &processedAt, &trialEndedAt); err != nil ||
			outcome != "promotion_ineligible" || reason != tc.reason || processedAt == nil || trialEndedAt == nil {
			t.Fatalf("%s outcome = %q/%q processed=%v activated=%v: %v", tc.reason, outcome, reason, processedAt, trialEndedAt, err)
		}
	}
	if len(stripe.creditGrantCalls) != 0 {
		t.Fatalf("denied promotions reached Stripe: %d", len(stripe.creditGrantCalls))
	}
}

func TestIntegration_StripePromotionEligibilityAndConcurrentActivation(t *testing.T) {
	ctx := context.Background()
	teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	invitedID := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO profile (id, email) VALUES ($1, $2)
	`, invitedID, "invited-"+invitedID.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed invited member: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')
	`, teamID, invitedID); err != nil {
		t.Fatalf("seed invited membership: %v", err)
	}
	seedActiveStripeAccount := func(team uuid.UUID) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
			VALUES ($1, $2, $3, 'incomplete')
		`, team, "cus_"+team.String(), "sub_"+team.String()); err != nil {
			t.Fatalf("seed billing account: %v", err)
		}
	}
	promoGrantCount := func(team uuid.UUID) int {
		t.Helper()
		var count int
		if err := testPool.QueryRow(ctx, `
			SELECT count(*)
			FROM team_credit_grant
			WHERE team_id = $1 AND reason = 'stripe promotional credit' AND amount_usd = 95
		`, team).Scan(&count); err != nil {
			t.Fatalf("count promotional grants for %s: %v", team, err)
		}
		return count
	}
	activate := func(team, user uuid.UUID, eventID string, stripe *fakeStripeClient) {
		t.Helper()
		created := time.Now().UTC().Truncate(time.Second)
		if w := sendStripeActivationWebhook(t, newBillingRouter(t, stripe), eventID, team, user, created); w.Code != http.StatusOK {
			t.Fatalf("activation webhook: expected 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	activateWithoutPromotion := func(team, user uuid.UUID, eventID string, stripe *fakeStripeClient) {
		t.Helper()
		created := time.Now().UTC().Truncate(time.Second)
		periodEnd := created.AddDate(0, 1, 0)
		payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, "customer.subscription.updated", "sub_"+team.String(), "cus_"+team.String(), "active", created, created, periodEnd, map[string]string{
			"activation_user_id": user.String(),
		})
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, created))
		if w := doRequest(newBillingRouter(t, stripe), req); w.Code != http.StatusOK {
			t.Fatalf("paid activation webhook: expected 200, got %d: %s", w.Code, w.Body.String())
		}
	}

	// A joined member may redeem the team promotion, and replaying the same
	// team or trying another team with that user cannot issue another grant.
	seedActiveStripeAccount(teamID)
	stripe := &fakeStripeClient{}
	activate(teamID, invitedID, "evt_invited_activation", stripe)
	activate(teamID, invitedID, "evt_invited_team_replay", stripe)
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("invited-user Stripe grant calls = %d, want 1", got)
	}
	var redeemedUser uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_user_id FROM team_billing_account WHERE team_id = $1`, teamID).Scan(&redeemedUser); err != nil {
		t.Fatalf("load activation user: %v", err)
	}
	if redeemedUser != invitedID {
		t.Fatalf("activation user = %s, want invited user %s", redeemedUser, invitedID)
	}
	if got := promoGrantCount(teamID); got != 1 {
		t.Fatalf("invited-team promotional grants = %d, want 1", got)
	}
	var invitedRedemptions int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM user_promotion_entitlement
		WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL AND stripe_redemption_team_id = $2
	`, invitedID, teamID).Scan(&invitedRedemptions); err != nil {
		t.Fatalf("count invited-user redemptions: %v", err)
	}
	if invitedRedemptions != 1 {
		t.Fatalf("invited-user redemptions = %d, want 1", invitedRedemptions)
	}
	// A different member cannot redeem a team promotion after that team has
	// already received its one $95 grant.
	repeatTeamUser := uuid.New()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO profile (id, email) VALUES ($1, $2)
	`, repeatTeamUser, "repeat-team-"+repeatTeamUser.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed repeat-team member: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')
	`, teamID, repeatTeamUser); err != nil {
		t.Fatalf("seed repeat-team membership: %v", err)
	}
	activate(teamID, repeatTeamUser, "evt_repeat_team", stripe)
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("repeat-team Stripe grant calls = %d, want 1", got)
	}
	if err := testPool.QueryRow(ctx, `SELECT stripe_activation_user_id FROM team_billing_account WHERE team_id = $1`, teamID).Scan(&redeemedUser); err != nil {
		t.Fatalf("reload activation user: %v", err)
	}
	if redeemedUser != invitedID {
		t.Fatalf("repeat-team activation user = %s, want original redeemer %s", redeemedUser, invitedID)
	}
	var repeatTeamRedemptions int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM user_promotion_entitlement
		WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL
	`, repeatTeamUser).Scan(&repeatTeamRedemptions); err != nil {
		t.Fatalf("count repeat-team-user redemptions: %v", err)
	}
	if repeatTeamRedemptions != 0 {
		t.Fatalf("repeat-team user redemptions = %d, want 0", repeatTeamRedemptions)
	}

	secondTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')
	`, secondTeam, invitedID); err != nil {
		t.Fatalf("seed repeat-user membership: %v", err)
	}
	seedActiveStripeAccount(secondTeam)
	activate(secondTeam, invitedID, "evt_repeat_user", stripe)
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("repeat-user Stripe grant calls = %d, want 1", got)
	}
	if got := promoGrantCount(secondTeam); got != 0 {
		t.Fatalf("repeat-user team promotional grants = %d, want 0", got)
	}
	var secondTeamTrialEndedAt *time.Time
	if err := testPool.QueryRow(ctx, `SELECT trial_ended_at FROM team_billing_account WHERE team_id = $1`, secondTeam).Scan(&secondTeamTrialEndedAt); err != nil {
		t.Fatalf("load repeat-user paid activation state: %v", err)
	}
	if secondTeamTrialEndedAt == nil {
		t.Fatal("repeat-user activation did not continue as normal paid billing")
	}
	if err := testPool.QueryRow(ctx, `
		SELECT count(*)
		FROM user_promotion_entitlement
		WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL
	`, invitedID).Scan(&invitedRedemptions); err != nil {
		t.Fatalf("reload invited-user redemptions: %v", err)
	}
	if invitedRedemptions != 1 {
		t.Fatalf("repeat-user changed redemption count to %d, want 1", invitedRedemptions)
	}

	// A user who already redeemed can still activate another team normally;
	// ineligibility must not reject paid billing.
	thirdTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')
	`, thirdTeam, invitedID); err != nil {
		t.Fatalf("seed paid-activation membership: %v", err)
	}
	seedActiveStripeAccount(thirdTeam)
	activateWithoutPromotion(thirdTeam, invitedID, "evt_paid_without_promo", stripe)
	var trialEndedAt *time.Time
	if err := testPool.QueryRow(ctx, `SELECT trial_ended_at FROM team_billing_account WHERE team_id = $1`, thirdTeam).Scan(&trialEndedAt); err != nil {
		t.Fatalf("load paid activation state: %v", err)
	}
	if trialEndedAt == nil {
		t.Fatal("paid activation did not end the trial")
	}
	if got := promoGrantCount(thirdTeam); got != 0 {
		t.Fatalf("non-promotional team promotional grants = %d, want 0", got)
	}
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("non-promotional activation changed Stripe grant calls to %d, want 1", got)
	}

	// Concurrent webhook deliveries must issue at most one external grant and
	// persist exactly one user/team redemption.
	concurrentTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	concurrentUser := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, concurrentUser, "concurrent-"+concurrentUser.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed concurrent user: %v", err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, concurrentTeam, concurrentUser); err != nil {
		t.Fatalf("seed concurrent membership: %v", err)
	}
	seedActiveStripeAccount(concurrentTeam)
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status = 'active' WHERE team_id = $1`, concurrentTeam); err != nil {
		t.Fatalf("activate concurrent billing account: %v", err)
	}
	concurrentRouter := newBillingRouter(t, stripe)
	const attempts = 4
	responses := make(chan *httptest.ResponseRecorder, attempts)
	start := make(chan struct{})
	created := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			<-start
			// Keep event times distinct; equal timestamps are treated as stale
			// replays by the subscription ordering guard and would bypass the
			// concurrent promotion gate entirely.
			eventCreated := created.Add(time.Duration(i+1) * time.Second)
			responses <- sendStripeActivationWebhook(t, concurrentRouter, fmt.Sprintf("evt_concurrent_activation_%d", i), concurrentTeam, concurrentUser, eventCreated)
		}(i)
	}
	close(start)
	for i := 0; i < attempts; i++ {
		if w := <-responses; w.Code != http.StatusOK {
			t.Fatalf("concurrent activation %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
	var userRedemptions, teamGrants int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM user_promotion_entitlement WHERE user_id = $1 AND stripe_redemption_at IS NOT NULL`, concurrentUser).Scan(&userRedemptions); err != nil {
		t.Fatalf("count concurrent user redemptions: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_billing_account WHERE team_id = $1 AND stripe_activation_credit_grant_id IS NOT NULL`, concurrentTeam).Scan(&teamGrants); err != nil {
		t.Fatalf("count concurrent team grants: %v", err)
	}
	if userRedemptions != 1 || teamGrants != 1 {
		t.Fatalf("concurrent user/team markers = (%d, %d), want (1, 1)", userRedemptions, teamGrants)
	}
	if got := promoGrantCount(concurrentTeam); got != 1 {
		t.Fatalf("concurrent team promotional grants = %d, want 1", got)
	}
	if got := len(stripe.creditGrantCalls); got != 2 {
		t.Fatalf("concurrent activation changed Stripe grant calls to %d, want 2 total", got)
	}
}

func TestIntegration_StripePendingCheckoutReconcilesLatestLifecycle(t *testing.T) {
	transport := &sentry.MockTransport{}
	previousSentryClient := sentry.CurrentHub().Client()
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://test@example.com/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sentry.CurrentHub().BindClient(previousSentryClient) })
	for _, tc := range []struct {
		name, initialStatus, eventType, finalStatus string
		equalTime, reverse                          bool
		wantGrants                                  int
	}{
		{name: "canceled", initialStatus: "active", eventType: "deleted", finalStatus: "canceled"},
		{name: "activated", initialStatus: "incomplete", eventType: "updated", finalStatus: "active", wantGrants: 1},
		{name: "canceled_reverse", initialStatus: "active", eventType: "deleted", finalStatus: "canceled", reverse: true},
		{name: "activated_reverse", initialStatus: "incomplete", eventType: "updated", finalStatus: "active", reverse: true, wantGrants: 1},
		{name: "canceled_equal_time", initialStatus: "active", eventType: "deleted", finalStatus: "canceled", equalTime: true},
		{name: "paused", initialStatus: "active", eventType: "paused", finalStatus: "paused"},
		{name: "resumed", initialStatus: "incomplete", eventType: "resumed", finalStatus: "active", wantGrants: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
			customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
			at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			checkoutEventID := "evt_checkout_" + teamID.String()
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id, checkout_initializing_at, checkout_session_id) VALUES ($1,$2,$3,$4)`, teamID, customerID, at, "cs_"+checkoutEventID); err != nil {
				t.Fatal(err)
			}
			stripe := &fakeStripeClient{}
			r := newBillingRouter(t, stripe)
			deliver := func(payload []byte) *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
				return doRequest(r, req)
			}
			later := at.Add(2 * time.Second)
			if tc.equalTime {
				later = at.Add(time.Second)
			}
			ids := []string{"evt_created_" + teamID.String(), "evt_lifecycle_" + teamID.String()}
			eventTypes := []string{"customer.subscription.created", "customer.subscription." + tc.eventType}
			payloads := [][]byte{
				stripeSubscriptionWebhookPayload(t, ids[0], eventTypes[0], subscriptionID, customerID, tc.initialStatus, at.Add(time.Second), at, at.AddDate(0, 1, 0)),
				stripeSubscriptionWebhookPayload(t, ids[1], eventTypes[1], subscriptionID, customerID, tc.finalStatus, later, at, at.AddDate(0, 1, 0)),
			}
			var warnings bytes.Buffer
			previousLogger := log.Logger
			log.Logger = zerolog.New(zerolog.MultiLevelWriter(&warnings, &sentrylog.Writer{}))
			t.Cleanup(func() { log.Logger = previousLogger })
			initialSentryEvents := len(transport.Events())
			order := []int{0, 1}
			if tc.reverse {
				order = []int{1, 0}
			}
			for _, i := range order {
				if response := deliver(payloads[i]); response.Code != http.StatusInternalServerError {
					t.Fatalf("pending delivery %s = %d, want retryable 500: %s", ids[i], response.Code, response.Body.String())
				}
				var processed bool
				var lastError string
				if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL, last_error FROM stripe_webhook_event WHERE event_id=$1`, ids[i]).Scan(&processed, &lastError); err != nil || processed || lastError != db.StripeCheckoutAssociationPendingError {
					t.Fatalf("pending event %s processed=%v last_error=%q err=%v", ids[i], processed, lastError, err)
				}
			}
			sentry.Flush(time.Second)
			if got := len(transport.Events()); got != initialSentryEvents {
				t.Fatalf("pending deliveries forwarded %d Sentry errors: %s", got-initialSentryEvents, warnings.String())
			}
			var warningRequests int
			for _, line := range bytes.Split(warnings.Bytes(), []byte{'\n'}) {
				var entry map[string]any
				if json.Unmarshal(line, &entry) == nil && entry["message"] == "request" && entry["status"] == float64(http.StatusInternalServerError) && entry["level"] == "warn" {
					warningRequests++
				}
			}
			if warningRequests != len(ids) {
				t.Fatalf("pending request warnings = %d, want %d: %s", warningRequests, len(ids), warnings.String())
			}
			for i, id := range ids {
				found := false
				for _, line := range bytes.Split(warnings.Bytes(), []byte{'\n'}) {
					var entry map[string]any
					if json.Unmarshal(line, &entry) == nil && entry["message"] == "Stripe checkout association pending" && entry["event_id"] == id && entry["event_type"] == eventTypes[i] && entry["level"] == "warn" {
						found = true
					}
				}
				if !found {
					t.Fatalf("pending event %s did not log a warning: %s", id, warnings.String())
				}
			}
			// A different subscription for the same customer must never be imported.
			foreign := stripeSubscriptionWebhookPayload(t, "evt_foreign_"+teamID.String(), "customer.subscription.updated", "sub_foreign_"+teamID.String(), customerID, "active", later.Add(time.Second), at, at.AddDate(0, 1, 0))
			if response := deliver(foreign); response.Code != http.StatusInternalServerError {
				t.Fatalf("foreign delivery = %d, want retryable 500", response.Code)
			}
			checkout := stripeCheckoutWebhookPayload(t, checkoutEventID, teamID.String(), customerID, subscriptionID, later.Add(2*time.Second))
			if response := deliver(checkout); response.Code != http.StatusOK {
				t.Fatalf("checkout = %d: %s", response.Code, response.Body.String())
			}
			verify := func() {
				t.Helper()
				account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				if derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != tc.finalStatus {
					t.Fatalf("subscription = %q/%q, want %s/%s", derefString(account.StripeSubscriptionID), derefString(account.StripeSubscriptionStatus), subscriptionID, tc.finalStatus)
				}
				if len(stripe.creditGrantCalls) != tc.wantGrants || account.TrialEndedAt.Valid != (tc.wantGrants == 1) || (account.StripeActivationCreditGrantID != nil) != (tc.wantGrants == 1) {
					t.Fatalf("grants=%d trialEnded=%v grantID=%v, want %d activations", len(stripe.creditGrantCalls), account.TrialEndedAt.Valid, account.StripeActivationCreditGrantID, tc.wantGrants)
				}
				for _, id := range ids {
					var processed bool
					if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL FROM stripe_webhook_event WHERE event_id=$1`, id).Scan(&processed); err != nil || !processed {
						t.Fatalf("event %s processed=%v err=%v", id, processed, err)
					}
				}
				if account.CheckoutInitializingAt.Valid || account.CheckoutSessionID != nil {
					t.Fatal("matching checkout reservation was not cleared")
				}
			}
			verify()
			for _, payload := range append(payloads, foreign, checkout) {
				if response := deliver(payload); response.Code != http.StatusOK {
					t.Fatalf("redelivery = %d: %s", response.Code, response.Body.String())
				}
			}
			verify()
		})
	}
	t.Run("unassociated_without_checkout", func(t *testing.T) {
		ctx := context.Background()
		teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
		customerID := "cus_" + teamID.String()
		if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id) VALUES ($1,$2)`, teamID, customerID); err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
		eventID := "evt_unassociated_" + teamID.String()
		payload := stripeSubscriptionWebhookPayload(t, eventID, "customer.subscription.updated", "sub_"+teamID.String(), customerID, "active", at, at, at.AddDate(0, 1, 0))
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
		if response := doRequest(newBillingRouter(t, &fakeStripeClient{}), req); response.Code != http.StatusInternalServerError {
			t.Fatalf("unassociated delivery = %d, want retryable 500: %s", response.Code, response.Body.String())
		}
		var processed bool
		var lastError string
		if err := testPool.QueryRow(ctx, `SELECT processed_at IS NOT NULL, last_error FROM stripe_webhook_event WHERE event_id=$1`, eventID).Scan(&processed, &lastError); err != nil || processed || lastError != db.StripeCheckoutAssociationPendingError {
			t.Fatalf("unassociated event processed=%v last_error=%q err=%v", processed, lastError, err)
		}
	})
}
func TestIntegration_CreateStripeCheckoutSessionBlocksExistingSubscription(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatalf("seed active billing account: %v", err)
	}
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/checkout-session", apiKey, `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("checkout session with active subscription: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.customerCalls); got != 0 {
		t.Fatalf("customer calls = %d, want 0", got)
	}
	if got := len(stripe.checkoutCalls); got != 0 {
		t.Fatalf("checkout calls = %d, want 0", got)
	}
}

func TestIntegration_CreateStripeCheckoutSessionDeniedInShadowMode(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable billing export for shadow-mode test: %v", err)
	}
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/checkout-session", apiKey, `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("checkout session in shadow mode: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.checkoutCalls); got != 0 {
		t.Fatalf("checkout calls = %d, want 0 in shadow mode", got)
	}
	if got := len(stripe.customerCalls); got != 0 {
		t.Fatalf("customer calls = %d, want 0 in shadow mode", got)
	}
}

func TestIntegration_CustomerPortalSessionDeniedInShadowMode(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', false)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("disable billing export for shadow-mode test: %v", err)
	}
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatalf("seed billing account: %v", err)
	}
	stripe := &fakeStripeClient{nextPortalURL: "https://billing.stripe.test/portal"}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/customer-portal-session", apiKey, `{"return_url":"https://app.superserve.test/billing"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("portal session in shadow mode: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.portalCalls); got != 0 {
		t.Fatalf("portal calls = %d, want 0", got)
	}
}

func TestIntegration_CustomerPortalSessionValidatesRedirectURL(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatalf("seed billing account: %v", err)
	}
	stripe := &fakeStripeClient{nextPortalURL: "https://billing.stripe.test/portal"}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/customer-portal-session", apiKey, `{"return_url":"https://app.superserve.test/billing"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("portal session: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.portalCalls); got != 1 {
		t.Fatalf("portal calls = %d, want 1", got)
	}
	if got := stripe.portalCalls[0].ReturnURL; got != "https://app.superserve.test/billing" {
		t.Fatalf("portal return url = %q, want validated url", got)
	}
}

func TestIntegration_ApproveExportRequiresPlatformAdminSession(t *testing.T) {
	teamID, periodID, _, _ := seedBillingPeriodForStripe(t, false, true)
	nonAdmin := seedSuperserveEmailProfile(t)
	r := newBillingRouter(t, &fakeStripeClient{})

	approve := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/approve", nonAdmin.String(), "")
	if approve.Code != http.StatusForbidden {
		t.Fatalf("approve without platform admin: expected 403, got %d: %s", approve.Code, approve.Body.String())
	}

	export := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", nonAdmin.String(), "")
	if export.Code != http.StatusForbidden {
		t.Fatalf("export without platform admin: expected 403, got %d: %s", export.Code, export.Body.String())
	}
}

func TestIntegration_TeamBillingUsageRequiresBillingRead(t *testing.T) {
	ctx := context.Background()
	teamID, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	userAdminKey := seedKeyForExistingTeamWithRole(t, teamID, "user_admin")
	periodStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage (
			team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 3600, 1024, 1024)
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	r := newBillingRouter(t, nil)
	okResp := do(r, "GET", "/teams/"+teamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), viewerKey, "")
	if okResp.Code != http.StatusOK {
		t.Fatalf("viewer billing usage: expected 200, got %d: %s", okResp.Code, okResp.Body.String())
	}
	denyResp := do(r, "GET", "/teams/"+teamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), userAdminKey, "")
	if denyResp.Code != http.StatusForbidden {
		t.Fatalf("user_admin billing usage: expected 403, got %d: %s", denyResp.Code, denyResp.Body.String())
	}
}

func TestIntegration_TeamBillingUsageReportsGiBBasedResources(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	periodStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	cw := do(newRouter(t), "POST", "/sandboxes", ownerKey, `{"name":"billing-usage-units"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 1, 1024, $3, $4, 'paused')
	`, sandboxID, teamID, periodStart, periodStart.Add(time.Second)); err != nil {
		t.Fatalf("seed compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (
			sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 2048, $3, $4, 'deleted')
	`, sandboxID, teamID, periodStart, periodStart.Add(time.Second)); err != nil {
		t.Fatalf("seed storage billing interval: %v", err)
	}

	r := newBillingRouter(t, nil)
	resp := do(r, "GET", "/teams/"+teamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), viewerKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("team billing usage: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	body := mustJSON(t, resp)
	resources, ok := body["resources"].([]interface{})
	if !ok || len(resources) != 3 {
		t.Fatalf("resources = %v, want 3 entries", body["resources"])
	}
	memoryResource := resources[1].(map[string]interface{})
	if got := memoryResource["usage"].(float64); got != 1 {
		t.Fatalf("memory resource usage = %v, want 1 GiB-second", got)
	}
	storageResource := resources[2].(map[string]interface{})
	if got := storageResource["usage"].(float64); got != 2 {
		t.Fatalf("storage resource usage = %v, want 2 GiB-seconds", got)
	}
	byKey, ok := body["resources_by_key"].(map[string]interface{})
	if !ok {
		t.Fatalf("resources_by_key not an object: %v", body["resources_by_key"])
	}
	if byKey["memory_gib"] == nil || byKey["storage_gib"] == nil {
		t.Fatalf("resources_by_key missing memory/storage entries: %v", body["resources_by_key"])
	}
}

func TestIntegration_TeamBillingUsageDoesNotCreatePeriodsForAdHocWindows(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	periodStart := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	cw := do(newRouter(t), "POST", "/sandboxes", ownerKey, `{"name":"billing-usage-read-only"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}

	r := newBillingRouter(t, nil)
	resp := do(r, "GET", "/teams/"+teamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), viewerKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("ad hoc billing usage: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	_, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ad hoc usage should not create a billing period row, got err=%v", err)
	}
}

func TestIntegration_TeamBillingExportPreviewDoesNotCreatePeriods(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	viewerKey := seedKeyForExistingTeamWithRole(t, teamID, "viewer")
	periodStart := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	cw := do(newRouter(t), "POST", "/sandboxes", ownerKey, `{"name":"billing-export-preview-read-only"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID := uuid.MustParse(mustJSON(t, cw)["id"].(string))
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}

	r := newBillingRouter(t, nil)
	resp := do(r, "GET", "/teams/"+teamID.String()+"/billing/periods/"+apiPeriodID(periodStart, periodEnd)+"/export-preview", viewerKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("billing export preview: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	_, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("export preview should not create a billing period row, got err=%v", err)
	}
}

func TestIntegration_TeamBillingUsageRejectsForeignPathTeam(t *testing.T) {
	ctx := context.Background()
	teamID, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	otherTeamID, _, _ := seedTeamAndKeyWithRole(t, "viewer")
	periodStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage (
			team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 3600, 1024, 1024)
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	r := newBillingRouter(t, nil)
	resp := do(r, "GET", "/teams/"+otherTeamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), viewerKey, "")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("foreign team billing usage: expected 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestIntegration_ExportedPeriodsCannotBeSilentlyRewritten(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "viewer")
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	sandboxID := uuid.New()

	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id)
		VALUES ($1, $2, 'frozen-period-box', 'deleted', 1, 1024, 'default')
	`, sandboxID, teamID); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage (
			team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds, exported_at
		)
		VALUES ($1, $2, $3, 10, 20, 30, now())
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed immutable usage: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_period (team_id, period_start, period_end, status, exported_at)
		VALUES ($1, $2, $3, 'exported', now())
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed immutable period: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 8, 8192, $3, $4, 'deleted')
	`, sandboxID, teamID, periodStart, periodStart.Add(12*time.Hour)); err != nil {
		t.Fatalf("seed recompute source interval: %v", err)
	}

	r := newBillingRouter(t, nil)
	resp := do(r, "GET", "/teams/"+teamID.String()+"/billing/usage?period_start="+periodStart.Format(time.RFC3339)+"&period_end="+periodEnd.Format(time.RFC3339), apiKey, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("immutable usage read: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := mustJSON(t, resp)
	if got := body["vcpu_seconds"].(float64); got != 10 {
		t.Fatalf("vcpu_seconds = %v, want frozen value 10", got)
	}
}

func TestIntegration_StripeWebhookDuplicateDeliveryIsSafe(t *testing.T) {
	ctx := context.Background()
	teamID, periodID, _, _ := seedBillingPeriodForStripe(t, true, false)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id) VALUES ($1, $2)`, teamID, "cus_"+teamID.String()); err != nil {
		t.Fatalf("seed Stripe customer mapping: %v", err)
	}
	_ = periodID
	r := newBillingRouter(t, &fakeStripeClient{})

	createdAt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	payload := stripeSubscriptionWebhookPayload(t, "evt_test_duplicate", "customer.subscription.created", "sub_duplicate", "cus_"+teamID.String(), "active", createdAt, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	sig := stripeSignature(t, payload, time.Now().UTC())

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", sig)
		w := doRequest(r, req)
		if w.Code != http.StatusOK {
			t.Fatalf("webhook attempt %d: expected 200, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	var n int
	if err := testPool.QueryRow(ctx, `SELECT COUNT(*) FROM stripe_webhook_event WHERE event_id = 'evt_test_duplicate'`).Scan(&n); err != nil {
		t.Fatalf("count webhook rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("stripe_webhook_event rows = %d, want 1", n)
	}
	if got := billingPeriodStatus(t, teamID, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); got != "approved" {
		t.Fatalf("duplicate webhook changed unrelated billing period status to %q", got)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account: %v", err)
	}
	if !account.CurrentPeriodStart.Valid || !account.CurrentPeriodStart.Time.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("subscription current period start = %v, want 2026-07-01", account.CurrentPeriodStart)
	}
	if !account.CurrentPeriodEnd.Valid || !account.CurrentPeriodEnd.Time.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("subscription current period end = %v, want 2026-08-01", account.CurrentPeriodEnd)
	}
	if !account.StripeSubscriptionEventAt.Valid || !account.StripeSubscriptionEventAt.Time.Equal(createdAt) {
		t.Fatalf("subscription event at = %v, want %v", account.StripeSubscriptionEventAt, createdAt)
	}
}

func TestIntegration_StripeWebhookIgnoresForeignOwnedEvents(t *testing.T) {
	ctx := context.Background()
	teamID, _, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	before, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account before foreign webhooks: %v", err)
	}
	beforeUsageExports, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports before foreign webhooks: %v", err)
	}
	beforeBillingPeriod, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing period before foreign webhooks: %v", err)
	}
	beforeCreditGrants, err := testQueries.ListTeamCreditGrants(ctx, teamID)
	if err != nil {
		t.Fatalf("load credit grants before foreign webhooks: %v", err)
	}
	r := newBillingRouter(t, &fakeStripeClient{})
	createdAt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	foreignTeamID := uuid.New()
	foreignCustomerID := "cus_" + foreignTeamID.String()
	if _, err := testQueries.GetTeamBillingAccountByStripeCustomerID(ctx, &foreignCustomerID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign Stripe customer should be absent before webhook delivery, got err=%v", err)
	}
	beforeForeignAccounts := teamBillingAccountRowCount(t, foreignTeamID)
	beforeForeignUsageExports := billingUsageExportRowCount(t, foreignTeamID)
	beforeForeignBillingPeriods := billingPeriodRowCount(t, foreignTeamID)
	beforeForeignCreditGrants := teamCreditGrantRowCount(t, foreignTeamID)
	assertForeignStateUnchanged := func(label string) {
		t.Helper()
		if got := teamBillingAccountRowCount(t, foreignTeamID); got != beforeForeignAccounts {
			t.Fatalf("%s: foreign team_billing_account row count changed from %d to %d", label, beforeForeignAccounts, got)
		}
		if got := billingUsageExportRowCount(t, foreignTeamID); got != beforeForeignUsageExports {
			t.Fatalf("%s: foreign billing_usage_export row count changed from %d to %d", label, beforeForeignUsageExports, got)
		}
		if got := billingPeriodRowCount(t, foreignTeamID); got != beforeForeignBillingPeriods {
			t.Fatalf("%s: foreign team_billing_period row count changed from %d to %d", label, beforeForeignBillingPeriods, got)
		}
		if got := teamCreditGrantRowCount(t, foreignTeamID); got != beforeForeignCreditGrants {
			t.Fatalf("%s: foreign team_credit_grant row count changed from %d to %d", label, beforeForeignCreditGrants, got)
		}
		if _, err := testQueries.GetTeamBillingAccountByStripeCustomerID(ctx, &foreignCustomerID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("%s: foreign Stripe customer should remain absent after webhook delivery, got err=%v", label, err)
		}
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "checkout",
			payload: stripeCheckoutWebhookPayload(t, "evt_foreign_checkout", foreignTeamID.String(), foreignCustomerID, "sub_foreign_checkout", createdAt),
		},
		{
			name:    "subscription-created",
			payload: stripeSubscriptionWebhookPayload(t, "evt_foreign_subscription_created", "customer.subscription.created", "sub_foreign_subscription_created", foreignCustomerID, "active", createdAt, createdAt, createdAt.Add(time.Hour)),
		},
		{
			name:    "subscription-updated",
			payload: stripeSubscriptionWebhookPayload(t, "evt_foreign_subscription_updated", "customer.subscription.updated", "sub_foreign_subscription_updated", foreignCustomerID, "active", createdAt, createdAt, createdAt.Add(time.Hour)),
		},
		{
			name:    "subscription-deleted",
			payload: stripeSubscriptionWebhookPayload(t, "evt_foreign_subscription_deleted", "customer.subscription.deleted", "sub_foreign_subscription_deleted", foreignCustomerID, "canceled", createdAt, createdAt, createdAt.Add(time.Hour)),
		},
		{
			name:    "invoice-finalized",
			payload: stripeInvoiceWebhookPayload(t, "evt_foreign_invoice_finalized", "invoice.finalized", foreignCustomerID, "sub_foreign_invoice_finalized", "open", createdAt),
		},
		{
			name:    "invoice-failed",
			payload: stripeInvoiceWebhookPayload(t, "evt_foreign_invoice_failed", "invoice.payment_failed", foreignCustomerID, "sub_foreign_invoice_failed", "open", createdAt),
		},
		{
			name:    "invoice-paid",
			payload: stripeInvoiceWebhookPayload(t, "evt_foreign_invoice_paid", "invoice.payment_succeeded", foreignCustomerID, "sub_foreign_invoice_paid", "paid", createdAt),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(tc.payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Stripe-Signature", stripeSignature(t, tc.payload, time.Now().UTC()))
			w := doRequest(r, req)
			if w.Code != http.StatusOK {
				t.Fatalf("foreign %s webhook: expected 200, got %d: %s", tc.name, w.Code, w.Body.String())
			}
			assertForeignStateUnchanged(tc.name)
		})
	}

	after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account after foreign webhooks: %v", err)
	}
	if derefString(after.StripeCustomerID) != derefString(before.StripeCustomerID) {
		t.Fatalf("stripe customer id changed from %q to %q", derefString(before.StripeCustomerID), derefString(after.StripeCustomerID))
	}
	if derefString(after.StripeSubscriptionID) != derefString(before.StripeSubscriptionID) {
		t.Fatalf("stripe subscription id changed from %q to %q", derefString(before.StripeSubscriptionID), derefString(after.StripeSubscriptionID))
	}
	if derefString(after.StripeSubscriptionStatus) != derefString(before.StripeSubscriptionStatus) {
		t.Fatalf("stripe subscription status changed from %q to %q", derefString(before.StripeSubscriptionStatus), derefString(after.StripeSubscriptionStatus))
	}
	if derefString(after.StripeInvoiceStatus) != derefString(before.StripeInvoiceStatus) {
		t.Fatalf("stripe invoice status changed from %q to %q", derefString(before.StripeInvoiceStatus), derefString(after.StripeInvoiceStatus))
	}
	if after.StripeSubscriptionEventAt.Valid != before.StripeSubscriptionEventAt.Valid || (after.StripeSubscriptionEventAt.Valid && !after.StripeSubscriptionEventAt.Time.Equal(before.StripeSubscriptionEventAt.Time)) {
		t.Fatalf("subscription event at changed from %v to %v", before.StripeSubscriptionEventAt, after.StripeSubscriptionEventAt)
	}
	if after.CurrentPeriodStart.Valid != before.CurrentPeriodStart.Valid || (after.CurrentPeriodStart.Valid && !after.CurrentPeriodStart.Time.Equal(before.CurrentPeriodStart.Time)) {
		t.Fatalf("current period start changed from %v to %v", before.CurrentPeriodStart, after.CurrentPeriodStart)
	}
	if after.CurrentPeriodEnd.Valid != before.CurrentPeriodEnd.Valid || (after.CurrentPeriodEnd.Valid && !after.CurrentPeriodEnd.Time.Equal(before.CurrentPeriodEnd.Time)) {
		t.Fatalf("current period end changed from %v to %v", before.CurrentPeriodEnd, after.CurrentPeriodEnd)
	}
	if after.CancelAtPeriodEnd != before.CancelAtPeriodEnd {
		t.Fatalf("cancel_at_period_end changed from %v to %v", before.CancelAtPeriodEnd, after.CancelAtPeriodEnd)
	}
	if after.StripeActivationCreditGrantedAt.Valid != before.StripeActivationCreditGrantedAt.Valid || (after.StripeActivationCreditGrantedAt.Valid && !after.StripeActivationCreditGrantedAt.Time.Equal(before.StripeActivationCreditGrantedAt.Time)) {
		t.Fatalf("stripe activation credit grant timestamp changed from %v to %v", before.StripeActivationCreditGrantedAt, after.StripeActivationCreditGrantedAt)
	}
	if derefString(after.StripeActivationCreditGrantID) != derefString(before.StripeActivationCreditGrantID) {
		t.Fatalf("stripe activation credit grant id changed from %q to %q", derefString(before.StripeActivationCreditGrantID), derefString(after.StripeActivationCreditGrantID))
	}
	afterUsageExports, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports after foreign webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterUsageExports, beforeUsageExports) {
		t.Fatalf("billing_usage_export rows changed from %#v to %#v", beforeUsageExports, afterUsageExports)
	}
	afterBillingPeriod, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing period after foreign webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterBillingPeriod, beforeBillingPeriod) {
		t.Fatalf("team_billing_period row changed from %#v to %#v", beforeBillingPeriod, afterBillingPeriod)
	}
	afterCreditGrants, err := testQueries.ListTeamCreditGrants(ctx, teamID)
	if err != nil {
		t.Fatalf("load credit grants after foreign webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterCreditGrants, beforeCreditGrants) {
		t.Fatalf("team_credit_grant rows changed from %#v to %#v", beforeCreditGrants, afterCreditGrants)
	}
	if got := teamBillingAccountRowCount(t, foreignTeamID); got != beforeForeignAccounts {
		t.Fatalf("foreign team_billing_account row count changed from %d to %d", beforeForeignAccounts, got)
	}
	if got := billingUsageExportRowCount(t, foreignTeamID); got != beforeForeignUsageExports {
		t.Fatalf("foreign billing_usage_export row count changed from %d to %d", beforeForeignUsageExports, got)
	}
	if got := billingPeriodRowCount(t, foreignTeamID); got != beforeForeignBillingPeriods {
		t.Fatalf("foreign team_billing_period row count changed from %d to %d", beforeForeignBillingPeriods, got)
	}
	if got := teamCreditGrantRowCount(t, foreignTeamID); got != beforeForeignCreditGrants {
		t.Fatalf("foreign team_credit_grant row count changed from %d to %d", beforeForeignCreditGrants, got)
	}
	if _, err := testQueries.GetTeamBillingAccountByStripeCustomerID(ctx, &foreignCustomerID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign Stripe customer should remain absent after webhook delivery, got err=%v", err)
	}
}

type stripeRecoveryBeforeFailureTracer struct {
	mu              sync.Mutex
	associationConn *pgx.Conn
	eventID         string
	failureReady    chan struct{}
	recovered       chan struct{}
}

func (tr *stripeRecoveryBeforeFailureTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "-- name: AssociateTeamBillingCheckoutSubscription ") {
		tr.mu.Lock()
		tr.associationConn = conn
		tr.mu.Unlock()
	}
	if strings.HasPrefix(data.SQL, "-- name: MarkStripeWebhookEventFailed ") && len(data.Args) == 2 && data.Args[1] == tr.eventID {
		close(tr.failureReady)
		select {
		case <-tr.recovered:
		case <-ctx.Done():
		}
	}
	return ctx
}

func (tr *stripeRecoveryBeforeFailureTracer) TraceQueryEnd(_ context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if data.Err == nil && data.CommandTag.String() == "COMMIT" && conn == tr.associationConn {
		tr.associationConn = nil
		close(tr.recovered)
	}
}

func TestIntegration_StripeCheckoutRecoveryBeforeFailurePersistence(t *testing.T) {
	for _, status := range []string{"paused", "canceled"} {
		t.Run(status, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
			customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
			eventID, checkoutID := "evt_pending_"+teamID.String(), "evt_checkout_"+teamID.String()
			at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id, stripe_customer_id, checkout_initializing_at, checkout_session_id)
				VALUES ($1, $2, $3, $4)`, teamID, customerID, at, "cs_"+checkoutID); err != nil {
				t.Fatal(err)
			}
			tracer := &stripeRecoveryBeforeFailureTracer{eventID: eventID, failureReady: make(chan struct{}), recovered: make(chan struct{})}
			poolConfig := testPool.Config().Copy()
			poolConfig.ConnConfig.Tracer = tracer
			pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			stripe := &fakeStripeClient{}
			router := newBillingRouterWithPool(t, stripe, pool)
			var logs bytes.Buffer
			previousLogger := log.Logger
			log.Logger = zerolog.New(zerolog.SyncWriter(&logs))
			t.Cleanup(func() { log.Logger = previousLogger })
			eventType := "customer.subscription.paused"
			if status == "canceled" {
				eventType = "customer.subscription.deleted"
			}
			request := func(payload []byte) *http.Request {
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload))).WithContext(ctx)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
				return req
			}
			pendingRequest := request(stripeSubscriptionWebhookPayload(t, eventID, eventType, subscriptionID, customerID, status, at.Add(time.Second), at, at.AddDate(0, 1, 0)))
			pendingResponse := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				router.ServeHTTP(pendingResponse, pendingRequest)
			}()
			// Join the request before restoring the logger, including on failure.
			defer func() { cancel(); <-done }()
			select {
			case <-tracer.failureReady:
			case <-ctx.Done():
				t.Fatal("pending delivery did not reach failure persistence")
			}
			before, err := testQueries.GetStripeWebhookEvent(ctx, eventID)
			if err != nil || before.ProcessedAt.Valid {
				t.Fatalf("event before recovery: %+v, %v", before, err)
			}
			// The association transaction processes the retained non-activating event
			// without the delivery lease, then releases the blocked failure write.
			checkoutResponse := doRequest(router, request(stripeCheckoutWebhookPayload(t, checkoutID, teamID.String(), customerID, subscriptionID, at.Add(2*time.Second))))
			<-done
			if checkoutResponse.Code != http.StatusOK || pendingResponse.Code != http.StatusInternalServerError {
				t.Fatalf("checkout=%d pending=%d; logs: %s", checkoutResponse.Code, pendingResponse.Code, logs.String())
			}
			for _, id := range []string{eventID, checkoutID} {
				event, err := testQueries.GetStripeWebhookEvent(ctx, id)
				if err != nil || !event.ProcessedAt.Valid || event.LastError != nil {
					t.Fatalf("recovered event %s: %+v, %v", id, event, err)
				}
				if id == eventID && !event.ReceivedAt.Equal(before.ReceivedAt) {
					t.Fatal("failure persistence changed receipt time")
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != status || len(stripe.creditGrantCalls) != 0 {
				t.Fatalf("recovered account: %+v, grants=%d, err=%v", account, len(stripe.creditGrantCalls), err)
			}
			pendingWarning := false
			for _, line := range bytes.Split(logs.Bytes(), []byte{'\n'}) {
				var entry map[string]any
				if json.Unmarshal(line, &entry) != nil {
					continue
				}
				if entry["level"] == "error" {
					t.Fatalf("successful recovery emitted an error: %s", line)
				}
				if entry["message"] == "Stripe checkout association pending" && entry["event_id"] == eventID && entry["level"] == "warn" {
					pendingWarning = true
				}
			}
			if !pendingWarning {
				t.Fatalf("missing pending diagnostic: %s", logs.String())
			}
		})
	}
}

func TestIntegration_StripeWebhookPersistsFailureAfterRollback(t *testing.T) {
	transport := &sentry.MockTransport{}
	previousSentryClient := sentry.CurrentHub().Client()
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://test@example.com/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sentry.CurrentHub().BindClient(previousSentryClient) })
	var logs bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(zerolog.MultiLevelWriter(&logs, &sentrylog.Writer{}))
	t.Cleanup(func() { log.Logger = previousLogger })
	ctx := context.Background()
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	r := newBillingRouter(t, &fakeStripeClient{})

	createdAt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	periodStart := createdAt.Add(2 * time.Hour)
	periodEnd := createdAt.Add(time.Hour)
	customerID := "cus_" + teamID.String()
	payload := stripeSubscriptionWebhookPayload(t, "evt_processing_failure", "customer.subscription.updated", "sub_"+teamID.String(), customerID, "active", createdAt, periodStart, periodEnd)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
	w := doRequest(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failing webhook: expected 500, got %d: %s", w.Code, w.Body.String())
	}
	sentry.Flush(time.Second)
	if len(transport.Events()) == 0 {
		t.Fatal("unexpected webhook failure did not reach Sentry")
	}
	requestError := false
	processingError := false
	for _, line := range bytes.Split(logs.Bytes(), []byte{'\n'}) {
		var entry map[string]any
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		if entry["message"] == "request" && entry["status"] == float64(http.StatusInternalServerError) && entry["level"] == "error" {
			requestError = true
		}
		if entry["message"] == "process Stripe webhook failed" && entry["level"] == "error" && entry["event_id"] == "evt_processing_failure" && entry["event_type"] == "customer.subscription.updated" {
			processingError = true
		}
	}
	if !requestError {
		t.Fatalf("unexpected failure did not retain error-level request telemetry: %s", logs.String())
	}
	if !processingError {
		t.Fatalf("unexpected failure did not retain error-level webhook processing telemetry: %s", logs.String())
	}

	var lastError string
	var processedAt pgtype.Timestamptz
	if err := testPool.QueryRow(ctx, `
		SELECT last_error, processed_at
		FROM stripe_webhook_event
		WHERE event_id = $1
	`, "evt_processing_failure").Scan(&lastError, &processedAt); err != nil {
		t.Fatalf("load failed webhook row: %v", err)
	}
	if !strings.Contains(lastError, "team_billing_account_period_valid") {
		t.Fatalf("failed webhook last_error = %v, want original constraint failure", lastError)
	}
	if processedAt.Valid {
		t.Fatalf("failed webhook processed_at = %v, want nil", processedAt)
	}
}

func TestIntegration_StripeWebhookPersistsFailureAfterProcessedMarkRollback(t *testing.T) {
	ctx := context.Background()
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	r := newBillingRouter(t, &fakeStripeClient{})

	_, err := testPool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_fail_stripe_webhook_mark_processed()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $$
		BEGIN
			IF NEW.processed_at IS DISTINCT FROM OLD.processed_at THEN
				RAISE EXCEPTION 'forced stripe webhook processed_at update failure';
			END IF;
			RETURN NEW;
		END;
		$$;
	`)
	if err != nil {
		t.Fatalf("create mark-processed failure trigger function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_fail_stripe_webhook_mark_processed_trg ON stripe_webhook_event`)
		_, _ = testPool.Exec(context.Background(), `DROP FUNCTION IF EXISTS test_fail_stripe_webhook_mark_processed()`)
	})
	if _, err := testPool.Exec(ctx, `
		CREATE TRIGGER test_fail_stripe_webhook_mark_processed_trg
		BEFORE UPDATE ON stripe_webhook_event
		FOR EACH ROW
		EXECUTE FUNCTION test_fail_stripe_webhook_mark_processed()
	`); err != nil {
		t.Fatalf("create mark-processed failure trigger: %v", err)
	}

	createdAt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	periodStart := createdAt.Add(2 * time.Hour)
	periodEnd := createdAt.Add(3 * time.Hour)
	customerID := "cus_" + teamID.String()
	payload := stripeSubscriptionWebhookPayload(t, "evt_mark_processed_failure", "customer.subscription.updated", "sub_"+teamID.String(), customerID, "active", createdAt, periodStart, periodEnd)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
	w := doRequest(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("mark-processed failing webhook: expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var lastError string
	var processedAt pgtype.Timestamptz
	if err := testPool.QueryRow(ctx, `
		SELECT last_error, processed_at
		FROM stripe_webhook_event
		WHERE event_id = $1
	`, "evt_mark_processed_failure").Scan(&lastError, &processedAt); err != nil {
		t.Fatalf("load mark-processed failed webhook row: %v", err)
	}
	if !strings.Contains(lastError, "forced stripe webhook processed_at update failure") {
		t.Fatalf("failed webhook last_error = %v, want original processed_at failure", lastError)
	}
	if processedAt.Valid {
		t.Fatalf("failed webhook processed_at = %v, want nil", processedAt)
	}
}

func TestIntegration_StripeWebhookPersistsFailureAfterCommitRollback(t *testing.T) {
	ctx := context.Background()
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	r := newBillingRouter(t, &fakeStripeClient{})

	_, err := testPool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_fail_stripe_webhook_commit()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $$
		BEGIN
			IF NEW.event_id = 'evt_commit_failure' AND NEW.processed_at IS DISTINCT FROM OLD.processed_at THEN
				RAISE EXCEPTION 'forced stripe webhook commit failure';
			END IF;
			RETURN NEW;
		END;
		$$;
	`)
	if err != nil {
		t.Fatalf("create commit failure trigger function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_fail_stripe_webhook_commit_trg ON stripe_webhook_event`)
		_, _ = testPool.Exec(context.Background(), `DROP FUNCTION IF EXISTS test_fail_stripe_webhook_commit()`)
	})
	if _, err := testPool.Exec(ctx, `
		CREATE CONSTRAINT TRIGGER test_fail_stripe_webhook_commit_trg
		AFTER UPDATE ON stripe_webhook_event
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW
		EXECUTE FUNCTION test_fail_stripe_webhook_commit()
	`); err != nil {
		t.Fatalf("create commit failure trigger: %v", err)
	}

	createdAt := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	periodStart := createdAt.Add(2 * time.Hour)
	periodEnd := createdAt.Add(3 * time.Hour)
	customerID := "cus_" + teamID.String()
	payload := stripeSubscriptionWebhookPayload(t, "evt_commit_failure", "customer.subscription.updated", "sub_"+teamID.String(), customerID, "active", createdAt, periodStart, periodEnd)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
	w := doRequest(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("commit failing webhook: expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var lastError string
	var processedAt pgtype.Timestamptz
	if err := testPool.QueryRow(ctx, `
		SELECT last_error, processed_at
		FROM stripe_webhook_event
		WHERE event_id = $1
	`, "evt_commit_failure").Scan(&lastError, &processedAt); err != nil {
		t.Fatalf("load commit-failed webhook row: %v", err)
	}
	if !strings.Contains(lastError, "forced stripe webhook commit failure") {
		t.Fatalf("failed webhook last_error = %v, want original commit failure", lastError)
	}
	if processedAt.Valid {
		t.Fatalf("failed webhook processed_at = %v, want nil", processedAt)
	}
}

func TestIntegration_StripeThinMeterErrorFailsOnMalformedExpansion(t *testing.T) {
	stripe := &thinEventStripeClient{fakeStripeClient: &fakeStripeClient{}, retrieved: []byte(`{"data":{}}`)}
	r := newBillingRouter(t, stripe)
	payload, err := json.Marshal(map[string]any{
		"id":      "evt_thin_meter_error_invalid",
		"type":    "v1.billing.meter.error_report_triggered",
		"created": time.Now().UTC().Unix(),
	})
	if err != nil {
		t.Fatalf("marshal thin meter error payload: %v", err)
	}
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC(), testStripeMeterErrorWebhookSecret))
	w := doRequest(r, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("malformed thin meter webhook: expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_StripeThinMeterErrorIgnoresForeignTeam(t *testing.T) {
	ctx := context.Background()
	teamID, _, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	beforeUsageExports := billingUsageExportRowCount(t, teamID)
	beforeBillingPeriods := billingPeriodRowCount(t, teamID)
	beforeCreditGrants := teamCreditGrantRowCount(t, teamID)
	seedValue := pgtype.Numeric{}
	if err := seedValue.Scan("0"); err != nil {
		t.Fatalf("seed billing usage export value: %v", err)
	}
	seededExport, err := testQueries.CreateBillingUsageExport(context.Background(), db.CreateBillingUsageExportParams{
		TeamID:                     teamID,
		PeriodStart:                periodStart,
		PeriodEnd:                  periodEnd,
		ResourceType:               "cpu",
		StripeCustomerID:           nil,
		StripeMeterEventIdentifier: "thin-meter-foreign-export-check",
		StripeIdempotencyKey:       nil,
		StripeEventName:            "meter_usage_reported",
		Value:                      seedValue,
		Status:                     "pending",
		Error:                      nil,
		SentAt:                     pgtype.Timestamptz{},
	})
	if err != nil {
		t.Fatalf("seed billing usage export: %v", err)
	}
	beforeUsageExports = billingUsageExportRowCount(t, teamID)
	beforeUsageExportRows, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports before foreign webhook: %v", err)
	}
	foreignTeamID := uuid.New()
	beforeForeignAccounts := teamBillingAccountRowCount(t, foreignTeamID)
	beforeForeignUsageExports := billingUsageExportRowCount(t, foreignTeamID)
	beforeForeignBillingPeriods := billingPeriodRowCount(t, foreignTeamID)
	beforeForeignCreditGrants := teamCreditGrantRowCount(t, foreignTeamID)
	identifier := fmt.Sprintf("team:%s:period:%d,%d:meter:cpu", foreignTeamID.String(), periodStart.Unix(), periodEnd.Unix())
	fullData, err := json.Marshal(map[string]any{
		"identifier":                identifier,
		"developer_message_summary": "foreign meter error",
	})
	if err != nil {
		t.Fatalf("marshal foreign meter error payload: %v", err)
	}
	retrieved, err := json.Marshal(map[string]json.RawMessage{"data": fullData})
	if err != nil {
		t.Fatalf("marshal foreign meter error retrieval payload: %v", err)
	}
	stripe := &thinEventStripeClient{fakeStripeClient: &fakeStripeClient{}, retrieved: retrieved}
	r := newBillingRouter(t, stripe)
	payload, err := json.Marshal(map[string]any{
		"id":      "evt_foreign_meter_error",
		"type":    "v1.billing.meter.error_report_triggered",
		"created": time.Now().UTC().Unix(),
	})
	if err != nil {
		t.Fatalf("marshal foreign meter error webhook payload: %v", err)
	}
	signedAt := time.Now().UTC()
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, signedAt, testStripeMeterErrorWebhookSecret))
	w := doRequest(r, req)
	if w.Code != http.StatusOK {
		t.Fatalf("foreign thin meter webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "approved" {
		t.Fatalf("foreign thin meter webhook changed local billing period status to %q", got)
	}
	afterExport, err := testQueries.GetBillingUsageExportByIdentifier(context.Background(), seededExport.StripeMeterEventIdentifier)
	if err != nil {
		t.Fatalf("load seeded billing usage export after foreign webhook: %v", err)
	}
	if afterExport.Status != seededExport.Status {
		t.Fatalf("billing_usage_export status changed from %q to %q", seededExport.Status, afterExport.Status)
	}
	if derefString(afterExport.Error) != derefString(seededExport.Error) {
		t.Fatalf("billing_usage_export error changed from %q to %q", derefString(seededExport.Error), derefString(afterExport.Error))
	}
	if afterExport.CreatedAt != seededExport.CreatedAt {
		t.Fatalf("billing_usage_export created_at changed from %v to %v", seededExport.CreatedAt, afterExport.CreatedAt)
	}
	if afterExport.UpdatedAt != seededExport.UpdatedAt {
		t.Fatalf("billing_usage_export updated_at changed from %v to %v", seededExport.UpdatedAt, afterExport.UpdatedAt)
	}
	if afterExport.SentAt.Valid != seededExport.SentAt.Valid || (afterExport.SentAt.Valid && !afterExport.SentAt.Time.Equal(seededExport.SentAt.Time)) {
		t.Fatalf("billing_usage_export sent_at changed from %v to %v", seededExport.SentAt, afterExport.SentAt)
	}
	if derefString(afterExport.StripeIdempotencyKey) != derefString(seededExport.StripeIdempotencyKey) {
		t.Fatalf("billing_usage_export idempotency key changed from %q to %q", derefString(seededExport.StripeIdempotencyKey), derefString(afterExport.StripeIdempotencyKey))
	}
	afterUsageExportRows, err := testQueries.ListBillingUsageExportsForPeriod(context.Background(), db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports after foreign webhook: %v", err)
	}
	if !reflect.DeepEqual(afterUsageExportRows, beforeUsageExportRows) {
		t.Fatalf("billing_usage_export rows changed from %#v to %#v", beforeUsageExportRows, afterUsageExportRows)
	}
	if got := billingUsageExportRowCount(t, teamID); got != beforeUsageExports {
		t.Fatalf("billing_usage_export row count changed from %d to %d", beforeUsageExports, got)
	}
	if got := billingPeriodRowCount(t, teamID); got != beforeBillingPeriods {
		t.Fatalf("team_billing_period row count changed from %d to %d", beforeBillingPeriods, got)
	}
	if got := teamCreditGrantRowCount(t, teamID); got != beforeCreditGrants {
		t.Fatalf("team_credit_grant row count changed from %d to %d", beforeCreditGrants, got)
	}
	if got := teamBillingAccountRowCount(t, foreignTeamID); got != beforeForeignAccounts {
		t.Fatalf("foreign team_billing_account row count changed from %d to %d", beforeForeignAccounts, got)
	}
	if got := billingUsageExportRowCount(t, foreignTeamID); got != beforeForeignUsageExports {
		t.Fatalf("foreign billing_usage_export row count changed from %d to %d", beforeForeignUsageExports, got)
	}
	if got := billingPeriodRowCount(t, foreignTeamID); got != beforeForeignBillingPeriods {
		t.Fatalf("foreign team_billing_period row count changed from %d to %d", beforeForeignBillingPeriods, got)
	}
	if got := teamCreditGrantRowCount(t, foreignTeamID); got != beforeForeignCreditGrants {
		t.Fatalf("foreign team_credit_grant row count changed from %d to %d", beforeForeignCreditGrants, got)
	}
}

func TestIntegration_StripeThinMeterErrorReconcilesByIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	baseStripe := &fakeStripeClient{}
	if w := doInternal(newBillingRouter(t, baseStripe), "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), ""); w.Code != http.StatusOK {
		t.Fatalf("live export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	rows, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{TeamID: teamID, PeriodStart: periodStart, PeriodEnd: periodEnd})
	if err != nil || len(rows) == 0 || rows[0].StripeIdempotencyKey == nil {
		t.Fatalf("load live export attempts: err=%v rows=%d", err, len(rows))
	}
	fullData, err := json.Marshal(map[string]any{
		"developer_message_summary": "There is 1 invalid event",
		"reason":                    map[string]any{"error_types": []any{map[string]any{"sample_errors": []any{map[string]any{"request": map[string]any{"idempotency_key": *rows[0].StripeIdempotencyKey}}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieved, err := json.Marshal(map[string]json.RawMessage{"data": fullData})
	if err != nil {
		t.Fatal(err)
	}
	stripe := &thinEventStripeClient{fakeStripeClient: &fakeStripeClient{}, retrieved: retrieved}
	r := newBillingRouter(t, stripe)
	payload, err := json.Marshal(map[string]any{"id": "evt_thin_meter_error", "type": "v1.billing.meter.error_report_triggered", "created": "2026-07-02T12:00:00.000Z"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC(), testStripeMeterErrorWebhookSecret))
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("thin meter webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := exportAttemptCount(t, teamID, "failed"); got == 0 {
		t.Fatal("thin meter webhook did not mark the matched export failed")
	}
	stripe.retrieveErrOnCall = 2
	dupReq := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	dupReq.Header.Set("Content-Type", "application/json")
	dupReq.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC(), testStripeMeterErrorWebhookSecret))
	if w := doRequest(r, dupReq); w.Code != http.StatusOK {
		t.Fatalf("duplicate thin meter webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	invalidReq := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	invalidReq.Header.Set("Content-Type", "application/json")
	invalidReq.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC(), "whsec_unconfigured"))
	if w := doRequest(r, invalidReq); w.Code != http.StatusUnauthorized {
		t.Fatalf("webhook with unknown signing secret: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_StripeSubscriptionEventArrivesBeforeCheckoutSubscriptionID(t *testing.T) {
	ctx := context.Background()
	teamID, _, ownerID := seedTeamAndKeyWithRole(t, "team_owner")
	customerID := "cus_" + teamID.String()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_status)
		VALUES ($1, $2, 'incomplete')
	`, teamID, customerID); err != nil {
		t.Fatalf("seed billing account without subscription: %v", err)
	}

	created := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	payload := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_subscription_before_checkout", "customer.subscription.updated", "sub_before_checkout", customerID, "active", created, created, created.AddDate(0, 1, 0), map[string]string{
		"activation_user_id": ownerID.String(),
	})
	r := newBillingRouter(t, &fakeStripeClient{})
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("subscription-before-checkout webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account: %v", err)
	}
	if account.StripeSubscriptionID == nil || *account.StripeSubscriptionID != "sub_before_checkout" {
		t.Fatalf("subscription id = %q, want sub_before_checkout", derefString(account.StripeSubscriptionID))
	}
}

func TestIntegration_StripeWebhookIgnoresForeignOrStaleSubscriptionEvents(t *testing.T) {
	ctx := context.Background()
	teamID, _, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, false)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id) VALUES ($1, $2)`, teamID, "cus_"+teamID.String()); err != nil {
		t.Fatalf("seed Stripe customer mapping: %v", err)
	}
	beforeUsageExports, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports before foreign/stale webhooks: %v", err)
	}
	beforeBillingPeriod, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing period before foreign/stale webhooks: %v", err)
	}
	beforeCreditGrants, err := testQueries.ListTeamCreditGrants(ctx, teamID)
	if err != nil {
		t.Fatalf("load credit grants before foreign/stale webhooks: %v", err)
	}
	r := newBillingRouter(t, &fakeStripeClient{})

	currentCreated := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	currentPayload := stripeSubscriptionWebhookPayload(t, "evt_subscription_current", "customer.subscription.created", "sub_current", "cus_"+teamID.String(), "active", currentCreated, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	currentSig := stripeSignature(t, currentPayload, time.Now().UTC())
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(currentPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", currentSig)
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("current subscription webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	foreignPayload := stripeSubscriptionWebhookPayload(t, "evt_subscription_foreign", "customer.subscription.deleted", "sub_foreign", "cus_"+teamID.String(), "canceled", currentCreated.Add(2*time.Hour), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	foreignSig := stripeSignature(t, foreignPayload, time.Now().UTC())
	req = httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(foreignPayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", foreignSig)
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("foreign subscription webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	stalePayload := stripeSubscriptionWebhookPayload(t, "evt_subscription_stale", "customer.subscription.updated", "sub_current", "cus_"+teamID.String(), "past_due", currentCreated.Add(-2*time.Hour), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	staleSig := stripeSignature(t, stalePayload, time.Now().UTC())
	req = httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(stalePayload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", staleSig)
	if w := doRequest(r, req); w.Code != http.StatusOK {
		t.Fatalf("stale subscription webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account: %v", err)
	}
	if account.StripeSubscriptionID == nil || *account.StripeSubscriptionID != "sub_current" {
		t.Fatalf("subscription id = %q, want sub_current", derefString(account.StripeSubscriptionID))
	}
	if account.StripeSubscriptionStatus == nil || *account.StripeSubscriptionStatus != "active" {
		t.Fatalf("subscription status = %q, want active", derefString(account.StripeSubscriptionStatus))
	}
	if !account.CurrentPeriodStart.Valid || !account.CurrentPeriodStart.Time.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("current period start = %v, want 2026-07-01", account.CurrentPeriodStart)
	}
	if !account.CurrentPeriodEnd.Valid || !account.CurrentPeriodEnd.Time.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("current period end = %v, want 2026-08-01", account.CurrentPeriodEnd)
	}
	if !account.StripeSubscriptionEventAt.Valid || !account.StripeSubscriptionEventAt.Time.Equal(currentCreated) {
		t.Fatalf("subscription event at = %v, want %v", account.StripeSubscriptionEventAt, currentCreated)
	}
	afterUsageExports, err := testQueries.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing usage exports after foreign/stale webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterUsageExports, beforeUsageExports) {
		t.Fatalf("billing_usage_export rows changed from %#v to %#v", beforeUsageExports, afterUsageExports)
	}
	afterBillingPeriod, err := testQueries.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		t.Fatalf("load billing period after foreign/stale webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterBillingPeriod, beforeBillingPeriod) {
		t.Fatalf("team_billing_period row changed from %#v to %#v", beforeBillingPeriod, afterBillingPeriod)
	}
	afterCreditGrants, err := testQueries.ListTeamCreditGrants(ctx, teamID)
	if err != nil {
		t.Fatalf("load credit grants after foreign/stale webhooks: %v", err)
	}
	if !reflect.DeepEqual(afterCreditGrants, beforeCreditGrants) {
		t.Fatalf("team_credit_grant rows changed from %#v to %#v", beforeCreditGrants, afterCreditGrants)
	}
}

func TestIntegration_StripeWebhookRejectsOversizedBodies(t *testing.T) {
	r := newBillingRouter(t, &fakeStripeClient{})
	body := strings.Repeat("x", (1<<20)+1)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", "t=1,v1=deadbeef")

	w := doRequest(r, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized webhook: expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_StripeInvoiceWebhookUpdatesInvoiceStatusOnly(t *testing.T) {
	ctx := context.Background()
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	r := newBillingRouter(t, &fakeStripeClient{})

	payload, err := json.Marshal(map[string]any{
		"id":   "evt_invoice_status",
		"type": "invoice.finalized",
		"data": map[string]any{
			"object": map[string]any{
				"id":           "in_test_status",
				"customer":     "cus_" + teamID.String(),
				"subscription": "sub_test_status",
				"status":       "open",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal invoice payload: %v", err)
	}
	sig := stripeSignature(t, payload, time.Now().UTC())

	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", sig)
	w := doRequest(r, req)
	if w.Code != http.StatusOK {
		t.Fatalf("invoice webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account: %v", err)
	}
	if account.StripeSubscriptionStatus == nil || *account.StripeSubscriptionStatus != "active" {
		t.Fatalf("subscription status = %v, want unchanged active", account.StripeSubscriptionStatus)
	}
	if account.StripeInvoiceStatus == nil || *account.StripeInvoiceStatus != "open" {
		t.Fatalf("invoice status = %v, want open", account.StripeInvoiceStatus)
	}
	if derefString(account.StripeSubscriptionID) != "sub_"+teamID.String() {
		t.Fatalf("invoice replaced subscription association: %v", account.StripeSubscriptionID)
	}
}

func TestIntegration_StripeSubmissionFailureDoesNotMarkExported(t *testing.T) {
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{reportErr: fmt.Errorf("meter rejected")}
	r := newBillingRouter(t, stripe)

	w := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("failed live export: expected 502, got %d: %s", w.Code, w.Body.String())
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exporting" {
		t.Fatalf("period status after failed export = %q, want exporting", got)
	}
	if !teamBillingUsageExportedAtValid(t, teamID, periodStart, periodEnd) {
		t.Fatal("team billing usage should be frozen after Stripe failure")
	}
	if got := exportAttemptCount(t, teamID, "failed"); got == 0 {
		t.Fatal("expected a failed billing export attempt to be recorded")
	}
}

func TestIntegration_StripeSubmissionFailureFreezesUsageOnRetry(t *testing.T) {
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{reportErr: fmt.Errorf("meter rejected"), reportErrAt: 2}
	r := newBillingRouter(t, stripe)

	first := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if first.Code != http.StatusBadGateway {
		t.Fatalf("partial live export: expected 502, got %d: %s", first.Code, first.Body.String())
	}
	if got := len(stripe.reportCalls); got != 2 {
		t.Fatalf("partial live export stripe calls = %d, want 2", got)
	}
	for i, call := range stripe.reportCalls {
		if got := call.Value; got != "2.000000000000" {
			t.Fatalf("partial export call %d quantity = %q, want 2 normalized hours", i, got)
		}
	}
	failedCall := stripe.reportCalls[1]

	if _, err := testPool.Exec(context.Background(), `
		UPDATE team_billing_usage
		SET vcpu_seconds = 10800,
		    memory_mib_seconds = 11059200
		WHERE team_id = $1 AND period_start = $2 AND period_end = $3
	`, teamID, periodStart, periodEnd); err != nil {
		t.Fatalf("mutate frozen usage for retry: %v", err)
	}

	second := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if second.Code != http.StatusOK {
		t.Fatalf("partial export retry: expected 200, got %d: %s", second.Code, second.Body.String())
	}
	if got := len(stripe.reportCalls); got != 3 {
		t.Fatalf("retry stripe calls = %d, want 3", got)
	}
	if got := stripe.reportCalls[2].Value; got != "3.000000000000" {
		t.Fatalf("retry stripe quantity = %q, want changed 3 normalized hours", got)
	}
	if got := stripe.reportCalls[2].Identifier; got == failedCall.Identifier {
		t.Fatalf("retry reused Stripe meter identifier %q after payload changed", got)
	}
	if !strings.HasPrefix(stripe.reportCalls[2].Identifier, "team:") {
		t.Fatalf("retry Stripe meter identifier = %q, want logical meter identifier prefix", stripe.reportCalls[2].Identifier)
	}
	if got := stripe.reportCalls[2].IdempotencyKey; got == failedCall.IdempotencyKey {
		t.Fatalf("retry reused idempotency key %q after payload changed", got)
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after retry = %q, want exported", got)
	}
}

func TestIntegration_StripeSubmissionFailureRetryKeepsIdentifierForUnchangedPayload(t *testing.T) {
	teamID, periodID, _, _ := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{reportErr: fmt.Errorf("meter rejected"), reportErrAt: 2}
	r := newBillingRouter(t, stripe)

	first := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if first.Code != http.StatusBadGateway {
		t.Fatalf("failed live export: expected 502, got %d: %s", first.Code, first.Body.String())
	}
	failedCall := stripe.reportCalls[1]

	second := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if second.Code != http.StatusOK {
		t.Fatalf("unchanged payload retry: expected 200, got %d: %s", second.Code, second.Body.String())
	}
	if got := stripe.reportCalls[2].Identifier; got != failedCall.Identifier {
		t.Fatalf("unchanged payload retry identifier = %q, want %q", got, failedCall.Identifier)
	}
	if got := stripe.reportCalls[2].IdempotencyKey; got != failedCall.IdempotencyKey {
		t.Fatalf("unchanged payload retry idempotency key = %q, want %q", got, failedCall.IdempotencyKey)
	}
	if got := stripe.reportCalls[2].Value; got != failedCall.Value {
		t.Fatalf("unchanged payload retry value = %q, want %q", got, failedCall.Value)
	}
}

func TestIntegration_LiveBillingSkipsZeroUsageExports(t *testing.T) {
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)

	if _, err := testPool.Exec(context.Background(), `
		DELETE FROM sandbox_compute_billing_interval
		WHERE team_id = $1
	`, teamID); err != nil {
		t.Fatalf("clear compute intervals: %v", err)
	}
	if _, err := testPool.Exec(context.Background(), `
		DELETE FROM sandbox_storage_interval
		WHERE team_id = $1
	`, teamID); err != nil {
		t.Fatalf("clear storage intervals: %v", err)
	}

	w := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("zero usage export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.reportCalls); got != 0 {
		t.Fatalf("zero usage export stripe calls = %d, want 0", got)
	}
	if got := exportAttemptCount(t, teamID, "skipped_zero"); got != 2 {
		t.Fatalf("skipped zero attempts = %d, want 2", got)
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after zero usage export = %q, want exported", got)
	}
	if !teamBillingUsageExportedAtValid(t, teamID, periodStart, periodEnd) {
		t.Fatal("team billing usage was not marked exported after zero usage export")
	}
}

func TestIntegration_ShadowExportDoesNotBlockLaterLiveExport(t *testing.T) {
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, false, false)
	adminID := seedPlatformAdminProfile(t)
	if _, err := testQueries.ApproveTeamBillingPeriod(context.Background(), db.ApproveTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		ApprovedBy:  pgtype.UUID{Bytes: adminID, Valid: true},
	}); err != nil {
		t.Fatalf("approve billing period: %v", err)
	}
	summaryCalls := make(map[string]int)
	stripe := &summaryStripeClient{
		fakeStripeClient: &fakeStripeClient{},
		countedUsage: func(eventName, customer string, start, end time.Time) (string, error) {
			if customer != "cus_"+teamID.String() || !start.Equal(periodStart) || !end.Equal(periodEnd) {
				return "", fmt.Errorf("unexpected summary scope: %s %s %s", customer, start, end)
			}
			summaryCalls[eventName]++
			switch summaryCalls[eventName] {
			case 1:
				return "0", nil
			case 2:
				return "2.000000000000", nil
			default:
				return "", fmt.Errorf("unexpected summary read for %s", eventName)
			}
		},
	}
	r := newBillingRouter(t, stripe)

	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')
	`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatalf("seed billing account: %v", err)
	}

	shadow := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if shadow.Code != http.StatusOK {
		t.Fatalf("shadow export: expected 200, got %d: %s", shadow.Code, shadow.Body.String())
	}
	if got := exportAttemptCount(t, teamID, "skipped_shadow"); got != 2 {
		t.Fatalf("skipped shadow attempts = %d, want 2", got)
	}
	if len(stripe.reportCalls) != 0 || len(summaryCalls) != 0 {
		t.Fatal("shadow export contacted Stripe")
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after shadow export = %q, want exported", got)
	}

	if _, err := testPool.Exec(context.Background(), `
		UPDATE team_feature_flag
		SET enabled = true
		WHERE team_id = $1
		  AND key = 'billing_export_enabled'
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}

	live := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if live.Code != http.StatusOK {
		t.Fatalf("live export after shadow attempts: expected 200, got %d: %s", live.Code, live.Body.String())
	}
	if got := len(stripe.reportCalls); got != 2 {
		t.Fatalf("live export stripe calls = %d, want 2", got)
	}
	if got := exportAttemptCount(t, teamID, "skipped_shadow"); got != 2 {
		t.Fatalf("preserved shadow attempts = %d, want 2", got)
	}
	var enrolled bool
	if err := testPool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM billing_incremental_period
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3)`, teamID, periodStart, periodEnd).Scan(&enrolled); err != nil {
		t.Fatal(err)
	}
	if !enrolled {
		t.Fatal("live export did not enroll the shadow period in incremental accounting")
	}
	for _, call := range stripe.reportCalls {
		if call.Value != "2.000000000000" || summaryCalls[call.EventName] != 2 {
			t.Fatalf("live export was not reconciled for the expected quantity: %+v, summary calls %v", call, summaryCalls)
		}
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after live export = %q, want exported", got)
	}
}
