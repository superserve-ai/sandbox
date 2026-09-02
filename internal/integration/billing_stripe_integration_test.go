//go:build integration

package integration

import (
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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

const testStripeWebhookSecret = "whsec_test_secret"
const testStripeMeterErrorWebhookSecret = "whsec_test_meter_error_secret"

type fakeStripeClient struct {
	mu               sync.Mutex
	reportCalls      []api.StripeReportMeterEventParams
	checkoutCalls    []api.StripeCreateCheckoutSessionParams
	portalCalls      []api.StripeCreateCustomerPortalSessionParams
	customerCalls    []api.StripeCreateCustomerParams
	creditGrantCalls []api.StripeCreateBillingCreditGrantParams
	reportErr        error
	reportErrAt      int
	nextCustomerID   string
	nextCheckoutURL  string
	nextPortalURL    string
}

type thinEventStripeClient struct {
	*fakeStripeClient
	retrieved         json.RawMessage
	retrieveCalls     int
	retrieveErrOnCall int
	retrieveErr       error
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
		// Keep the fixture's Stripe customer IDs unique across integration tests;
		// the database enforces uniqueness globally, while each test uses its own team.
		id = "cus_test_" + params.TeamID.String()
	}
	return api.StripeCustomer{ID: id}, nil
}

func (f *fakeStripeClient) CreateBillingCreditGrant(_ context.Context, params api.StripeCreateBillingCreditGrantParams) (api.StripeBillingCreditGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creditGrantCalls = append(f.creditGrantCalls, params)
	return api.StripeBillingCreditGrant{ID: "credgrant_test_123"}, nil
}

func (f *fakeStripeClient) CreateCheckoutSession(_ context.Context, params api.StripeCreateCheckoutSessionParams) (api.StripeCheckoutSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkoutCalls = append(f.checkoutCalls, params)
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
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	cfg := &config.Config{
		Port:                          "0",
		VMDAddress:                    "localhost:0",
		SystemTeamID:                  testSystemTeamID.String(),
		StripeWebhookSecret:           testStripeWebhookSecret,
		StripeMeterErrorWebhookSecret: testStripeMeterErrorWebhookSecret,
		StripeAPIVersion:              "2025-06-30",
		StripeCheckoutPriceIDs:        []string{"price_cpu", "price_memory", "price_storage"},
		AppAllowedOrigins:             []string{"https://app.superserve.test"},
	}
	h := api.NewHandlers(&stubVMD{}, testQueries, cfg)
	h.Pool = testPool
	h.Stripe = stripe
	return api.SetupRouter(t.Context(), h, testPool)
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
				"id":                  "cs_test_123",
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

func TestIntegration_ExportTeamBillingPeriodClaimsCommercialAnchor(t *testing.T) {
	ctx := context.Background()
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, false)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{}
	r := newBillingRouter(t, stripe)

	w := doInternal(r, "POST", "/internal/teams/"+teamID.String()+"/billing/periods/"+periodID+"/export", adminID.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("shadow export with anchor claim: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.reportCalls); got != 0 {
		t.Fatalf("stripe report calls = %d, want 0 in shadow mode", got)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account after export: %v", err)
	}
	if !account.CommercialBillingAnchor.Valid {
		t.Fatal("commercial billing anchor was not claimed during export")
	}
	if !account.CommercialBillingAnchor.Time.Equal(periodStart) {
		t.Fatalf("commercial billing anchor = %s, want %s", account.CommercialBillingAnchor.Time, periodStart)
	}
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after shadow export = %q, want exported", got)
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
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	stripe := &fakeStripeClient{nextCheckoutURL: "https://checkout.stripe.test/session"}
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
	if got := stripe.checkoutCalls[0].IdempotencyKey; got == "" {
		t.Fatal("checkout idempotency key was not set")
	}
}

func TestIntegration_CreateStripeCheckoutSessionWithCommercialAnchorUsesCurrentActivation(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatalf("enable billing export: %v", err)
	}
	anchor := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	if _, err := testQueries.ClaimTeamCommercialBillingAnchor(ctx, db.ClaimTeamCommercialBillingAnchorParams{
		TeamID: teamID,
		Anchor: anchor,
	}); err != nil {
		t.Fatalf("claim commercial billing anchor: %v", err)
	}

	stripe := &fakeStripeClient{nextCheckoutURL: "https://checkout.stripe.test/session"}
	r := newBillingRouter(t, stripe)

	w := do(r, "POST", "/stripe/checkout-session", apiKey, `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("checkout session with commercial anchor: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := len(stripe.checkoutCalls); got != 1 {
		t.Fatalf("checkout calls = %d, want 1", got)
	}
	if stripe.checkoutCalls[0].BackdateStartDate != nil {
		t.Fatalf("checkout backdate_start_date = %v, want nil for normal activation", stripe.checkoutCalls[0].BackdateStartDate)
	}

	customerID := "cus_test_" + teamID.String()
	subscriptionID := "sub_" + teamID.String()
	checkoutCreatedAt := anchor.Add(2 * time.Hour)
	checkoutPayload := stripeCheckoutWebhookPayload(t, "evt_checkout_completed", teamID.String(), customerID, subscriptionID, checkoutCreatedAt)
	checkoutReq := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(checkoutPayload)))
	checkoutReq.Header.Set("Content-Type", "application/json")
	checkoutReq.Header.Set("Stripe-Signature", stripeSignature(t, checkoutPayload, time.Now().UTC()))
	if checkoutResp := doRequest(r, checkoutReq); checkoutResp.Code != http.StatusOK {
		t.Fatalf("checkout webhook: expected 200, got %d: %s", checkoutResp.Code, checkoutResp.Body.String())
	}

	periodStart := anchor
	periodEnd := anchor.AddDate(0, 1, 0)
	subscriptionCreatedAt := checkoutCreatedAt.Add(time.Minute)
	subscriptionPayload := stripeSubscriptionWebhookPayload(t, "evt_subscription_created", "customer.subscription.created", subscriptionID, customerID, "active", subscriptionCreatedAt, periodStart, periodEnd)
	subscriptionReq := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(subscriptionPayload)))
	subscriptionReq.Header.Set("Content-Type", "application/json")
	subscriptionReq.Header.Set("Stripe-Signature", stripeSignature(t, subscriptionPayload, time.Now().UTC()))
	if subscriptionResp := doRequest(r, subscriptionReq); subscriptionResp.Code != http.StatusOK {
		t.Fatalf("subscription created webhook: expected 200, got %d: %s", subscriptionResp.Code, subscriptionResp.Body.String())
	}

	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatalf("load billing account after subscription activation: %v", err)
	}
	if !account.CommercialBillingAnchor.Valid || !account.CommercialBillingAnchor.Time.Equal(anchor) {
		t.Fatalf("commercial billing anchor = %v, want %s", account.CommercialBillingAnchor, anchor)
	}
	if account.StripeSubscriptionID == nil || *account.StripeSubscriptionID != subscriptionID {
		t.Fatalf("stripe subscription id = %q, want %q", derefString(account.StripeSubscriptionID), subscriptionID)
	}
	if !account.CurrentPeriodStart.Valid || !account.CurrentPeriodStart.Time.Equal(periodStart) {
		t.Fatalf("current period start = %v, want %s", account.CurrentPeriodStart, periodStart)
	}
	if !account.CurrentPeriodEnd.Valid || !account.CurrentPeriodEnd.Time.Equal(periodEnd) {
		t.Fatalf("current period end = %v, want %s", account.CurrentPeriodEnd, periodEnd)
	}
}

func TestIntegration_StripeActivationEndsTrialAndGrantsPromoCreditOnce(t *testing.T) {
	ctx := context.Background()
	teamID, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
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
		payload := stripeSubscriptionWebhookPayload(t, eventID, "customer.subscription.updated", subscriptionID, customerID, "active", eventCreated, periodStart, periodEnd)
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
	if got := len(stripe.creditGrantCalls); got != 1 {
		t.Fatalf("Stripe credit grant calls = %d, want 1", got)
	}
	if got := stripe.creditGrantCalls[0].AmountCents; got != 9500 {
		t.Fatalf("Stripe credit grant amount = %d, want 9500 cents", got)
	}
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
	_ = teamID
}

func TestIntegration_CustomerPortalSessionDeniedInShadowMode(t *testing.T) {
	teamID, apiKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
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
	teamID, periodID, _, _ := seedBillingPeriodForStripe(t, true, true)
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

func TestIntegration_StripeWebhookPersistsFailureAfterRollback(t *testing.T) {
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

func TestIntegration_StripeWebhookIgnoresForeignOrStaleSubscriptionEvents(t *testing.T) {
	ctx := context.Background()
	teamID, _, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, true)
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
	teamID, periodID, periodStart, periodEnd := seedBillingPeriodForStripe(t, true, false)
	adminID := seedPlatformAdminProfile(t)
	stripe := &fakeStripeClient{}
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
	if got := billingPeriodStatus(t, teamID, periodStart, periodEnd); got != "exported" {
		t.Fatalf("period status after live export = %q, want exported", got)
	}
}
