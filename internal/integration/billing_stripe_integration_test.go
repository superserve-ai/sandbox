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

type fakeStripeClient struct {
	mu              sync.Mutex
	reportCalls     []api.StripeReportMeterEventParams
	checkoutCalls   []api.StripeCreateCheckoutSessionParams
	portalCalls     []api.StripeCreateCustomerPortalSessionParams
	customerCalls   []api.StripeCreateCustomerParams
	reportErr       error
	reportErrAt     int
	nextCustomerID  string
	nextCheckoutURL string
	nextPortalURL   string
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
		Port:                   "0",
		VMDAddress:             "localhost:0",
		SystemTeamID:           testSystemTeamID.String(),
		StripeWebhookSecret:    testStripeWebhookSecret,
		StripeAPIVersion:       "2025-06-30",
		StripeCheckoutPriceIDs: []string{"price_cpu", "price_memory", "price_storage"},
		AppAllowedOrigins:      []string{"https://app.superserve.test"},
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

func stripeSignature(t *testing.T, payload []byte, ts time.Time) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(testStripeWebhookSecret))
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

func TestIntegration_StripeWebhookIgnoresForeignOrStaleSubscriptionEvents(t *testing.T) {
	ctx := context.Background()
	teamID, _, _, _ := seedBillingPeriodForStripe(t, true, true)
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
