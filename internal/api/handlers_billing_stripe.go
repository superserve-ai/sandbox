package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	billingModeShadow         = "shadow"
	billingModeLive           = "live"
	maxStripeWebhookBodyBytes = 1 << 20

	platformBillingWritePermission = "platform:billing:write"
)

var errBillingRedirectOriginsNotConfigured = errors.New("billing redirect origins are not configured")

type StripeBillingClient interface {
	CreateCustomer(ctx context.Context, params StripeCreateCustomerParams) (StripeCustomer, error)
	CreateCheckoutSession(ctx context.Context, params StripeCreateCheckoutSessionParams) (StripeCheckoutSession, error)
	CreateCustomerPortalSession(ctx context.Context, params StripeCreateCustomerPortalSessionParams) (StripePortalSession, error)
	ReportMeterEvent(ctx context.Context, params StripeReportMeterEventParams) error
}

type stripeEventRetriever interface {
	RetrieveEvent(ctx context.Context, eventID string) (json.RawMessage, error)
}

type StripeCreateCustomerParams struct {
	TeamID         uuid.UUID
	Name           string
	IdempotencyKey string
}

type StripeCustomer struct {
	ID string
}

type StripeCreateCheckoutSessionParams struct {
	CustomerID        string
	SuccessURL        string
	CancelURL         string
	ClientReferenceID string
	PriceIDs          []string
	IdempotencyKey    string
}

type StripeCheckoutSession struct {
	ID  string
	URL string
}

type StripeCreateCustomerPortalSessionParams struct {
	CustomerID string
	ReturnURL  string
}

type StripePortalSession struct {
	URL string
}

type StripeReportMeterEventParams struct {
	Identifier     string
	IdempotencyKey string
	EventName      string
	CustomerID     string
	Value          string
	Timestamp      int64
}

type stripeHTTPClient struct {
	baseURL    string
	secretKey  string
	apiVersion string
	httpClient *http.Client
}

type billingUsageResponse struct {
	PeriodID          string                          `json:"period_id"`
	TeamID            string                          `json:"team_id"`
	Status            string                          `json:"status"`
	PeriodStart       time.Time                       `json:"period_start"`
	PeriodEnd         time.Time                       `json:"period_end"`
	VCPUSeconds       float64                         `json:"vcpu_seconds"`
	MemoryMiBSeconds  float64                         `json:"memory_mib_seconds"`
	StorageMiBSeconds float64                         `json:"storage_mib_seconds"`
	CPUVCPUHours      float64                         `json:"cpu_vcpu_hours"`
	MemoryGiBHours    float64                         `json:"memory_gib_hours"`
	StorageGiBHours   float64                         `json:"storage_gib_hours"`
	Resources         []billingUsageResource          `json:"resources"`
	ResourcesByKey    map[string]billingUsageResource `json:"resources_by_key,omitempty"`
	ExportedAt        *time.Time                      `json:"exported_at,omitempty"`
	FinalizedAt       *time.Time                      `json:"finalized_at,omitempty"`
	UpdatedAt         time.Time                       `json:"updated_at"`
}

type billingPeriodResponse struct {
	PeriodID           string     `json:"period_id"`
	PeriodStart        time.Time  `json:"period_start"`
	PeriodEnd          time.Time  `json:"period_end"`
	Status             string     `json:"status"`
	BlockedReason      *string    `json:"blocked_reason,omitempty"`
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
	ExportedAt         *time.Time `json:"exported_at,omitempty"`
	FinalizedAt        *time.Time `json:"finalized_at,omitempty"`
	CancelAtPeriodEnd  *bool      `json:"cancel_at_period_end,omitempty"`
	StripeCustomerID   *string    `json:"stripe_customer_id,omitempty"`
	StripeSubscription *string    `json:"stripe_subscription_id,omitempty"`
	SubscriptionStatus *string    `json:"stripe_subscription_status,omitempty"`
	InvoiceStatus      *string    `json:"stripe_invoice_status,omitempty"`
	CurrentPeriodStart *time.Time `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty"`
}

type billingExportPreviewResponse struct {
	Mode             string                       `json:"mode"`
	PeriodID         string                       `json:"period_id"`
	TeamID           string                       `json:"team_id"`
	Status           string                       `json:"status"`
	StripeCustomerID *string                      `json:"stripe_customer_id,omitempty"`
	Items            []billingExportPreviewItem   `json:"items"`
	Attempts         []billingExportAttemptRecord `json:"attempts"`
}

type billingExportPreviewItem struct {
	ResourceType string  `json:"resource_type"`
	ResourceKey  string  `json:"resource_key"`
	DisplayName  string  `json:"display_name"`
	SortOrder    int     `json:"sort_order"`
	DisplayUnit  string  `json:"display_unit"`
	EventName    string  `json:"stripe_event_name"`
	Identifier   string  `json:"stripe_meter_event_identifier"`
	Value        float64 `json:"value"`
}

type billingExportAttemptRecord struct {
	ID                         string     `json:"id"`
	ResourceType               string     `json:"resource_type"`
	StripeMeterEventIdentifier string     `json:"stripe_meter_event_identifier"`
	StripeEventName            string     `json:"stripe_event_name"`
	Value                      float64    `json:"value"`
	Status                     string     `json:"status"`
	Error                      *string    `json:"error,omitempty"`
	SentAt                     *time.Time `json:"sent_at,omitempty"`
	CreatedAt                  time.Time  `json:"created_at"`
}

type billingCheckoutSessionRequest struct {
	SuccessURL string `json:"success_url"`
	CancelURL  string `json:"cancel_url"`
}

type billingPortalSessionRequest struct {
	ReturnURL string `json:"return_url"`
}

type billingSessionResponse struct {
	URL string `json:"url"`
	ID  string `json:"id,omitempty"`
}

type stripeEventEnvelope struct {
	ID      string                  `json:"id"`
	Type    string                  `json:"type"`
	Created stripeEventTimestamp    `json:"created"`
	Data    stripeEventEnvelopeData `json:"data"`
}

type stripeEventTimestamp int64

func (t *stripeEventTimestamp) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return err
		}
		*t = stripeEventTimestamp(parsed.Unix())
		return nil
	}
	var value int64
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*t = stripeEventTimestamp(value)
	return nil
}

type stripeEventEnvelopeData struct {
	Object json.RawMessage `json:"object"`
}

type stripeSubscriptionObject struct {
	ID                 string                        `json:"id"`
	Customer           string                        `json:"customer"`
	Status             string                        `json:"status"`
	CurrentPeriodStart int64                         `json:"current_period_start"`
	CurrentPeriodEnd   int64                         `json:"current_period_end"`
	CancelAtPeriodEnd  bool                          `json:"cancel_at_period_end"`
	Items              stripeSubscriptionObjectItems `json:"items"`
}

type stripeSubscriptionObjectItems struct {
	Data []stripeSubscriptionItem `json:"data"`
}

type stripeSubscriptionItem struct {
	CurrentPeriodStart int64 `json:"current_period_start"`
	CurrentPeriodEnd   int64 `json:"current_period_end"`
}

type stripeCheckoutCompletedObject struct {
	ID                string `json:"id"`
	Customer          string `json:"customer"`
	Subscription      string `json:"subscription"`
	ClientReferenceID string `json:"client_reference_id"`
}

type stripeInvoiceObject struct {
	ID           string `json:"id"`
	Customer     string `json:"customer"`
	Subscription string `json:"subscription"`
	Status       string `json:"status"`
}

func NewStripeBillingClient(cfg *config.Config) StripeBillingClient {
	if cfg == nil || strings.TrimSpace(cfg.StripeSecretKey) == "" || strings.TrimSpace(cfg.StripeAPIVersion) == "" {
		return nil
	}
	return &stripeHTTPClient{
		baseURL:    strings.TrimRight(cfg.StripeAPIBaseURL, "/"),
		secretKey:  cfg.StripeSecretKey,
		apiVersion: strings.TrimSpace(cfg.StripeAPIVersion),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *stripeHTTPClient) CreateCustomer(ctx context.Context, params StripeCreateCustomerParams) (StripeCustomer, error) {
	form := url.Values{}
	form.Set("name", params.Name)
	form.Set("metadata[team_id]", params.TeamID.String())
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/customers", form, &resp, params.IdempotencyKey); err != nil {
		return StripeCustomer{}, err
	}
	return StripeCustomer{ID: resp.ID}, nil
}

func (c *stripeHTTPClient) CreateCheckoutSession(ctx context.Context, params StripeCreateCheckoutSessionParams) (StripeCheckoutSession, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("customer", params.CustomerID)
	form.Set("success_url", params.SuccessURL)
	form.Set("cancel_url", params.CancelURL)
	form.Set("client_reference_id", params.ClientReferenceID)
	for i, priceID := range params.PriceIDs {
		form.Set(fmt.Sprintf("line_items[%d][price]", i), priceID)
	}
	var resp struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/checkout/sessions", form, &resp, params.IdempotencyKey); err != nil {
		return StripeCheckoutSession{}, err
	}
	return StripeCheckoutSession{ID: resp.ID, URL: resp.URL}, nil
}

func (c *stripeHTTPClient) CreateCustomerPortalSession(ctx context.Context, params StripeCreateCustomerPortalSessionParams) (StripePortalSession, error) {
	form := url.Values{}
	form.Set("customer", params.CustomerID)
	form.Set("return_url", params.ReturnURL)
	var resp struct {
		URL string `json:"url"`
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/billing_portal/sessions", form, &resp, ""); err != nil {
		return StripePortalSession{}, err
	}
	return StripePortalSession{URL: resp.URL}, nil
}

func (c *stripeHTTPClient) ReportMeterEvent(ctx context.Context, params StripeReportMeterEventParams) error {
	form := url.Values{}
	form.Set("event_name", params.EventName)
	form.Set("identifier", params.Identifier)
	if params.Timestamp > 0 {
		form.Set("timestamp", strconv.FormatInt(params.Timestamp, 10))
	}
	form.Set("payload[stripe_customer_id]", params.CustomerID)
	form.Set("payload[value]", params.Value)
	return c.doForm(ctx, http.MethodPost, "/v1/billing/meter_events", form, nil, params.IdempotencyKey)
}

func (c *stripeHTTPClient) RetrieveEvent(ctx context.Context, eventID string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.doForm(ctx, http.MethodGet, "/v2/core/events/"+url.PathEscape(eventID), nil, &raw, ""); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *stripeHTTPClient) doForm(ctx context.Context, method, path string, form url.Values, out any, idempotencyKey string) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.apiVersion == "" {
		return fmt.Errorf("stripe API version is not configured")
	}
	req.Header.Set("Stripe-Version", c.apiVersion)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("stripe %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode stripe response: %w", err)
	}
	return nil
}

func (h *Handlers) nowUTC() time.Time {
	if h != nil && h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) billingExportEnabled(ctx context.Context, teamID uuid.UUID) (bool, error) {
	return h.DB.IsFeatureEnabledForTeam(ctx, db.IsFeatureEnabledForTeamParams{
		Key:    "billing_export_enabled",
		TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
	})
}

func (h *Handlers) billingExportMode(ctx context.Context, teamID uuid.UUID) (string, error) {
	enabled, err := h.billingExportEnabled(ctx, teamID)
	if err != nil {
		return "", err
	}
	// The flag is the billing mode switch: disabled means shadow, enabled means live.
	if enabled {
		return billingModeLive, nil
	}
	return billingModeShadow, nil
}

func (h *Handlers) billingStorageBillingEnabled(ctx context.Context, teamID uuid.UUID) (bool, error) {
	return h.DB.IsFeatureEnabledForTeam(ctx, db.IsFeatureEnabledForTeamParams{
		Key:    "billing_storage_billing_enabled",
		TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
	})
}

func (h *Handlers) validateBillingRedirectURL(raw string) (string, error) {
	if h.Config == nil || len(h.Config.AppAllowedOrigins) == 0 {
		return "", errBillingRedirectOriginsNotConfigured
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("redirect URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("redirect URL must be absolute and must not contain credentials")
	}
	for _, origin := range h.Config.AppAllowedOrigins {
		allowed, err := url.Parse(origin)
		if err != nil {
			continue
		}
		if allowed.Scheme == parsed.Scheme && allowed.Host == parsed.Host {
			return parsed.String(), nil
		}
	}
	return "", fmt.Errorf("redirect URL must match an allowed application origin")
}

func (h *Handlers) periodStatusForWindow(periodEnd, now time.Time) string {
	if periodEnd.After(now.UTC()) {
		return "open"
	}
	return "validating"
}

func (h *Handlers) requirePlatformBilling(c *gin.Context, permission string) (uuid.UUID, bool) {
	actorID, err := internalActorID(c)
	if err != nil {
		return uuid.Nil, false
	}
	if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
		if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrForbidden)
			return uuid.Nil, false
		}
		log.Error().Err(err).Str("permission", permission).Msg("platform billing session validation failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	svc := h.rbacService()
	if svc == nil {
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if err := svc.RequirePlatformPermission(c.Request.Context(), actorID, permission); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return uuid.Nil, false
		}
		log.Error().Err(err).Str("permission", permission).Msg("platform billing permission check failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	return actorID, true
}

func (h *Handlers) GetTeamBillingUsage(c *gin.Context) {
	h.getTeamBillingUsage(c, false)
}

func (h *Handlers) GetPlatformTeamBillingUsage(c *gin.Context) {
	h.getTeamBillingUsage(c, true)
}

func (h *Handlers) getTeamBillingUsage(c *gin.Context, platform bool) {
	teamID, ok := h.authorizeTeamBillingRead(c, platform)
	if !ok {
		return
	}
	periodStart, periodEnd, err := billingPeriodFromRequest(c)
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	usage, period, err := h.readBillingSnapshot(c.Request.Context(), teamID, periodStart, periodEnd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing snapshot failed")
		respondError(c, ErrInternal)
		return
	}
	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, h.billingUsageResponseFromUsage(period, usage, h.billingResourceStates(storageBillingEnabled)))
}

func (h *Handlers) ListTeamBillingPeriods(c *gin.Context) {
	h.listTeamBillingPeriods(c, false)
}

func (h *Handlers) ListPlatformTeamBillingPeriods(c *gin.Context) {
	h.listTeamBillingPeriods(c, true)
}

func (h *Handlers) listTeamBillingPeriods(c *gin.Context, platform bool) {
	teamID, ok := h.authorizeTeamBillingRead(c, platform)
	if !ok {
		return
	}
	now := h.nowUTC()
	currentStart, currentEnd := currentBillingPeriod(now)
	if _, _, err := h.upsertBillingSnapshot(c.Request.Context(), teamID, currentStart, currentEnd); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("seed current billing period failed")
		respondError(c, ErrInternal)
		return
	}

	limitCount := int32(12)
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 100 {
			respondErrorMsg(c, "bad_request", "limit must be between 1 and 100", http.StatusBadRequest)
			return
		}
		limitCount = int32(n)
	}

	periods, err := h.DB.ListTeamBillingPeriods(c.Request.Context(), db.ListTeamBillingPeriodsParams{
		TeamID:     teamID,
		LimitCount: limitCount,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("list billing periods failed")
		respondError(c, ErrInternal)
		return
	}

	account, _ := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	resp := make([]billingPeriodResponse, 0, len(periods))
	for _, period := range periods {
		resp = append(resp, billingPeriodResponseFromDB(period, account))
	}
	c.JSON(http.StatusOK, gin.H{"periods": resp})
}

func (h *Handlers) GetTeamBillingExportPreview(c *gin.Context) {
	h.getTeamBillingExportPreview(c, false)
}

func (h *Handlers) GetPlatformTeamBillingExportPreview(c *gin.Context) {
	h.getTeamBillingExportPreview(c, true)
}

func (h *Handlers) getTeamBillingExportPreview(c *gin.Context, platform bool) {
	teamID, ok := h.authorizeTeamBillingRead(c, platform)
	if !ok {
		return
	}
	periodStart, periodEnd, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	usage, period, err := h.readBillingSnapshot(c.Request.Context(), teamID, periodStart, periodEnd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing snapshot for preview failed")
		respondError(c, ErrInternal)
		return
	}
	account, _ := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	exports, err := h.DB.ListBillingUsageExportsForPeriod(c.Request.Context(), db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("list billing exports for preview failed")
		respondError(c, ErrInternal)
		return
	}

	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	resourceStates := h.billingResourceStates(storageBillingEnabled)

	items, err := billingPreviewItems(teamID, periodStart, periodEnd, usage, resourceStates, derefString(account.StripeCustomerID))
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("build billing preview failed")
		respondError(c, ErrInternal)
		return
	}
	mode, err := h.billingExportMode(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing export mode failed")
		respondError(c, ErrInternal)
		return
	}
	resp := billingExportPreviewResponse{
		Mode:     mode,
		PeriodID: billingPeriodID(periodStart, periodEnd),
		TeamID:   teamID.String(),
		Status:   period.Status,
		Items:    items,
		Attempts: billingExportAttemptsFromRows(exports),
	}
	if account.StripeCustomerID != nil {
		resp.StripeCustomerID = account.StripeCustomerID
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handlers) ApproveTeamBillingPeriod(c *gin.Context) {
	actorID, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	periodStart, periodEnd, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if periodEnd.After(h.nowUTC()) {
		respondErrorMsg(c, "conflict", "cannot approve an open billing period", http.StatusConflict)
		return
	}
	if _, _, err := h.upsertBillingSnapshot(c.Request.Context(), teamID, periodStart, periodEnd); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("prepare billing period approval failed")
		respondError(c, ErrInternal)
		return
	}
	period, err := h.DB.ApproveTeamBillingPeriod(c.Request.Context(), db.ApproveTeamBillingPeriodParams{
		ApprovedBy:  pgtype.UUID{Bytes: actorID, Valid: true},
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "conflict", "billing period is not approvable", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("approve billing period failed")
		respondError(c, ErrInternal)
		return
	}
	account, _ := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	c.JSON(http.StatusOK, billingPeriodResponseFromDB(period, account))
}

func (h *Handlers) ExportTeamBillingPeriod(c *gin.Context) {
	_, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	periodStart, periodEnd, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	resourceStates := h.billingResourceStates(storageBillingEnabled)
	exportEnabled, err := h.billingExportEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing export feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	mode := billingModeShadow
	if exportEnabled {
		mode = billingModeLive
	}

	account, err := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if exportEnabled {
				respondErrorMsg(c, "conflict", "team has no Stripe billing account", http.StatusConflict)
				return
			}
		} else {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("load billing account failed")
			respondError(c, ErrInternal)
			return
		}
	}
	if exportEnabled && (account.StripeCustomerID == nil || strings.TrimSpace(*account.StripeCustomerID) == "") {
		respondErrorMsg(c, "conflict", "team has no Stripe customer mapping", http.StatusConflict)
		return
	}
	if exportEnabled && (account.StripeSubscriptionStatus == nil || strings.TrimSpace(*account.StripeSubscriptionStatus) != "active") {
		respondErrorMsg(c, "conflict", "team subscription must be active before export", http.StatusConflict)
		return
	}
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "billing transactions are not configured", http.StatusServiceUnavailable)
		return
	}
	if exportEnabled && h.Stripe == nil {
		respondErrorMsg(c, "service_unavailable", "Stripe billing is not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := c.Request.Context()

	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("begin billing export transaction failed")
		respondError(c, ErrInternal)
		return
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	q := h.DB.WithTx(tx)

	period, err := q.GetTeamBillingPeriodForUpdate(ctx, db.GetTeamBillingPeriodForUpdateParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "conflict", "billing period could not be loaded", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("lock billing period for export failed")
		respondError(c, ErrInternal)
		return
	}

	existing, err := q.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("list existing billing export attempts failed")
		respondError(c, ErrInternal)
		return
	}
	liveExisting := latestLiveExportByResource(existing)

	var usage db.TeamBillingUsage
	switch {
	case period.Status == "exporting" || period.Status == "exported" || len(liveExisting) > 0:
		frozenUsage, err := q.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("load frozen billing usage failed")
			respondError(c, ErrInternal)
			return
		}
		usage = frozenUsage
	default:
		usageRow, updatedPeriod, err := h.upsertBillingSnapshotWithQueries(ctx, q, teamID, periodStart, periodEnd)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("prepare billing export failed")
			respondError(c, ErrInternal)
			return
		}
		period = updatedPeriod
		usage = billingTeamUsageFromUpsertRow(usageRow)
	}

	items, err := billingPreviewItems(teamID, periodStart, periodEnd, usage, resourceStates, derefString(account.StripeCustomerID))
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("build billing export items failed")
		respondError(c, ErrInternal)
		return
	}
	if err := validateBillingExportItems(items); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	activeResources := make(map[string]struct{}, len(items))
	for _, item := range items {
		activeResources[item.ResourceType] = struct{}{}
	}
	for i, row := range existing {
		if (row.Status != "pending" && row.Status != "failed") || (exportEnabled && hasResource(activeResources, row.ResourceType)) {
			continue
		}
		updatedRow, updateErr := q.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
			ID:     row.ID,
			Status: "skipped_disabled",
		})
		if updateErr != nil {
			log.Error().Err(updateErr).Str("team_id", teamID.String()).Msg("mark disabled billing export attempt skipped failed")
			respondError(c, ErrInternal)
			return
		}
		existing[i] = updatedRow
	}
	liveExisting = latestLiveExportByResource(existing)
	if period.Status == "exported" && len(liveExisting) > 0 {
		if !billingExportRowsFinalized(existing) {
			respondErrorMsg(c, "conflict", "billing export is still in progress", http.StatusConflict)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit already-exported billing period failed")
			respondError(c, ErrInternal)
			return
		}
		c.JSON(http.StatusOK, billingExportPreviewResponse{
			Mode:             mode,
			PeriodID:         billingPeriodID(periodStart, periodEnd),
			TeamID:           teamID.String(),
			Status:           period.Status,
			StripeCustomerID: account.StripeCustomerID,
			Items:            items,
			Attempts:         billingExportAttemptsFromRows(existing),
		})
		return
	}

	if !exportEnabled {
		if period.Status == "exported" {
			if err := tx.Commit(ctx); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit already-exported shadow billing period failed")
				respondError(c, ErrInternal)
				return
			}
			c.JSON(http.StatusOK, billingExportPreviewResponse{
				Mode:             mode,
				PeriodID:         billingPeriodID(periodStart, periodEnd),
				TeamID:           teamID.String(),
				Status:           period.Status,
				StripeCustomerID: account.StripeCustomerID,
				Items:            items,
				Attempts:         billingExportAttemptsFromRows(existing),
			})
			return
		}
		for _, item := range items {
			resourceType := billingExportResourceType(item.ResourceType)
			if _, err := q.CreateBillingUsageExport(ctx, db.CreateBillingUsageExportParams{
				TeamID:                     teamID,
				PeriodStart:                periodStart,
				PeriodEnd:                  periodEnd,
				ResourceType:               resourceType,
				StripeCustomerID:           account.StripeCustomerID,
				StripeMeterEventIdentifier: item.Identifier,
				StripeEventName:            item.EventName,
				Value:                      numericFromFloat(item.Value),
				Status:                     "skipped_shadow",
			}); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("record skipped shadow billing export failed")
				respondError(c, ErrInternal)
				return
			}
		}
		updated, err := q.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("list shadow billing export attempts failed")
			respondError(c, ErrInternal)
			return
		}
		if _, err := tx.Exec(ctx, `
			UPDATE team_billing_period
			SET status = 'exported',
			    exported_at = COALESCE(exported_at, now()),
			    updated_at = now()
			WHERE team_id = $1
			  AND period_start = $2
			  AND period_end = $3
			  AND finalized_at IS NULL
		`, teamID, periodStart, periodEnd); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("advance shadow billing period failed")
			respondError(c, ErrInternal)
			return
		}
		if _, err := tx.Exec(ctx, `
			UPDATE team_billing_usage
			SET exported_at = COALESCE(exported_at, now()),
			    updated_at = now()
			WHERE team_id = $1
			  AND period_start = $2
			  AND period_end = $3
			  AND finalized_at IS NULL
		`, teamID, periodStart, periodEnd); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("advance shadow billing usage failed")
			respondError(c, ErrInternal)
			return
		}
		period.Status = "exported"
		if err := tx.Commit(ctx); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit shadow billing export failed")
			respondError(c, ErrInternal)
			return
		}
		c.JSON(http.StatusOK, billingExportPreviewResponse{
			Mode:             mode,
			PeriodID:         billingPeriodID(periodStart, periodEnd),
			TeamID:           teamID.String(),
			Status:           period.Status,
			StripeCustomerID: account.StripeCustomerID,
			Items:            items,
			Attempts:         billingExportAttemptsFromRows(updated),
		})
		return
	}

	if period.Status == "exporting" && !billingExportHasFailedRow(existing) {
		if billingExportAllFinalized(items, liveExisting) {
			if err := tx.Commit(ctx); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit already-finalized billing export failed")
				respondError(c, ErrInternal)
				return
			}
			exported, err := h.DB.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{
				TeamID:      teamID,
				PeriodStart: periodStart,
				PeriodEnd:   periodEnd,
			})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					respondErrorMsg(c, "conflict", "billing period could not be marked exported", http.StatusConflict)
					return
				}
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("mark team billing period exported failed")
				respondError(c, ErrInternal)
				return
			}
			updated, err := h.DB.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
				TeamID:      teamID,
				PeriodStart: periodStart,
				PeriodEnd:   periodEnd,
			})
			if err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("refresh exported billing attempts failed")
				respondError(c, ErrInternal)
				return
			}
			c.JSON(http.StatusOK, billingExportPreviewResponse{
				Mode:             mode,
				PeriodID:         billingPeriodID(periodStart, periodEnd),
				TeamID:           teamID.String(),
				Status:           exported.Status,
				StripeCustomerID: account.StripeCustomerID,
				Items:            items,
				Attempts:         billingExportAttemptsFromRows(updated),
			})
			return
		}
	}

	if period.Status == "approved" || period.Status == "exporting" || period.Status == "exported" || len(liveExisting) > 0 {
		for _, item := range items {
			resourceType := billingExportResourceType(item.ResourceType)
			if existing, ok := liveExisting[resourceType]; ok {
				if (existing.Status != "failed" && existing.Status != "skipped_disabled") || existing.StripeMeterEventIdentifier == item.Identifier {
					continue
				}
			}
			_, meterOK := stripeMeterQuantity(item.Value)
			status := "pending"
			if !meterOK {
				status = "skipped_zero"
			}
			created, err := q.CreateBillingUsageExport(ctx, db.CreateBillingUsageExportParams{
				TeamID:                     teamID,
				PeriodStart:                periodStart,
				PeriodEnd:                  periodEnd,
				ResourceType:               resourceType,
				StripeCustomerID:           account.StripeCustomerID,
				StripeMeterEventIdentifier: item.Identifier,
				StripeIdempotencyKey:       stringPtr(stripeMeterEventIdempotencyKey(item.Identifier, item.EventName, derefString(account.StripeCustomerID), stripeMeterQuantityString(item.Value), periodEnd.UTC().Add(-time.Second).Unix())),
				StripeEventName:            item.EventName,
				Value:                      numericFromFloat(item.Value),
				Status:                     status,
			})
			if err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("create billing export attempt failed")
				respondError(c, ErrInternal)
				return
			}
			liveExisting[resourceType] = created
		}
		if _, err := q.MarkTeamBillingPeriodExporting(ctx, db.MarkTeamBillingPeriodExportingParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				respondErrorMsg(c, "conflict", "billing period could not be marked exporting", http.StatusConflict)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("mark team billing period exporting failed")
			respondError(c, ErrInternal)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit billing export claim failed")
		respondError(c, ErrInternal)
		return
	}

	updated, err := h.DB.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("refresh billing export attempts failed")
		respondError(c, ErrInternal)
		return
	}
	updatedLive := latestLiveExportByResource(updated)
	for _, item := range items {
		resourceType := billingExportResourceType(item.ResourceType)
		row, ok := updatedLive[resourceType]
		if !ok {
			continue
		}
		if row.Status == "sent" || row.Status == "accepted" || row.Status == "skipped_zero" {
			continue
		}
		if row.Status == "failed" || row.Status == "skipped_disabled" {
			row, err = h.DB.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
				ID:     row.ID,
				Status: "pending",
			})
			if err != nil {
				respondError(c, ErrInternal)
				return
			}
		}
		rowValue, err := numericFloat64(row.Value)
		if err != nil {
			respondError(c, ErrInternal)
			return
		}
		meterValue, ok := stripeMeterQuantity(rowValue)
		if !ok {
			if _, err := h.DB.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
				ID:     row.ID,
				Status: "skipped_zero",
			}); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("mark zero billing export attempt skipped failed")
				respondError(c, ErrInternal)
				return
			}
			continue
		}
		idempotencyKey := derefString(row.StripeIdempotencyKey)
		if idempotencyKey == "" {
			idempotencyKey = stripeMeterEventIdempotencyKey(row.StripeMeterEventIdentifier, row.StripeEventName, derefString(row.StripeCustomerID), meterValue, periodEnd.UTC().Add(-time.Second).Unix())
			_, setErr := h.DB.SetBillingUsageExportIdempotencyKey(ctx, db.SetBillingUsageExportIdempotencyKeyParams{
				ID:                   row.ID,
				StripeIdempotencyKey: stringPtr(idempotencyKey),
			})
			if setErr != nil {
				if !errors.Is(setErr, pgx.ErrNoRows) {
					respondError(c, ErrInternal)
					return
				}
			}
		}

		err = h.Stripe.ReportMeterEvent(ctx, StripeReportMeterEventParams{
			Identifier:     row.StripeMeterEventIdentifier,
			IdempotencyKey: idempotencyKey,
			EventName:      row.StripeEventName,
			CustomerID:     derefString(row.StripeCustomerID),
			Value:          meterValue,
			Timestamp:      periodEnd.UTC().Add(-time.Second).Unix(),
		})
		if err != nil {
			msg := err.Error()
			if _, uerr := h.DB.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
				ID:     row.ID,
				Status: "failed",
				Error:  &msg,
			}); uerr != nil {
				log.Error().Err(uerr).Str("team_id", teamID.String()).Msg("record failed billing export attempt failed")
				respondError(c, ErrInternal)
				return
			}
			respondErrorMsg(c, "bad_gateway", "Stripe meter event submission failed", http.StatusBadGateway)
			return
		}

		sentAt := h.nowUTC()
		if _, err := h.DB.MarkBillingUsageExportSent(ctx, db.MarkBillingUsageExportSentParams{
			ID:     row.ID,
			SentAt: pgtype.Timestamptz{Time: sentAt, Valid: true},
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				respondErrorMsg(c, "conflict", "billing export attempt was superseded", http.StatusConflict)
				return
			}
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("mark billing export sent failed")
			respondError(c, ErrInternal)
			return
		}
	}

	updated, err = h.DB.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("refresh billing export attempts failed")
		respondError(c, ErrInternal)
		return
	}
	updatedLive = latestLiveExportByResource(updated)
	if !billingExportRowsFinalized(updated) {
		respondErrorMsg(c, "conflict", "billing export is still in progress", http.StatusConflict)
		return
	}
	exported, err := h.DB.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "conflict", "billing period could not be marked exported", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("mark team billing period exported failed")
		respondError(c, ErrInternal)
		return
	}
	updated, err = h.DB.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("refresh exported billing attempts failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, billingExportPreviewResponse{
		Mode:             mode,
		PeriodID:         billingPeriodID(periodStart, periodEnd),
		TeamID:           teamID.String(),
		Status:           exported.Status,
		StripeCustomerID: account.StripeCustomerID,
		Items:            items,
		Attempts:         billingExportAttemptsFromRows(updated),
	})
}

func (h *Handlers) CreateStripeCheckoutSession(c *gin.Context) {
	teamID, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, teamID, "billing:write") {
		return
	}
	if h.Stripe == nil {
		respondErrorMsg(c, "service_unavailable", "Stripe billing is not configured", http.StatusServiceUnavailable)
		return
	}
	var req billingCheckoutSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", "invalid checkout session request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SuccessURL) == "" || strings.TrimSpace(req.CancelURL) == "" {
		respondErrorMsg(c, "bad_request", "success_url and cancel_url are required", http.StatusBadRequest)
		return
	}
	successURL, err := h.validateBillingRedirectURL(req.SuccessURL)
	if err != nil {
		if errors.Is(err, errBillingRedirectOriginsNotConfigured) {
			respondErrorMsg(c, "service_unavailable", "billing redirect origins are not configured", http.StatusServiceUnavailable)
			return
		}
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	cancelURL, err := h.validateBillingRedirectURL(req.CancelURL)
	if err != nil {
		if errors.Is(err, errBillingRedirectOriginsNotConfigured) {
			respondErrorMsg(c, "service_unavailable", "billing redirect origins are not configured", http.StatusServiceUnavailable)
			return
		}
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	exportEnabled, err := h.billingExportEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing export feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	if !exportEnabled {
		respondErrorMsg(c, "forbidden", "Stripe checkout is unavailable in shadow billing mode", http.StatusForbidden)
		return
	}
	account, err := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("load billing account failed")
		respondError(c, ErrInternal)
		return
	}
	if billingAccountHasEstablishedSubscription(account) {
		respondErrorMsg(c, "conflict", "team already has an active Stripe subscription; use the customer portal", http.StatusConflict)
		return
	}
	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	priceIDs, err := billingCheckoutPriceIDs(h.billingResourceStates(storageBillingEnabled))
	if err != nil {
		respondErrorMsg(c, "service_unavailable", err.Error(), http.StatusServiceUnavailable)
		return
	}
	customerID, err := h.ensureStripeCustomer(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("ensure Stripe customer failed")
		respondError(c, ErrInternal)
		return
	}
	session, err := h.Stripe.CreateCheckoutSession(c.Request.Context(), StripeCreateCheckoutSessionParams{
		CustomerID:        customerID,
		SuccessURL:        successURL,
		CancelURL:         cancelURL,
		ClientReferenceID: teamID.String(),
		PriceIDs:          priceIDs,
		IdempotencyKey:    checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs),
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("create Stripe checkout session failed")
		respondErrorMsg(c, "bad_gateway", "Stripe checkout session creation failed", http.StatusBadGateway)
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{ID: session.ID, URL: session.URL})
}

func (h *Handlers) CreateStripeCustomerPortalSession(c *gin.Context) {
	teamID, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, teamID, "billing:write") {
		return
	}
	if h.Stripe == nil {
		respondErrorMsg(c, "service_unavailable", "Stripe billing is not configured", http.StatusServiceUnavailable)
		return
	}
	var req billingPortalSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", "invalid portal session request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ReturnURL) == "" {
		respondErrorMsg(c, "bad_request", "return_url is required", http.StatusBadRequest)
		return
	}
	returnURL, err := h.validateBillingRedirectURL(req.ReturnURL)
	if err != nil {
		if errors.Is(err, errBillingRedirectOriginsNotConfigured) {
			respondErrorMsg(c, "service_unavailable", "billing redirect origins are not configured", http.StatusServiceUnavailable)
			return
		}
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	exportEnabled, err := h.billingExportEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing export feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	if !exportEnabled {
		respondErrorMsg(c, "forbidden", "Stripe customer portal is unavailable in shadow billing mode", http.StatusForbidden)
		return
	}
	account, err := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "conflict", "team has no Stripe billing account", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("get billing account failed")
		respondError(c, ErrInternal)
		return
	}
	if account.StripeCustomerID == nil {
		respondErrorMsg(c, "conflict", "team has no Stripe customer mapping", http.StatusConflict)
		return
	}
	if !billingAccountHasEstablishedSubscription(account) {
		respondErrorMsg(c, "conflict", "team does not have an active Stripe subscription", http.StatusConflict)
		return
	}
	session, err := h.Stripe.CreateCustomerPortalSession(c.Request.Context(), StripeCreateCustomerPortalSessionParams{
		CustomerID: *account.StripeCustomerID,
		ReturnURL:  returnURL,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("create Stripe portal session failed")
		respondErrorMsg(c, "bad_gateway", "Stripe customer portal session creation failed", http.StatusBadGateway)
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{URL: session.URL})
}

func (h *Handlers) HandleStripeWebhook(c *gin.Context) {
	if h.Config == nil || strings.TrimSpace(h.Config.StripeWebhookSecret) == "" {
		respondErrorMsg(c, "service_unavailable", "Stripe webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxStripeWebhookBodyBytes)
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			respondErrorMsg(c, "request_entity_too_large", "Stripe webhook payload is too large", http.StatusRequestEntityTooLarge)
			return
		}
		respondError(c, ErrInternal)
		return
	}
	if err := verifyStripeWebhookSignature(payload, c.GetHeader("Stripe-Signature"), h.Config.StripeWebhookSecret, h.nowUTC()); err != nil {
		respondErrorMsg(c, "unauthorized", "invalid Stripe webhook signature", http.StatusUnauthorized)
		return
	}

	var event stripeEventEnvelope
	if err := json.Unmarshal(payload, &event); err != nil {
		respondErrorMsg(c, "bad_request", "invalid Stripe webhook payload", http.StatusBadRequest)
		return
	}
	if event.ID == "" || event.Type == "" {
		respondErrorMsg(c, "bad_request", "Stripe webhook payload is missing id or type", http.StatusBadRequest)
		return
	}
	if isStripeMeterErrorEvent(event.Type) && len(bytes.TrimSpace(event.Data.Object)) == 0 {
		retriever, ok := h.Stripe.(stripeEventRetriever)
		if !ok {
			respondErrorMsg(c, "service_unavailable", "Stripe event retrieval is not configured", http.StatusServiceUnavailable)
			return
		}
		fullEvent, err := retriever.RetrieveEvent(c.Request.Context(), event.ID)
		if err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("retrieve Stripe thin event failed")
			respondError(c, ErrInternal)
			return
		}
		var retrieved struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(fullEvent, &retrieved); err != nil || len(bytes.TrimSpace(retrieved.Data)) == 0 {
			if err == nil {
				err = errors.New("Stripe thin event response has no data")
			}
			log.Error().Err(err).Str("event_id", event.ID).Msg("decode Stripe thin event failed")
			respondError(c, ErrInternal)
			return
		}
		event.Data.Object = retrieved.Data
	}

	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "billing transactions are not configured", http.StatusServiceUnavailable)
		return
	}

	tx, err := h.Pool.BeginTx(c.Request.Context(), pgx.TxOptions{})
	if err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("begin Stripe webhook transaction failed")
		respondError(c, ErrInternal)
		return
	}
	defer func() {
		_ = tx.Rollback(c.Request.Context())
	}()
	q := h.DB.WithTx(tx)

	row, err := q.CreateStripeWebhookEvent(c.Request.Context(), db.CreateStripeWebhookEventParams{
		EventID:   event.ID,
		EventType: event.Type,
		Payload:   payload,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			existing, gerr := q.GetStripeWebhookEventForUpdate(c.Request.Context(), event.ID)
			if gerr != nil {
				log.Error().Err(gerr).Str("event_id", event.ID).Msg("load existing Stripe webhook event failed")
				respondError(c, ErrInternal)
				return
			}
			if existing.ProcessedAt.Valid {
				if err := tx.Commit(c.Request.Context()); err != nil {
					log.Error().Err(err).Str("event_id", event.ID).Msg("commit duplicate Stripe webhook failed")
					respondError(c, ErrInternal)
					return
				}
				c.JSON(http.StatusOK, gin.H{"status": "duplicate"})
				return
			}
			if err := h.processStripeWebhookEvent(c.Request.Context(), q, event); err != nil {
				msg := err.Error()
				if _, uerr := q.MarkStripeWebhookEventFailed(c.Request.Context(), db.MarkStripeWebhookEventFailedParams{
					EventID:   event.ID,
					LastError: &msg,
				}); uerr != nil {
					log.Error().Err(uerr).Str("event_id", event.ID).Msg("mark Stripe webhook failed state failed")
					respondError(c, ErrInternal)
					return
				}
				if err := tx.Commit(c.Request.Context()); err != nil {
					log.Error().Err(err).Str("event_id", event.ID).Msg("commit failed Stripe webhook state failed")
					respondError(c, ErrInternal)
					return
				}
				log.Error().Err(err).Str("event_id", event.ID).Str("event_type", event.Type).Msg("process Stripe webhook retry failed")
				respondError(c, ErrInternal)
				return
			}
			if _, err := q.MarkStripeWebhookEventProcessed(c.Request.Context(), event.ID); err != nil {
				log.Error().Err(err).Str("event_id", event.ID).Msg("mark Stripe webhook processed failed")
				respondError(c, ErrInternal)
				return
			}
			if err := tx.Commit(c.Request.Context()); err != nil {
				log.Error().Err(err).Str("event_id", event.ID).Msg("commit retried Stripe webhook failed")
				respondError(c, ErrInternal)
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		log.Error().Err(err).Str("event_id", event.ID).Msg("record Stripe webhook event failed")
		respondError(c, ErrInternal)
		return
	}
	_ = row

	if err := h.processStripeWebhookEvent(c.Request.Context(), q, event); err != nil {
		msg := err.Error()
		if _, uerr := q.MarkStripeWebhookEventFailed(c.Request.Context(), db.MarkStripeWebhookEventFailedParams{
			EventID:   event.ID,
			LastError: &msg,
		}); uerr != nil {
			log.Error().Err(uerr).Str("event_id", event.ID).Msg("mark Stripe webhook failed state failed")
			respondError(c, ErrInternal)
			return
		}
		if err := tx.Commit(c.Request.Context()); err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("commit failed Stripe webhook state failed")
			respondError(c, ErrInternal)
			return
		}
		log.Error().Err(err).Str("event_id", event.ID).Str("event_type", event.Type).Msg("process Stripe webhook failed")
		respondError(c, ErrInternal)
		return
	}
	if _, err := q.MarkStripeWebhookEventProcessed(c.Request.Context(), event.ID); err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("mark Stripe webhook processed failed")
		respondError(c, ErrInternal)
		return
	}
	if err := tx.Commit(c.Request.Context()); err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("commit Stripe webhook failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func isStripeMeterErrorEvent(eventType string) bool {
	return eventType == "billing.meter.error_report_triggered" || eventType == "v1.billing.meter.error_report_triggered"
}

func (h *Handlers) processStripeWebhookEvent(ctx context.Context, q *db.Queries, event stripeEventEnvelope) error {
	eventAt := stripeEventTime(int64(event.Created))
	switch event.Type {
	case "checkout.session.completed":
		var obj stripeCheckoutCompletedObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
		if err != nil {
			return nil
		}
		_, err = q.UpsertTeamBillingAccountSubscription(ctx, db.UpsertTeamBillingAccountSubscriptionParams{
			TeamID:               teamID,
			StripeCustomerID:     stringPtr(obj.Customer),
			StripeSubscriptionID: stringPtr(obj.Subscription),
		})
		return err
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if obj.ID == "" {
			return nil
		}
		if eventAt.IsZero() {
			return nil
		}
		if account.StripeSubscriptionEventAt.Valid && !eventAt.After(account.StripeSubscriptionEventAt.Time.UTC()) {
			return nil
		}
		if event.Type != "customer.subscription.created" {
			if account.StripeSubscriptionID == nil || *account.StripeSubscriptionID != obj.ID {
				return nil
			}
		}
		start, end, ok := stripeSubscriptionPeriodBounds(obj)
		if !ok {
			return nil
		}
		_, err = q.UpsertTeamBillingAccountSubscription(ctx, db.UpsertTeamBillingAccountSubscriptionParams{
			TeamID:                    account.TeamID,
			StripeCustomerID:          stringPtr(obj.Customer),
			StripeSubscriptionID:      stringPtr(obj.ID),
			StripeSubscriptionStatus:  stringPtr(obj.Status),
			CurrentPeriodStart:        timestamptzFromUnix(start),
			CurrentPeriodEnd:          timestamptzFromUnix(end),
			CancelAtPeriodEnd:         boolPtr(obj.CancelAtPeriodEnd),
			StripeSubscriptionEventAt: timestamptzFromUnix(int64(event.Created)),
		})
		return err
	case "invoice.payment_failed", "invoice.payment_succeeded", "invoice.finalized":
		var obj stripeInvoiceObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		status := strings.TrimSpace(obj.Status)
		if status == "" {
			return nil
		}
		_, err = q.UpsertTeamBillingAccountSubscription(ctx, db.UpsertTeamBillingAccountSubscriptionParams{
			TeamID:               account.TeamID,
			StripeCustomerID:     stringPtr(obj.Customer),
			StripeSubscriptionID: stringPtr(obj.Subscription),
			StripeInvoiceStatus:  stringPtr(status),
		})
		return err
	case "billing.meter.error_report_triggered", "v1.billing.meter.error_report_triggered":
		if samples := stripeMeterErrorSamplePayloads(event.Data.Object); len(samples) > 1 {
			for _, sample := range samples[1:] {
				if err := h.processStripeWebhookEvent(ctx, q, stripeEventEnvelope{
					ID:   event.ID,
					Type: event.Type,
					Data: stripeEventEnvelopeData{Object: sample},
				}); err != nil {
					return err
				}
			}
		}
		identifier, eventName, customerID, requestKey, errMsg, err := stripeMeterErrorDetails(event.Data.Object)
		if err != nil {
			return err
		}
		if identifier == "" && requestKey != "" {
			row, lookupErr := q.GetBillingUsageExportByIdempotencyKey(ctx, stringPtr(requestKey))
			if lookupErr == nil {
				identifier = row.StripeMeterEventIdentifier
			}
		}
		if identifier == "" {
			return fmt.Errorf("stripe meter error event has no export identifier")
		}
		teamID, start, end, resourceType, err := parseMeterIdentifier(identifier)
		if err != nil {
			return nil
		}
		if customerID == "" {
			if account, aerr := q.GetTeamBillingAccount(ctx, teamID); aerr == nil {
				customerID = derefString(account.StripeCustomerID)
			}
		}
		period, perr := q.GetTeamBillingPeriodForUpdate(ctx, db.GetTeamBillingPeriodForUpdateParams{
			TeamID:      teamID,
			PeriodStart: start,
			PeriodEnd:   end,
		})
		if perr != nil {
			if errors.Is(perr, pgx.ErrNoRows) {
				return nil
			}
			return perr
		}
		existing, lerr := q.ListBillingUsageExportsForPeriod(ctx, db.ListBillingUsageExportsForPeriodParams{
			TeamID:      teamID,
			PeriodStart: start,
			PeriodEnd:   end,
		})
		if lerr != nil {
			return lerr
		}
		if period.FinalizedAt.Valid {
			for i := len(existing) - 1; i >= 0; i-- {
				if existing[i].StripeMeterEventIdentifier != identifier {
					continue
				}
				_, err = q.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
					ID:     existing[i].ID,
					Status: "failed",
					Error:  stringPtr(errMsg),
				})
				if err != nil {
					return err
				}
				return nil
			}
			return fmt.Errorf("stripe meter error has no matching finalized export")
		}
		latest := latestLiveExportByResource(existing)[billingExportResourceType(resourceType)]
		if latest.ID != uuid.Nil && latest.StripeMeterEventIdentifier != identifier {
			return nil
		}
		for i := len(existing) - 1; i >= 0; i-- {
			row := existing[i]
			if row.StripeMeterEventIdentifier != identifier {
				continue
			}
			_, err = q.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
				ID:     row.ID,
				Status: "failed",
				Error:  stringPtr(errMsg),
			})
			if err != nil {
				return err
			}
			_, err = q.MarkTeamBillingPeriodExporting(ctx, db.MarkTeamBillingPeriodExportingParams{
				TeamID:      teamID,
				PeriodStart: start,
				PeriodEnd:   end,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				enabled, featureErr := q.IsFeatureEnabledForTeam(ctx, db.IsFeatureEnabledForTeamParams{
					Key:    "billing_export_enabled",
					TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
				})
				if featureErr != nil {
					return featureErr
				}
				if enabled {
					return err
				}
				_, err = q.UpdateBillingUsageExportStatus(ctx, db.UpdateBillingUsageExportStatusParams{
					ID:     row.ID,
					Status: "skipped_disabled",
					Error:  stringPtr(errMsg),
				})
				return err
			}
			return err
		}
		_, err = q.CreateBillingUsageExport(ctx, db.CreateBillingUsageExportParams{
			TeamID:                     teamID,
			PeriodStart:                start,
			PeriodEnd:                  end,
			ResourceType:               billingExportResourceType(resourceType),
			StripeCustomerID:           stringPtr(customerID),
			StripeMeterEventIdentifier: identifier,
			StripeIdempotencyKey:       stringPtr(requestKey),
			StripeEventName:            eventName,
			Value:                      numericFromFloat(0),
			Status:                     "failed",
			Error:                      stringPtr(errMsg),
		})
		return err
	default:
		return nil
	}
}

func stripeMeterErrorSamplePayloads(payload []byte) [][]byte {
	var value any
	if json.Unmarshal(payload, &value) != nil {
		return nil
	}
	var samples []map[string]any
	var walk func(any)
	walk = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			if request, ok := item["request"].(map[string]any); ok {
				sample := map[string]any{}
				for key, value := range request {
					sample[key] = value
				}
				if message, ok := item["error_message"].(string); ok {
					sample["reason"] = message
				}
				samples = append(samples, sample)
			}
			for _, nested := range item {
				walk(nested)
			}
		case []any:
			for _, nested := range item {
				walk(nested)
			}
		}
	}
	walk(value)
	if len(samples) == 0 {
		return [][]byte{payload}
	}
	encoded := make([][]byte, 0, len(samples))
	for _, sample := range samples {
		data, err := json.Marshal(sample)
		if err == nil {
			encoded = append(encoded, data)
		}
	}
	return encoded
}

func stripeMeterErrorDetails(payload []byte) (identifier, eventName, customerID, requestKey, message string, err error) {
	var value any
	if err = json.Unmarshal(payload, &value); err != nil {
		return "", "", "", "", "", err
	}
	var summary string
	var walk func(any)
	walk = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			for key, nested := range item {
				text, ok := nested.(string)
				if ok {
					switch key {
					case "identifier":
						if identifier == "" {
							identifier = text
						}
					case "event_name":
						if eventName == "" {
							eventName = text
						}
					case "stripe_customer_id":
						if customerID == "" {
							customerID = text
						}
					case "idempotency_key":
						if requestKey == "" {
							requestKey = text
						}
					case "reason", "error_message", "developer_message_summary":
						if key == "developer_message_summary" {
							summary = text
						}
						if message == "" {
							message = text
						}
					}
				}
				walk(nested)
			}
		case []any:
			for _, nested := range item {
				walk(nested)
			}
		}
	}
	walk(value)
	if summary != "" {
		message = summary
	}
	return
}

func (h *Handlers) authorizeTeamBillingRead(c *gin.Context, platform bool) (uuid.UUID, bool) {
	if platform {
		if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
			return uuid.Nil, false
		}
		teamID, err := internalTeamID(c)
		if err != nil {
			return uuid.Nil, false
		}
		return teamID, true
	}
	teamID, err := customerTeamID(c)
	if err != nil {
		return uuid.Nil, false
	}
	if !h.requireCustomerTeamPermission(c, teamID, "billing:read") {
		return uuid.Nil, false
	}
	enabled, err := h.DB.IsFeatureEnabledForTeam(c.Request.Context(), db.IsFeatureEnabledForTeamParams{
		Key:    "tenant_usage_dashboard",
		TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB IsFeatureEnabledForTeam failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if !enabled {
		respondErrorMsg(c, "not_found", "Billing is not available", http.StatusNotFound)
		return uuid.Nil, false
	}
	return teamID, true
}

func (h *Handlers) ensureStripeCustomer(ctx context.Context, teamID uuid.UUID) (string, error) {
	account, err := h.DB.GetTeamBillingAccount(ctx, teamID)
	if err == nil && account.StripeCustomerID != nil && strings.TrimSpace(*account.StripeCustomerID) != "" {
		return *account.StripeCustomerID, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	team, err := h.DB.GetTeam(ctx, teamID)
	if err != nil {
		return "", err
	}
	customer, err := h.Stripe.CreateCustomer(ctx, StripeCreateCustomerParams{
		TeamID:         teamID,
		Name:           team.Name,
		IdempotencyKey: customerCreationIdempotencyKey(teamID),
	})
	if err != nil {
		return "", err
	}
	if _, err := h.DB.UpsertTeamBillingAccountCustomer(ctx, db.UpsertTeamBillingAccountCustomerParams{
		TeamID:           teamID,
		StripeCustomerID: stringPtr(customer.ID),
	}); err != nil {
		return "", err
	}
	return customer.ID, nil
}

type billingSnapshotQuerier interface {
	UpsertTeamBillingUsage(context.Context, db.UpsertTeamBillingUsageParams) (db.UpsertTeamBillingUsageRow, error)
	UpsertTeamBillingPeriod(context.Context, db.UpsertTeamBillingPeriodParams) (db.TeamBillingPeriod, error)
}

func (h *Handlers) upsertBillingSnapshot(ctx context.Context, teamID uuid.UUID, periodStart, periodEnd time.Time) (db.TeamBillingUsage, db.TeamBillingPeriod, error) {
	usageRow, period, err := h.upsertBillingSnapshotWithQueries(ctx, h.DB, teamID, periodStart, periodEnd)
	if err != nil {
		return db.TeamBillingUsage{}, db.TeamBillingPeriod{}, err
	}
	return billingTeamUsageFromUpsertRow(usageRow), period, nil
}

func (h *Handlers) readBillingSnapshot(ctx context.Context, teamID uuid.UUID, periodStart, periodEnd time.Time) (db.TeamBillingUsage, db.TeamBillingPeriod, error) {
	period, err := h.DB.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return db.TeamBillingUsage{}, db.TeamBillingPeriod{}, err
		}
		period = db.TeamBillingPeriod{
			TeamID:      teamID,
			PeriodStart: periodStart.UTC(),
			PeriodEnd:   periodEnd.UTC(),
			Status:      h.periodStatusForWindow(periodEnd, h.nowUTC()),
		}
	}

	if period.ExportedAt.Valid || period.FinalizedAt.Valid || period.Status == "exported" || period.Status == "finalized" {
		usage, err := h.DB.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			return db.TeamBillingUsage{}, db.TeamBillingPeriod{}, err
		}
		return usage, period, nil
	}

	usageRow, err := h.DB.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		return db.TeamBillingUsage{}, db.TeamBillingPeriod{}, err
	}

	usage, err := billingTeamUsageFromReadRow(usageRow)
	if err != nil {
		return db.TeamBillingUsage{}, db.TeamBillingPeriod{}, err
	}
	return usage, period, nil
}

func (h *Handlers) upsertBillingSnapshotWithQueries(ctx context.Context, q billingSnapshotQuerier, teamID uuid.UUID, periodStart, periodEnd time.Time) (db.UpsertTeamBillingUsageRow, db.TeamBillingPeriod, error) {
	usage, err := q.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: pgtype.Timestamptz{Time: periodStart.UTC(), Valid: true},
		PeriodEnd:   pgtype.Timestamptz{Time: periodEnd.UTC(), Valid: true},
	})
	if err != nil {
		return db.UpsertTeamBillingUsageRow{}, db.TeamBillingPeriod{}, err
	}
	period, err := q.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart.UTC(),
		PeriodEnd:   periodEnd.UTC(),
		Status:      h.periodStatusForWindow(periodEnd, h.nowUTC()),
	})
	if err != nil {
		return db.UpsertTeamBillingUsageRow{}, db.TeamBillingPeriod{}, err
	}
	return usage, period, nil
}

func billingTeamUsageFromUpsertRow(usage db.UpsertTeamBillingUsageRow) db.TeamBillingUsage {
	return db.TeamBillingUsage{
		TeamID:            usage.TeamID,
		PeriodStart:       usage.PeriodStart,
		PeriodEnd:         usage.PeriodEnd,
		VcpuSeconds:       usage.VcpuSeconds,
		MemoryMibSeconds:  usage.MemoryMibSeconds,
		StorageMibSeconds: usage.StorageMibSeconds,
		FinalizedAt:       usage.FinalizedAt,
		ExportedAt:        usage.ExportedAt,
		UpdatedAt:         usage.UpdatedAt,
	}
}

func billingTeamUsageFromReadRow(usage db.GetTeamBillingUsageRow) (db.TeamBillingUsage, error) {
	memoryGibSeconds, err := numericFloat64(usage.MemoryGibSeconds)
	if err != nil {
		return db.TeamBillingUsage{}, err
	}
	storageGibSeconds, err := numericFloat64(usage.StorageGibSeconds)
	if err != nil {
		return db.TeamBillingUsage{}, err
	}
	return db.TeamBillingUsage{
		TeamID:            usage.TeamID,
		PeriodStart:       usage.PeriodStart,
		PeriodEnd:         usage.PeriodEnd,
		VcpuSeconds:       usage.VcpuSeconds,
		MemoryMibSeconds:  numericFromFloat(memoryGibSeconds * 1024.0),
		StorageMibSeconds: numericFromFloat(storageGibSeconds * 1024.0),
	}, nil
}

func billingPeriodFromRequest(c *gin.Context) (time.Time, time.Time, error) {
	startRaw := strings.TrimSpace(c.Query("period_start"))
	endRaw := strings.TrimSpace(c.Query("period_end"))
	if startRaw == "" && endRaw == "" {
		start, end := currentBillingPeriod(time.Now().UTC())
		return start, end, nil
	}
	if startRaw == "" || endRaw == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("period_start and period_end must be provided together")
	}
	start, err := time.Parse(time.RFC3339, startRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period_start must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, endRaw)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period_end must be RFC3339")
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("period_end must be after period_start")
	}
	return start.UTC(), end.UTC(), nil
}

func parseBillingPeriodID(raw string) (time.Time, time.Time, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 2 {
		return time.Time{}, time.Time{}, fmt.Errorf("period_id must be start,end in RFC3339 form")
	}
	start, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period_id start must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, parts[1])
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period_id end must be RFC3339")
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("period_id end must be after start")
	}
	return start.UTC(), end.UTC(), nil
}

func billingPeriodID(start, end time.Time) string {
	return start.UTC().Format(time.RFC3339) + "," + end.UTC().Format(time.RFC3339)
}

func (h *Handlers) billingUsageResponseFromUsage(period db.TeamBillingPeriod, usage db.TeamBillingUsage, resources []billingResourceState) billingUsageResponse {
	vcpuSeconds, _ := numericFloat64(usage.VcpuSeconds)
	memoryMiBSeconds, _ := numericFloat64(usage.MemoryMibSeconds)
	storageMiBSeconds, _ := numericFloat64(usage.StorageMibSeconds)
	resourceUsage := billingUsageResourcesFromState(resources, vcpuSeconds, memoryMiBSeconds, storageMiBSeconds)
	return billingUsageResponse{
		PeriodID:          billingPeriodID(usage.PeriodStart, usage.PeriodEnd),
		TeamID:            usage.TeamID.String(),
		Status:            period.Status,
		PeriodStart:       usage.PeriodStart,
		PeriodEnd:         usage.PeriodEnd,
		VCPUSeconds:       vcpuSeconds,
		MemoryMiBSeconds:  memoryMiBSeconds,
		StorageMiBSeconds: storageMiBSeconds,
		CPUVCPUHours:      vcpuSeconds / 3600.0,
		MemoryGiBHours:    memoryMiBSeconds / 1024.0 / 3600.0,
		StorageGiBHours:   storageMiBSeconds / 1024.0 / 3600.0,
		Resources:         resourceUsage,
		ResourcesByKey:    billingUsageResourcesByKey(resourceUsage),
		ExportedAt:        timePtrFromPG(usage.ExportedAt),
		FinalizedAt:       timePtrFromPG(usage.FinalizedAt),
		UpdatedAt:         usage.UpdatedAt,
	}
}

func billingUsageResourcesFromState(resources []billingResourceState, vcpuSeconds, memoryMiBSeconds, storageMiBSeconds float64) []billingUsageResource {
	out := make([]billingUsageResource, 0, len(resources))
	for _, resource := range resources {
		var usage float64
		switch resource.ResourceKey {
		case "vcpu":
			usage = vcpuSeconds
		case "memory_gib":
			usage = memoryMiBSeconds / 1024.0
		case "storage_gib":
			usage = storageMiBSeconds / 1024.0
		}
		out = append(out, billingUsageResource{
			ResourceKey: resource.ResourceKey,
			Resource:    resource.ResourceKey,
			DisplayName: resource.DisplayName,
			SortOrder:   resource.SortOrder,
			Unit:        resource.UsageUnit,
			DisplayUnit: resource.DisplayUnit,
			Usage:       usage,
			Tracked:     resource.Tracked,
			Billable:    resource.Billable,
		})
	}
	return out
}

func billingUsageResourcesByKey(resources []billingUsageResource) map[string]billingUsageResource {
	out := make(map[string]billingUsageResource, len(resources))
	for _, resource := range resources {
		out[resource.ResourceKey] = resource
	}
	return out
}

func billingPeriodResponseFromDB(period db.TeamBillingPeriod, account db.GetTeamBillingAccountRow) billingPeriodResponse {
	resp := billingPeriodResponse{
		PeriodID:      billingPeriodID(period.PeriodStart, period.PeriodEnd),
		PeriodStart:   period.PeriodStart,
		PeriodEnd:     period.PeriodEnd,
		Status:        period.Status,
		BlockedReason: period.BlockedReason,
		ApprovedAt:    timePtrFromPG(period.ApprovedAt),
		ExportedAt:    timePtrFromPG(period.ExportedAt),
		FinalizedAt:   timePtrFromPG(period.FinalizedAt),
	}
	if account.TeamID != uuid.Nil {
		resp.StripeCustomerID = account.StripeCustomerID
		resp.StripeSubscription = account.StripeSubscriptionID
		resp.SubscriptionStatus = account.StripeSubscriptionStatus
		resp.InvoiceStatus = account.StripeInvoiceStatus
		resp.CurrentPeriodStart = timePtrFromPG(account.CurrentPeriodStart)
		resp.CurrentPeriodEnd = timePtrFromPG(account.CurrentPeriodEnd)
		resp.CancelAtPeriodEnd = &account.CancelAtPeriodEnd
	}
	return resp
}

func billingPreviewItems(teamID uuid.UUID, periodStart, periodEnd time.Time, usage db.TeamBillingUsage, resources []billingResourceState, customerID string) ([]billingExportPreviewItem, error) {
	vcpuSeconds, err := numericFloat64(usage.VcpuSeconds)
	if err != nil {
		return nil, err
	}
	memoryMiBSeconds, err := numericFloat64(usage.MemoryMibSeconds)
	if err != nil {
		return nil, err
	}
	storageMiBSeconds, err := numericFloat64(usage.StorageMibSeconds)
	if err != nil {
		return nil, err
	}
	items := make([]billingExportPreviewItem, 0, len(resources))
	for _, resource := range resources {
		if !resource.Billable || !resource.CheckoutEnabled {
			continue
		}
		var value float64
		switch resource.ResourceKey {
		case "vcpu":
			value = vcpuSeconds / 3600.0
		case "memory_gib":
			value = memoryMiBSeconds / 1024.0 / 3600.0
		case "storage_gib":
			value = storageMiBSeconds / 1024.0 / 3600.0
		default:
			continue
		}
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("billing export quantity must be finite and non-negative")
		}
		value = stripeMeterRoundedValue(value)
		items = append(items, billingExportPreviewItem{
			ResourceType: billingExportResourceType(resource.ResourceKey),
			ResourceKey:  resource.ResourceKey,
			DisplayName:  resource.DisplayName,
			SortOrder:    resource.SortOrder,
			DisplayUnit:  resource.DisplayUnit,
			EventName:    resource.StripeEventName,
			Identifier:   meterIdentifierForPayload(teamID, periodStart, periodEnd, billingExportResourceType(resource.ResourceKey), resource.StripeEventName, customerID, value),
			Value:        value,
		})
	}
	return items, nil
}

func validateBillingExportItems(items []billingExportPreviewItem) error {
	for _, item := range items {
		if item.Value < 0 || math.IsNaN(item.Value) || math.IsInf(item.Value, 0) {
			return fmt.Errorf("billing export quantity must be finite and non-negative")
		}
	}
	return nil
}

func hasResource(resources map[string]struct{}, resource string) bool {
	_, ok := resources[resource]
	return ok
}

func billingExportResourceType(resourceKey string) string {
	switch resourceKey {
	case "vcpu":
		return "cpu"
	case "memory_gib":
		return "memory"
	case "storage_gib":
		return "storage"
	default:
		return resourceKey
	}
}

func meterIdentifier(teamID uuid.UUID, periodStart, periodEnd time.Time, resourceType string) string {
	return fmt.Sprintf(
		"team:%s:period:%d,%d:meter:%s",
		teamID.String(),
		periodStart.UTC().Unix(),
		periodEnd.UTC().Unix(),
		resourceType,
	)
}

func meterIdentifierForPayload(teamID uuid.UUID, periodStart, periodEnd time.Time, resourceType, eventName, customerID string, value float64) string {
	quantity := strconv.FormatFloat(stripeMeterRoundedValue(value), 'f', 12, 64)
	digest := sha256.Sum256([]byte(strings.Join([]string{
		eventName,
		customerID,
		strconv.FormatInt(periodEnd.UTC().Add(-time.Second).Unix(), 10),
		quantity,
	}, "\x00")))
	return meterIdentifier(teamID, periodStart, periodEnd, resourceType) + ":" + hex.EncodeToString(digest[:])[:12]
}

func stripeMeterEventIdempotencyKey(identifier, eventName, customerID, value string, timestamp int64) string {
	parts := []string{
		identifier,
		eventName,
		customerID,
		value,
	}
	if timestamp > 0 {
		parts = append(parts, strconv.FormatInt(timestamp, 10))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "meter-event:" + hex.EncodeToString(digest[:])
}

func parseMeterIdentifier(raw string) (uuid.UUID, time.Time, time.Time, string, error) {
	const periodMarker = ":period:"
	const meterMarker = ":meter:"
	if !strings.HasPrefix(raw, "team:") {
		return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier")
	}
	rest := strings.TrimPrefix(raw, "team:")
	teamIDRaw, remainder, ok := strings.Cut(rest, periodMarker)
	if !ok {
		return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier")
	}
	teamID, err := uuid.Parse(teamIDRaw)
	if err != nil {
		return uuid.Nil, time.Time{}, time.Time{}, "", err
	}
	periodRaw, resourceType, ok := strings.Cut(remainder, meterMarker)
	if !ok {
		return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier")
	}
	parts := strings.SplitN(resourceType, ":", 2)
	resourceType = parts[0]
	if resourceType != "cpu" && resourceType != "memory" && resourceType != "storage" {
		return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter resource type")
	}
	if len(parts) == 2 {
		if len(parts[1]) != 12 {
			return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier fingerprint")
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier fingerprint: %w", err)
		}
	}
	bounds := strings.SplitN(periodRaw, ",", 2)
	if len(bounds) != 2 {
		return uuid.Nil, time.Time{}, time.Time{}, "", fmt.Errorf("invalid meter identifier bounds")
	}
	startUnix, err := strconv.ParseInt(bounds[0], 10, 64)
	if err != nil {
		return uuid.Nil, time.Time{}, time.Time{}, "", err
	}
	endUnix, err := strconv.ParseInt(bounds[1], 10, 64)
	if err != nil {
		return uuid.Nil, time.Time{}, time.Time{}, "", err
	}
	return teamID, time.Unix(startUnix, 0).UTC(), time.Unix(endUnix, 0).UTC(), resourceType, nil
}

func latestSubmittedByResource(rows []db.BillingUsageExport) map[string]db.BillingUsageExport {
	out := map[string]db.BillingUsageExport{}
	for _, row := range rows {
		// `accepted` is retained for older rows; `sent` is the primary success state.
		if row.Status != "sent" && row.Status != "accepted" && row.Status != "skipped_zero" {
			continue
		}
		out[row.ResourceType] = row
	}
	return out
}

func latestLiveExportByResource(rows []db.BillingUsageExport) map[string]db.BillingUsageExport {
	out := map[string]db.BillingUsageExport{}
	for _, row := range rows {
		if row.Status == "skipped_shadow" {
			continue
		}
		out[row.ResourceType] = row
	}
	return out
}

func billingExportHasFailedRow(rows []db.BillingUsageExport) bool {
	for _, row := range rows {
		if row.Status == "failed" {
			return true
		}
	}
	return false
}

func billingExportRowsFinalized(rows []db.BillingUsageExport) bool {
	for _, row := range latestLiveExportByResource(rows) {
		switch row.Status {
		case "sent", "accepted", "skipped_zero", "skipped_shadow", "skipped_disabled":
			continue
		default:
			return false
		}
	}
	return true
}

func billingExportAllFinalized(items []billingExportPreviewItem, rows map[string]db.BillingUsageExport) bool {
	for _, item := range items {
		row, ok := rows[item.ResourceType]
		if !ok {
			return false
		}
		switch row.Status {
		case "sent", "accepted", "skipped_zero":
			continue
		default:
			return false
		}
	}
	return true
}

func billingExportAttemptsFromRows(rows []db.BillingUsageExport) []billingExportAttemptRecord {
	out := make([]billingExportAttemptRecord, 0, len(rows))
	for _, row := range rows {
		value, _ := numericFloat64(row.Value)
		out = append(out, billingExportAttemptRecord{
			ID:                         row.ID.String(),
			ResourceType:               row.ResourceType,
			StripeMeterEventIdentifier: row.StripeMeterEventIdentifier,
			StripeEventName:            row.StripeEventName,
			Value:                      value,
			Status:                     row.Status,
			Error:                      row.Error,
			SentAt:                     timePtrFromPG(row.SentAt),
			CreatedAt:                  row.CreatedAt,
		})
	}
	return out
}

func verifyStripeWebhookSignature(payload []byte, header, secret string, now time.Time) error {
	var timestamp string
	signatures := []string{}
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			timestamp = value
		case "v1":
			signatures = append(signatures, value)
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return fmt.Errorf("missing Stripe signature fields")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return err
	}
	if math.Abs(now.Sub(time.Unix(ts, 0).UTC()).Seconds()) > 300 {
		return fmt.Errorf("Stripe signature timestamp is outside tolerance")
	}
	signedPayload := append([]byte(timestamp+"."), payload...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signedPayload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, sig := range signatures {
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("no valid Stripe signature found")
}

func numericFromFloat(v float64) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(formatDecimal(v))
	return n
}

func formatDecimal(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Stripe meter events should carry the same normalized billing quantity that
// appears in the export preview, not the raw interval seconds.
func stripeMeterQuantity(value float64) (string, bool) {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return "", false
	}
	formatted := strconv.FormatFloat(value, 'f', 12, 64)
	rounded, err := strconv.ParseFloat(formatted, 64)
	if err != nil || rounded <= 0 {
		return "", false
	}
	return formatted, true
}

func stripeMeterQuantityString(value float64) string {
	formatted, _ := stripeMeterQuantity(value)
	return formatted
}

func stripeMeterRoundedValue(value float64) float64 {
	rounded, err := strconv.ParseFloat(strconv.FormatFloat(value, 'f', 12, 64), 64)
	if err != nil {
		return value
	}
	return rounded
}

func stripeSubscriptionPeriodBounds(obj stripeSubscriptionObject) (int64, int64, bool) {
	if obj.CurrentPeriodStart > 0 && obj.CurrentPeriodEnd > 0 {
		return obj.CurrentPeriodStart, obj.CurrentPeriodEnd, true
	}
	for _, item := range obj.Items.Data {
		if item.CurrentPeriodStart > 0 && item.CurrentPeriodEnd > 0 {
			return item.CurrentPeriodStart, item.CurrentPeriodEnd, true
		}
	}
	return 0, 0, false
}

func stripeEventTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func checkoutSessionIdempotencyKey(teamID uuid.UUID, customerID, successURL, cancelURL string, priceIDs []string) string {
	raw := strings.Join([]string{
		"checkout-v2",
		teamID.String(),
		customerID,
		successURL,
		cancelURL,
		strings.Join(priceIDs, ","),
	}, "|")

	sum := sha256.Sum256([]byte(raw))

	return "checkout:" + hex.EncodeToString(sum[:])
}

func customerCreationIdempotencyKey(teamID uuid.UUID) string {
	return fmt.Sprintf("customer:%s", teamID.String())
}

func stringPtr(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	s := v
	return &s
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}

func timePtrFromUnix(v int64) *time.Time {
	if v <= 0 {
		return nil
	}
	t := time.Unix(v, 0).UTC()
	return &t
}

func timestamptzFromUnix(v int64) pgtype.Timestamptz {
	if v <= 0 {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: time.Unix(v, 0).UTC(), Valid: true}
}

func timePtrFromPG(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time.UTC()
	return &t
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
