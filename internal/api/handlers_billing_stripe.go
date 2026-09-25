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
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	billingModeShadow           = "shadow"
	billingModeLive             = "live"
	maxStripeWebhookBodyBytes   = 1 << 20
	checkoutSessionLifetime     = 24 * time.Hour
	stripePromotionReplayWindow = 23 * time.Hour

	platformBillingWritePermission = "platform:billing:write"
)

var errBillingRedirectOriginsNotConfigured = errors.New("billing redirect origins are not configured")
var errStripeCheckoutAssociationPending = errors.New("Stripe checkout association is still being established")
var errStripePromotionSettlementRequired = errors.New("Stripe promotion requires explicit settlement after its safe idempotency replay window")

type StripeBillingClient interface {
	CreateCustomer(ctx context.Context, params StripeCreateCustomerParams) (StripeCustomer, error)
	CreateBillingCreditGrant(ctx context.Context, params StripeCreateBillingCreditGrantParams) (StripeBillingCreditGrant, error)
	CreateCheckoutSession(ctx context.Context, params StripeCreateCheckoutSessionParams) (StripeCheckoutSession, error)
	CreateCustomerPortalSession(ctx context.Context, params StripeCreateCustomerPortalSessionParams) (StripePortalSession, error)
	ReportMeterEvent(ctx context.Context, params StripeReportMeterEventParams) error
}

type StripeCreditBalance struct {
	AvailableUSD float64
	ObservedAt   time.Time
	// IncludesCurrentPeriodUsage states whether Stripe has already applied or
	// reserved this period's usage in AvailableUSD. The credit balance summary
	// endpoint is post-application, so callers must not subtract local usage
	// from it again.
	IncludesCurrentPeriodUsage bool
}

type stripeCreditBalanceReader interface {
	GetCustomerCreditBalance(context.Context, string) (StripeCreditBalance, error)
}

type stripeEventRetriever interface {
	RetrieveEvent(ctx context.Context, eventID string) (json.RawMessage, error)
}

type commercialBillingAnchorRequest struct {
	Anchor *time.Time `json:"anchor"`
}
type billingCutoverRequest struct {
	CutoverAt        time.Time   `json:"cutover_at"`
	PreservedTeamIDs []uuid.UUID `json:"preserved_team_ids"`
}

type stripePromotionGrantError struct {
	TeamID             uuid.UUID
	UserID             uuid.UUID
	ReleaseReservation bool
	Err                error
}

func (e *stripePromotionGrantError) Error() string { return e.Err.Error() }
func (e *stripePromotionGrantError) Unwrap() error { return e.Err }

func wrapStripePromotionReservationError(processErr error, attempted bool, teamID, userID uuid.UUID) error {
	if !attempted {
		return processErr
	}
	return &stripePromotionGrantError{TeamID: teamID, UserID: userID, ReleaseReservation: true, Err: processErr}
}

func wrapStripePromotionGrantFinalizationError(processErr error, teamID, userID uuid.UUID) error {
	return &stripePromotionGrantError{TeamID: teamID, UserID: userID, Err: processErr}
}

func wrapStripePromotionGrantRequestError(processErr error, teamID, userID uuid.UUID, previouslyAttempted bool) error {
	msg := processErr.Error()
	if !previouslyAttempted && (strings.Contains(msg, " returned 4") || strings.Contains(msg, "billing client is not configured")) {
		return wrapStripePromotionReservationError(processErr, true, teamID, userID)
	}
	// A transport, timeout, or response-decode error may occur after Stripe
	// accepted the request. A later rejection cannot disprove that earlier
	// grant: authentication and rate limits can precede Stripe's idempotency
	// lookup. Retain the reservation until the grant is reconciled.
	return &stripePromotionGrantError{TeamID: teamID, UserID: userID, Err: processErr}
}

type StripeCreateCustomerParams struct {
	TeamID         uuid.UUID
	Name           string
	IdempotencyKey string
}

type StripeCustomer struct {
	ID string
}

type StripeCreateBillingCreditGrantParams struct {
	CustomerID     string
	AmountCents    int64
	IdempotencyKey string
}

type StripeBillingCreditGrant struct {
	ID string
}

type StripeCreateCheckoutSessionParams struct {
	CustomerID        string
	SuccessURL        string
	CancelURL         string
	ClientReferenceID string
	Metadata          map[string]string
	PriceIDs          []string
	IdempotencyKey    string
	ExpiresAt         *time.Time
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
	PeriodID                string     `json:"period_id"`
	PeriodStart             time.Time  `json:"period_start"`
	PeriodEnd               time.Time  `json:"period_end"`
	Status                  string     `json:"status"`
	BlockedReason           *string    `json:"blocked_reason,omitempty"`
	ApprovedAt              *time.Time `json:"approved_at,omitempty"`
	ExportedAt              *time.Time `json:"exported_at,omitempty"`
	FinalizedAt             *time.Time `json:"finalized_at,omitempty"`
	CancelAtPeriodEnd       *bool      `json:"cancel_at_period_end,omitempty"`
	StripeCustomerID        *string    `json:"stripe_customer_id,omitempty"`
	StripeSubscription      *string    `json:"stripe_subscription_id,omitempty"`
	SubscriptionStatus      *string    `json:"stripe_subscription_status,omitempty"`
	InvoiceStatus           *string    `json:"stripe_invoice_status,omitempty"`
	CommercialBillingAnchor *time.Time `json:"commercial_billing_anchor,omitempty"`
	CurrentPeriodStart      *time.Time `json:"current_period_start,omitempty"`
	CurrentPeriodEnd        *time.Time `json:"current_period_end,omitempty"`
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
	ResourceType     string      `json:"resource_type"`
	ResourceKey      string      `json:"resource_key"`
	DisplayName      string      `json:"display_name"`
	SortOrder        int         `json:"sort_order"`
	DisplayUnit      string      `json:"display_unit"`
	EventName        string      `json:"stripe_event_name"`
	Identifier       string      `json:"stripe_meter_event_identifier"`
	Value            json.Number `json:"value"`
	legacyIdentifier string
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
	Metadata           map[string]string             `json:"metadata"`
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
	ID                string            `json:"id"`
	Customer          string            `json:"customer"`
	Subscription      string            `json:"subscription"`
	ClientReferenceID string            `json:"client_reference_id"`
	Metadata          map[string]string `json:"metadata"`
}

type stripeInvoiceObject struct {
	ID           string `json:"id"`
	Customer     string `json:"customer"`
	Subscription string `json:"subscription"`
	Status       string `json:"status"`
}

type stripeWebhookRoutingDecision string

const (
	stripeWebhookRoutingDecisionInvalid  stripeWebhookRoutingDecision = "invalid"
	stripeWebhookRoutingDecisionOwned    stripeWebhookRoutingDecision = "owned"
	stripeWebhookRoutingDecisionNotOwned stripeWebhookRoutingDecision = "not_owned"
	stripeWebhookRoutingDecisionGlobal   stripeWebhookRoutingDecision = "global"
)

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

func (c *stripeHTTPClient) CreateBillingCreditGrant(ctx context.Context, params StripeCreateBillingCreditGrantParams) (StripeBillingCreditGrant, error) {
	form := url.Values{}
	form.Set("customer", params.CustomerID)
	form.Set("category", "promotional")
	form.Set("amount[type]", "monetary")
	form.Set("amount[monetary][currency]", "usd")
	form.Set("amount[monetary][value]", strconv.FormatInt(params.AmountCents, 10))
	form.Set("applicability_config[scope][price_type]", "metered")
	if params.AmountCents == 9500 && strings.TrimSpace(params.IdempotencyKey) != "" {
		form.Set("metadata[activation_identity]", params.IdempotencyKey)
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &resp, params.IdempotencyKey); err != nil {
		return StripeBillingCreditGrant{}, err
	}
	return StripeBillingCreditGrant{ID: resp.ID}, nil
}

// GetCustomerCreditBalance reads Stripe's authoritative aggregate credit balance.
func (c *stripeHTTPClient) GetCustomerCreditBalance(ctx context.Context, customerID string) (StripeCreditBalance, error) {
	var resp struct {
		Balances []struct {
			AvailableBalance struct {
				Monetary *struct {
					Currency string `json:"currency"`
					Value    int64  `json:"value"`
				} `json:"monetary"`
			} `json:"available_balance"`
		} `json:"balances"`
	}
	// credit_balance_summary is Stripe's aggregate view: it applies the
	// applicability filter and excludes expired grants server-side. Unlike the
	// credit-grants list API, this response is not capped at the first page, so
	// iterating every returned balance preserves credits when a customer has
	// more than 100 grants.
	path := "/v1/billing/credit_balance_summary?customer=" + url.QueryEscape(customerID) + "&filter[type]=applicability_scope&filter[applicability_scope][price_type]=metered"
	if err := c.doForm(ctx, http.MethodGet, path, nil, &resp, ""); err != nil {
		return StripeCreditBalance{}, err
	}
	var cents int64
	seenUSD := false
	for _, b := range resp.Balances {
		// Stripe may omit the monetary object when a balance is not
		// representable. Treat that as an unavailable read, not as a known
		// zero: decoding a missing object into a value struct would silently
		// turn malformed/partial responses into an authoritative zero.
		if b.AvailableBalance.Monetary == nil {
			return StripeCreditBalance{}, fmt.Errorf("stripe credit balance summary contained an unrepresentable balance")
		}
		if b.AvailableBalance.Monetary.Currency == "usd" {
			cents += b.AvailableBalance.Monetary.Value
			seenUSD = true
		}
	}
	if !seenUSD {
		return StripeCreditBalance{}, fmt.Errorf("stripe credit balance summary contained no usable usd balance")
	}
	// The aggregate grant balance does not attest which active-period meter
	// events have been applied, even when usage is submitted incrementally.
	return StripeCreditBalance{AvailableUSD: float64(cents) / 100, ObservedAt: time.Now().UTC(), IncludesCurrentPeriodUsage: false}, nil
}

func (c *stripeHTTPClient) CreateCheckoutSession(ctx context.Context, params StripeCreateCheckoutSessionParams) (StripeCheckoutSession, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("customer", params.CustomerID)
	form.Set("success_url", params.SuccessURL)
	form.Set("cancel_url", params.CancelURL)
	form.Set("client_reference_id", params.ClientReferenceID)
	if params.ExpiresAt != nil {
		form.Set("expires_at", strconv.FormatInt(params.ExpiresAt.UTC().Unix(), 10))
	}
	for key, value := range params.Metadata {
		form.Set("metadata["+key+"]", value)
		form.Set("subscription_data[metadata]["+key+"]", value)
	}
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
	if method == http.MethodPost && (path == "/v1/checkout/sessions" || path == "/v1/billing/credit_grants") {
		// Account for retries durably at the application boundary. A transparent
		// transport replay could mask an accepted first request with a later 4xx.
		req.GetBody = nil
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
	if strings.TrimSpace(c.Query("period_start")) == "" && strings.TrimSpace(c.Query("period_end")) == "" {
		if account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID); accountErr == nil && account.CommercialBillingAnchor.Valid {
			if start, end, anchored := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, h.nowUTC()); anchored {
				periodStart, periodEnd = start, end
			}
		} else if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
			respondError(c, ErrInternal)
			return
		}
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
	account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	anchored := accountErr == nil && account.CommercialBillingAnchor.Valid
	if anchored {
		if start, end, anchored := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, now); anchored {
			currentStart, currentEnd = start, end
		}
	}
	if anchored {
		if _, err := h.DB.UpsertTeamBillingPeriod(c.Request.Context(), db.UpsertTeamBillingPeriodParams{
			TeamID:      teamID,
			PeriodStart: currentStart,
			PeriodEnd:   currentEnd,
			Status:      h.periodStatusForWindow(currentEnd, now),
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("seed current billing period failed")
			respondError(c, ErrInternal)
			return
		}
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
	exports, err := h.billingPreviewExports(c.Request.Context(), db.ListBillingUsageExportsForPeriodParams{
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
	account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
		log.Error().Err(accountErr).Str("team_id", teamID.String()).Msg("load billing account for period approval failed")
		respondError(c, ErrInternal)
		return
	}
	if accountErr == nil && account.CommercialBillingAnchor.Valid {
		expectedStart, expectedEnd, anchored := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, periodStart)
		if !anchored || !periodStart.Equal(expectedStart) || !periodEnd.Equal(expectedEnd) {
			respondErrorMsg(c, "conflict", "period does not match the team's commercial billing anchor", http.StatusConflict)
			return
		}
	}
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "billing transactions are not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), billing.StorageReportSettlementTimeout)
	defer cancel()
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("begin billing period approval transaction failed")
		respondError(c, ErrInternal)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := h.DB.WithTx(tx)
	if err := prepareBillingStorageSnapshot(ctx, tx, teamID, periodEnd); err != nil {
		respondBillingStorageSettlementError(c, err)
		return
	}
	if _, _, err := h.upsertBillingSnapshotWithQueries(ctx, q, teamID, periodStart, periodEnd); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("prepare billing period approval failed")
		respondBillingStorageSettlementError(c, err)
		return
	}
	period, err := q.ApproveTeamBillingPeriod(ctx, db.ApproveTeamBillingPeriodParams{
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
	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit billing period approval transaction failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, billingPeriodResponseFromDB(period, account))
}

func (h *Handlers) ExportTeamBillingPeriod(c *gin.Context) {
	_, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	h.exportTeamBillingPeriod(c)
}

func (h *Handlers) exportTeamBillingPeriod(c *gin.Context) {
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	periodStart, periodEnd, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if h.Pool != nil {
		var enrolled bool
		var hasShadowExport bool
		lookupErr := h.Pool.QueryRow(c.Request.Context(), `
			SELECT EXISTS(SELECT 1 FROM billing_incremental_period
			    WHERE team_id=$1 AND period_start=$2 AND period_end=$3),
			       EXISTS(SELECT 1 FROM billing_usage_export
			        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='skipped_shadow')
		`, teamID, periodStart, periodEnd).Scan(&enrolled, &hasShadowExport)
		if lookupErr != nil {
			respondError(c, ErrInternal)
			return
		}
		enrolledByAnchor := false
		accountHasAnchor := false
		if enrolled {
			account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
			if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
				respondError(c, ErrInternal)
				return
			}
			accountHasAnchor = accountErr == nil && account.CommercialBillingAnchor.Valid
		}
		if !enrolled {
			account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
			enabled, flagErr := h.billingExportEnabled(c.Request.Context(), teamID)
			if flagErr != nil {
				respondError(c, ErrInternal)
				return
			}
			if accountErr == nil && account.CommercialBillingAnchor.Valid && enabled {
				var legacy bool
				if err := h.Pool.QueryRow(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM billing_usage_export
                    WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status NOT IN ('skipped_shadow','skipped_zero','skipped_disabled'))`, teamID, periodStart, periodEnd).Scan(&legacy); err != nil {
					respondError(c, ErrInternal)
					return
				}
				if !legacy {
					if h.nowUTC().Before(periodEnd) {
						ctx := c.Request.Context()
						if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_export_work(team_id) VALUES($1) ON CONFLICT DO NOTHING`, teamID); err != nil {
							respondError(c, ErrInternal)
							return
						}
						complete, err := h.seedExportMeasurements(ctx, teamID, account.CommercialBillingAnchor.Time)
						if err != nil {
							respondError(c, ErrInternal)
							return
						}
						measured, err := h.consumeExportMeasurements(ctx, teamID, account.CommercialBillingAnchor.Time)
						if err != nil {
							respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
							return
						}
						if !complete || measured == exportMeasurementBatch {
							c.JSON(http.StatusAccepted, gin.H{"status": "measurement_pending"})
							return
						}
					}
					enrolled = true
					enrolledByAnchor = true
				}
			}
		}
		incrementalEligible := enrolledByAnchor || accountHasAnchor
		if hasShadowExport {
			// Shadow replays remain on the legacy path while export is disabled;
			// the handoff only occurs once live export is explicitly enabled.
			incrementalEligible, lookupErr = h.billingExportEnabled(c.Request.Context(), teamID)
			if lookupErr != nil {
				respondError(c, ErrInternal)
				return
			}
		}
		if enrolled && incrementalEligible {
			// Incremental replay requires a commercial anchor or a pre-enrolled
			// shadow handoff. Legacy provider events require explicit adoption.
			account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
			if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
				respondError(c, ErrInternal)
				return
			}
			if accountErr == nil && (account.CommercialBillingAnchor.Valid || hasShadowExport) {
				result, exportErr := h.exportIncrementalPeriod(c.Request.Context(), billing.ExportPeriod{TeamID: teamID, Start: periodStart, End: periodEnd})
				if exportErr != nil {
					respondErrorMsg(c, "conflict", exportErr.Error(), http.StatusConflict)
					return
				}
				c.JSON(http.StatusOK, result)
				return
			}
		}
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
	txCtx, cancelTx := context.WithTimeout(ctx, billing.StorageReportSettlementTimeout)
	defer cancelTx()
	tx, err := h.Pool.BeginTx(txCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("begin billing export transaction failed")
		respondError(c, ErrInternal)
		return
	}
	defer func() {
		_ = tx.Rollback(txCtx)
	}()
	q := h.DB.WithTx(tx)

	period, err := q.GetTeamBillingPeriodForUpdate(txCtx, db.GetTeamBillingPeriodForUpdateParams{
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

	existing, err := q.ListBillingUsageExportsForPeriod(txCtx, db.ListBillingUsageExportsForPeriodParams{
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
		frozenUsage, err := q.GetTeamBillingUsageRollup(txCtx, db.GetTeamBillingUsageRollupParams{
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
		if err := prepareBillingStorageSnapshot(txCtx, tx, teamID, periodEnd); err != nil {
			respondBillingStorageSettlementError(c, err)
			return
		}
		usageRow, updatedPeriod, err := h.upsertBillingSnapshotWithQueries(txCtx, q, teamID, periodStart, periodEnd)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("prepare billing export failed")
			respondBillingStorageSettlementError(c, err)
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
		updatedRow, updateErr := q.UpdateBillingUsageExportStatus(txCtx, db.UpdateBillingUsageExportStatusParams{
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
		if exportEnabled {
			// Reopen and enroll shadow-only history through the incremental
			// handoff, which validates that no legacy provider events already
			// exist. Mixed shadow/live history remains unenrolled for explicit
			// reconciliation rather than entering the incremental close gate
			// without allocation and observation evidence.
			var hasShadowExport, shadowOnly bool
			if err := tx.QueryRow(txCtx, `
				SELECT EXISTS(
					SELECT 1 FROM billing_usage_export
					WHERE team_id = $1 AND period_start = $2 AND period_end = $3
					  AND status = 'skipped_shadow'
				), NOT EXISTS(
					SELECT 1 FROM billing_usage_export
					WHERE team_id = $1 AND period_start = $2 AND period_end = $3
					  AND status <> 'skipped_shadow'
				)
			`, teamID, periodStart, periodEnd).Scan(&hasShadowExport, &shadowOnly); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("check exported shadow billing handoff failed")
				respondError(c, ErrInternal)
				return
			}
			if hasShadowExport && shadowOnly {
				if _, err := tx.Exec(txCtx, `
					UPDATE team_billing_usage
					SET exported_at = NULL, updated_at = now()
					WHERE team_id = $1 AND period_start = $2 AND period_end = $3 AND finalized_at IS NULL
				`, teamID, periodStart, periodEnd); err != nil {
					respondError(c, ErrInternal)
					return
				}
				if _, err := tx.Exec(txCtx, `
					UPDATE team_billing_period
					SET status = CASE WHEN approved_at IS NOT NULL THEN 'approved' ELSE 'validating' END,
					    exported_at = NULL, updated_at = now()
					WHERE team_id = $1 AND period_start = $2 AND period_end = $3
				`, teamID, periodStart, periodEnd); err != nil {
					respondError(c, ErrInternal)
					return
				}
				if _, err := tx.Exec(txCtx, `
					INSERT INTO billing_incremental_period (team_id, period_start, period_end)
					VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
				`, teamID, periodStart, periodEnd); err != nil {
					respondError(c, ErrInternal)
					return
				}
			}
		}
		if err := tx.Commit(txCtx); err != nil {
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
			if err := tx.Commit(txCtx); err != nil {
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
			if _, err := q.CreateBillingUsageExport(txCtx, db.CreateBillingUsageExportParams{
				TeamID:                     teamID,
				PeriodStart:                periodStart,
				PeriodEnd:                  periodEnd,
				ResourceType:               resourceType,
				StripeCustomerID:           account.StripeCustomerID,
				StripeMeterEventIdentifier: item.Identifier,
				StripeEventName:            item.EventName,
				Value:                      billingPreviewNumeric(item.Value),
				Status:                     "skipped_shadow",
			}); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("record skipped shadow billing export failed")
				respondError(c, ErrInternal)
				return
			}
		}
		updated, err := q.ListBillingUsageExportsForPeriod(txCtx, db.ListBillingUsageExportsForPeriodParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("list shadow billing export attempts failed")
			respondError(c, ErrInternal)
			return
		}
		if _, err := tx.Exec(txCtx, `
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
		if _, err := tx.Exec(txCtx, `
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
		// A completed shadow period becomes eligible for incremental reconciliation
		// when live export is enabled. This handoff is limited to closed periods;
		// legacy-only exports must not acquire an incremental enrollment marker.
		if !h.nowUTC().Before(periodEnd) {
			if _, err := tx.Exec(txCtx, `
				INSERT INTO billing_incremental_period (team_id, period_start, period_end)
				VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING
			`, teamID, periodStart, periodEnd); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("enroll shadow billing period in incremental accounting failed")
				respondError(c, ErrInternal)
				return
			}
		}
		period.Status = "exported"
		if err := tx.Commit(txCtx); err != nil {
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
			if err := tx.Commit(txCtx); err != nil {
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
				if (existing.Status != "failed" && existing.Status != "skipped_disabled") || (existing.StripeMeterEventIdentifier == item.Identifier || existing.StripeMeterEventIdentifier == item.legacyIdentifier) {
					continue
				}
			}
			meterOK := item.Value.String() != "0.000000000000"
			status := "pending"
			if !meterOK {
				status = "skipped_zero"
			}
			created, err := q.CreateBillingUsageExport(txCtx, db.CreateBillingUsageExportParams{
				TeamID:                     teamID,
				PeriodStart:                periodStart,
				PeriodEnd:                  periodEnd,
				ResourceType:               resourceType,
				StripeCustomerID:           account.StripeCustomerID,
				StripeMeterEventIdentifier: item.Identifier,
				StripeIdempotencyKey:       stringPtr(stripeMeterEventIdempotencyKey(item.Identifier, item.EventName, derefString(account.StripeCustomerID), item.Value.String(), periodEnd.UTC().Add(-time.Second).Unix())),
				StripeEventName:            item.EventName,
				Value:                      billingPreviewNumeric(item.Value),
				Status:                     status,
			})
			if err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("create billing export attempt failed")
				respondError(c, ErrInternal)
				return
			}
			liveExisting[resourceType] = created
		}
		if _, err := q.MarkTeamBillingPeriodExporting(txCtx, db.MarkTeamBillingPeriodExportingParams{
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

	if err := tx.Commit(txCtx); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit billing export claim failed")
		respondError(c, ErrInternal)
		return
	}
	cancelTx()

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
		meterValue, ok, err := billingExportRetryQuantity(row, periodStart, periodEnd)
		if err != nil {
			respondError(c, ErrInternal)
			return
		}
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
		if idempotencyKey == "" || idempotencyKey == row.StripeMeterEventIdentifier {
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
	actorID, err := customerActorID(c)
	if err != nil {
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
	if err := h.DB.PrepareStripeCheckoutIdentity(c.Request.Context(), db.PrepareStripeCheckoutIdentityParams{TeamID: teamID, UserID: actorID}); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("prepare Stripe checkout identity failed")
		respondErrorMsg(c, "service_unavailable", "billing identity evidence is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	customerID, err := h.ensureStripeCustomer(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("ensure Stripe customer failed")
		respondError(c, ErrInternal)
		return
	}
	requestKey := checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs)
	attemptID := uuid.New()
	checkoutAccount, err := h.DB.BeginTeamBillingCheckout(c.Request.Context(), db.BeginTeamBillingCheckoutParams{
		TeamID:     teamID,
		ActorID:    pgtype.UUID{Bytes: actorID, Valid: true},
		RequestKey: stringPtr(requestKey),
		AttemptID:  attemptID,
	})
	resumed := errors.Is(err, pgx.ErrNoRows)
	if resumed {
		checkoutAccount, err = h.DB.ResumeTeamBillingCheckout(c.Request.Context(), db.ResumeTeamBillingCheckoutParams{
			TeamID:     teamID,
			ActorID:    pgtype.UUID{Bytes: actorID, Valid: true},
			RequestKey: stringPtr(requestKey),
			AttemptID:  attemptID,
		})
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "conflict", "another checkout is already in progress", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("begin Stripe checkout failed")
		respondError(c, ErrInternal)
		return
	}
	checkoutActor := uuid.UUID(checkoutAccount.StripeCheckoutActorID.Bytes)
	leaseStartedAt := checkoutAccount.CheckoutInitializingAt.Time.UTC()
	// Replays use the original expiration and actor as well as the same key.
	// The local fence outlives this deadline until expiration is confirmed.
	expiresAt := leaseStartedAt.Add(checkoutSessionLifetime - time.Minute)
	session, err := h.Stripe.CreateCheckoutSession(c.Request.Context(), StripeCreateCheckoutSessionParams{
		CustomerID:        customerID,
		SuccessURL:        successURL,
		CancelURL:         cancelURL,
		ClientReferenceID: teamID.String(),
		PriceIDs:          priceIDs,
		ExpiresAt:         &expiresAt,
		Metadata: map[string]string{
			"activation_user_id":  checkoutActor.String(),
			"checkout_generation": leaseStartedAt.Format(time.RFC3339Nano),
		},
		IdempotencyKey: checkoutSessionIdempotencyKeyForLease(teamID, customerID, successURL, cancelURL, priceIDs, leaseStartedAt),
	})
	if err != nil {
		// A transport, timeout, or decode failure is ambiguous: Stripe may have
		// created the session even though the response did not reach us. Keep the
		// lease until the matching Checkout session expires so another writer
		// cannot create a second subscription-capable session.
		msg := strings.ToLower(err.Error())
		definitiveFailure := strings.Contains(msg, " returned 4") || strings.Contains(msg, "not configured")
		h.finishFailedStripeCheckoutAttempt(teamID, attemptID, checkoutAccount.CheckoutInitializingAt, !definitiveFailure)
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("create Stripe checkout session failed")
		respondErrorMsg(c, "bad_gateway", "Stripe checkout session creation failed", http.StatusBadGateway)
		return
	}
	if _, err := h.DB.SetTeamBillingCheckoutSession(c.Request.Context(), db.SetTeamBillingCheckoutSessionParams{
		TeamID: teamID, SessionID: stringPtr(session.ID), LeaseStartedAt: checkoutAccount.CheckoutInitializingAt, AttemptID: attemptID,
	}); err != nil {
		// Do not return a Checkout URL that cannot be authenticated by the
		// completion webhook. The local lease remains in place for retry.
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("persist Stripe checkout session failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{ID: session.ID, URL: session.URL})
}

func (h *Handlers) finishFailedStripeCheckoutAttempt(teamID, attemptID uuid.UUID, leaseStartedAt pgtype.Timestamptz, mayExist bool) {
	// Release only after every registered attempt failed definitively. An
	// unfinished or ambiguous attempt may already have created a session. The
	// attempt ID makes retries safe even if a committed reply was lost.
	var err error
	for retry := 0; retry < 3; retry++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = h.DB.FinishFailedTeamBillingCheckoutAttempt(ctx, db.FinishFailedTeamBillingCheckoutAttemptParams{TeamID: teamID, LeaseStartedAt: leaseStartedAt, AttemptID: attemptID, MayExist: mayExist})
		cancel()
		if err == nil {
			return
		}
		if retry < 2 {
			time.Sleep(time.Duration(retry+1) * 100 * time.Millisecond)
		}
	}
	log.Error().Err(err).Str("team_id", teamID.String()).Str("attempt_id", attemptID.String()).Msg("record failed Stripe checkout attempt failed after retries")
}

// EstablishCommercialBillingAnchor is the sales-assisted cutover operation.
func (h *Handlers) EstablishCommercialBillingAnchor(c *gin.Context) {
	_, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	teamID, err := internalTeamID(c)
	if err != nil {
		return
	}
	var req commercialBillingAnchorRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		respondErrorMsg(c, "bad_request", "invalid commercial billing anchor request", http.StatusBadRequest)
		return
	}
	anchor := h.nowUTC()
	if req.Anchor != nil {
		anchor = req.Anchor.UTC()
	}
	anchor = anchor.Truncate(time.Second)
	if anchor.After(h.nowUTC()) {
		respondErrorMsg(c, "bad_request", "commercial billing anchor cannot be in the future", http.StatusBadRequest)
		return
	}
	claimed, err := h.DB.ClaimTeamCommercialBillingAnchor(c.Request.Context(), db.ClaimTeamCommercialBillingAnchorParams{TeamID: teamID, Anchor: anchor})
	if err != nil {
		respondErrorMsg(c, "conflict", "commercial billing anchor could not be established", http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"team_id": teamID.String(), "commercial_billing_anchor": claimed.UTC()})
}

// EstablishBillingCutover sets the production cutover boundary.
func (h *Handlers) EstablishBillingCutover(c *gin.Context) {
	_, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	var req billingCutoverRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.CutoverAt.IsZero() {
		respondErrorMsg(c, "bad_request", "cutover_at is required", http.StatusBadRequest)
		return
	}
	cutover := req.CutoverAt.UTC().Truncate(time.Second)
	count, err := h.DB.EstablishBillingCutover(c.Request.Context(), db.EstablishBillingCutoverParams{Cutover: cutover, PreservedTeamIds: req.PreservedTeamIDs})
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"cutover_at": cutover, "teams_updated": count})
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
	if h.Config == nil || (strings.TrimSpace(h.Config.StripeWebhookSecret) == "" && strings.TrimSpace(h.Config.StripeMeterErrorWebhookSecret) == "") {
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
	if err := verifyStripeWebhookSignatureWithSecrets(payload, c.GetHeader("Stripe-Signature"), h.nowUTC(), h.Config.StripeWebhookSecret, h.Config.StripeMeterErrorWebhookSecret); err != nil {
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
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "billing transactions are not configured", http.StatusServiceUnavailable)
		return
	}

	routing, err := h.resolveStripeWebhookRouting(c.Request.Context(), &event)
	if err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Str("event_type", event.Type).Msg("resolve Stripe webhook routing failed")
		respondError(c, ErrInternal)
		return
	}
	if routing == stripeWebhookRoutingDecisionNotOwned {
		log.Info().Str("routing_decision", string(routing)).Str("event_id", event.ID).Str("event_type", event.Type).Msg("Stripe webhook ignored for non-local ownership")
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}
	if routing == stripeWebhookRoutingDecisionInvalid {
		respondError(c, ErrInternal)
		return
	}
	recordTx, err := h.Pool.BeginTx(c.Request.Context(), pgx.TxOptions{})
	if err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("begin Stripe webhook record transaction failed")
		respondError(c, ErrInternal)
		return
	}
	defer func() {
		_ = recordTx.Rollback(c.Request.Context())
	}()
	recordQ := h.DB.WithTx(recordTx)

	if _, err := recordQ.CreateStripeWebhookEvent(c.Request.Context(), db.CreateStripeWebhookEventParams{
		EventID:   event.ID,
		EventType: event.Type,
		Payload:   payload,
	}); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("event_id", event.ID).Msg("record Stripe webhook event failed")
			respondError(c, ErrInternal)
			return
		}
		existing, gerr := recordQ.GetStripeWebhookEventForUpdate(c.Request.Context(), event.ID)
		if gerr != nil {
			log.Error().Err(gerr).Str("event_id", event.ID).Msg("load existing Stripe webhook event failed")
			respondError(c, ErrInternal)
			return
		}
		if existing.ProcessedAt.Valid {
			if err := recordTx.Commit(c.Request.Context()); err != nil {
				log.Error().Err(err).Str("event_id", event.ID).Msg("commit duplicate Stripe webhook failed")
				respondError(c, ErrInternal)
				return
			}
			h.scheduleBillingEligibilityReconciliation(c.Request.Context(), event)
			c.JSON(http.StatusOK, gin.H{"status": "duplicate"})
			return
		}
	}
	if err := recordTx.Commit(c.Request.Context()); err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Msg("commit Stripe webhook record failed")
		respondError(c, ErrInternal)
		return
	}
	if err := h.processRecordedStripeWebhook(c.Request.Context(), event); err != nil {
		log.Error().Err(err).Str("event_id", event.ID).Str("event_type", event.Type).Msg("process Stripe webhook failed")
		respondError(c, ErrInternal)
		return
	}
	h.scheduleBillingEligibilityReconciliation(c.Request.Context(), event)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) processRecordedStripeWebhook(ctx context.Context, event stripeEventEnvelope) error {
	if event.Type == "checkout.session.completed" {
		pending, err := h.associateStripeCheckoutBeforeReconciliation(ctx, event)
		if err != nil {
			return err
		}
		if err := h.reconcilePendingStripeSubscriptionEvents(ctx, pending); err != nil {
			return err
		}
	}
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	queries := db.New(conn)
	var lease *stripeWebhookProcessingLease
	if strings.HasPrefix(event.Type, "customer.subscription.") {
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		lease, err = claimStripeWebhookProcessingLease(ctx, queries, obj.Customer)
		if err != nil {
			return err
		}
		defer func() {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := queries.ReleaseStripeWebhookProcessingLease(releaseCtx, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: lease.CustomerID, Token: lease.Token}); err != nil {
				log.Error().Err(err).Str("event_id", event.ID).Msg("release Stripe webhook processing lease failed")
			}
		}()
		// Bound work below the durable lease lifetime. Every committing phase
		// additionally checks the token, so an expired worker cannot finalize.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	// A concurrent delivery may have completed while this one waited for the
	// lease. Recheck before creating a reservation that processing would skip.
	existingEvent, err := queries.GetStripeWebhookEvent(ctx, event.ID)
	if err != nil {
		return err
	}
	if existingEvent.ProcessedAt.Valid {
		return nil
	}
	preReservation, err := h.reserveStripePromotionBeforeWebhook(ctx, queries, event)
	if err != nil {
		return err
	}
	processTx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		_ = processTx.Rollback(ctx)
	}()
	q := h.DB.WithTx(processTx)
	if err := lease.lock(ctx, q); err != nil {
		return err
	}

	if err := h.lockStripeWebhookAccountForProcessing(ctx, q, event); err != nil {
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, processTx, event.ID, err, false)
		return err
	}
	existing, err := q.GetStripeWebhookEventForUpdate(ctx, event.ID)
	if err != nil {
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, processTx, event.ID, err, false)
		return err
	}
	if existing.ProcessedAt.Valid {
		return processTx.Commit(ctx)
	}

	if err := h.processStripeWebhookEventWithPreReservation(ctx, processTx, event, preReservation); err != nil {
		var pending *stripePromotionPendingGrant
		if errors.As(err, &pending) {
			if err := processTx.Commit(ctx); err != nil {
				return err
			}
			grant, err := h.createReservedStripePromotion(ctx, pending)
			if err != nil {
				h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, nil, event.ID, err, false)
				return err
			}
			return h.finalizeRecordedStripePromotion(ctx, conn, event.ID, pending, grant.ID, lease)
		}
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, processTx, event.ID, err, false)
		return err
	}
	if _, err := q.MarkStripeWebhookEventProcessed(ctx, event.ID); err != nil {
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, processTx, event.ID, err, true)
		return err
	}
	if err := processTx.Commit(ctx); err != nil {
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, processTx, event.ID, err, true)
		return err
	}
	return nil
}

type stripeWebhookProcessingLease struct {
	CustomerID string
	Token      uuid.UUID
}

func claimStripeWebhookProcessingLease(ctx context.Context, q *db.Queries, customerID string) (*stripeWebhookProcessingLease, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lease := &stripeWebhookProcessingLease{CustomerID: customerID, Token: uuid.New()}
	for {
		_, err := q.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: lease.Token})
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (lease *stripeWebhookProcessingLease) lock(ctx context.Context, q *db.Queries) error {
	if lease == nil {
		return nil
	}
	_, err := q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: lease.CustomerID, Token: lease.Token})
	return err
}

// reserveStripePromotionBeforeWebhook commits the durable user/team fence
// before any Stripe side effect. The subsequent processing transaction may
// crash or roll back without reopening the entitlement to another team.
type stripePromotionPreReservation struct {
	EventID   string
	TeamID    uuid.UUID
	UserID    uuid.UUID
	Reserved  bool
	Retryable bool
}

func (h *Handlers) reserveStripePromotionBeforeWebhook(ctx context.Context, queries *db.Queries, event stripeEventEnvelope) (*stripePromotionPreReservation, error) {
	if event.Type != "customer.subscription.created" && event.Type != "customer.subscription.updated" && event.Type != "customer.subscription.resumed" {
		return nil, nil
	}
	var obj stripeSubscriptionObject
	if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
		return nil, err
	}
	if !strings.EqualFold(obj.Status, "active") && !strings.EqualFold(obj.Status, "trialing") {
		return nil, nil
	}
	// Match the processing guards before reserving. Malformed active events are
	// intentionally ignored by processing and must not leave a durable fence.
	if strings.TrimSpace(obj.ID) == "" || event.Created == 0 {
		return nil, nil
	}
	if _, _, ok := stripeSubscriptionPeriodBounds(obj); !ok {
		return nil, nil
	}
	if strings.TrimSpace(obj.Customer) == "" {
		return nil, nil
	}
	account, err := queries.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	orderingAccount := db.TeamBillingAccount{
		TeamID:                          account.TeamID,
		StripeCustomerID:                account.StripeCustomerID,
		StripeSubscriptionID:            account.StripeSubscriptionID,
		StripeSubscriptionStatus:        account.StripeSubscriptionStatus,
		StripeSubscriptionEventAt:       account.StripeSubscriptionEventAt,
		TrialEndedAt:                    account.TrialEndedAt,
		StripeActivationCreditGrantedAt: account.StripeActivationCreditGrantedAt,
		StripeActivationCreditGrantID:   account.StripeActivationCreditGrantID,
		CheckoutInitializingAt:          account.CheckoutInitializingAt,
		CheckoutSessionID:               account.CheckoutSessionID,
	}
	// Apply the same ordering and subscription identity guards as webhook
	// processing before establishing a durable reservation. An ignored stale
	// event must not fence the user from redeeming on another team.
	eventAt := stripeEventTime(int64(event.Created))
	associated := stripeSubscriptionMatchesCurrentAssociation(orderingAccount, obj.ID)
	if event.Type == "customer.subscription.created" {
		deferProcessing, ignore := shouldIgnoreUnassociatedStripeSubscriptionCreated(orderingAccount, obj.ID)
		if deferProcessing || ignore {
			return nil, nil
		}
		associated = true
	} else if !associated && !canAssociateStripeSubscription(account, obj) {
		return nil, nil
	}
	if account.StripeSubscriptionEventAt.Valid {
		previousAt := account.StripeSubscriptionEventAt.Time.UTC()
		orderingStatus := obj.Status
		if event.Type == "customer.subscription.deleted" {
			orderingStatus = "canceled"
		}
		if eventAt.Before(previousAt) || (eventAt.Equal(previousAt) && shouldSkipEqualTimestampStripeSubscription(orderingAccount, obj.ID, orderingStatus)) {
			return nil, nil
		}
	}
	if account.StripeActivationCreditGrantID != nil || account.StripeActivationCreditGrantedAt.Valid {
		return nil, nil
	}
	userID := stripePromotionActorForSubscription(account, obj)
	if userID == uuid.Nil {
		userID, err = queries.GetLegacyStripeActivationUser(ctx, account.TeamID)
		if errors.Is(err, pgx.ErrNoRows) {
			if event.Type != "customer.subscription.created" {
				userID, err = queries.GetCurrentStripeActivationUser(ctx, account.TeamID)
			}
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	state, err := queries.ReserveStripePromotionForSubscriptionEventState(ctx, stripePromotionSubscriptionReservationParams(account.TeamID, userID, event.ID, obj))
	if err != nil {
		return nil, err
	}
	return &stripePromotionPreReservation{
		EventID:   event.ID,
		TeamID:    account.TeamID,
		UserID:    userID,
		Reserved:  state == "acquired" || state == "existing",
		Retryable: state == "blocked",
	}, nil
}

func (h *Handlers) expandStripeThinMeterEvent(ctx context.Context, event *stripeEventEnvelope) error {
	if !isStripeMeterErrorEvent(event.Type) || len(bytes.TrimSpace(event.Data.Object)) != 0 {
		return nil
	}
	retriever, ok := h.Stripe.(stripeEventRetriever)
	if !ok {
		return errors.New("Stripe event retrieval is not configured")
	}
	fullEvent, err := retriever.RetrieveEvent(ctx, event.ID)
	if err != nil {
		return err
	}
	var retrieved struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(fullEvent, &retrieved); err != nil {
		return err
	}
	if len(bytes.TrimSpace(retrieved.Data)) == 0 {
		return errors.New("Stripe thin event response has no data")
	}
	event.Data.Object = retrieved.Data
	return nil
}

func (h *Handlers) persistStripeWebhookFailure(ctx context.Context, queries *db.Queries, eventID, lastError string) error {
	_, err := queries.MarkStripeWebhookEventFailed(ctx, db.MarkStripeWebhookEventFailedParams{
		EventID:   eventID,
		LastError: &lastError,
	})
	return err
}

func (h *Handlers) rollbackAndPersistStripeWebhookFailure(ctx context.Context, conn *pgxpool.Conn, lease *stripeWebhookProcessingLease, tx pgx.Tx, eventID string, processErr error, preserveReservation bool) {
	if tx != nil {
		if rerr := tx.Rollback(ctx); rerr != nil {
			log.Error().Err(rerr).Str("event_id", eventID).Msg("rollback failed Stripe webhook transaction failed")
		}
	}
	// Recovery runs on a detached, bounded context because the webhook request
	// may already be canceled by the time the database work is attempted.
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recoveryTx, err := conn.BeginTx(recoveryCtx, pgx.TxOptions{})
	if err != nil {
		log.Error().Err(err).Str("event_id", eventID).Msg("begin Stripe webhook recovery failed")
		return
	}
	defer recoveryTx.Rollback(recoveryCtx)
	queries := h.DB.WithTx(recoveryTx)
	if err := lease.lock(recoveryCtx, queries); err != nil {
		log.Error().Err(err).Str("event_id", eventID).Msg("Stripe webhook recovery no longer owns processing lease")
		return
	}
	// A grant finalization failure occurs after Stripe has accepted the grant.
	// Re-establish the durable reservation after rolling back the webhook
	// transaction so a retry (or another team activation) cannot redeem it.
	var grantErr *stripePromotionGrantError
	if errors.As(processErr, &grantErr) {
		if grantErr.ReleaseReservation {
			if rerr := queries.ReleaseStripePromotionForEvent(recoveryCtx, db.ReleaseStripePromotionForEventParams{TeamID: grantErr.TeamID, UserID: grantErr.UserID, EventID: eventID}); rerr != nil {
				log.Error().Err(rerr).Str("event_id", eventID).Msg("release Stripe promotion reservation after definitive grant failure failed")
			}
		} else if state, rerr := queries.ReserveStripePromotionForEventState(recoveryCtx, db.ReserveStripePromotionForEventStateParams{TeamID: grantErr.TeamID, UserID: grantErr.UserID, EventID: eventID}); rerr != nil || (state != "acquired" && state != "existing") {
			log.Error().Err(rerr).Str("reservation_state", state).Str("event_id", eventID).Msg("preserve Stripe promotion reservation after grant failure failed")
		}
	}
	if preserveReservation {
		if err := h.preserveStripePromotionReservation(recoveryCtx, queries, eventID); err != nil {
			log.Error().Err(err).Str("event_id", eventID).Msg("preserve Stripe promotion reservation after bookkeeping failure failed")
		}
	}
	if ferr := h.persistStripeWebhookFailure(recoveryCtx, queries, eventID, processErr.Error()); ferr != nil {
		log.Error().Err(ferr).Str("event_id", eventID).Msg("persist Stripe webhook failed state failed")
	}
	if err := recoveryTx.Commit(recoveryCtx); err != nil {
		log.Error().Err(err).Str("event_id", eventID).Msg("commit Stripe webhook recovery failed")
	}
}

func (h *Handlers) preserveStripePromotionReservation(ctx context.Context, queries *db.Queries, eventID string) error {
	event, err := queries.GetStripeWebhookEvent(ctx, eventID)
	if err != nil {
		return err
	}
	if event.EventType != "customer.subscription.created" && event.EventType != "customer.subscription.updated" && event.EventType != "customer.subscription.resumed" {
		return nil
	}
	var obj stripeSubscriptionObject
	var envelope struct {
		Data struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(event.Payload, &envelope); err != nil {
		return err
	}
	if err := json.Unmarshal(envelope.Data.Object, &obj); err != nil {
		return err
	}
	if !strings.EqualFold(obj.Status, "active") && !strings.EqualFold(obj.Status, "trialing") {
		return nil
	}
	if obj.Customer == "" {
		return nil
	}
	account, err := queries.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
	if err != nil {
		return err
	}
	if account.StripeActivationCreditGrantID != nil {
		return nil
	}
	userID := stripePromotionActorForSubscription(account, obj)
	if userID == uuid.Nil {
		userID, err = queries.GetLegacyStripeActivationUser(ctx, account.TeamID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	_, err = queries.ReserveStripePromotionForSubscriptionEventState(ctx, stripePromotionSubscriptionReservationParams(account.TeamID, userID, eventID, obj))
	return err
}

func stripePromotionSubscriptionReservationParams(teamID, userID uuid.UUID, eventID string, obj stripeSubscriptionObject) db.ReserveStripePromotionForSubscriptionEventStateParams {
	var generation pgtype.Timestamptz
	rawGeneration, hasGeneration := obj.Metadata["checkout_generation"]
	if parsed, err := time.Parse(time.RFC3339Nano, rawGeneration); err == nil && parsed.Nanosecond()%1000 == 0 {
		generation = pgtype.Timestamptz{Time: parsed.UTC(), Valid: true}
	}
	return db.ReserveStripePromotionForSubscriptionEventStateParams{
		TeamID: teamID, UserID: userID, EventID: eventID,
		SubscriptionID: stringPtr(obj.ID), CheckoutGeneration: generation,
		HasCheckoutGeneration: hasGeneration,
	}
}

// lockStripeWebhookAccountForProcessing establishes the lock order shared by
// normal webhook delivery and checkout reconciliation: promotion locks precede
// the team billing row, which precedes any webhook row.
func (h *Handlers) lockStripeWebhookAccountForProcessing(ctx context.Context, q *db.Queries, event stripeEventEnvelope) error {
	switch event.Type {
	case "checkout.session.completed", "checkout.session.expired":
		var obj stripeCheckoutCompletedObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
		if err != nil {
			return err
		}
		_, err = q.LockTeamBillingAccount(ctx, teamID)
		return err
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "customer.subscription.paused", "customer.subscription.resumed":
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		if err != nil {
			return err
		}
		if account.StripeActivationUserID.Valid {
			if err := q.LockStripePromotion(ctx, db.LockStripePromotionParams{
				TeamID: account.TeamID, UserID: uuid.UUID(account.StripeActivationUserID.Bytes),
			}); err != nil {
				return err
			}
		}
		_, err = q.LockTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		return err
	case "invoice.payment_failed", "invoice.payment_succeeded", "invoice.finalized":
		var obj stripeInvoiceObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		_, err := q.LockTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		return err
	default:
		return nil
	}
}

func (h *Handlers) resolveStripeWebhookRouting(ctx context.Context, event *stripeEventEnvelope) (stripeWebhookRoutingDecision, error) {
	switch event.Type {
	case "checkout.session.completed", "checkout.session.expired":
		var obj stripeCheckoutCompletedObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return stripeWebhookRoutingDecisionInvalid, err
		}
		teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
		if err != nil {
			return stripeWebhookRoutingDecisionNotOwned, nil
		}
		if _, err := h.DB.GetTeam(ctx, teamID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return stripeWebhookRoutingDecisionNotOwned, nil
			}
			return stripeWebhookRoutingDecisionInvalid, err
		}
		return stripeWebhookRoutingDecisionOwned, nil
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "customer.subscription.paused", "customer.subscription.resumed":
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return stripeWebhookRoutingDecisionInvalid, err
		}
		customerID := strings.TrimSpace(obj.Customer)
		if customerID == "" {
			return stripeWebhookRoutingDecisionInvalid, fmt.Errorf("stripe subscription event has no customer")
		}
		if _, err := h.DB.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(customerID)); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return stripeWebhookRoutingDecisionNotOwned, nil
			}
			return stripeWebhookRoutingDecisionInvalid, err
		}
		return stripeWebhookRoutingDecisionOwned, nil
	case "invoice.payment_failed", "invoice.payment_succeeded", "invoice.finalized":
		var obj stripeInvoiceObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return stripeWebhookRoutingDecisionInvalid, err
		}
		customerID := strings.TrimSpace(obj.Customer)
		if customerID == "" {
			return stripeWebhookRoutingDecisionInvalid, fmt.Errorf("stripe invoice event has no customer")
		}
		if _, err := h.DB.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(customerID)); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return stripeWebhookRoutingDecisionNotOwned, nil
			}
			return stripeWebhookRoutingDecisionInvalid, err
		}
		return stripeWebhookRoutingDecisionOwned, nil
	case "billing.meter.error_report_triggered", "v1.billing.meter.error_report_triggered", "billing.meter.no_meter_found", "v1.billing.meter.no_meter_found":
		return stripeWebhookRoutingDecisionGlobal, nil
	default:
		return stripeWebhookRoutingDecisionGlobal, nil
	}
}

func isStripeMeterErrorEvent(eventType string) bool {
	return eventType == "billing.meter.error_report_triggered" || eventType == "v1.billing.meter.error_report_triggered" ||
		eventType == "billing.meter.no_meter_found" || eventType == "v1.billing.meter.no_meter_found"
}

func isActivatingStripeSubscriptionStatus(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "active") || strings.EqualFold(strings.TrimSpace(status), "trialing")
}

func isTerminalStripeSubscriptionStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "canceled", "unpaid", "paused", "incomplete_expired":
		return true
	default:
		return false
	}
}

type stripeSubscriptionState struct {
	SubscriptionID *string
	Status         *string
	TrialEndedAt   pgtype.Timestamptz
	GrantAt        pgtype.Timestamptz
	GrantID        *string
	CheckoutAt     pgtype.Timestamptz
	CheckoutID     *string
	CustomerID     *string
}

func stripeSubscriptionStateFrom(account any) stripeSubscriptionState {
	switch a := account.(type) {
	case db.TeamBillingAccount:
		return stripeSubscriptionState{a.StripeSubscriptionID, a.StripeSubscriptionStatus, a.TrialEndedAt, a.StripeActivationCreditGrantedAt, a.StripeActivationCreditGrantID, a.CheckoutInitializingAt, a.CheckoutSessionID, a.StripeCustomerID}
	case db.GetTeamBillingAccountByStripeCustomerIDRow:
		return stripeSubscriptionState{a.StripeSubscriptionID, a.StripeSubscriptionStatus, a.TrialEndedAt, a.StripeActivationCreditGrantedAt, a.StripeActivationCreditGrantID, a.CheckoutInitializingAt, a.CheckoutSessionID, a.StripeCustomerID}
	default:
		return stripeSubscriptionState{}
	}
}

func isStripeActivationStateComplete(account any) bool {
	a := stripeSubscriptionStateFrom(account)
	return a.TrialEndedAt.Valid && a.GrantAt.Valid && strings.TrimSpace(derefString(a.GrantID)) != ""
}

func shouldSkipEqualTimestampStripeSubscription(account any, incomingSubscriptionID, incomingStatus string) bool {
	a := stripeSubscriptionStateFrom(account)
	currentSubscriptionID := strings.TrimSpace(derefString(a.SubscriptionID))
	if currentSubscriptionID == "" || currentSubscriptionID != strings.TrimSpace(incomingSubscriptionID) {
		return false
	}
	previousStatus := derefString(a.Status)
	if isTerminalStripeSubscriptionStatus(incomingStatus) {
		return isTerminalStripeSubscriptionStatus(previousStatus)
	}
	if isTerminalStripeSubscriptionStatus(previousStatus) || !isActivatingStripeSubscriptionStatus(incomingStatus) {
		return true
	}
	return isActivatingStripeSubscriptionStatus(previousStatus) && isStripeActivationStateComplete(account)
}

func stripeSubscriptionMatchesCurrentAssociation(account any, subscriptionID string) bool {
	currentSubscriptionID := strings.TrimSpace(derefString(stripeSubscriptionStateFrom(account).SubscriptionID))
	return currentSubscriptionID != "" && currentSubscriptionID == strings.TrimSpace(subscriptionID)
}

func canAssociateStripeSubscription(account db.GetTeamBillingAccountByStripeCustomerIDRow, obj stripeSubscriptionObject) bool {
	if account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid {
		if !account.CheckoutInitializingAt.Valid || !account.StripeCheckoutActorID.Valid {
			return false
		}
		if account.CheckoutSubscriptionID != nil {
			return *account.CheckoutSubscriptionID == obj.ID
		}
		// Customer ownership alone cannot distinguish an older subscription
		// from the checkout whose actor would receive this promotion.
		return obj.Metadata["checkout_generation"] == account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano)
	}
	return account.StripeSubscriptionID == nil && strings.TrimSpace(obj.Metadata["activation_user_id"]) != ""
}

func stripePromotionActorForSubscription(account db.GetTeamBillingAccountByStripeCustomerIDRow, obj stripeSubscriptionObject) uuid.UUID {
	if account.StripeActivationCreditReservedAt.Valid && account.StripeActivationUserID.Valid {
		return uuid.UUID(account.StripeActivationUserID.Bytes)
	}
	if account.StripeCheckoutActorID.Valid {
		associated := obj.ID != "" && account.CheckoutSubscriptionID != nil && *account.CheckoutSubscriptionID == obj.ID
		if obj.ID != "" && account.CheckoutSubscriptionID == nil && account.CheckoutInitializingAt.Valid {
			associated = associated || obj.Metadata["checkout_generation"] == account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano)
		}
		if associated {
			return uuid.UUID(account.StripeCheckoutActorID.Bytes)
		}
	}
	userID, _ := uuid.Parse(strings.TrimSpace(obj.Metadata["activation_user_id"]))
	return userID
}

func shouldIgnoreUnassociatedStripeSubscriptionCreated(account any, subscriptionID string) (bool, bool) {
	a := stripeSubscriptionStateFrom(account)
	if stripeSubscriptionMatchesCurrentAssociation(account, subscriptionID) {
		return false, false
	}
	if a.CheckoutAt.Valid {
		return true, false
	}
	if strings.TrimSpace(derefString(a.SubscriptionID)) != "" || a.CheckoutID != nil {
		return false, true
	}
	if strings.TrimSpace(derefString(a.CustomerID)) != "" {
		return false, false
	}
	return false, true
}

// Commit the verified association while retaining the checkout lease. Each
// retained event can then reserve credit durably before taking the account lock.
func (h *Handlers) associateStripeCheckoutBeforeReconciliation(ctx context.Context, event stripeEventEnvelope) ([]db.StripeWebhookEvent, error) {
	var obj stripeCheckoutCompletedObject
	if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
		return nil, err
	}
	teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(obj.Customer) == "" || strings.TrimSpace(obj.Subscription) == "" {
		return nil, nil
	}
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	account, err := q.LockTeamBillingAccount(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(derefString(account.CheckoutSessionID)) != strings.TrimSpace(obj.ID) ||
		strings.TrimSpace(obj.ID) == "" || strings.TrimSpace(derefString(account.StripeCustomerID)) != strings.TrimSpace(obj.Customer) {
		return nil, nil
	}
	if err := q.AssociateTeamBillingCheckoutSubscription(ctx, db.AssociateTeamBillingCheckoutSubscriptionParams{
		TeamID: teamID, SubscriptionID: stringPtr(obj.Subscription),
	}); err != nil {
		return nil, err
	}
	pending, err := q.LockPendingStripeSubscriptionEvents(ctx, obj.Customer, obj.Subscription)
	if err != nil {
		return nil, err
	}
	ordered, err := orderedStripeSubscriptionEvents(pending)
	if err != nil {
		return nil, err
	}
	// Publish a retained non-activating state with the association, so an older
	// activation retry cannot grant credit before its newer state is visible.
	if len(ordered) > 0 && !ordered[0].activating {
		latest := ordered[0].event
		if err := h.processStripeWebhookEvent(ctx, tx, latest); err != nil {
			return nil, err
		}
		if _, err := q.MarkStripeWebhookEventProcessed(ctx, latest.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pending, nil
}

type pendingStripeSubscriptionEvent struct {
	event      stripeEventEnvelope
	terminal   bool
	activating bool
}

func orderedStripeSubscriptionEvents(pending []db.StripeWebhookEvent) ([]pendingStripeSubscriptionEvent, error) {
	events := make([]pendingStripeSubscriptionEvent, 0, len(pending))
	for _, row := range pending {
		var event stripeEventEnvelope
		if err := json.Unmarshal(row.Payload, &event); err != nil {
			return nil, fmt.Errorf("decode deferred Stripe subscription event %s: %w", row.EventID, err)
		}
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return nil, fmt.Errorf("decode deferred Stripe subscription object %s: %w", row.EventID, err)
		}
		events = append(events, pendingStripeSubscriptionEvent{
			event:      event,
			terminal:   event.Type == "customer.subscription.deleted" || isTerminalStripeSubscriptionStatus(obj.Status),
			activating: isActivatingStripeSubscriptionStatus(obj.Status),
		})
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].event.Created != events[j].event.Created {
			return events[i].event.Created > events[j].event.Created
		}
		return events[i].terminal && !events[j].terminal
	})
	return events, nil
}

func (h *Handlers) reconcilePendingStripeSubscriptionEvents(ctx context.Context, pending []db.StripeWebhookEvent) error {
	events, err := orderedStripeSubscriptionEvents(pending)
	if err != nil {
		return err
	}
	for _, pendingEvent := range events {
		if err := h.processRecordedStripeWebhook(ctx, pendingEvent.event); err != nil {
			return err
		}
		h.scheduleBillingEligibilityReconciliation(ctx, pendingEvent.event)
	}
	return nil
}

func (h *Handlers) processStripeWebhookEvent(ctx context.Context, tx pgx.Tx, event stripeEventEnvelope) error {
	return h.processStripeWebhookEventWithPreReservation(ctx, tx, event, nil)
}

type stripePromotionPendingGrant struct {
	TeamID, UserID      uuid.UUID
	CustomerID          string
	PreviouslyAttempted bool
	FirstAttemptAt      time.Time
}

func (*stripePromotionPendingGrant) Error() string { return "Stripe promotion grant is ready" }

func prepareStripePromotionGrant(ctx context.Context, q *db.Queries, teamID, userID uuid.UUID, eventID, customerID string) error {
	previouslyAttempted, err := q.StripePromotionWasAttempted(ctx, db.StripePromotionWasAttemptedParams{TeamID: pgtype.UUID{Bytes: teamID, Valid: true}, UserID: userID})
	if err != nil {
		return err
	}
	attemptedAt, err := q.MarkStripePromotionAttempt(ctx, db.MarkStripePromotionAttemptParams{TeamID: pgtype.UUID{Bytes: teamID, Valid: true}, UserID: userID, EventID: stringPtr(eventID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("Stripe promotion reservation is no longer owned by this event")
	}
	if err != nil {
		return err
	}
	if !attemptedAt.Valid || attemptedAt.InfinityModifier != pgtype.Finite {
		return wrapStripePromotionGrantFinalizationError(errStripePromotionSettlementRequired, teamID, userID)
	}
	if err := stripePromotionReplayWindowError(attemptedAt.Time, time.Now().UTC()); err != nil {
		return wrapStripePromotionGrantFinalizationError(err, teamID, userID)
	}
	return &stripePromotionPendingGrant{TeamID: teamID, UserID: userID, CustomerID: customerID, PreviouslyAttempted: previouslyAttempted, FirstAttemptAt: attemptedAt.Time}
}

func stripePromotionReplayWindowError(firstAttemptAt, now time.Time) error {
	if firstAttemptAt.IsZero() || !now.Before(firstAttemptAt.Add(stripePromotionReplayWindow)) {
		return errStripePromotionSettlementRequired
	}
	return nil
}

func (h *Handlers) createReservedStripePromotion(ctx context.Context, pending *stripePromotionPendingGrant) (StripeBillingCreditGrant, error) {
	teamID, userID := pending.TeamID, pending.UserID
	if h.Stripe == nil {
		return StripeBillingCreditGrant{}, wrapStripePromotionGrantFinalizationError(errors.New("Stripe billing client is not configured"), teamID, userID)
	}
	// Stripe may discard idempotency results after 24 hours. Recheck after the
	// database commit so a delayed attempt cannot outlive the safe replay window.
	if err := stripePromotionReplayWindowError(pending.FirstAttemptAt, h.nowUTC()); err != nil {
		return StripeBillingCreditGrant{}, wrapStripePromotionGrantFinalizationError(err, teamID, userID)
	}
	grant, err := h.Stripe.CreateBillingCreditGrant(ctx, StripeCreateBillingCreditGrantParams{
		CustomerID: pending.CustomerID, AmountCents: 9500, IdempotencyKey: "stripe-activation-credit-" + teamID.String(),
	})
	if err == nil && strings.TrimSpace(grant.ID) == "" {
		err = errors.New("Stripe credit grant response did not include an ID")
	}
	if err != nil {
		return StripeBillingCreditGrant{}, wrapStripePromotionGrantRequestError(err, teamID, userID, pending.PreviouslyAttempted)
	}
	return grant, nil
}

func (h *Handlers) finalizeRecordedStripePromotion(ctx context.Context, conn *pgxpool.Conn, eventID string, pending *stripePromotionPendingGrant, grantID string, lease *stripeWebhookProcessingLease) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if err := lease.lock(ctx, q); err != nil {
		return err
	}
	finalize := func() error {
		if err := q.LockStripePromotion(ctx, db.LockStripePromotionParams{TeamID: pending.TeamID, UserID: pending.UserID}); err != nil {
			return err
		}
		account, err := q.LockTeamBillingAccount(ctx, pending.TeamID)
		if err != nil {
			return err
		}
		if _, err := q.GetStripeWebhookEventForUpdate(ctx, eventID); err != nil {
			return err
		}
		if account.StripeActivationUserID != (pgtype.UUID{Bytes: pending.UserID, Valid: true}) || derefString(account.StripeActivationCreditReservationEventID) != eventID {
			return errors.New("Stripe promotion reservation changed before finalization")
		}
		if err := q.FinalizeStripePromotion(ctx, db.FinalizeStripePromotionParams{TeamID: pending.TeamID, UserID: pending.UserID, StripeGrantID: grantID}); err != nil {
			return err
		}
		if err := q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: pending.TeamID, UserID: pgtype.UUID{Bytes: pending.UserID, Valid: true}, StripeGrantID: grantID}); err != nil {
			return err
		}
		if err := q.FinishTeamBillingCheckoutForSubscription(ctx, db.FinishTeamBillingCheckoutForSubscriptionParams{TeamID: pending.TeamID, SubscriptionID: account.StripeSubscriptionID}); err != nil {
			return err
		}
		_, err = q.MarkStripeWebhookEventProcessed(ctx, eventID)
		return err
	}
	if err := finalize(); err != nil {
		h.rollbackAndPersistStripeWebhookFailure(ctx, conn, lease, tx, eventID, wrapStripePromotionGrantFinalizationError(err, pending.TeamID, pending.UserID), false)
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) settleStaleStripePromotion(ctx context.Context, q *db.Queries, account db.GetTeamBillingAccountByStripeCustomerIDRow, eventID, customerID string) error {
	if !account.StripeActivationUserID.Valid || derefString(account.StripeActivationCreditReservationEventID) != eventID ||
		account.StripeActivationCreditGrantedAt.Valid || derefString(account.StripeActivationCreditGrantID) != "" {
		return nil
	}
	userID := uuid.UUID(account.StripeActivationUserID.Bytes)
	attempted, err := q.StripePromotionWasAttempted(ctx, db.StripePromotionWasAttemptedParams{TeamID: pgtype.UUID{Bytes: account.TeamID, Valid: true}, UserID: userID})
	if err != nil {
		return err
	}
	if !attempted {
		// Release and mark the webhook processed in the same transaction. Any
		// failure rolls both back, so the next delivery retries the cleanup.
		return q.ReleaseStripePromotionForEvent(ctx, db.ReleaseStripePromotionForEventParams{TeamID: account.TeamID, UserID: userID, EventID: eventID})
	}
	return prepareStripePromotionGrant(ctx, q, account.TeamID, userID, eventID, customerID)
}

func (h *Handlers) processStripeWebhookEventWithPreReservation(ctx context.Context, tx pgx.Tx, event stripeEventEnvelope, preReservation *stripePromotionPreReservation) error {
	q := h.DB.WithTx(tx)
	eventAt := stripeEventTime(int64(event.Created))
	if isStripeMeterErrorEvent(event.Type) && len(bytes.TrimSpace(event.Data.Object)) == 0 {
		if err := h.expandStripeThinMeterEvent(ctx, &event); err != nil {
			return err
		}
	}
	switch event.Type {
	case "checkout.session.expired":
		var obj stripeCheckoutCompletedObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
		if err != nil {
			return err
		}
		account, err := q.LockTeamBillingAccount(ctx, teamID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !account.CheckoutInitializingAt.Valid || account.CheckoutSubscriptionID != nil || account.CheckoutCompletedAt.Valid ||
			strings.TrimSpace(obj.ID) == "" ||
			strings.TrimSpace(obj.Customer) == "" || strings.TrimSpace(derefString(account.StripeCustomerID)) != strings.TrimSpace(obj.Customer) {
			return nil
		}
		if sessionID := strings.TrimSpace(derefString(account.CheckoutSessionID)); sessionID != "" {
			if sessionID != strings.TrimSpace(obj.ID) {
				return nil
			}
		} else if obj.Metadata["checkout_generation"] != account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano) {
			// Creation can succeed before its session ID is saved. A signed
			// expiration for that exact generation can still retire the fence.
			return nil
		}
		return q.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: teamID, LeaseStartedAt: account.CheckoutInitializingAt})
	case "checkout.session.completed":
		var obj stripeCheckoutCompletedObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		teamID, err := uuid.Parse(strings.TrimSpace(obj.ClientReferenceID))
		if err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccount(ctx, teamID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if account.CheckoutSessionID == nil || strings.TrimSpace(*account.CheckoutSessionID) == "" || strings.TrimSpace(*account.CheckoutSessionID) != strings.TrimSpace(obj.ID) {
			return nil
		}
		if account.StripeCustomerID != nil && strings.TrimSpace(*account.StripeCustomerID) != strings.TrimSpace(obj.Customer) {
			return nil
		}
		if strings.TrimSpace(obj.Subscription) != "" {
			// The association committed before reconciliation. Only a processed
			// lifecycle event can finish the lease for this subscription.
			return q.FinishTeamBillingCheckoutForSubscription(ctx, db.FinishTeamBillingCheckoutForSubscriptionParams{TeamID: teamID, SubscriptionID: stringPtr(obj.Subscription)})
		}
		// Completion outlives the initial lease, even while the subscription
		// association is still waiting on another delivery.
		return q.CompleteTeamBillingCheckoutWithoutSubscription(ctx, db.CompleteTeamBillingCheckoutWithoutSubscriptionParams{TeamID: teamID, SessionID: stringPtr(obj.ID)})
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "customer.subscription.paused", "customer.subscription.resumed":
		var obj stripeSubscriptionObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		if err != nil {
			return err
		}
		if obj.ID == "" {
			return nil
		}
		if eventAt.IsZero() {
			return nil
		}
		associated := stripeSubscriptionMatchesCurrentAssociation(account, obj.ID)
		if event.Type == "customer.subscription.created" {
			deferProcessing, ignore := shouldIgnoreUnassociatedStripeSubscriptionCreated(account, obj.ID)
			if deferProcessing {
				return errStripeCheckoutAssociationPending
			}
			if ignore {
				return h.settleStaleStripePromotion(ctx, q, account, event.ID, obj.Customer)
			}
			associated = true
		} else if !associated && !canAssociateStripeSubscription(account, obj) {
			return h.settleStaleStripePromotion(ctx, q, account, event.ID, obj.Customer)
		}
		if account.StripeSubscriptionEventAt.Valid {
			previousAt := account.StripeSubscriptionEventAt.Time.UTC()
			orderingStatus := obj.Status
			if event.Type == "customer.subscription.deleted" {
				orderingStatus = "canceled"
			}
			if eventAt.Before(previousAt) || (eventAt.Equal(previousAt) && shouldSkipEqualTimestampStripeSubscription(account, obj.ID, orderingStatus)) {
				return h.settleStaleStripePromotion(ctx, q, account, event.ID, obj.Customer)
			}
		}
		start, end, ok := stripeSubscriptionPeriodBounds(obj)
		terminalStatus := strings.EqualFold(obj.Status, "unpaid") || strings.EqualFold(obj.Status, "canceled") || strings.EqualFold(obj.Status, "paused") || event.Type == "customer.subscription.deleted"
		if !ok && !terminalStatus {
			return nil
		}
		var periodStart, periodEnd pgtype.Timestamptz
		if ok {
			periodStart = timestamptzFromUnix(start)
			periodEnd = timestamptzFromUnix(end)
		}
		promotionReserved := false
		promotionReservationAttempted := false
		var activationUser pgtype.UUID
		if strings.EqualFold(obj.Status, "active") || strings.EqualFold(obj.Status, "trialing") {
			if actor := stripePromotionActorForSubscription(account, obj); actor != uuid.Nil {
				activationUser = pgtype.UUID{Bytes: actor, Valid: true}
			}
			if !activationUser.Valid {
				legacyUser, lookupErr := q.GetLegacyStripeActivationUser(ctx, account.TeamID)
				if errors.Is(lookupErr, pgx.ErrNoRows) && event.Type != "customer.subscription.created" {
					legacyUser, lookupErr = q.GetCurrentStripeActivationUser(ctx, account.TeamID)
				}
				if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
					return lookupErr
				}
				if lookupErr == nil {
					activationUser = pgtype.UUID{Bytes: legacyUser, Valid: true}
				}
			}
			if derefString(account.StripeActivationCreditGrantID) == "" && !account.StripeActivationCreditGrantedAt.Valid && activationUser.Valid {
				if preReservation != nil && preReservation.EventID == event.ID && preReservation.Retryable {
					return errors.New("Stripe promotion reservation is contended; retry webhook")
				}
				promotionReservationAttempted = true
				if preReservation != nil && preReservation.EventID == event.ID {
					// The pre-handler reservation is the durable fence used for
					// this delivery. Never retry a false result inside the
					// processing transaction: a competing fence may have been
					// released, and reserving here would put Stripe back inside
					// the transaction's crash window.
					promotionReserved = preReservation.Reserved && preReservation.TeamID == account.TeamID && preReservation.UserID == uuid.UUID(activationUser.Bytes)
				} else {
					// Association or actor state changed after pre-processing.
					// Retry through the committed reservation phase before Stripe.
					return errors.New("Stripe promotion requires a committed reservation; retry webhook")
				}
			}
		}
		wrapPromotionReservationErr := func(processErr error) error {
			if account.StripeActivationCreditReservationEventID != nil {
				return wrapStripePromotionGrantFinalizationError(processErr, account.TeamID, uuid.UUID(activationUser.Bytes))
			}
			return wrapStripePromotionReservationError(processErr, promotionReservationAttempted, account.TeamID, uuid.UUID(activationUser.Bytes))
		}
		if account.CheckoutCompletedAt.Valid && account.CheckoutSubscriptionID == nil {
			if err := q.AssociateCompletedTeamBillingCheckoutSubscription(ctx, db.AssociateCompletedTeamBillingCheckoutSubscriptionParams{TeamID: account.TeamID, SubscriptionID: stringPtr(obj.ID)}); err != nil {
				return wrapPromotionReservationErr(err)
			}
		}
		_, err = q.UpsertTeamBillingAccountSubscription(ctx, db.UpsertTeamBillingAccountSubscriptionParams{
			TeamID:                   account.TeamID,
			StripeCustomerID:         stringPtr(obj.Customer),
			StripeSubscriptionID:     stringPtr(obj.ID),
			StripeSubscriptionStatus: stringPtr(obj.Status),
			CurrentPeriodStart:       periodStart,
			CurrentPeriodEnd:         periodEnd,
			CommercialBillingAnchor: func() pgtype.Timestamptz {
				if ok {
					return timestamptzFromUnix(start)
				}
				return pgtype.Timestamptz{}
			}(),
			CancelAtPeriodEnd:         boolPtr(obj.CancelAtPeriodEnd),
			StripeSubscriptionEventAt: timestamptzFromUnix(int64(event.Created)),
		})
		if err != nil {
			return wrapPromotionReservationErr(err)
		}
		if strings.EqualFold(obj.Status, "active") || strings.EqualFold(obj.Status, "trialing") {
			if derefString(account.StripeActivationCreditGrantID) == "" && !account.StripeActivationCreditGrantedAt.Valid {
				if !promotionReserved {
					if err := q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: account.TeamID, UserID: activationUser, StripeGrantID: ""}); err != nil {
						return wrapPromotionReservationErr(err)
					}
					return q.FinishTeamBillingCheckoutForSubscription(ctx, db.FinishTeamBillingCheckoutForSubscriptionParams{TeamID: account.TeamID, SubscriptionID: stringPtr(obj.ID)})
				}
				if err := q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: account.TeamID, UserID: activationUser, StripeGrantID: ""}); err != nil {
					return wrapPromotionReservationErr(err)
				}
				return prepareStripePromotionGrant(ctx, q, account.TeamID, uuid.UUID(activationUser.Bytes), event.ID, obj.Customer)
			}
			if err := q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: account.TeamID, UserID: activationUser, StripeGrantID: derefString(account.StripeActivationCreditGrantID)}); err != nil {
				return err
			}
		}
		return q.FinishTeamBillingCheckoutForSubscription(ctx, db.FinishTeamBillingCheckoutForSubscriptionParams{TeamID: account.TeamID, SubscriptionID: stringPtr(obj.ID)})
	case "invoice.payment_failed", "invoice.payment_succeeded", "invoice.finalized":
		var obj stripeInvoiceObject
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return err
		}
		account, err := q.GetTeamBillingAccountByStripeCustomerID(ctx, stringPtr(obj.Customer))
		if err != nil {
			return err
		}
		// An invoice cannot replace a lifecycle association while retaining the
		// previous subscription's ordering watermark. Checkout or an accepted
		// lifecycle event must establish a replacement subscription first.
		incomingSubscription := strings.TrimSpace(obj.Subscription)
		var subscriptionID *string
		if strings.TrimSpace(derefString(account.StripeSubscriptionID)) == "" && incomingSubscription != "" {
			subscriptionID = &incomingSubscription
		}
		status := strings.TrimSpace(obj.Status)
		if status == "" {
			return nil
		}
		_, err = q.UpsertTeamBillingAccountSubscription(ctx, db.UpsertTeamBillingAccountSubscriptionParams{
			TeamID:               account.TeamID,
			StripeCustomerID:     stringPtr(obj.Customer),
			StripeSubscriptionID: subscriptionID,
			StripeInvoiceStatus:  stringPtr(status),
		})
		return err
	case "billing.meter.error_report_triggered", "v1.billing.meter.error_report_triggered", "billing.meter.no_meter_found", "v1.billing.meter.no_meter_found":
		if samples := stripeMeterErrorSamplePayloads(event.Data.Object); len(samples) > 1 {
			for _, sample := range samples[1:] {
				if err := h.processStripeWebhookEvent(ctx, tx, stripeEventEnvelope{
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
		if h.Pool != nil {
			handled, rejectErr := (billing.ExportStore{}).RejectTx(ctx, tx, identifier, requestKey, customerID, eventName, errMsg)
			if rejectErr != nil {
				return rejectErr
			}
			if handled {
				return nil
			}
		}
		if identifier == "" && requestKey != "" {
			row, lookupErr := q.GetBillingUsageExportByIdempotencyKey(ctx, stringPtr(requestKey))
			if lookupErr == nil {
				identifier = row.StripeMeterEventIdentifier
			} else if errors.Is(lookupErr, pgx.ErrNoRows) {
				row, lookupErr = q.GetBillingUsageExportByIdentifier(ctx, requestKey)
				if lookupErr == nil {
					identifier = row.StripeMeterEventIdentifier
				}
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

func prepareBillingStorageSnapshot(ctx context.Context, tx pgx.Tx, teamID uuid.UUID, periodEnd time.Time) error {
	if err := billing.CheckStorageSettlementBoundary(ctx, tx, periodEnd); err != nil {
		return err
	}
	return billing.FenceStorageReportReceipts(ctx, tx, teamID)
}

func respondBillingStorageSettlementError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, billing.ErrStorageReportsIncomplete):
		respondErrorMsg(c, "conflict", "storage reports are still being accepted or processed; retry billing settlement", http.StatusConflict)
	case errors.Is(err, billing.ErrStorageSettlementBoundaryOpen):
		respondErrorMsg(c, "conflict", "billing period is still open according to the database clock; retry after it closes", http.StatusConflict)
	case errors.Is(err, pgx.ErrNoRows):
		respondErrorMsg(c, "conflict", "billing usage is not ready for settlement; retry after storage reports finish processing", http.StatusConflict)
	default:
		respondError(c, ErrInternal)
	}
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

// Callers must fence storage receipts in the same READ COMMITTED transaction
// before this raw usage snapshot, retaining the fence through commit.
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
		resp.CommercialBillingAnchor = timePtrFromPG(account.CommercialBillingAnchor)
		resp.CancelAtPeriodEnd = &account.CancelAtPeriodEnd
	}
	return resp
}

func billingPreviewItems(teamID uuid.UUID, periodStart, periodEnd time.Time, usage db.TeamBillingUsage, resources []billingResourceState, customerID string) ([]billingExportPreviewItem, error) {
	items := make([]billingExportPreviewItem, 0, len(resources))
	for _, resource := range resources {
		if !resource.Billable || !resource.CheckoutEnabled {
			continue
		}
		var raw pgtype.Numeric
		var divisor float64
		switch resource.ResourceKey {
		case "vcpu":
			raw, divisor = usage.VcpuSeconds, 3600
		case "memory_gib":
			raw, divisor = usage.MemoryMibSeconds, 1024*3600
		case "storage_gib":
			raw, divisor = usage.StorageMibSeconds, 1024*3600
		default:
			continue
		}
		quantity, err := billing.MeterUsageQuantity(raw, resource.ResourceKey)
		if err != nil {
			return nil, err
		}
		// Recognize existing attempts made before decimal-native normalization.
		legacyValue, err := numericFloat64(raw)
		if err != nil {
			return nil, err
		}
		items = append(items, billingExportPreviewItem{
			ResourceType:     billingExportResourceType(resource.ResourceKey),
			ResourceKey:      resource.ResourceKey,
			DisplayName:      resource.DisplayName,
			SortOrder:        resource.SortOrder,
			DisplayUnit:      resource.DisplayUnit,
			EventName:        resource.StripeEventName,
			Identifier:       meterIdentifierForQuantity(teamID, periodStart, periodEnd, billingExportResourceType(resource.ResourceKey), resource.StripeEventName, customerID, quantity),
			legacyIdentifier: meterIdentifierForPayload(teamID, periodStart, periodEnd, billingExportResourceType(resource.ResourceKey), resource.StripeEventName, customerID, legacyValue/divisor),
			Value:            json.Number(quantity),
		})
	}
	return items, nil
}

func validateBillingExportItems(items []billingExportPreviewItem) error {
	for _, item := range items {
		if value, ok := new(big.Rat).SetString(item.Value.String()); !ok || value.Sign() < 0 {
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
	return meterIdentifierForQuantity(teamID, periodStart, periodEnd, resourceType, eventName, customerID, quantity)
}

func meterIdentifierForQuantity(teamID uuid.UUID, periodStart, periodEnd time.Time, resourceType, eventName, customerID, quantity string) string {
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

// Select the accounting model in the same snapshot as its history so enrollment
// cannot leave a preview showing stale legacy attempts. Keep superseded events
// visible for tracing rejection and recovery.
func (h *Handlers) billingPreviewExports(ctx context.Context, p db.ListBillingUsageExportsForPeriodParams) ([]db.BillingUsageExport, error) {
	if h.Pool == nil {
		return h.DB.ListBillingUsageExportsForPeriod(ctx, p)
	}
	rows, err := h.Pool.Query(ctx, `WITH enrolled AS (
        SELECT 1 FROM billing_incremental_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3
    )
    SELECT e.id, a.resource_type, e.identifier, e.event_name, e.quantity,
           e.status, e.last_error, e.submitted_at, e.created_at
    FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id
    WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND EXISTS(SELECT 1 FROM enrolled)
    UNION ALL
    SELECT id, resource_type, stripe_meter_event_identifier, stripe_event_name, value,
           status, error, sent_at, created_at
    FROM billing_usage_export
    WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND NOT EXISTS(SELECT 1 FROM enrolled)
    ORDER BY created_at, id`, p.TeamID, p.PeriodStart, p.PeriodEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exports []db.BillingUsageExport
	for rows.Next() {
		var row db.BillingUsageExport
		if err := rows.Scan(&row.ID, &row.ResourceType, &row.StripeMeterEventIdentifier,
			&row.StripeEventName, &row.Value, &row.Status, &row.Error, &row.SentAt, &row.CreatedAt); err != nil {
			return nil, err
		}
		exports = append(exports, row)
	}
	return exports, rows.Err()
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

func billingPreviewNumeric(quantity json.Number) pgtype.Numeric {
	var value pgtype.Numeric
	_ = value.Scan(quantity.String()) // Constructed by MeterUsageQuantity.
	return value
}

func billingExportRetryQuantity(row db.BillingUsageExport, start, end time.Time) (string, bool, error) {
	raw, err := row.Value.Value()
	if err != nil {
		return "", false, err
	}
	decimal, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("invalid persisted billing quantity")
	}
	value, ok := new(big.Rat).SetString(decimal)
	if !ok || value.Sign() < 0 {
		return "", false, fmt.Errorf("invalid persisted billing quantity")
	}
	quantity := value.FloatString(12)
	identifier := meterIdentifierForQuantity(row.TeamID, start, end, row.ResourceType, row.StripeEventName, derefString(row.StripeCustomerID), quantity)
	if row.StripeMeterEventIdentifier == identifier {
		return quantity, quantity != "0.000000000000", nil
	}
	// Older rows stored a float's shortest decimal representation. Reconstruct
	// their original payload rather than changing a persisted retry identity.
	legacyValue, err := numericFloat64(row.Value)
	if err != nil {
		return "", false, err
	}
	quantity, ok = stripeMeterQuantity(legacyValue)
	return quantity, ok, nil
}

func numericFromFloat(v float64) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(formatDecimal(v))
	return n
}

func formatDecimal(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Preserve float normalization only for retries of legacy persisted attempts.
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

func stripeMeterRoundedValue(value float64) float64 {
	rounded, err := strconv.ParseFloat(strconv.FormatFloat(value, 'f', 12, 64), 64)
	if err != nil {
		return value
	}
	return rounded
}

func stripeSubscriptionPeriodBounds(obj stripeSubscriptionObject) (int64, int64, bool) {
	for _, item := range obj.Items.Data {
		if item.CurrentPeriodStart > 0 && item.CurrentPeriodEnd > 0 {
			return item.CurrentPeriodStart, item.CurrentPeriodEnd, true
		}
	}
	if obj.CurrentPeriodStart > 0 && obj.CurrentPeriodEnd > 0 {
		return obj.CurrentPeriodStart, obj.CurrentPeriodEnd, true
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
	return checkoutSessionIdempotencyKeyForLease(teamID, customerID, successURL, cancelURL, priceIDs, time.Time{})
}

func checkoutSessionIdempotencyKeyForLease(teamID uuid.UUID, customerID, successURL, cancelURL string, priceIDs []string, leaseStartedAt time.Time) string {
	raw := strings.Join([]string{
		"checkout-v2",
		teamID.String(),
		customerID,
		successURL,
		cancelURL,
		strings.Join(priceIDs, ","),
		leaseStartedAt.UTC().Format(time.RFC3339Nano),
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
