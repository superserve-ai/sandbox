package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	publicPricingPlanKey       = "payg"
	publicPricingCacheControl  = "public, max-age=300, s-maxage=300"
	privatePricingCacheControl = "private, max-age=60"
)

var requiredPricingResources = map[string]struct{}{
	"memory_gib":  {},
	"storage_gib": {},
	"vcpu":        {},
}

type billingPricingRateResponse struct {
	Resource       string    `json:"resource"`
	Unit           string    `json:"unit"`
	PriceUSD       float64   `json:"price_usd"`
	PriceUSDHourly float64   `json:"price_usd_hourly"`
	EffectiveFrom  time.Time `json:"effective_from"`
}

type billingPricingResponse struct {
	PlanKey  string                       `json:"plan_key"`
	PlanName string                       `json:"plan_name"`
	Currency string                       `json:"currency"`
	Rates    []billingPricingRateResponse `json:"rates"`
}

type billingSummaryResponse struct {
	CurrentChargesUSD        float64                     `json:"current_charges_usd"`
	CreditsAppliedUSD        float64                     `json:"credits_applied_usd"`
	CreditsRemainingUSD      float64                     `json:"credits_remaining_usd"`
	ExpectedInvoiceAmountUSD float64                     `json:"expected_invoice_amount_usd"`
	CostBreakdownUSD         billingSummaryCostBreakdown `json:"cost_breakdown_usd"`
	BillingPeriod            billingSummaryPeriod        `json:"billing_period"`
	PricingTier              billingSummaryPricingTier   `json:"pricing_tier"`
	CalculatedAt             time.Time                   `json:"calculated_at"`
}

type billingSummaryCostBreakdown struct {
	Compute float64 `json:"compute"`
	Memory  float64 `json:"memory"`
	Storage float64 `json:"storage"`
}

type billingSummaryPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type billingSummaryPricingTier struct {
	PlanKey  string `json:"plan_key"`
	PlanName string `json:"plan_name"`
	Currency string `json:"currency"`
}

func (h *Handlers) GetPublicBillingPricing(c *gin.Context) {
	h.writeBillingPricing(c, publicPricingPlanKey, "public", publicPricingCacheControl)
}

func (h *Handlers) GetBillingPricing(c *gin.Context) {
	teamID, ok := h.requireBillingRead(c)
	if !ok {
		return
	}

	rates, err := h.DB.ListActivePricingRatesForTeamCurrent(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB ListActivePricingRatesForTeamCurrent failed")
		respondError(c, ErrInternal)
		return
	}

	h.writeBillingPricingRates(c, pricingRatesFromTeamCurrentRows(rates), teamID.String(), privatePricingCacheControl)
}

func (h *Handlers) GetBillingSummary(c *gin.Context) {
	teamID, ok := h.requireBillingRead(c)
	if !ok {
		return
	}

	now := time.Now().UTC()
	periodStart, periodEnd := billing.CurrentBillingPeriod(now)
	period, err := h.DB.GetActiveTeamBillingPeriod(c.Request.Context(), teamID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetActiveTeamBillingPeriod failed")
			respondError(c, ErrInternal)
			return
		}
	} else {
		periodStart = period.PeriodStart
		periodEnd = period.PeriodEnd
	}

	var (
		usage         db.GetTeamBillingUsageRow
		pricingRows   []db.ListActivePricingRatesForTeamCurrentRow
		creditBalance pgtype.Numeric
	)
	g, ctx := errgroup.WithContext(c.Request.Context())
	g.Go(func() error {
		var err error
		usage, err = h.DB.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			return fmt.Errorf("get team billing usage: %w", err)
		}
		return nil
	})

	// Phase 1 applies the team's currently active pricing rates to the whole
	// current billing period. This assumes there are no mid-period pricing tier
	// or rate changes; period-aware pricing should replace this before invoices.
	g.Go(func() error {
		var err error
		pricingRows, err = h.DB.ListActivePricingRatesForTeamCurrent(ctx, teamID)
		if err != nil {
			return fmt.Errorf("list active pricing rates for team current: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		creditBalance, err = h.DB.GetTeamCreditBalance(ctx, teamID)
		if err != nil {
			return fmt.Errorf("get team credit balance: %w", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing summary dependency fetch failed")
		respondError(c, ErrInternal)
		return
	}

	pricingCatalog, ok := h.billingRateCatalog(pricingRatesFromTeamCurrentRows(pricingRows), teamID.String())
	if !ok {
		respondPricingUnavailable(c)
		return
	}

	vcpuSeconds, err := numericFloat64(usage.VcpuSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert vcpu usage failed")
		respondError(c, ErrInternal)
		return
	}
	memoryGibSeconds, err := numericFloat64(usage.MemoryGibSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert memory usage failed")
		respondError(c, ErrInternal)
		return
	}
	storageGibSeconds, err := numericFloat64(usage.StorageGibSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert storage usage failed")
		respondError(c, ErrInternal)
		return
	}

	vcpuRate, err := numericFloat64(pricingCatalog.RateByResource["vcpu"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert vcpu price failed")
		respondError(c, ErrInternal)
		return
	}
	memoryRate, err := numericFloat64(pricingCatalog.RateByResource["memory_gib"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert memory price failed")
		respondError(c, ErrInternal)
		return
	}
	storageRate, err := numericFloat64(pricingCatalog.RateByResource["storage_gib"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert storage price failed")
		respondError(c, ErrInternal)
		return
	}

	creditsAvailable, err := numericFloat64(creditBalance)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert credit balance failed")
		respondError(c, ErrInternal)
		return
	}
	charges := billing.CalculateSummaryCharges(
		vcpuSeconds,
		memoryGibSeconds,
		storageGibSeconds,
		vcpuRate,
		memoryRate,
		storageRate,
		creditsAvailable,
	)

	setPrivateBillingCacheHeaders(c)
	c.JSON(http.StatusOK, billingSummaryResponse{
		CurrentChargesUSD:        charges.CurrentChargesUSD,
		CreditsAppliedUSD:        charges.CreditsAppliedUSD,
		CreditsRemainingUSD:      charges.CreditsRemainingUSD,
		ExpectedInvoiceAmountUSD: charges.ExpectedInvoiceAmountUSD,
		CostBreakdownUSD: billingSummaryCostBreakdown{
			Compute: charges.Breakdown.ComputeUSD,
			Memory:  charges.Breakdown.MemoryUSD,
			Storage: charges.Breakdown.StorageUSD,
		},
		BillingPeriod: billingSummaryPeriod{Start: periodStart, End: periodEnd},
		PricingTier: billingSummaryPricingTier{
			PlanKey:  pricingCatalog.PlanKey,
			PlanName: pricingCatalog.PlanName,
			Currency: pricingCatalog.Currency,
		},
		CalculatedAt: now,
	})
}

func (h *Handlers) requireBillingRead(c *gin.Context) (uuid.UUID, bool) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, false
	}
	actorID := actorIDFromContext(c)
	if actorID == nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, false
	}
	authzSvc := h.authzService()
	if authzSvc == nil {
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	allowed, err := authzSvc.CanTeam(c.Request.Context(), *actorID, teamID, "billing:read")
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", actorID.String()).Msg("RBAC billing read check failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if !allowed {
		respondError(c, ErrForbidden)
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

func (h *Handlers) writeBillingPricing(c *gin.Context, planKey string, subject string, cacheControl string) {
	rates, err := h.DB.ListActivePricingRates(c.Request.Context(), planKey)
	if err != nil {
		log.Error().Err(err).Str("subject", subject).Str("plan_key", planKey).Msg("DB ListActivePricingRates failed")
		respondError(c, ErrInternal)
		return
	}

	h.writeBillingPricingRates(c, pricingRatesFromActiveRows(rates), subject, cacheControl)
}

type billingPricingRate struct {
	PlanKey       string
	PlanName      string
	Currency      string
	Resource      string
	Unit          string
	PriceUsd      pgtype.Numeric
	EffectiveFrom time.Time
}

func pricingRatesFromActiveRows(rows []db.ListActivePricingRatesRow) []billingPricingRate {
	out := make([]billingPricingRate, 0, len(rows))
	for _, row := range rows {
		out = append(out, billingPricingRate{
			PlanKey:       row.PlanKey,
			PlanName:      row.PlanName,
			Currency:      row.Currency,
			Resource:      row.Resource,
			Unit:          row.Unit,
			PriceUsd:      row.PriceUsd,
			EffectiveFrom: row.EffectiveFrom,
		})
	}
	return out
}

func pricingRatesFromTeamCurrentRows(rows []db.ListActivePricingRatesForTeamCurrentRow) []billingPricingRate {
	out := make([]billingPricingRate, 0, len(rows))
	for _, row := range rows {
		out = append(out, billingPricingRate{
			PlanKey:       row.PlanKey,
			PlanName:      row.PlanName,
			Currency:      row.Currency,
			Resource:      row.Resource,
			Unit:          row.Unit,
			PriceUsd:      row.PriceUsd,
			EffectiveFrom: row.EffectiveFrom,
		})
	}
	return out
}

type billingRateCatalog struct {
	PlanKey        string
	PlanName       string
	Currency       string
	OrderedRates   []billingPricingRate
	RateByResource map[string]billingPricingRate
}

func (h *Handlers) billingRateCatalog(rates []billingPricingRate, subject string) (billingRateCatalog, bool) {
	if len(rates) == 0 {
		log.Error().Str("subject", subject).Msg("billing pricing plan has no active rates")
		return billingRateCatalog{}, false
	}

	catalog := billingRateCatalog{
		PlanKey:        rates[0].PlanKey,
		PlanName:       rates[0].PlanName,
		Currency:       rates[0].Currency,
		OrderedRates:   make([]billingPricingRate, 0, len(rates)),
		RateByResource: make(map[string]billingPricingRate, len(requiredPricingResources)),
	}
	for _, rate := range rates {
		if _, ok := requiredPricingResources[rate.Resource]; !ok {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan has an unsupported active rate")
			return billingRateCatalog{}, false
		}
		if rate.Unit != "second" {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan has an unsupported active required rate")
			return billingRateCatalog{}, false
		}
		if _, ok := catalog.RateByResource[rate.Resource]; ok {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan returned duplicate active required rates")
			return billingRateCatalog{}, false
		}
		catalog.OrderedRates = append(catalog.OrderedRates, rate)
		catalog.RateByResource[rate.Resource] = rate
	}
	for resource := range requiredPricingResources {
		if _, ok := catalog.RateByResource[resource]; !ok {
			log.Error().Str("subject", subject).Str("plan_key", catalog.PlanKey).Str("resource", resource).Msg("billing pricing plan is missing an active rate")
			return billingRateCatalog{}, false
		}
	}
	return catalog, true
}

func (h *Handlers) writeBillingPricingRates(c *gin.Context, rates []billingPricingRate, subject string, cacheControl string) {
	catalog, ok := h.billingRateCatalog(rates, subject)
	if !ok {
		respondPricingUnavailable(c)
		return
	}

	out := billingPricingResponse{
		PlanKey:  catalog.PlanKey,
		PlanName: catalog.PlanName,
		Currency: catalog.Currency,
		Rates:    make([]billingPricingRateResponse, 0, len(catalog.OrderedRates)),
	}
	for _, rate := range catalog.OrderedRates {
		price, err := numericFloat64(rate.PriceUsd)
		if err != nil {
			log.Error().Err(err).Str("subject", subject).Str("plan_key", catalog.PlanKey).Str("resource", rate.Resource).Msg("convert pricing rate failed")
			respondError(c, ErrInternal)
			return
		}
		out.Rates = append(out.Rates, billingPricingRateResponse{
			Resource:       rate.Resource,
			Unit:           rate.Unit,
			PriceUSD:       price,
			PriceUSDHourly: price * 3600,
			EffectiveFrom:  rate.EffectiveFrom,
		})
	}

	if cacheControl == privatePricingCacheControl {
		setPrivateBillingCacheHeaders(c)
	} else {
		c.Header("Cache-Control", cacheControl)
	}
	c.JSON(http.StatusOK, out)
}

func setPrivateBillingCacheHeaders(c *gin.Context) {
	c.Header("Cache-Control", privatePricingCacheControl)
	c.Header("Vary", "X-API-Key")
}

func respondPricingUnavailable(c *gin.Context) {
	respondErrorMsg(c, "pricing_unavailable", "Billing pricing is not available", http.StatusServiceUnavailable)
}

func numericFloat64(n pgtype.Numeric) (float64, error) {
	v, err := n.Float64Value()
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, fmt.Errorf("numeric value is null")
	}
	return v.Float64, nil
}
