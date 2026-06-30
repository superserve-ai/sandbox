package api

import (
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

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
	periodStart, periodEnd := currentBillingPeriod(now)

	usage, err := h.DB.GetTeamBillingUsage(c.Request.Context(), db.GetTeamBillingUsageParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetTeamBillingUsage failed")
		respondError(c, ErrInternal)
		return
	}

	// Phase 1 applies the team's currently active pricing rates to the whole
	// current billing period. This assumes there are no mid-period pricing tier
	// or rate changes; period-aware pricing should replace this before invoices.
	rates, err := h.DB.ListActivePricingRatesForTeamCurrent(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB ListActivePricingRatesForTeamCurrent failed")
		respondError(c, ErrInternal)
		return
	}
	pricingRates := pricingRatesFromTeamCurrentRows(rates)
	if len(pricingRates) == 0 {
		log.Error().Str("team_id", teamID.String()).Msg("billing pricing plan has no active rates for summary")
		respondPricingUnavailable(c)
		return
	}
	rateByResource := make(map[string]billingPricingRate, len(pricingRates))
	for _, rate := range pricingRates {
		if _, ok := requiredPricingResources[rate.Resource]; !ok {
			continue
		}
		if rate.Unit != "second" {
			log.Error().
				Str("team_id", teamID.String()).
				Str("plan_key", rate.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing summary pricing plan has an unsupported active required rate")
			respondPricingUnavailable(c)
			return
		}
		key := rate.Resource + ":" + rate.Unit
		if _, ok := rateByResource[key]; ok {
			log.Error().
				Str("team_id", teamID.String()).
				Str("plan_key", rate.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing summary pricing plan returned duplicate active rates")
			respondPricingUnavailable(c)
			return
		}
		rateByResource[key] = rate
	}
	for resource := range requiredPricingResources {
		if _, ok := rateByResource[resource+":second"]; !ok {
			log.Error().Str("team_id", teamID.String()).Str("plan_key", pricingRates[0].PlanKey).Str("resource", resource).Msg("billing summary pricing plan is missing an active rate")
			respondPricingUnavailable(c)
			return
		}
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

	vcpuRate, err := numericFloat64(rateByResource["vcpu:second"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert vcpu price failed")
		respondError(c, ErrInternal)
		return
	}
	memoryRate, err := numericFloat64(rateByResource["memory_gib:second"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert memory price failed")
		respondError(c, ErrInternal)
		return
	}
	storageRate, err := numericFloat64(rateByResource["storage_gib:second"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert storage price failed")
		respondError(c, ErrInternal)
		return
	}

	breakdown := billingSummaryCostBreakdown{
		Compute: vcpuSeconds * vcpuRate,
		Memory:  memoryGibSeconds * memoryRate,
		Storage: storageGibSeconds * storageRate,
	}
	currentCharges := breakdown.Compute + breakdown.Memory + breakdown.Storage

	creditBalance, err := h.DB.GetTeamCreditBalance(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetTeamCreditBalance failed")
		respondError(c, ErrInternal)
		return
	}
	creditsAvailable, err := numericFloat64(creditBalance)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert credit balance failed")
		respondError(c, ErrInternal)
		return
	}
	// GetTeamCreditBalance sums remaining_usd, so creditsAvailable is net of
	// any credit already consumed by prior billing application.
	creditsApplied := math.Min(currentCharges, creditsAvailable)

	c.Header("Cache-Control", privatePricingCacheControl)
	c.Header("Vary", "X-API-Key")
	c.JSON(http.StatusOK, billingSummaryResponse{
		CurrentChargesUSD:        currentCharges,
		CreditsAppliedUSD:        creditsApplied,
		CreditsRemainingUSD:      creditsAvailable - creditsApplied,
		ExpectedInvoiceAmountUSD: currentCharges - creditsApplied,
		CostBreakdownUSD:         breakdown,
		BillingPeriod:            billingSummaryPeriod{Start: periodStart, End: periodEnd},
		PricingTier: billingSummaryPricingTier{
			PlanKey:  pricingRates[0].PlanKey,
			PlanName: pricingRates[0].PlanName,
			Currency: pricingRates[0].Currency,
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
	return teamID, true
}

func currentBillingPeriod(now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
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

func (h *Handlers) writeBillingPricingRates(c *gin.Context, rates []billingPricingRate, subject string, cacheControl string) {
	if len(rates) == 0 {
		log.Error().Str("subject", subject).Msg("billing pricing plan has no active rates")
		respondPricingUnavailable(c)
		return
	}

	planKey := rates[0].PlanKey
	out := billingPricingResponse{
		PlanKey:  planKey,
		PlanName: rates[0].PlanName,
		Currency: rates[0].Currency,
		Rates:    make([]billingPricingRateResponse, 0, len(rates)),
	}
	seen := make(map[string]struct{}, len(requiredPricingResources))
	for _, rate := range rates {
		if _, ok := requiredPricingResources[rate.Resource]; !ok || rate.Unit != "second" {
			log.Error().
				Str("subject", subject).
				Str("plan_key", planKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan has an unsupported active rate")
			respondPricingUnavailable(c)
			return
		}

		key := rate.Resource + ":" + rate.Unit
		if _, ok := seen[key]; ok {
			log.Error().
				Str("subject", subject).
				Str("plan_key", planKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan returned duplicate active rates")
			respondPricingUnavailable(c)
			return
		}
		seen[key] = struct{}{}

		price, err := numericFloat64(rate.PriceUsd)
		if err != nil {
			log.Error().Err(err).Str("subject", subject).Str("plan_key", planKey).Str("resource", rate.Resource).Msg("convert pricing rate failed")
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

	for resource := range requiredPricingResources {
		if _, ok := seen[resource+":second"]; !ok {
			log.Error().Str("subject", subject).Str("plan_key", planKey).Str("resource", resource).Msg("billing pricing plan is missing an active rate")
			respondPricingUnavailable(c)
			return
		}
	}

	c.Header("Cache-Control", cacheControl)
	if cacheControl == privatePricingCacheControl {
		c.Header("Vary", "X-API-Key")
	}
	c.JSON(http.StatusOK, out)
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
