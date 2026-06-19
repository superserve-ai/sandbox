package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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

func (h *Handlers) GetPublicBillingPricing(c *gin.Context) {
	h.writeBillingPricing(c, publicPricingPlanKey, "public", publicPricingCacheControl)
}

func (h *Handlers) GetBillingPricing(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		respondError(c, ErrUnauthorized)
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
