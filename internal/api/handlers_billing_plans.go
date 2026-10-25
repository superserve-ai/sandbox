package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type billingPlanLimits struct {
	MaxSandboxes         int32  `json:"max_sandboxes"`
	MaxTemplateVCPU      *int32 `json:"max_template_vcpu"`
	MaxTemplateMemoryMiB *int32 `json:"max_template_memory_mib"`
	MaxTemplateDiskMiB   *int32 `json:"max_template_disk_mib"`
}

// billingPlan is a purchasable offer, in the shape the plan catalog first
// published.
type billingPlan struct {
	Key                string            `json:"key"`
	Family             string            `json:"family"`
	Name               string            `json:"name"`
	IntervalMonths     int32             `json:"interval_months"`
	PriceCents         int64             `json:"price_cents"`
	MonthlyCreditCents int64             `json:"monthly_credit_cents"`
	Limits             billingPlanLimits `json:"limits"`
}

type billingPlanPrice struct {
	OfferKey               string `json:"offer_key"`
	PriceCents             int64  `json:"price_cents"`
	MonthlyEquivalentCents int64  `json:"monthly_equivalent_cents"`
	Available              bool   `json:"available"`
}

type billingPlanAllowance struct {
	planAllowance
	Summary string `json:"summary"`
}

type billingPlanCard struct {
	Family             string                `json:"family"`
	Version            int32                 `json:"version"`
	Kind               string                `json:"kind"`
	Name               string                `json:"name"`
	PriceLabel         string                `json:"price_label"`
	Tagline            string                `json:"tagline"`
	Features           []string              `json:"features"`
	DisplayOnly        bool                  `json:"display_only"`
	Monthly            *billingPlanPrice     `json:"monthly"`
	Annual             *billingPlanPrice     `json:"annual"`
	CreditSummary      string                `json:"credit_summary"`
	MonthlyCreditCents *int64                `json:"monthly_credit_cents"`
	Allowance          *billingPlanAllowance `json:"allowance"`
	Matching           *planMatching         `json:"matching"`
	Limits             planLimits            `json:"limits"`
}

func allowanceSummary(a *planAllowance) string {
	if a == nil {
		return ""
	}
	period := map[string]string{"day_window": "every 24 hours", "month": "every month"}[a.Period]
	if a.Compute != nil {
		return formatUSDCents(a.AmountCents) + " of compute " + period
	}
	return formatUSDCents(a.AmountCents) + " of usage included " + period
}

func (h *Handlers) planCard(v planVersion, allowance *planAllowance) billingPlanCard {
	card := billingPlanCard{Family: v.Family, Version: v.Version, Kind: v.Kind, Name: v.DisplayName, PriceLabel: v.PriceLabel, Tagline: v.Tagline,
		Features: v.Features, DisplayOnly: v.DisplayOnly, CreditSummary: planCreditSummary(v.CreditSchedule), Matching: v.Matching, Limits: v.Limits}
	if allowance != nil {
		card.Allowance = &billingPlanAllowance{planAllowance: *allowance, Summary: allowanceSummary(allowance)}
	}
	if credit, uniform := uniformMonthlyCredit(v.CreditSchedule); uniform {
		card.MonthlyCreditCents = &credit
	}
	priced := func(months int32, key string) bool {
		return v.sellable() && h.planPriced(planTerms{OfferKey: key, Version: v.Version, PricingVersion: v.PricingVersion, IntervalMonths: months})
	}
	if v.MonthlyFeeCents != nil {
		card.Monthly = &billingPlanPrice{OfferKey: v.Family + "_monthly", PriceCents: *v.MonthlyFeeCents, MonthlyEquivalentCents: *v.MonthlyFeeCents, Available: priced(1, v.Family+"_monthly")}
	}
	if v.AnnualFeeCents != nil {
		card.Annual = &billingPlanPrice{OfferKey: v.Family + "_annual", PriceCents: *v.AnnualFeeCents, MonthlyEquivalentCents: *v.AnnualFeeCents / 12, Available: priced(12, v.Family+"_annual")}
	}
	return card
}

// purchasablePlans lists the offers new customers can check out.
func purchasablePlans(cards []billingPlanCard) []billingPlan {
	plans := []billingPlan{}
	for _, card := range cards {
		for _, price := range []*billingPlanPrice{card.Monthly, card.Annual} {
			if price == nil || !price.Available || card.MonthlyCreditCents == nil || card.Limits.MaxConcurrent == nil {
				continue
			}
			months := int32(1)
			if price == card.Annual {
				months = 12
			}
			plans = append(plans, billingPlan{Key: price.OfferKey, Family: card.Family, Name: card.Name, IntervalMonths: months, PriceCents: price.PriceCents,
				MonthlyCreditCents: *card.MonthlyCreditCents, Limits: billingPlanLimits{MaxSandboxes: *card.Limits.MaxConcurrent, MaxTemplateVCPU: card.Limits.MaxVCPU,
					MaxTemplateMemoryMiB: card.Limits.MaxMemoryMiB, MaxTemplateDiskMiB: card.Limits.MaxDiskMiB}})
		}
	}
	return plans
}

// GetPublicBillingPlans returns the live pricing model and its public plan
// cards. Like public pricing it is unauthenticated so the website and signup
// pages render from the catalog.
func (h *Handlers) GetPublicBillingPlans(c *gin.Context) {
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "plans are not available", http.StatusServiceUnavailable)
		return
	}
	ctx := c.Request.Context()
	state, err := h.publicPricingState(ctx)
	if err != nil {
		log.Error().Err(err).Msg("read pricing version failed")
		respondError(c, ErrInternal)
		return
	}
	rows, err := h.Pool.Query(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE state='published' AND public AND pricing_version=$1 ORDER BY sort_order,family`, state.Version)
	if err != nil {
		log.Error().Err(err).Msg("list billing plans failed")
		respondError(c, ErrInternal)
		return
	}
	var versions []planVersion
	for rows.Next() {
		v, err := scanPlanVersion(rows)
		if err != nil {
			rows.Close()
			log.Error().Err(err).Msg("list billing plans failed")
			respondError(c, ErrInternal)
			return
		}
		versions = append(versions, v)
	}
	if err = rows.Err(); err != nil {
		log.Error().Err(err).Msg("list billing plans failed")
		respondError(c, ErrInternal)
		return
	}
	cards := []billingPlanCard{}
	for _, v := range versions {
		allowance, err := h.resolveAllowance(ctx, v.Allowance)
		if err != nil {
			log.Error().Err(err).Msg("price plan allowance failed")
			respondError(c, ErrInternal)
			return
		}
		card := h.planCard(v, allowance)
		if !state.EntryOpen && !state.LegacyOpen {
			if card.Monthly != nil {
				card.Monthly.Available = false
			}
			if card.Annual != nil {
				card.Annual.Available = false
			}
		}
		cards = append(cards, card)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"pricing_version": state.Version, "cards": cards, "plans": purchasablePlans(cards)})
}
