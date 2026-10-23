package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

type billingPlanLimits struct {
	MaxSandboxes         int32  `json:"max_sandboxes"`
	MaxTemplateVCPU      *int32 `json:"max_template_vcpu"`
	MaxTemplateMemoryMiB *int32 `json:"max_template_memory_mib"`
	MaxTemplateDiskMiB   *int32 `json:"max_template_disk_mib"`
}

type billingPlan struct {
	Key                string            `json:"key"`
	Family             string            `json:"family"`
	Name               string            `json:"name"`
	IntervalMonths     int32             `json:"interval_months"`
	PriceCents         int64             `json:"price_cents"`
	MonthlyCreditCents int64             `json:"monthly_credit_cents"`
	Limits             billingPlanLimits `json:"limits"`
}

// GetPublicBillingPlans lists the plans new customers can buy in this
// environment. Like public pricing it is unauthenticated so signup pages
// render from the catalog.
func (h *Handlers) GetPublicBillingPlans(c *gin.Context) {
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "plans are not available", http.StatusServiceUnavailable)
		return
	}
	rows, err := h.Pool.Query(c.Request.Context(), `SELECT p.offer_key,p.family,p.display_name,p.charge_interval_months,p.charge_amount_cents,p.monthly_credit_cents,
 l.max_sandboxes,l.max_template_vcpu,l.max_template_memory_mib,l.max_template_disk_mib
 FROM billing_plan p JOIN plan_limits l USING(offer_key) WHERE p.available ORDER BY p.sort_order,p.offer_key`)
	if err != nil {
		log.Error().Err(err).Msg("list billing plans failed")
		respondError(c, ErrInternal)
		return
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (billingPlan, error) {
		var p billingPlan
		err := row.Scan(&p.Key, &p.Family, &p.Name, &p.IntervalMonths, &p.PriceCents, &p.MonthlyCreditCents,
			&p.Limits.MaxSandboxes, &p.Limits.MaxTemplateVCPU, &p.Limits.MaxTemplateMemoryMiB, &p.Limits.MaxTemplateDiskMiB)
		return p, err
	})
	if err != nil {
		log.Error().Err(err).Msg("list billing plans failed")
		respondError(c, ErrInternal)
		return
	}
	plans := []billingPlan{}
	for _, p := range all {
		if h.Config != nil && h.Config.PlanPriceID(p.Key) != "" {
			plans = append(plans, p)
		}
	}
	c.Header("Cache-Control", publicPricingCacheControl)
	c.JSON(http.StatusOK, gin.H{"plans": plans})
}
