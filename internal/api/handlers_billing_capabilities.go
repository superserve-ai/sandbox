package api

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"net/http"
)

// GetBillingCapabilities supplies current-team admission and its matching
// catalog. These capabilities do not replace billing permissions or previews.
func (h *Handlers) GetBillingCapabilities(c *gin.Context) {
	team, ok := h.requireBillingRead(c)
	if !ok {
		return
	}
	state, err := h.teamPricingState(c.Request.Context(), team)
	if err != nil {
		log.Warn().Err(err).Str("team_id", team.String()).Msg("team pricing state unavailable")
		respondErrorMsg(c, "service_unavailable", "team plan admission requires verification", http.StatusServiceUnavailable)
		return
	}
	catalog, err := h.billingCatalog(c.Request.Context(), state.Version, state.EntryOpen || state.LegacyOpen)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	fresh := state.Version == "v2" && state.EntryOpen
	awaiting, err := teamAwaitingPlan(c.Request.Context(), h.Pool, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	// A team on its trial chooses Developer or Pro; it is never offered Free,
	// Starter credit or a top-off before it has a plan.
	other := fresh && !awaiting
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"schema_version": 1, "team_id": team, "pricing_version": state.Version,
		"admission_source": pricingSource(state), "entry_open": state.EntryOpen || state.LegacyOpen,
		"epoch": pricingEpoch(state), "enrollment_epoch": state.EnrollmentEpoch,
		"fresh_entry": gin.H{"starter": other, "pro": fresh, "auto_recharge": other, "choose_free": other},
		"actions":     gin.H{"recover_payment": true, "disable_auto_recharge": true}, "catalog": catalog, "offers": catalogOffers(catalog.Cards)})
}
