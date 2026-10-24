package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type pricingSwitchState struct {
	PricingVersion string  `json:"pricing_version"`
	ChangedBy      *string `json:"changed_by"`
	Reason         *string `json:"reason"`
	ChangedAt      string  `json:"changed_at"`
}

// GetPlatformPricingVersion reports this region's pricing switch.
func (h *Handlers) GetPlatformPricingVersion(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	h.writePricingSwitch(c)
}

func (h *Handlers) writePricingSwitch(c *gin.Context) {
	var s pricingSwitchState
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT pricing_version,changed_by::text,reason,to_char(changed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"') FROM billing_pricing_switch`).
		Scan(&s.PricingVersion, &s.ChangedBy, &s.Reason, &s.ChangedAt)
	if err != nil {
		log.Error().Err(err).Msg("read pricing switch failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, s)
}

// SetPlatformPricingVersion flips this region's pricing switch. Setting the
// version it already has changes nothing, so a retry is safe.
func (h *Handlers) SetPlatformPricingVersion(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	var req struct {
		PricingVersion string `json:"pricing_version"`
		Reason         string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.PricingVersion != "legacy" && req.PricingVersion != "v2") {
		respondErrorMsg(c, "bad_request", "pricing_version must be legacy or v2", http.StatusBadRequest)
		return
	}
	reason, ok := checkCatalogReason(c, req.Reason)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	var current string
	if err = tx.QueryRow(ctx, `SELECT pricing_version FROM billing_pricing_switch FOR UPDATE`).Scan(&current); err != nil {
		log.Error().Err(err).Msg("lock pricing switch failed")
		respondError(c, ErrInternal)
		return
	}
	if current == req.PricingVersion {
		if err = tx.Rollback(ctx); err != nil {
			log.Error().Err(err).Msg("release pricing switch failed")
			respondError(c, ErrInternal)
			return
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version=$1,changed_by=$2,reason=$3,changed_at=clock_timestamp()`, req.PricingVersion, actor, reason); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO billing_pricing_switch_audit(actor_id,from_version,to_version,reason) VALUES($1,$2,$3,$4)`, actor, current, req.PricingVersion, reason)
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		forgetPricingVersion()
	}
	if err != nil {
		log.Error().Err(err).Msg("flip pricing switch failed")
		respondError(c, ErrInternal)
		return
	}
	h.writePricingSwitch(c)
}
