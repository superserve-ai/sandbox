//go:build integration

package api

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequireBillingEligibleForTest exercises the create/resume gate with a fresh handler.
func RequireBillingEligibleForTest(h *Handlers, c *gin.Context, teamID uuid.UUID) bool {
	return h.requireBillingEligible(c, teamID)
}
