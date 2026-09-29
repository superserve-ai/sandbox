package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The signed decision comes from Console's trusted registration flow. It is
// persisted with the team before any trigger can evaluate saved device evidence.
func (h *Handlers) CreateTeamWithPromotionAttempt(c *gin.Context) {
	var input struct {
		promotionAccountRequest
		TeamID               uuid.UUID `json:"team_id"`
		Name                 string    `json:"name"`
		HomeRegion           string    `json:"home_region"`
		AuthorityUnavailable *bool     `json:"authority_unavailable"`
	}
	if !decodePromotionRequest(c, &input) || !promotionAccountActor(c, input.promotionAccountRequest) {
		return
	}
	value, _ := c.Get("promotion_account")
	claims, ok := value.(*promotionAccountClaims)
	if !ok || claims == nil || claims.Operation != "create-team" ||
		claims.AttemptID != input.AttemptID.String() || claims.TeamID != input.TeamID.String() ||
		claims.HomeRegion != input.HomeRegion || input.AuthorityUnavailable == nil ||
		claims.AuthorityUnavailable == nil || *claims.AuthorityUnavailable != *input.AuthorityUnavailable {
		respondErrorMsg(c, "forbidden", "team creation provenance mismatch", http.StatusForbidden)
		return
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 256 {
		respondErrorMsg(c, "invalid_request", "invalid team name", http.StatusBadRequest)
		return
	}
	if !promotionSource(c, h.Pool) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	var teamID uuid.UUID
	var outcome, reason string
	err := h.Pool.QueryRow(ctx, `SELECT team_id,outcome,reason FROM create_team_with_promotion_attempt($1,$2,$3,$4,$5,$6)`,
		input.AttemptID, input.TeamID, input.UserID, input.Name, input.HomeRegion, *input.AuthorityUnavailable).
		Scan(&teamID, &outcome, &reason)
	if err != nil {
		promotionDBError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"team_id": teamID, "outcome": outcome, "reason": reason})
}
