package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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

type preparedTeamRequest struct {
	promotionAccountRequest
	OperationID          uuid.UUID `json:"operation_id"`
	TeamID               uuid.UUID `json:"team_id"`
	Name                 string    `json:"name"`
	HomeRegion           string    `json:"home_region"`
	AuthorityUnavailable *bool     `json:"authority_unavailable"`
	After                string    `json:"after"`
}

func (h *Handlers) PrepareTeamPromotionCreation(c *gin.Context) {
	h.teamPromotionCreationOperation(c, "prepare-team")
}

func (h *Handlers) RecoverTeamPromotionCreation(c *gin.Context) {
	h.teamPromotionCreationOperation(c, "recover-team")
}

func (h *Handlers) CompleteTeamPromotionCreation(c *gin.Context) {
	h.teamPromotionCreationOperation(c, "complete-team")
}

func (h *Handlers) DiscoverTeamPromotionCreations(c *gin.Context) {
	h.teamPromotionCreationOperation(c, "discover-team-creations")
}

func (h *Handlers) teamPromotionCreationOperation(c *gin.Context, operation string) {
	var input preparedTeamRequest
	if !decodePromotionRequest(c, &input) || !promotionAccountActor(c, input.promotionAccountRequest) {
		return
	}
	value, _ := c.Get("promotion_account")
	claims, ok := value.(*promotionAccountClaims)
	if !ok || claims == nil || claims.Operation != operation || claims.HomeRegion != input.HomeRegion {
		respondErrorMsg(c, "forbidden", "team creation provenance mismatch", http.StatusForbidden)
		return
	}
	valid := true
	if operation == "discover-team-creations" {
		valid = input.OperationID == uuid.Nil && input.After == claims.After
	} else {
		valid = input.OperationID != uuid.Nil && input.OperationID.String() == claims.OperationID && input.After == ""
	}
	if operation == "prepare-team" || operation == "complete-team" {
		valid = valid && input.Name == claims.Name && input.AuthorityUnavailable != nil &&
			claims.AuthorityUnavailable != nil && *input.AuthorityUnavailable == *claims.AuthorityUnavailable
	} else {
		valid = valid && input.Name == "" && input.AuthorityUnavailable == nil
	}
	if operation == "complete-team" {
		valid = valid && input.AttemptID.String() == claims.AttemptID && input.TeamID.String() == claims.TeamID
	} else {
		valid = valid && input.AttemptID == uuid.Nil && input.TeamID == uuid.Nil
	}
	if !valid {
		respondErrorMsg(c, "forbidden", "team creation provenance mismatch", http.StatusForbidden)
		return
	}
	if !promotionSource(c, h.Pool) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	var query string
	var args []any
	switch operation {
	case "prepare-team":
		query = `SELECT prepare_team_promotion_creation($1,$2,$3,$4,$5)`
		args = []any{input.OperationID, input.UserID, input.Name, input.HomeRegion, *input.AuthorityUnavailable}
	case "recover-team":
		query = `SELECT recover_team_promotion_creation($1,$2,$3)`
		args = []any{input.OperationID, input.UserID, input.HomeRegion}
	case "complete-team":
		query = `SELECT complete_team_promotion_creation($1,$2,$3,$4,$5,$6,$7)`
		args = []any{input.OperationID, input.AttemptID, input.TeamID, input.UserID, input.Name, input.HomeRegion, *input.AuthorityUnavailable}
	case "discover-team-creations":
		query = `SELECT discover_team_promotion_creations($1,$2,$3)`
		var after any
		if input.After != "" {
			after = input.After
		}
		args = []any{input.UserID, input.HomeRegion, after}
	}
	var result []byte
	if err := h.Pool.QueryRow(ctx, query, args...).Scan(&result); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			message := "team creation binding conflict"
			if pgErr.ConstraintName == "team_name_key" {
				message = "team name already exists"
			}
			respondErrorMsg(c, "creation_conflict", message, http.StatusConflict)
		} else {
			promotionDBError(c, err)
		}
		return
	}
	if len(result) == 0 {
		respondErrorMsg(c, "creation_missing", "team creation operation unavailable", http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "application/json", result)
}
