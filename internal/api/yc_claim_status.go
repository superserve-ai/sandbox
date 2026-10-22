package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PendingYCClaims is a paginated, durable handoff for the operator activation
// workflow. A scan is repeatable; billing adopts the existing approval ID.
func (h *Handlers) PendingYCClaims(c *gin.Context) {
	p := gin.H{}
	if after := c.Query("after_id"); after != "" {
		id, e := uuid.Parse(after)
		if e != nil {
			respondErrorMsg(c, "invalid_cursor", "Invalid cursor.", 400)
			return
		}
		p["after_id"] = id
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, e := h.ycStaffRPC(ctx, "activation-pending", p)
	if e != nil {
		ycClaimError(c, e)
		return
	}
	c.Data(200, "application/json", out)
}

// Status is read from billing's home-region operation, never inferred from a
// claim approval or from cached client state. No provider details leave here.
func (h *Handlers) YCClaimBillingStatus(c *gin.Context) {
	var in ycClaimRequest
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ID == uuid.Nil || in.UserID == uuid.Nil || in.TeamID == uuid.Nil || in.Token != "" {
		respondErrorMsg(c, "invalid_request", "Invalid status request.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	if _, err := h.ycClaimTeam(ctx, in.UserID, in.TeamID); err != nil {
		respondErrorMsg(c, "forbidden", "An authorized team administrator must view billing status.", 403)
		return
	}
	raw, err := h.ycClaimRPC(ctx, "account-get", gin.H{"id": in.ID, "user_id": in.UserID})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	var claim struct {
		Approval uuid.UUID `json:"approval_id"`
		Team     uuid.UUID `json:"team_id"`
		State    string    `json:"state"`
		Company  string    `json:"company_identity"`
	}
	if json.Unmarshal(raw, &claim) != nil || claim.Team != in.TeamID || claim.Approval == uuid.Nil {
		respondErrorMsg(c, "claim_missing", "Bound claim unavailable.", 404)
		return
	}
	if claim.State != "bound" {
		c.JSON(200, gin.H{"state": "requires_review"})
		return
	}
	var globalOK bool
	err = h.PromotionAuthPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($1,$2) WHERE approval_id=$3 AND team_id=$2 AND revoked_at IS NULL)`, claim.Company, in.TeamID, claim.Approval).Scan(&globalOK)
	if err != nil {
		ycClaimError(c, err)
		return
	}
	if !globalOK {
		c.JSON(200, gin.H{"state": "requires_review"})
		return
	}
	var contract uuid.UUID
	var state string
	var ready, revoked, failed, term, paymentRequired bool
	err = h.Pool.QueryRow(ctx, `SELECT contract_id,state,COALESCE(payment_method_ready AND payment_method_checked_at>clock_timestamp()-interval '5 minutes',false),revoked_at IS NOT NULL,last_error IS NOT NULL,COALESCE(last_error LIKE 'payment_method_required:%',false),COALESCE(ends_at>clock_timestamp(),false) FROM public.billing_yc_operation WHERE team_id=$1 AND id=$2`, in.TeamID, claim.Approval).Scan(&contract, &state, &ready, &revoked, &failed, &paymentRequired, &term)
	var pg *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pg) && pg.Code == "42P01") {
		c.JSON(200, gin.H{"state": "activation_pending", "approval_id": claim.Approval})
		return
	}
	if err != nil {
		ycClaimError(c, err)
		return
	}
	display := ycClaimDisplayStatus(state, ready, revoked, failed, paymentRequired, term)
	_, err = h.ycClaimRPC(ctx, "billing-status", gin.H{"id": in.ID, "team_id": in.TeamID, "approval_id": claim.Approval, "contract_id": contract, "state": display})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.JSON(200, gin.H{"state": display, "approval_id": claim.Approval, "contract_id": contract})
}

func ycClaimDisplayStatus(state string, ready, revoked, failed, paymentRequired, term bool) string {
	display := "activation_pending"
	switch {
	case revoked || state == "ended":
		display = "requires_review"
	case paymentRequired:
		display = "awaiting_payment_method"
	case failed:
		display = "requires_review"
	case (state == "active" || state == "renewed") && !ready:
		display = "awaiting_payment_method"
	case state == "active" && ready && term:
		display = "active"
	// ends_at belongs to the original promotional year, not the paid renewal.
	// Billing's renewed state verifies renewal receipts; Console links to billing
	// for current plan details rather than claiming the promotional term is live.
	case state == "renewed" && ready:
		display = "renewed"
	}
	return display
}
