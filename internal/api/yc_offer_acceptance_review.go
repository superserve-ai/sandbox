package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func (h *Handlers) ycPreferredRPC(ctx context.Context, op string, p any) (json.RawMessage, error) {
	if h.PromotionAuthPool == nil {
		return nil, errYCAcceptanceUnavailable
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = h.PromotionAuthPool.QueryRow(ctx, `SELECT public.yc_preferred_claim_rpc($1,$2::jsonb)`, op, raw).Scan(&out)
	return out, err
}

func (h *Handlers) ReviewYCOfferIdentity(c *gin.Context) {
	if !c.GetBool("yc_acceptance_verified") || actorIDFromContext(c) == nil {
		respondError(c, ErrForbidden)
		return
	}
	var in struct {
		ClaimID   uuid.UUID `json:"claim_id"`
		TeamID    uuid.UUID `json:"team_id"`
		RequestID uuid.UUID `json:"request_id"`
		Link      string    `json:"verification_link"`
	}
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ClaimID == uuid.Nil || in.TeamID == uuid.Nil || in.RequestID == uuid.Nil {
		respondErrorMsg(c, "invalid_review", "Claim, team and request required.", 400)
		return
	}
	if _, err := ycclaims.VerificationURL(in.Link); err != nil {
		respondErrorMsg(c, "invalid_link", "Valid verification link required.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	user := *actorIDFromContext(c)
	region, err := h.ycClaimTeam(ctx, user, in.TeamID)
	if err != nil {
		respondError(c, ErrForbidden)
		return
	}
	// The existing global capture budget also bounds verifier work for review.
	budget, err := h.ycClaimRPC(ctx, "budget", gin.H{"email_hash": ycclaims.Hash("review/" + user.String())})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	var allowance struct {
		Allowed bool `json:"allowed"`
	}
	if json.Unmarshal(budget, &allowance) != nil || !allowance.Allowed {
		respondErrorMsg(c, "rate_limited", "Please try again later.", 429)
		return
	}
	evidence, reference, err := ycclaims.NewVerifier().Verify(ctx, in.Link)
	if err != nil {
		status := 400
		if errors.Is(err, ycclaims.ErrUnavailable) {
			status = 503
		}
		respondErrorMsg(c, "verification_pending", "Verification could not complete. Review remains pending.", status)
		return
	}
	company := evidence.AutomaticCompany()
	if company == "" {
		respondErrorMsg(c, "claim_review_required", "Verified company evidence requires staff review.", 409)
		return
	}
	p := gin.H{"id": in.ClaimID, "user_id": user, "team_id": in.TeamID, "request_id": in.RequestID, "home_region": region, "verification_reference": reference, "company_identity": company}
	// Shared preparation pins the target before regional intent commits. The
	// second RPC makes the review ready only after that durable fence exists.
	out, err := h.ycBindWithIntentRPC(ctx, "review", p, h.ycPreferredRPC)
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.Data(200, "application/json", out)
}
