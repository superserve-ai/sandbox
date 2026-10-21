package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func (h *Handlers) ycStaffRPC(ctx context.Context, op string, p any) (json.RawMessage, error) {
	if h.PromotionAuthPool == nil {
		return nil, errors.New("shared claim authority unavailable")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = h.PromotionAuthPool.QueryRow(ctx, "SELECT public.yc_preferred_staff_rpc($1,$2::jsonb)", op, b).Scan(&out)
	return out, err
}

func (h *Handlers) ListStaffYCClaims(c *gin.Context) {
	if _, ok := h.requireYCStaff(c, platformBillingReadPermission); !ok {
		return
	}
	p := gin.H{"state": c.DefaultQuery("state", "manual_review")}
	if after := c.Query("after_id"); after != "" {
		id, err := uuid.Parse(after)
		if err != nil {
			respondErrorMsg(c, "invalid_cursor", "Invalid cursor.", 400)
			return
		}
		p["after_id"] = id
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, err := h.ycStaffRPC(ctx, "list", p)
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) GetStaffYCClaim(c *gin.Context) {
	if _, ok := h.requireYCStaff(c, platformBillingReadPermission); !ok {
		return
	}
	id, err := uuid.Parse(c.Param("claim_id"))
	if err != nil {
		respondErrorMsg(c, "invalid_claim", "Invalid claim.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	out, err := h.ycStaffRPC(ctx, "operator-get", gin.H{"id": id})
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}

func (h *Handlers) DecideStaffYCClaim(c *gin.Context) {
	actor, ok := h.requireYCStaff(c, platformBillingWritePermission)
	if !ok {
		return
	}
	var in struct {
		ID              uuid.UUID  `json:"id"`
		UserID          uuid.UUID  `json:"user_id"`
		TeamID          uuid.UUID  `json:"team_id"`
		RequestID       uuid.UUID  `json:"request_id"`
		Revision        *int64     `json:"expected_revision"`
		Decision        string     `json:"decision"`
		Reason          string     `json:"reason"`
		Evidence        string     `json:"evidence_reference"`
		Company         string     `json:"company_identity"`
		ReviewRequestID *uuid.UUID `json:"review_request_id"`
		ReviewRevision  *int64     `json:"review_revision"`
	}
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ID == uuid.Nil || in.RequestID == uuid.Nil || in.Revision == nil || *in.Revision < 0 ||
		(in.Decision != "approve" && in.Decision != "reject" && in.Decision != "revoke" && in.Decision != "retry-approval-email") ||
		strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 1000 || strings.TrimSpace(in.Evidence) == "" || len(in.Evidence) > 1000 {
		respondErrorMsg(c, "invalid_decision", "A revision, request identifier, reason and evidence are required.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	p := gin.H{"id": in.ID, "actor_id": actor, "request_id": in.RequestID, "expected_revision": *in.Revision, "reason": in.Reason, "evidence_reference": in.Evidence, "home_region": ycClaimRegion()}
	if (in.ReviewRequestID == nil) != (in.ReviewRevision == nil) || (in.ReviewRequestID != nil && (*in.ReviewRequestID == uuid.Nil || *in.ReviewRevision < 0 || in.Decision != "approve")) {
		respondErrorMsg(c, "invalid_review", "Exact review identity and revision required for approval.", 400)
		return
	}
	if in.ReviewRequestID != nil {
		p["review_request_id"] = *in.ReviewRequestID
		p["review_revision"] = *in.ReviewRevision
	}
	var out json.RawMessage
	var err error
	if in.Decision == "approve" {
		region, e := h.ycClaimTeam(ctx, in.UserID, in.TeamID)
		if e != nil {
			respondErrorMsg(c, "forbidden", "Target account must be authorized for its home team.", 403)
			return
		}
		p["user_id"], p["team_id"], p["home_region"] = in.UserID, in.TeamID, region
		if in.Company != "" {
			company := ycclaims.CompanyIdentity(in.Company)
			if company == "" {
				respondErrorMsg(c, "invalid_company", "Canonical YC directory identity required.", 400)
				return
			}
			p["company_identity"] = company
		}
		out, err = h.ycBindWithIntentRPC(ctx, "approve", p, h.ycStaffRPC)
	} else {
		if in.UserID != uuid.Nil || in.TeamID != uuid.Nil || in.Company != "" {
			respondErrorMsg(c, "invalid_decision", "Target binding is only valid for approval.", 400)
			return
		}
		out, err = h.ycStaffRPC(ctx, in.Decision, p)
		if err == nil && (in.Decision == "reject" || in.Decision == "revoke") {
			var claim struct {
				Team   uuid.UUID `json:"intent_team_id"`
				Region string    `json:"intent_region"`
			}
			err = json.Unmarshal(out, &claim)
			if err == nil && claim.Region != "" {
				err = h.ycReleaseClaimIntent(ctx, in.ID, claim.Team)
			}
		}
	}
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Data(200, "application/json", out)
}
