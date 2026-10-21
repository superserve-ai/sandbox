package api

import (
	"context"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ycAcceptanceControl struct {
	RequestID    uuid.UUID `json:"request_id"`
	AcceptanceID uuid.UUID `json:"acceptance_id"`
	Action       string    `json:"action"`
	Reason       string    `json:"reason"`
}

func (s *YCOfferAcceptanceService) control(ctx context.Context, actor uuid.UUID, in ycAcceptanceControl) error {
	if !s.available() {
		return errYCAcceptanceUnavailable
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackYCAcceptance(ctx, tx)
	var team, claim uuid.UUID
	var assignment *uuid.UUID
	var busy bool
	var state string
	err = tx.QueryRow(ctx, `SELECT team_id,claim_id,COALESCE(lease_until>clock_timestamp(),false),state,assignment_id FROM yc_offer_acceptance WHERE id=$1 AND home_region=$2 FOR UPDATE`, in.AcceptanceID, s.Region).Scan(&team, &claim, &busy, &state, &assignment)
	if err != nil {
		return err
	}
	var exists, same bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM yc_offer_acceptance_control WHERE request_id=$1),EXISTS(SELECT 1 FROM yc_offer_acceptance_control WHERE request_id=$1 AND acceptance_id=$2 AND actor_id=$3 AND action=$4 AND reason=$5)`, in.RequestID, in.AcceptanceID, actor, in.Action, in.Reason).Scan(&exists, &same)
	if err != nil {
		return err
	}
	if exists {
		if same {
			return nil
		}
		return errYCAcceptanceConflict
	}
	if assignment != nil {
		// A lost enqueue response may leave local state behind the durable provider
		// journal. Once it exists, only the provisioner's audited controls apply.
		var handedOff bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2)`, team, *assignment).Scan(&handedOff); err != nil {
			return err
		}
		if handedOff {
			return errYCAcceptanceConflict
		}
	}
	if busy || state == "offered" || state == "dispatched" || state == "revoked" {
		return errYCAcceptanceConflict
	}
	if in.Action == "retry" {
		if state != "held" {
			return errYCAcceptanceConflict
		}
		r, err := loadYCAcceptance(ctx, tx, team, claim)
		if err != nil {
			return err
		}
		// A retry cannot override revoked authority or changed accepted economics.
		op := "guard"
		if r.AssignmentID == nil {
			op = "accept"
		}
		if _, err = s.rpc(ctx, s.Shared, op, ycAcceptanceParameters(r)); err != nil {
			return err
		}
		state = "accepted"
		if r.AssignmentID != nil {
			state = "assignment_linked"
		}
	} else {
		state = "held"
	}
	_, err = tx.Exec(ctx, `UPDATE yc_offer_acceptance SET state=$2,attempts=0,next_attempt_at=clock_timestamp(),lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1`, in.AcceptanceID, state)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO yc_offer_acceptance_control(request_id,acceptance_id,actor_id,action,reason) VALUES($1,$2,$3,$4,$5)`, in.RequestID, in.AcceptanceID, actor, in.Action, in.Reason)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) ControlYCOfferAcceptance(c *gin.Context) {
	actor, ok := h.requireYCStaff(c, platformBillingWritePermission)
	if !ok {
		return
	}
	var in ycAcceptanceControl
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.RequestID == uuid.Nil || in.AcceptanceID == uuid.Nil || (in.Action != "hold" && in.Action != "retry") || strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 1000 {
		respondErrorMsg(c, "invalid_control", "Audited hold or retry required.", 400)
		return
	}
	ctx, cancel := promotionContext(c)
	defer cancel()
	err := h.YCOfferAcceptance.control(ctx, actor, in)
	if errors.Is(err, errYCAcceptanceConflict) {
		respondErrorMsg(c, "acceptance_conflict", "Handoff is active or requires review.", 409)
		return
	}
	if err != nil {
		ycClaimError(c, err)
		return
	}
	c.Status(204)
}
