package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (h *Handlers) ycAuthorityPreflight(ctx context.Context, team uuid.UUID, in ycApproval) error {
	if h.PromotionAuthPool == nil {
		return errors.New("shared company approval authority is unavailable")
	}
	var conflict bool
	err := h.PromotionAuthPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($1,$2) WHERE (company_identity<>$1 OR team_id<>$2 OR home_region<>$3 OR revoked_at IS NOT NULL))`, in.CompanyIdentity, team, in.Region).Scan(&conflict)
	if err != nil {
		return err
	}
	if conflict {
		return errors.New("company eligibility is already bound or revoked")
	}
	if in.ClaimID != "" {
		_, err = h.ycClaimApproval(ctx, team, in)
	}
	return err
}

// A bound claim carries its audited existing-account exception into billing.
// Adopt that authority without rewriting evidence or opening general plan choice.
func (h *Handlers) ycClaimApproval(ctx context.Context, team uuid.UUID, in ycApproval) (uuid.UUID, error) {
	id, err := uuid.Parse(in.ClaimID)
	if err != nil {
		return uuid.Nil, errors.New("invalid YC claim identity")
	}
	var user uuid.UUID
	err = h.Pool.QueryRow(ctx, `SELECT user_id FROM public.yc_claim_team_intent WHERE team_id=$1 AND claim_id=$2 AND released_at IS NULL`, team, id).Scan(&user)
	if err != nil {
		return uuid.Nil, errors.New("active YC claim intent unavailable")
	}
	raw, err := h.ycClaimRPC(ctx, "account-get", gin.H{"id": id, "user_id": user})
	if err != nil {
		return uuid.Nil, err
	}
	var claim struct {
		ID           uuid.UUID `json:"id"`
		User         uuid.UUID `json:"claimed_user_id"`
		Team         uuid.UUID `json:"team_id"`
		Approval     uuid.UUID `json:"approval_id"`
		State        string    `json:"state"`
		Company      string    `json:"company_identity"`
		Region       string    `json:"home_region"`
		SignupEmail  string    `json:"submitted_email"`
		FounderEmail string    `json:"founder_email"`
	}
	if err = json.Unmarshal(raw, &claim); err != nil {
		return uuid.Nil, err
	}
	if claim.ID != id || claim.User != user || claim.Team != team || claim.Approval == uuid.Nil || claim.State != "bound" || claim.Company != in.CompanyIdentity || claim.Region != in.Region ||
		!strings.EqualFold(claim.SignupEmail, strings.TrimSpace(in.SignupEmail)) || !strings.EqualFold(claim.FounderEmail, strings.TrimSpace(in.FounderEmail)) {
		return uuid.Nil, errors.New("YC claim differs from billing approval")
	}
	var valid bool
	err = h.PromotionAuthPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($1,$2) WHERE approval_id=$3 AND company_identity=$1 AND team_id=$2 AND home_region=$4 AND offer_key='yc_2026' AND offer_version=1 AND revoked_at IS NULL)`, in.CompanyIdentity, team, claim.Approval, in.Region).Scan(&valid)
	if err != nil {
		return uuid.Nil, err
	}
	if !valid {
		return uuid.Nil, errors.New("YC claim activation authority is unavailable")
	}
	return claim.Approval, nil
}
func (h *Handlers) reserveYCAuthority(ctx context.Context, team, actor uuid.UUID, in ycApproval) (uuid.UUID, error) {
	if in.ClaimID != "" {
		return h.ycClaimApproval(ctx, team, in)
	}
	var id uuid.UUID
	err := h.PromotionAuthPool.QueryRow(ctx, `SELECT approval_id FROM public.reserve_yc_activation_authority($1,$2,$3,$4,'operator',$5,NULL)`, in.CompanyIdentity, team, in.Region, actor, in.Evidence).Scan(&id)
	return id, err
}
func (h *Handlers) verifyYCAuthority(ctx context.Context, o ycOperation) error {
	if h.PromotionAuthPool == nil {
		return errors.New("shared company approval authority is unavailable")
	}
	var valid bool
	err := h.PromotionAuthPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($4,$2) WHERE approval_id=$1 AND team_id=$2 AND home_region=$3 AND company_identity=$4 AND offer_key='yc_2026' AND offer_version=1 AND revoked_at IS NULL)`, o.ID, o.Team, o.Request.Region, o.Request.CompanyIdentity).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("company activation approval is revoked or differs from regional binding")
	}
	return nil
}

// Revocation is projected before activation checks so a shared-auth revocation
// cannot strand an otherwise usable subscription or its already-issued credit.
func (h *Handlers) syncYCRevocation(ctx context.Context, o *ycOperation) error {
	if h.PromotionAuthPool == nil {
		return errors.New("shared company approval authority is unavailable")
	}
	var at pgtype.Timestamptz
	var by pgtype.UUID
	err := h.PromotionAuthPool.QueryRow(ctx, `SELECT revoked_at,revoked_by FROM public.read_yc_activation_authority($1,$2) WHERE approval_id=$3 AND home_region=$4`, o.Request.CompanyIdentity, o.Team, o.ID, o.Request.Region).Scan(&at, &by)
	if err != nil {
		return err
	}
	if at.Valid {
		_, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET revoked_at=COALESCE(revoked_at,$2),revoked_by=COALESCE(revoked_by,$3) WHERE team_id=$1`, o.Team, at, uuid.UUID(by.Bytes).String())
		o.Revoked = at
	}
	return err
}

// The row lock serializes global revocation with provider dispatch. A revocation
// waits for an already-dispatched outcome; it cannot authorize another grant.
var ycAuthoritySlots = make(chan struct{}, 2)

func (h *Handlers) lockYCAuthority(ctx context.Context, o ycOperation) (func(), error) {
	if h.PromotionAuthPool == nil {
		return nil, errors.New("shared company approval authority unavailable")
	}
	select {
	case ycAuthoritySlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	tx, err := h.PromotionAuthPool.Begin(ctx)
	if err != nil {
		<-ycAuthoritySlots
		return nil, err
	}
	release := func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(ack)
		<-ycAuthoritySlots
	}
	_, err = tx.Exec(ctx, `SET LOCAL idle_in_transaction_session_timeout='60s'`)
	var valid bool
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,$3)`, o.ID, o.Team, o.Request.Region).Scan(&valid)
	}
	if err != nil || !valid {
		release()
		if err == nil {
			err = errors.New("company approval revoked or binding differs")
		}
		return nil, err
	}
	return release, nil
}
