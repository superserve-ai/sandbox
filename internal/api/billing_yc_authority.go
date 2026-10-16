package api

import (
	"context"
	"errors"
	"time"

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
	return nil
}
func (h *Handlers) reserveYCAuthority(ctx context.Context, team, actor uuid.UUID, in ycApproval) (uuid.UUID, error) {
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
