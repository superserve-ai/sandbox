package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Admission is a recoverable two-database protocol: commit a local plan fence
// before reserving the global company. Shared intent pins the exact retry target.
// A timeout never removes either fence; an audited rejection can release local
// plan selection only after the shared authority has been revoked.
func (h *Handlers) ycBindWithIntent(ctx context.Context, op string, p gin.H) (json.RawMessage, error) {
	team := p["team_id"]
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var created time.Time
	if err = tx.QueryRow(ctx, "SELECT created_at FROM public.team WHERE id=$1 FOR UPDATE", team).Scan(&created); err != nil {
		return nil, err
	}
	var migrating bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM public.stripe_promotion_migration_fence WHERE team_id=$1)", team).Scan(&migrating); err != nil {
		return nil, err
	}
	if migrating {
		return nil, errors.New("team migration requires operator review")
	}
	if _, err = tx.Exec(ctx, "INSERT INTO public.team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING", team); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "SELECT team_id FROM public.team_billing_account WHERE team_id=$1 FOR UPDATE", team); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "SELECT team_id FROM public.billing_signup_choice WHERE team_id=$1 FOR UPDATE", team); err != nil {
		return nil, err
	}
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.billing_signup_choice WHERE team_id=$1 AND state='selecting')
 AND NOT EXISTS(SELECT 1 FROM public.billing_commercial_contract WHERE team_id=$1)
 AND NOT EXISTS(SELECT 1 FROM public.team_billing_account WHERE team_id=$1 AND (stripe_customer_id IS NOT NULL OR stripe_subscription_id IS NOT NULL OR checkout_initializing_at IS NOT NULL OR stripe_activation_credit_reserved_at IS NOT NULL OR stripe_activation_credit_grant_id IS NOT NULL))`, team).Scan(&eligible)
	if err != nil {
		return nil, err
	}
	p["team_created_at"], p["team_eligible"] = created, eligible
	prepare := "prepare"
	if op == "approve" {
		prepare = "prepare-approve"
	}
	out, err := h.ycClaimRPC(ctx, prepare, p)
	if err != nil {
		return nil, err
	}
	var result struct {
		State    string     `json:"state"`
		Approval *uuid.UUID `json:"approval_id"`
	}
	if err = json.Unmarshal(out, &result); err != nil {
		return nil, err
	}
	if result.State == "manual_review" && op != "approve" {
		return out, nil
	}
	if result.Approval != nil {
		return out, nil
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.yc_claim_team_intent(team_id,claim_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, team, p["id"], p["user_id"]); err != nil {
		return nil, err
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT claim_id=$2 AND user_id=$3 AND released_at IS NULL FROM public.yc_claim_team_intent WHERE team_id=$1`, team, p["id"], p["user_id"]).Scan(&same); err != nil {
		return nil, err
	}
	if !same {
		return nil, errors.New("team claim intent requires operator review")
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return h.ycClaimRPC(ctx, op, p)
}

// Wait for an admission transaction even if its intent row is not visible yet.
// Terminal shared state is committed first, so later admission cannot restart.
func (h *Handlers) ycReleaseClaimIntent(ctx context.Context, claim, team uuid.UUID) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT id FROM public.team WHERE id=$1 FOR UPDATE", team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE public.yc_claim_team_intent SET released_at=COALESCE(released_at,clock_timestamp()) WHERE claim_id=$1 AND team_id=$2", claim, team); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
