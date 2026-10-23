package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

// WithAcceptedOfferRemoval permits only SQL benefit removal and its exact journal
// confirmation. The caller checks choice, actor, revision, original boundary and
// fresh provider proof. A wrapper error can follow a committed regional removal;
// recover its journal before retrying. Invalidation drains must not use this guard.
func (h *Handlers) WithAcceptedOfferRemoval(ctx context.Context, r YCAcceptanceRecord, requester, successor uuid.UUID, apply func(context.Context, pgx.Tx) error) error {
	if h == nil || h.Pool == nil || !h.YCOfferAcceptance.available() || r.AssignmentID == nil || r.OperationID == nil || requester == uuid.Nil || successor == uuid.Nil || successor == *r.AssignmentID || successor == *r.OperationID || apply == nil {
		return provisioning.ErrUnavailable
	}
	return h.YCOfferAcceptance.withGuardForActor(ctx, r, "guard", requester, func(ctx context.Context) error {
		tx, err := h.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer rollbackYCAcceptance(ctx, tx)
		if err = lockOfferFinancialAccount(ctx, tx, r.TeamID); err != nil {
			return err
		}
		initial := provisioning.InitialFinancialTarget(r.TeamID, *r.AssignmentID)
		if err = provisioning.CheckFinancialTarget(ctx, tx, initial); err != nil {
			return err
		}
		target := provisioning.FinancialTarget{TeamID: r.TeamID, AssignmentID: *r.AssignmentID, Phase: "successor", TargetID: successor}
		if err = provisioning.CheckFinancialTarget(ctx, tx, target); err != nil {
			return err
		}
		var finalized bool
		if err = tx.QueryRow(ctx, `SELECT finalized_at IS NOT NULL FROM billing_offer_financial_fence WHERE team_id=$1 AND assignment_id=$2 AND phase='successor' AND target_id=$3`, r.TeamID, *r.AssignmentID, successor).Scan(&finalized); err != nil {
			return err
		}
		if finalized {
			return provisioning.ErrConflict
		}
		if err = authz.New(tx).RequireTeamPermission(ctx, requester, r.TeamID, "billing:write"); err != nil {
			return err
		}
		var home string
		if err = tx.QueryRow(ctx, `SELECT home_region FROM team WHERE id=$1`, r.TeamID).Scan(&home); err != nil {
			return err
		}
		if home != r.HomeRegion || home != h.YCOfferAcceptance.Region {
			return provisioning.ErrConflict
		}
		if _, err = tx.Exec(ctx, `SELECT id FROM yc_offer_acceptance WHERE id=$1 FOR UPDATE`, r.ID); err != nil {
			return err
		}
		admission := &YCAcceptedProvisioningAdmission{Service: h.YCOfferAcceptance, Handlers: h}
		current, err := admission.record(ctx, tx, r.TeamID, *r.AssignmentID)
		if err != nil {
			return err
		}
		if current.ID != r.ID || current.OperationID == nil || *current.OperationID != *r.OperationID {
			return provisioning.ErrConflict
		}
		pinned, err := acceptedProvisioningSnapshot(r)
		if err != nil {
			return err
		}
		observed, err := acceptedProvisioningSnapshot(current)
		if err != nil {
			return err
		}
		var exact bool
		if err = tx.QueryRow(ctx, `SELECT accepted_offer->'snapshot'=$4::jsonb AND accepted_offer->'snapshot'=$5::jsonb
 AND finalized_at IS NOT NULL AND NOT held AND NOT control_pending AND revoked_at IS NULL
 FROM billing_offer_provisioning_operation WHERE id=$1 AND team_id=$2 AND assignment_id=$3 FOR UPDATE`,
			*r.OperationID, r.TeamID, *r.AssignmentID, pinned.Snapshot, observed.Snapshot).Scan(&exact); err != nil {
			return err
		}
		if !exact {
			return provisioning.ErrConflict
		}
		if err = apply(ctx, tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
}
