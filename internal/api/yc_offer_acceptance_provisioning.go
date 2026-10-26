package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
	"github.com/superserve-ai/sandbox/internal/db"
)

// YCAcceptedProvisioningAdmission authorizes pending journal work and dispatch.
// It rejects new finalization: a shared-session loss cannot safely authorize a
// regional benefit commit. Activation requires a separate reviewed protocol.
type YCAcceptedProvisioningAdmission struct {
	Service  *YCOfferAcceptanceService
	Handlers *Handlers
}

var _ provisioning.Admission = (*YCAcceptedProvisioningAdmission)(nil)

func (a *YCAcceptedProvisioningAdmission) record(ctx context.Context, q db.DBTX, team, assignment uuid.UUID) (YCAcceptanceRecord, error) {
	var r YCAcceptanceRecord
	if a == nil || !a.Service.available() || a.Handlers == nil || team == uuid.Nil || assignment == uuid.Nil {
		return r, provisioning.ErrUnavailable
	}
	var claim uuid.UUID
	if err := q.QueryRow(ctx, `SELECT claim_id FROM yc_offer_acceptance WHERE team_id=$1 AND assignment_id=$2`, team, assignment).Scan(&claim); err != nil {
		return r, err
	}
	r, err := loadYCAcceptance(ctx, q, team, claim)
	if err != nil {
		return r, err
	}
	if r.AcceptedAt == nil || r.RequestID == nil || r.AssignmentID == nil || *r.AssignmentID != assignment || r.HomeRegion != a.Service.Region || r.State == "held" || r.State == "revoked" {
		return r, provisioning.ErrConflict
	}
	if err = verifyAcceptedAssignment(ctx, q, r, assignment); err != nil {
		return r, err
	}
	if err = commercialOfferEnabled(ctx, q, team); err != nil {
		return r, err
	}
	return r, nil
}

func acceptedProvisioningSnapshot(r YCAcceptanceRecord) (provisioning.AcceptedOffer, error) {
	// Operational state and provider mapping must never change the saved acceptance.
	snapshot := struct {
		YCAcceptanceAuthority
		AcceptanceID       uuid.UUID         `json:"acceptance_id"`
		RequestID          *uuid.UUID        `json:"request_id"`
		AssignmentID       *uuid.UUID        `json:"assignment_id"`
		Terms              YCAcceptanceTerms `json:"terms"`
		RenewalTerms       YCAcceptanceTerms `json:"renewal_terms"`
		TermsDigest        string            `json:"terms_digest"`
		RenewalTermsDigest string            `json:"renewal_terms_digest"`
		PricingAt          time.Time         `json:"pricing_at"`
		AcceptedAt         *time.Time        `json:"accepted_at"`
	}{r.YCAcceptanceAuthority, r.ID, r.RequestID, r.AssignmentID, r.Terms, r.RenewalTerms, r.TermsDigest, r.RenewalTermsDigest, r.PricingAt, r.AcceptedAt}
	raw, err := json.Marshal(snapshot)
	return provisioning.AcceptedOffer{AcceptanceID: r.ID, TermsDigest: r.TermsDigest, Snapshot: raw}, err
}

// WithAcceptedOffer permits regional SQL only. Bounded locks turn conflicts with
// existing regional-before-shared signup paths into retries, never provider I/O.
func (a *YCAcceptedProvisioningAdmission) WithAcceptedOffer(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error) error {
	if a == nil || !a.Service.available() {
		return provisioning.ErrUnavailable
	}
	r, err := a.record(ctx, a.Service.Pool, team, assignment)
	if err != nil {
		return err
	}
	return a.Service.withGuard(ctx, r, "guard", func(guardCtx context.Context) error {
		tx, err := a.Service.Pool.Begin(guardCtx)
		if err != nil {
			return err
		}
		defer rollbackYCAcceptance(guardCtx, tx)
		if _, err = tx.Exec(guardCtx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if _, err = tx.Exec(guardCtx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
			return err
		}
		if err = lockCommercialOfferAccount(guardCtx, tx, team); err != nil {
			return err
		}
		if _, err = tx.Exec(guardCtx, `SELECT id FROM yc_offer_acceptance WHERE id=$1 FOR UPDATE`, r.ID); err != nil {
			return err
		}
		current, err := a.record(guardCtx, tx, team, assignment)
		if err != nil {
			return err
		}
		var finalized bool
		if err = tx.QueryRow(guardCtx, `SELECT EXISTS(SELECT 1 FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2 AND finalized_at IS NOT NULL)`, team, assignment).Scan(&finalized); err != nil {
			return err
		}
		if !finalized {
			if err = a.Service.lockNewSignup(guardCtx, tx, current.YCAcceptanceAuthority); err != nil {
				return err
			}
			if err = a.Handlers.sponsoredLocalPreflight(guardCtx, tx, team); err != nil {
				return err
			}
			var reserved bool
			if err = tx.QueryRow(guardCtx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_checkout_attempt WHERE team_id=$1 AND (state IN ('dispatched','customer_observed') OR (state='prepared' AND prepared_until>clock_timestamp())))`, team).Scan(&reserved); err != nil {
				return err
			}
			if reserved {
				return provisioning.ErrConflict
			}
		}
		offer, err := acceptedProvisioningSnapshot(current)
		if err != nil {
			return err
		}
		if err = f(guardCtx, tx, offer); err != nil {
			return err
		}
		var finalizedAfter bool
		if err = tx.QueryRow(guardCtx, `SELECT EXISTS(SELECT 1 FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2 AND finalized_at IS NOT NULL)`, team, assignment).Scan(&finalizedAfter); err != nil {
			return err
		}
		if finalizedAfter != finalized {
			return provisioning.ErrUnavailable
		}
		return tx.Commit(guardCtx)
	})
}

// WithDispatchGuard begins only after the regional marker commits. Its callback
// performs provider I/O only and must never acquire regional rows.
func (a *YCAcceptedProvisioningAdmission) WithDispatchGuard(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, provisioning.AcceptedOffer) error) error {
	if a == nil || !a.Service.available() {
		return provisioning.ErrUnavailable
	}
	r, err := a.record(ctx, a.Service.Pool, team, assignment)
	if err != nil {
		return err
	}
	offer, err := acceptedProvisioningSnapshot(r)
	if err != nil {
		return err
	}
	return a.Service.WithGuard(ctx, r, func(guardCtx context.Context) error { return f(guardCtx, offer) })
}

type ycAcceptanceProvisioner struct{ service *provisioning.Service }

func (p ycAcceptanceProvisioner) Enqueue(ctx context.Context, team, assignment uuid.UUID) (uuid.UUID, error) {
	return p.service.Enqueue(ctx, team, assignment)
}
func (p ycAcceptanceProvisioner) Status(ctx context.Context, team, assignment uuid.UUID) (YCAcceptanceProvisioningStatus, error) {
	status, err := p.service.Status(ctx, team, assignment)
	return YCAcceptanceProvisioningStatus{OperationID: status.OperationID, State: status.State, Ready: status.Ready, Held: status.Held, Revoked: status.Revoked, ControlPending: status.ControlPending}, err
}

// RecoverAcceptance reads immutable journal evidence even after revocation. This
// only repairs a lost local acknowledgement; Status and dispatch recheck authority.
func (p ycAcceptanceProvisioner) RecoverAcceptance(ctx context.Context, r YCAcceptanceRecord) (uuid.UUID, bool, error) {
	if p.service == nil || p.service.Pool == nil || r.AssignmentID == nil {
		return uuid.Nil, false, provisioning.ErrUnavailable
	}
	offer, err := acceptedProvisioningSnapshot(r)
	if err != nil {
		return uuid.Nil, false, err
	}
	var id uuid.UUID
	var same bool
	err = p.service.Pool.QueryRow(ctx, `SELECT id,accepted_offer->>'acceptance_id'=$3 AND accepted_offer->>'terms_digest'=$4 AND accepted_offer->'snapshot'=$5::jsonb FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2`, r.TeamID, *r.AssignmentID, r.ID.String(), r.TermsDigest, offer.Snapshot).Scan(&id, &same)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	if !same {
		return uuid.Nil, false, errYCAcceptanceConflict
	}
	return id, true, nil
}

// ValidateFinancialAcceptance validates initial activation inside the caller's
// regional transaction, after its team/account and permanent financial fence
// locks. The caller supplies an exact committed shared receipt. This method
// performs regional SQL only and neither commits nor opens another connection.
func (a *YCAcceptedProvisioningAdmission) ValidateFinancialAcceptance(ctx context.Context, tx pgx.Tx, operation provisioning.Operation, authorization YCFinancialAuthorization) (provisioning.AcceptedOffer, error) {
	var empty provisioning.AcceptedOffer
	if tx == nil || a == nil || !a.Service.available() || a.Handlers == nil {
		return empty, provisioning.ErrUnavailable
	}
	if authorization.AuthorizationID == uuid.Nil || authorization.AuthorizedAt.IsZero() || authorization.InvalidatedAt != nil || authorization.Phase != "initial" || authorization.OperationID != operation.ID || authorization.TeamID != operation.TeamID || authorization.AssignmentID != operation.AssignmentID || authorization.HomeRegion != a.Service.Region || authorization.TargetTermsDigest != authorization.TermsDigest {
		return empty, provisioning.ErrConflict
	}
	var home string
	if err := tx.QueryRow(ctx, `SELECT home_region FROM public.team WHERE id=$1 FOR NO KEY UPDATE`, operation.TeamID).Scan(&home); err != nil {
		return empty, err
	}
	if home != a.Service.Region {
		return empty, provisioning.ErrConflict
	}
	if err := lockCommercialOfferAccount(ctx, tx, operation.TeamID); err != nil {
		return empty, err
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM public.yc_offer_acceptance WHERE team_id=$1 AND assignment_id=$2 FOR UPDATE`, operation.TeamID, operation.AssignmentID); err != nil {
		return empty, err
	}
	r, err := a.record(ctx, tx, operation.TeamID, operation.AssignmentID)
	if err != nil {
		return empty, err
	}
	if authorization.AcceptanceID != r.ID || authorization.ClaimID != r.ClaimID || authorization.UserID != r.UserID || authorization.Company != r.Company || authorization.ApprovalID != r.ApprovalID || authorization.ApprovalRevision != r.ApprovalRevision || authorization.TermsDigest != r.TermsDigest || authorization.RenewalTermsDigest != r.RenewalTermsDigest || (r.OperationID != nil && *r.OperationID != operation.ID) {
		return empty, provisioning.ErrConflict
	}
	if err = authz.New(tx).RequireTeamPermission(ctx, r.UserID, r.TeamID, "billing:write"); err != nil {
		return empty, err
	}
	offer, err := acceptedProvisioningSnapshot(r)
	if err != nil {
		return empty, err
	}
	var same, finalized bool
	err = tx.QueryRow(ctx, `SELECT accepted_offer->>'acceptance_id'=$4 AND accepted_offer->>'terms_digest'=$5 AND accepted_offer->'snapshot'=$6::jsonb
 AND accepted_offer->'snapshot'=$7::jsonb AND NOT held AND NOT control_pending AND revoked_at IS NULL,finalized_at IS NOT NULL
 FROM public.billing_offer_provisioning_operation WHERE id=$1 AND team_id=$2 AND assignment_id=$3 FOR UPDATE`, operation.ID, r.TeamID, operation.AssignmentID, r.ID.String(), r.TermsDigest, offer.Snapshot, operation.Offer.Snapshot).Scan(&same, &finalized)
	if err != nil {
		return empty, err
	}
	if !same {
		return empty, provisioning.ErrConflict
	}
	if !finalized {
		if err = a.Service.lockNewSignup(ctx, tx, r.YCAcceptanceAuthority); err != nil {
			return empty, err
		}
		if err = a.Handlers.sponsoredLocalPreflight(ctx, tx, r.TeamID); err != nil {
			return empty, err
		}
		var reserved bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.billing_commercial_checkout_attempt WHERE team_id=$1 AND (state IN ('dispatched','customer_observed') OR (state='prepared' AND prepared_until>clock_timestamp())))`, r.TeamID).Scan(&reserved); err != nil {
			return empty, err
		}
		if reserved {
			return empty, provisioning.ErrConflict
		}
	}
	return offer, nil
}
