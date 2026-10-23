package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
	"github.com/superserve-ai/sandbox/internal/db"
)

// ReadProviderPairFinancialAuthority is a current read, never a substitute for
// the regional fence held through an entitlement dispatch or refresh commit.
func (h *Handlers) ReadProviderPairFinancialAuthority(ctx context.Context, binding ContractProviderBinding) (YCFinancialAuthorization, error) {
	var shared YCFinancialAuthorization
	if h == nil || h.Pool == nil || !h.YCOfferAcceptance.available() {
		return shared, provisioning.ErrUnavailable
	}
	i := binding.Identity
	var raw json.RawMessage
	err := h.Pool.QueryRow(ctx, `SELECT authorization_receipt FROM billing_offer_financial_fence
 WHERE team_id=$1 AND assignment_id=$2 AND finalized_at IS NOT NULL AND revoked_at IS NULL
 AND authorization_receipt->>'operation_id'=$3 AND
 ((phase='initial' AND target_id=assignment_id) OR (phase='successor' AND target_id=$4))`,
		i.TeamID, i.AssignmentID, i.OperationID.String(), i.OperationID).Scan(&raw)
	if err != nil {
		return shared, err
	}
	var regional provisioning.FinancialAuthorization
	if json.Unmarshal(raw, &regional) != nil || regional.OperationID != i.OperationID || regional.AcceptanceID != i.AcceptanceID || regional.ApprovalRevision != i.ApprovalSemanticRevision || regional.HomeRegion != h.YCOfferAcceptance.Region || binding.ContractID != i.OperationID || regional.TargetTermsDigest != i.TermsDigest {
		return shared, provisioning.ErrConflict
	}
	shared, err = h.YCOfferAcceptance.ReadFinancialAuthorization(ctx, i.AcceptanceID, regional.Target.Phase, i.OperationID)
	if err != nil {
		return shared, err
	}
	if shared.InvalidatedAt != nil || shared.AuthorizationID != regional.ID || shared.TeamID != i.TeamID || shared.AssignmentID != i.AssignmentID || shared.AcceptanceID != i.AcceptanceID || shared.OperationID != i.OperationID || shared.ApprovalRevision != i.ApprovalSemanticRevision || shared.Phase != regional.Target.Phase || shared.TermsDigest != regional.TermsDigest || shared.TargetTermsDigest != regional.TargetTermsDigest || shared.HomeRegion != regional.HomeRegion {
		return shared, provisioning.ErrConflict
	}
	state, err := h.YCOfferAcceptance.FinancialState(ctx, shared.ClaimID)
	if err != nil {
		return shared, err
	}
	if state == nil || !state.valid() {
		return shared, provisioning.ErrRevoked
	}
	return shared, nil
}

type offerProvisioningAuthority struct {
	h                  *Handlers
	admission          *YCAcceptedProvisioningAdmission
	client             *stripeHTTPClient
	successorRequester func(context.Context, pgx.Tx, ContractProviderBinding) (uuid.UUID, error)
	dispatchesResolved func(context.Context, db.DBTX, ContractProviderBinding) error
}

var _ provisioning.Authority = (*offerProvisioningAuthority)(nil)
var _ ProviderPairEntitlementAuthority = (*offerProvisioningAuthority)(nil)

// WithProviderPairAuthority is the entitlement worker's SQL-only dispatch and
// refresh boundary. Remote authority is observed before any regional lock.
func (a *offerProvisioningAuthority) WithProviderPairAuthority(ctx context.Context, binding ContractProviderBinding, apply func(context.Context, pgx.Tx) error) error {
	if apply == nil {
		return provisioning.ErrConflict
	}
	shared, err := a.h.ReadProviderPairFinancialAuthority(ctx, binding)
	if err != nil {
		return err
	}
	tx, err := a.h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if err = lockOfferFinancialAccount(ctx, tx, shared.TeamID); err != nil {
		return err
	}
	target := provisioning.InitialFinancialTarget(shared.TeamID, shared.AssignmentID)
	if shared.Phase == "successor" {
		target.Phase, target.TargetID = shared.Phase, shared.OperationID
	}
	if err = provisioning.CheckFinancialTarget(ctx, tx, target); err != nil {
		return err
	}
	var exact bool
	if err = tx.QueryRow(ctx, `SELECT finalized_at IS NOT NULL AND revoked_at IS NULL
 AND authorization_receipt->>'authorization_id'=$5 AND authorization_receipt->>'operation_id'=$6
 AND authorization_receipt->>'acceptance_id'=$7 AND authorization_receipt->>'terms_digest'=$8
 AND authorization_receipt->>'target_terms_digest'=$9 AND authorization_receipt->>'home_region'=$10
 AND (authorization_receipt->>'approval_revision')::bigint=$11
 FROM billing_offer_financial_fence WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4`,
		target.TeamID, target.AssignmentID, target.Phase, target.TargetID, shared.AuthorizationID.String(), shared.OperationID.String(),
		shared.AcceptanceID.String(), shared.TermsDigest, shared.TargetTermsDigest, shared.HomeRegion, shared.ApprovalRevision).Scan(&exact); err != nil {
		return err
	}
	if !exact {
		return provisioning.ErrConflict
	}
	requester := shared.UserID
	if shared.Phase == "successor" {
		if a.successorRequester == nil {
			return provisioning.ErrUnavailable
		}
		requester, err = a.successorRequester(ctx, tx, binding)
		if err != nil {
			return err
		}
	}
	if err = authz.New(tx).RequireTeamPermission(ctx, requester, shared.TeamID, "billing:write"); err != nil {
		return err
	}
	r, err := a.admission.record(ctx, tx, shared.TeamID, shared.AssignmentID)
	if err != nil {
		return err
	}
	if r.ID != shared.AcceptanceID || r.UserID != shared.UserID || r.ClaimID != shared.ClaimID || r.ApprovalID != shared.ApprovalID || r.ApprovalRevision != shared.ApprovalRevision || r.TermsDigest != shared.TermsDigest || r.RenewalTermsDigest != shared.RenewalTermsDigest || r.Company != shared.Company {
		return provisioning.ErrConflict
	}
	var contract uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM billing_commercial_contract WHERE id=$1 AND team_id=$2 AND status='active' FOR UPDATE`, binding.ContractID, shared.TeamID).Scan(&contract); err != nil {
		return err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT binding=$2::jsonb AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation WHERE contract_id=$1) FROM billing_contract_provider_binding WHERE contract_id=$1`, binding.ContractID, raw).Scan(&exact); err != nil {
		return err
	}
	if !exact {
		return provisioning.ErrConflict
	}
	if err = apply(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *offerProvisioningAuthority) runFinancialInvalidations(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		started := time.Now()
		count, err := a.drainFinancialInvalidations(work)
		cancel()
		currentBillingRecorder().RecordBillingWork(ctx, "offer_provisioning", err != nil, time.Since(started), int64(count))
		if err != nil && ctx.Err() == nil {
			log.Warn().Msg("offer financial revocation delivery requires recovery")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (a *offerProvisioningAuthority) WithFinalization(ctx context.Context, operation provisioning.Operation, f func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error) error {
	r, err := a.admission.record(ctx, a.h.Pool, operation.TeamID, operation.AssignmentID)
	if err != nil {
		return err
	}
	return a.h.FinalizeAcceptedOfferFinancial(ctx, r, "initial", operation.ID, operation.Offer.TermsDigest, time.Time{}, func(ctx context.Context, tx pgx.Tx, authorization YCFinancialAuthorization) error {
		offer, err := a.admission.ValidateFinancialAcceptance(ctx, tx, operation, authorization)
		if err != nil {
			return err
		}
		return f(ctx, tx, enrichOfferProvisioning(offer, operation.Offer))
	})
}

// FinalizeAcceptedOfferFinancial is the shared initial/successor commit boundary.
// apply must revalidate current regional permission and its exact immutable
// journal, then materialize and finalize that journal using only this transaction.
func (h *Handlers) FinalizeAcceptedOfferFinancial(ctx context.Context, r YCAcceptanceRecord, phase string, operation uuid.UUID, targetDigest string, boundary time.Time, apply func(context.Context, pgx.Tx, YCFinancialAuthorization) error) error {
	if h == nil || h.Pool == nil || !h.YCOfferAcceptance.available() || r.AssignmentID == nil || apply == nil || (phase != "initial" && phase != "successor") {
		return provisioning.ErrUnavailable
	}
	// This durable shared commit precedes every regional effect. A lost response
	// returns without finalizing; retry recovers the same immutable authorization.
	authorization, err := h.YCOfferAcceptance.IssueFinancialAuthorization(ctx, r, phase, operation, targetDigest)
	if err != nil {
		return err
	}
	if authorization.InvalidatedAt != nil || authorization.AuthorizationID == uuid.Nil || authorization.AuthorizedAt.IsZero() || authorization.TeamID != r.TeamID || authorization.AssignmentID != *r.AssignmentID || authorization.OperationID != operation || authorization.AcceptanceID != r.ID || authorization.UserID != r.UserID || authorization.ClaimID != r.ClaimID || authorization.ApprovalID != r.ApprovalID || authorization.ApprovalRevision != r.ApprovalRevision || authorization.HomeRegion != r.HomeRegion || authorization.Company != r.Company || authorization.Phase != phase || authorization.TermsDigest != r.TermsDigest || authorization.RenewalTermsDigest != r.RenewalTermsDigest || authorization.TargetTermsDigest != targetDigest {
		return provisioning.ErrConflict
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if err = lockOfferFinancialAccount(ctx, tx, r.TeamID); err != nil {
		return err
	}
	target := provisioning.InitialFinancialTarget(r.TeamID, *r.AssignmentID)
	if phase == "successor" {
		target.Phase, target.TargetID = phase, operation
	}
	if err = provisioning.CheckFinancialTarget(ctx, tx, target); err != nil {
		return err
	}
	regional := provisioning.FinancialAuthorization{ID: authorization.AuthorizationID, Target: target, OperationID: authorization.OperationID,
		AcceptanceID: authorization.AcceptanceID, ApprovalRevision: authorization.ApprovalRevision, HomeRegion: authorization.HomeRegion,
		TermsDigest: authorization.TermsDigest, TargetTermsDigest: authorization.TargetTermsDigest, Boundary: boundary}
	if err = provisioning.FinalizeFinancialAuthorization(ctx, tx, regional, func(ctx context.Context, tx pgx.Tx) error {
		return apply(ctx, tx, authorization)
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (*offerProvisioningAuthority) Finalize(ctx context.Context, tx pgx.Tx, operation provisioning.Operation, evidence provisioning.Verification) error {
	return finalizeInitialOffer(ctx, tx, operation, evidence)
}

func lockOfferFinancialAccount(ctx context.Context, tx pgx.Tx, team uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return err
	}
	// Missing teams still need durable tombstones; creation of an account is an
	// admission responsibility. Existing account locks serialize every effect.
	_, err := tx.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, team)
	return err
}

func (a *offerProvisioningAuthority) drainFinancialInvalidations(ctx context.Context) (int, error) {
	deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 8)
	if err != nil {
		return 0, err
	}
	var failures []error
	for _, delivery := range deliveries {
		if err := a.revokeFinancialDelivery(ctx, delivery); err != nil {
			failures = append(failures, err)
		}
	}
	return len(deliveries), errors.Join(failures...)
}

func (a *offerProvisioningAuthority) revokeFinancialDelivery(ctx context.Context, d YCFinancialInvalidation) error {
	if d.HomeRegion != a.admission.Service.Region || d.AuthorizationID == uuid.Nil || d.AcceptanceID == uuid.Nil || d.OperationID == uuid.Nil || d.LeaseID == uuid.Nil {
		return provisioning.ErrConflict
	}
	target := provisioning.InitialFinancialTarget(d.TeamID, d.AssignmentID)
	if d.Phase == "successor" {
		target.Phase, target.TargetID = d.Phase, d.OperationID
	} else if d.Phase != "initial" {
		return provisioning.ErrConflict
	}
	tx, err := a.h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if err = lockOfferFinancialAccount(ctx, tx, d.TeamID); err != nil {
		return err
	}
	err = provisioning.RevokeFinancialTarget(ctx, tx, target, d.InvalidationID, func(ctx context.Context, tx pgx.Tx, saved provisioning.FinancialAuthorization) error {
		if saved.ID != d.AuthorizationID || saved.OperationID != d.OperationID || saved.AcceptanceID != d.AcceptanceID || saved.HomeRegion != d.HomeRegion {
			return provisioning.ErrConflict
		}
		binding, err := loadContractProviderBinding(ctx, tx, saved.OperationID)
		if err != nil {
			return err
		}
		i := binding.Identity
		if i.OperationID != saved.OperationID || i.TeamID != target.TeamID || i.AssignmentID != target.AssignmentID || i.AcceptanceID != saved.AcceptanceID || i.ApprovalSemanticRevision != saved.ApprovalRevision {
			return provisioning.ErrConflict
		}
		return RevokeProviderPairAuthority(ctx, tx, binding.ContractID, i)
	})
	if err != nil {
		return err
	}
	commitErr := tx.Commit(ctx)
	// A commit error can mean success. Read only committed state through the pool;
	// failure to prove the permanent fence leaves the shared delivery unacked.
	receipt, err := provisioning.LoadFinancialRevocationReceipt(ctx, a.h.Pool, target, d.InvalidationID)
	if err != nil {
		return errors.Join(commitErr, err)
	}
	if err = a.checkRevocationDispatches(ctx, d, receipt); err != nil {
		return err
	}
	return a.admission.Service.AcknowledgeFinancialInvalidation(ctx, d, receipt.AcknowledgementID, receipt.FenceID)
}

func (a *offerProvisioningAuthority) checkRevocationDispatches(ctx context.Context, d YCFinancialInvalidation, receipt provisioning.FinancialRevocationReceipt) error {
	if receipt.Authorization == nil {
		// A target that never finalized could not admit a paired grant dispatch.
		return nil
	}
	saved := receipt.Authorization
	if saved.ID != d.AuthorizationID || saved.OperationID != d.OperationID || saved.AcceptanceID != d.AcceptanceID || saved.HomeRegion != d.HomeRegion {
		return provisioning.ErrConflict
	}
	binding, err := loadContractProviderBinding(ctx, a.h.Pool, saved.OperationID)
	if err != nil {
		return err
	}
	i := binding.Identity
	if binding.ContractID != saved.OperationID || i.OperationID != saved.OperationID || i.TeamID != saved.Target.TeamID || i.AssignmentID != saved.Target.AssignmentID || i.AcceptanceID != saved.AcceptanceID || i.ApprovalSemanticRevision != saved.ApprovalRevision || i.TermsDigest != saved.TargetTermsDigest {
		return provisioning.ErrConflict
	}
	if a.dispatchesResolved == nil {
		return provisioning.ErrUnavailable
	}
	// The committed permanent tombstone prevents new admissions. Resolution must
	// be monotone for every previously admitted attempt; repeat this read even
	// when an earlier delivery already committed regional revocation.
	return a.dispatchesResolved(ctx, a.h.Pool, binding)
}
