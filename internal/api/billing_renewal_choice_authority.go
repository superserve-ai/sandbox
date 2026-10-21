package api

import (
	"context"
	"reflect"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/db"
)

type acceptedRenewalAuthority struct {
	Admission      *YCAcceptedProvisioningAdmission
	Verifier       renewalScheduleVerifier
	Monthly        *ProviderPairTerms
	MonthlyVersion int
}

func (a *acceptedRenewalAuthority) ready() bool {
	return a != nil && a.Admission != nil && a.Admission.Service.available() && a.Admission.Handlers != nil
}
func (a *acceptedRenewalAuthority) accepted(ctx context.Context, q db.DBTX, k renewalChoiceKey, actor uuid.UUID) (YCAcceptanceRecord, ContractProviderBinding, error) {
	var r YCAcceptanceRecord
	var b ContractProviderBinding
	if !a.ready() || actor == uuid.Nil || !validRenewalKey(k) {
		return r, b, errRenewalDisabled
	}
	if err := authz.New(q).RequireTeamPermission(ctx, actor, k.Team, "billing:write"); err != nil {
		return r, b, err
	}
	r, err := a.Admission.record(ctx, q, k.Team, k.Assignment)
	if err != nil {
		return r, b, err
	}
	actual, b, err := loadRenewalChoicePair(ctx, q, k.Team, k.Assignment)
	if err != nil {
		return r, b, err
	}
	if !actual.Boundary.Equal(k.Boundary) || b.Identity.AcceptanceID != r.ID || b.Identity.ApprovalSemanticRevision != r.ApprovalRevision || b.Identity.TermsDigest != r.TermsDigest {
		return r, b, errRenewalConflict
	}
	var revoked bool
	if err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_provider_pair_revocation WHERE contract_id=$1)`, b.ContractID).Scan(&revoked); err != nil {
		return r, b, err
	}
	if revoked {
		return r, b, errRenewalConflict
	}
	return r, b, nil
}
func (a *acceptedRenewalAuthority) Locate(ctx context.Context, team, assignment, actor uuid.UUID) (renewalChoiceKey, error) {
	if !a.ready() {
		return renewalChoiceKey{}, errRenewalDisabled
	}
	if err := authz.New(a.Admission.Service.Pool).RequireTeamPermission(ctx, actor, team, "billing:write"); err != nil {
		return renewalChoiceKey{}, err
	}
	k, _, err := loadRenewalChoicePair(ctx, a.Admission.Service.Pool, team, assignment)
	if err != nil {
		return k, err
	}
	_, _, err = a.accepted(ctx, a.Admission.Service.Pool, k, actor)
	return k, err
}
func (a *acceptedRenewalAuthority) Admit(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, f func(context.Context) error) error {
	if !a.ready() {
		return errRenewalDisabled
	}
	r, _, err := a.accepted(ctx, a.Admission.Service.Pool, k, actor)
	if err != nil {
		return err
	}
	// Release the shared guard before opening any regional transaction. This
	// point-in-time check permits pending metadata only, never a financial effect.
	if err = a.Admission.Service.WithSuccessorGuard(ctx, r, actor, func(context.Context) error { return nil }); err != nil {
		return err
	}
	return f(ctx)
}
func (a *acceptedRenewalAuthority) DispatchGuard(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, f func(context.Context) error) error {
	if !a.ready() {
		return errRenewalDisabled
	}
	r, b, err := a.accepted(ctx, a.Admission.Service.Pool, k, op.Actor)
	if err != nil {
		return err
	}
	if r.ID != op.Request.Acceptance || r.ApprovalRevision != op.Request.ApprovalRevision || renewalHash(renewalChoiceBindingFromPair(b)) != renewalHash(op.Binding) {
		return errRenewalConflict
	}
	return a.Admission.Service.WithSuccessorGuard(ctx, r, op.Actor, f)
}
func (a *acceptedRenewalAuthority) Authorize(ctx context.Context, tx pgx.Tx, k renewalChoiceKey, actor uuid.UUID) (renewalChoiceAuthority, error) {
	if !a.ready() {
		return renewalChoiceAuthority{}, errRenewalDisabled
	}
	var q db.DBTX = a.Admission.Service.Pool
	if tx != nil {
		q = tx
	}
	r, b, err := a.accepted(ctx, q, k, actor)
	if err != nil {
		return renewalChoiceAuthority{}, err
	}
	return renewalChoiceAuthority{Acceptance: r.ID, Revision: r.ApprovalRevision, Binding: renewalChoiceBindingFromPair(b)}, nil
}
func (a *acceptedRenewalAuthority) Resolve(ctx context.Context, tx pgx.Tx, k renewalChoiceKey, choice string) (*renewalChoiceTerms, error) {
	if !a.ready() || tx == nil {
		return nil, errRenewalDisabled
	}
	r, err := a.Admission.record(ctx, tx, k.Team, k.Assignment)
	if err != nil {
		return nil, err
	}
	_, b, err := loadRenewalChoicePair(ctx, tx, k.Team, k.Assignment)
	if err != nil {
		return nil, err
	}
	if choice == "free" {
		return nil, nil
	}
	mapping, version := b.Terms, r.RenewalTerms.OfferVersion
	if choice == "monthly" {
		if a.Monthly == nil || a.MonthlyVersion < 1 || !reflect.DeepEqual(a.Monthly.Resources, b.Terms.Resources) || a.Monthly.Rounding != b.Terms.Rounding {
			return nil, errRenewalDisabled
		}
		mapping, version = *a.Monthly, a.MonthlyVersion
	} else if choice != "annual" || r.RenewalTerms.OfferKey != "pro_annual" {
		return nil, errRenewalConflict
	}
	return loadRenewalChoiceTerms(ctx, tx, choice, version, mapping)
}
func (a *acceptedRenewalAuthority) DefaultProof(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if !a.ready() || a.Verifier == nil {
		return renewalChoiceProof{}, errRenewalDisabled
	}
	return a.Verifier.ObserveChoice(ctx, k, op)
}
