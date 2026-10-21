package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

// RenewalSuccessorRequester resolves regional permission ownership without
// replacing the original accepter's shared identity or financial receipt.
func RenewalSuccessorRequester(ctx context.Context, tx pgx.Tx, b ContractProviderBinding) (uuid.UUID, error) {
	if tx == nil {
		return uuid.Nil, errRenewalDisabled
	}
	k, previous, err := loadRenewalChoicePair(ctx, tx, b.Identity.TeamID, b.Identity.AssignmentID)
	if err != nil {
		return uuid.Nil, err
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT snapshot FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3 FOR UPDATE`, k.Team, k.Assignment, k.Boundary).Scan(&raw); err != nil {
		return uuid.Nil, err
	}
	var j renewalChoiceJournal
	if json.Unmarshal(raw, &j) != nil || j.Confirmed == nil || j.SuccessorState != "active" || j.Successor != b.ContractID || j.Successor != renewalSuccessorID(k) || j.Confirmed.Actor == uuid.Nil || j.Confirmed.Request.Acceptance != b.Identity.AcceptanceID || j.Confirmed.Request.ApprovalRevision != b.Identity.ApprovalSemanticRevision || j.Confirmed.State != "confirmed" {
		return uuid.Nil, errRenewalConflict
	}
	expected, err := renewalSuccessorBinding(k, *j.Confirmed, previous, b.FeeItemID)
	if err != nil || renewalHash(expected) != renewalHash(b) {
		return uuid.Nil, errRenewalConflict
	}
	return j.Confirmed.Actor, nil
}

type renewalFinancialFinalizer func(context.Context, YCAcceptanceRecord, string, uuid.UUID, string, time.Time, func(context.Context, pgx.Tx, YCFinancialAuthorization) error) error
type renewalBenefitRemoval func(context.Context, YCAcceptanceRecord, uuid.UUID, uuid.UUID, func(context.Context, pgx.Tx) error) error

func renewalGrantFeeStart(b ContractProviderBinding, now time.Time) (time.Time, time.Time, error) {
	start, _, ok := billing.AnniversaryPeriod(b.Anchor, now)
	months := (start.Year()-b.Anchor.Year())*12 + int(start.Month()-b.Anchor.Month()) - 12
	if !ok || months < 0 || (b.Terms.FeeMonths != 1 && b.Terms.FeeMonths != 12) {
		return time.Time{}, time.Time{}, errRenewalPending
	}
	first := (b.StartsAt.Year()-b.FeeAnchor.Year())*12 + int(b.StartsAt.Month()-b.FeeAnchor.Month())
	return start, annualBoundary(b.FeeAnchor, first+months/int(b.Terms.FeeMonths)*int(b.Terms.FeeMonths)), nil
}

type acceptedRenewalSuccessors struct {
	Authority *acceptedRenewalAuthority
	Handlers  *Handlers
	Client    *stripeHTTPClient
	Finalize  renewalFinancialFinalizer
	Remove    renewalBenefitRemoval
}

// The legacy transaction-first port cannot acquire shared financial authority.
func (*acceptedRenewalSuccessors) Reconcile(context.Context, pgx.Tx, renewalChoiceKey, renewalChoiceOperation, uuid.UUID) (string, error) {
	return "", errRenewalDisabled
}

func (a *acceptedRenewalSuccessors) ReconcileFinancial(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, commit func(context.Context, pgx.Tx, func() (string, error)) error) error {
	if a == nil || a.Authority == nil || !a.Authority.ready() || a.Handlers == nil || a.Client == nil || op.Proof == nil || op.Proof.Timing != "boundary_history" {
		return errRenewalDisabled
	}
	pending := func(state string) error {
		return commit(ctx, nil, func() (string, error) { return state, nil })
	}
	if op.Request.Choice == "free" {
		if a.Remove == nil {
			return pending("review_required")
		}
		r, previous, err := a.Authority.accepted(ctx, a.Authority.Admission.Service.Pool, k, op.Actor)
		if err != nil {
			return err
		}
		return a.Remove(ctx, r, op.Actor, renewalSuccessorID(k), func(ctx context.Context, tx pgx.Tx) error {
			return commit(ctx, tx, func() (string, error) {
				if time.Since(op.Proof.VerifiedAt) > time.Minute {
					return "", errRenewalPending
				}
				q := db.New(tx)
				old, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: k.Team, ContractID: previous.ContractID})
				if err != nil {
					return "", err
				}
				if !old.EndsAt.Valid || !old.EndsAt.Time.Equal(k.Boundary) {
					return "", errRenewalConflict
				}
				if old.Status != "ended" {
					_, err = q.EndCommercialContract(ctx, db.EndCommercialContractParams{TeamID: k.Team, ContractID: old.ID, ExpectedRevision: old.Revision})
				}
				return "free", err
			})
		})
	}
	if a.Finalize == nil {
		return errRenewalDisabled
	}
	verified := op.Proof.successor
	if verified == nil || verified.Binding.ContractID != renewalSuccessorID(k) || verified.Binding.Identity.TermsDigest != renewalTargetDigest(k, op) || validateRenewalTerms(op.Request.Choice, op.Terms) != nil {
		return errRenewalPending
	}
	for _, amount := range op.Terms.Allowances {
		if amount != op.Terms.Allowances[0] {
			return errRenewalConflict
		}
	}
	b := verified.Binding
	r, previous, err := a.Authority.accepted(ctx, a.Authority.Admission.Service.Pool, k, op.Actor)
	if err != nil || previous.ContractID != verified.Previous.ContractID || r.ID != op.Request.Acceptance || r.ApprovalRevision != op.Request.ApprovalRevision {
		if err != nil {
			return err
		}
		return errRenewalConflict
	}
	start, feeStart, err := renewalGrantFeeStart(b, time.Now().UTC())
	if err != nil {
		return err
	}
	inventory, err := a.Client.renewalFeeInvoices(ctx, b)
	if err != nil {
		return pending("review_required")
	}
	var invoice *proPaidInvoice
	for i := range inventory.Data {
		inv := &inventory.Data[i]
		for _, line := range inv.Lines.Data {
			if line.Period.Start == feeStart.Unix() {
				if invoice != nil {
					return pending("review_required")
				}
				invoice = inv
			}
		}
	}
	if invoice == nil || invoice.Status == "open" || invoice.Status == "uncollectible" {
		return pending("payment_pending")
	}
	cash, err := a.Client.verifyProviderPairPayment(ctx, b, invoice.ID)
	if err != nil {
		return pending("review_required")
	}
	debt, err := a.Client.entitlementDebt(ctx, b.CustomerID)
	if err != nil || debt != "" {
		return pending("review_required")
	}
	contract := db.BillingCommercialContract{ID: b.ContractID, TeamID: k.Team, CustomerID: b.CustomerID, SubscriptionID: b.UsageSubscriptionID, EntitlementAnchor: b.Anchor}
	if err = a.Handlers.entitlementClosingInvoice(ctx, contract, start, a.Client); err != nil {
		return pending("review_required")
	}
	observed := time.Now().UTC()
	return a.Finalize(ctx, r, "successor", b.ContractID, b.Identity.TermsDigest, k.Boundary, func(ctx context.Context, tx pgx.Tx, auth YCFinancialAuthorization) error {
		if auth.InvalidatedAt != nil || auth.Phase != "successor" || auth.OperationID != b.ContractID || auth.TeamID != k.Team || auth.AssignmentID != k.Assignment || auth.AcceptanceID != r.ID || auth.TermsDigest != r.TermsDigest || auth.TargetTermsDigest != b.Identity.TermsDigest || auth.ApprovalRevision != r.ApprovalRevision {
			return errRenewalConflict
		}
		return commit(ctx, tx, func() (string, error) {
			if time.Since(observed) > 30*time.Second || time.Since(verified.VerifiedAt) > time.Minute {
				return "", errRenewalPending
			}
			q := db.New(tx)
			old, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: k.Team, ContractID: previous.ContractID})
			if err != nil || !old.EndsAt.Valid || !old.EndsAt.Time.Equal(k.Boundary) {
				if err != nil {
					return "", err
				}
				return "", errRenewalConflict
			}
			if old.Status != "ended" {
				if _, err = q.EndCommercialContract(ctx, db.EndCommercialContractParams{TeamID: k.Team, ContractID: old.ID, ExpectedRevision: old.Revision}); err != nil {
					return "", err
				}
			}
			if _, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'metered_usage',$10,'monthly',$11)`, b.ContractID, k.Team, op.Terms.Offer, k.Boundary, b.CustomerID, b.UsageSubscriptionID, b.Terms.FeePriceID, b.Terms.FeeAmount, b.Terms.FeeMonths, op.Terms.Allowances[0], b.Anchor); err != nil {
				return "", err
			}
			if _, err = ConfirmSuccessorProviderPair(ctx, tx, *verified); err != nil {
				return "", err
			}
			payment, err := q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: k.Team, ContractID: b.ContractID, InvoiceID: cash.Invoice.ID, PaymentReference: cash.Reference, CustomerID: b.CustomerID, SubscriptionID: &b.FeeSubscriptionID, BasePriceID: b.Terms.FeePriceID, ServicePeriodStart: time.Unix(cash.Start, 0).UTC(), ServicePeriodEnd: time.Unix(cash.End, 0).UTC(), BaseAmountPaidCents: b.Terms.FeeAmount, InvoiceAmountPaidCents: cash.Invoice.AmountPaid, Currency: "usd", PaidAt: time.Unix(cash.Invoice.StatusTransitions.PaidAt, 0).UTC(), VerifiedAt: observed, Evidence: cash.Raw})
			if err != nil {
				return "", err
			}
			if err = observeProPaymentReviewTx(ctx, tx, k.Team, cash.Invoice.ID, cash, nil); err != nil {
				return "", err
			}
			if op.Request.Choice == "monthly" {
				if _, err = ConfirmProviderPairMonthlyPayment(ctx, tx, b.ContractID, b.Identity, payment.ID); err != nil {
					return "", err
				}
			}
			current, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: k.Team, ContractID: b.ContractID})
			if err != nil {
				return "", err
			}
			if _, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: k.Team, ContractID: b.ContractID, ExpectedRevision: current.Revision}); err != nil {
				return "", err
			}
			_, err = tx.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id,next_check_at) VALUES($1,clock_timestamp()) ON CONFLICT(contract_id) DO UPDATE SET next_check_at=excluded.next_check_at`, b.ContractID)
			return "active", err
		})
	})
}
