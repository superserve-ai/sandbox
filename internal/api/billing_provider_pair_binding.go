package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// ContractProviderBinding keeps the usage-ledger identity separate from the
// licensed fee identity. Every successor contract must bind its actual item.
type ContractProviderBinding struct {
	ContractID          uuid.UUID            `json:"contract_id"`
	Identity            ProviderPairIdentity `json:"identity"`
	Terms               ProviderPairTerms    `json:"terms"`
	CustomerID          string               `json:"customer_id"`
	UsageSubscriptionID string               `json:"usage_subscription_id"`
	FeeSubscriptionID   string               `json:"fee_subscription_id"`
	FeeItemID           string               `json:"fee_item_id"`
	FeeAnchor           time.Time            `json:"fee_anchor"`
	Anchor              time.Time            `json:"anchor"`
	StartsAt            time.Time            `json:"starts_at"`
	EndsAt              *time.Time           `json:"ends_at,omitempty"`
}

// ConfirmContractProviderBinding must run in the caller's admission transaction,
// while its current acceptance/approval guard is held. It creates no entitlement
// authority and performs no provider I/O.
func ConfirmContractProviderBinding(ctx context.Context, tx pgx.Tx, contract uuid.UUID, verified VerifiedProviderPair) (ContractProviderBinding, error) {
	var b ContractProviderBinding
	if tx == nil || contract == uuid.Nil {
		return b, errors.New("fresh verified provider pair is required")
	}
	if err := verified.validateFresh(); err != nil {
		return b, err
	}
	p := verified.Input
	end := annualBoundary(p.Anchor, 12)
	b = ContractProviderBinding{ContractID: contract, Identity: p.Identity, Terms: p.Terms, CustomerID: p.CustomerID, UsageSubscriptionID: p.UsageSubscriptionID, FeeSubscriptionID: p.FeeSubscriptionID, FeeItemID: p.FeeItemID, Anchor: p.Anchor, FeeAnchor: p.Anchor, StartsAt: p.Anchor, EndsAt: &end}
	return confirmProviderBinding(ctx, tx, b, verified.Evidence, verified.VerifiedAt)
}

func confirmProviderBinding(ctx context.Context, tx pgx.Tx, b ContractProviderBinding, evidence json.RawMessage, verifiedAt time.Time) (ContractProviderBinding, error) {
	payload, err := json.Marshal(b)
	if err != nil {
		return ContractProviderBinding{}, err
	}
	var saved []byte
	if _, err = tx.Exec(ctx, `SELECT 1 FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, b.Identity.TeamID); err != nil {
		return ContractProviderBinding{}, err
	}
	var revoked bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_provider_pair_revocation WHERE contract_id=$1)`, b.ContractID).Scan(&revoked); err != nil {
		return ContractProviderBinding{}, err
	}
	if revoked {
		return ContractProviderBinding{}, errors.New("paired authority is revoked")
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT binding=$2::jsonb FROM billing_contract_provider_binding WHERE contract_id=$1`, b.ContractID, payload).Scan(&same)
	if err == nil {
		if !same {
			return ContractProviderBinding{}, errors.New("provider binding replay changed immutable terms")
		}
		return b, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ContractProviderBinding{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO billing_contract_provider_binding(contract_id,team_id,assignment_id,acceptance_id,approval_semantic_revision,merchant,live_mode,api_version,terms_digest,provider_terms_digest,customer_id,usage_subscription_id,fee_subscription_id,fee_item_id,anchor,fee_anchor,starts_at,ends_at,binding,evidence,verified_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT(contract_id) DO NOTHING RETURNING binding`, b.ContractID, b.Identity.TeamID, b.Identity.AssignmentID, b.Identity.AcceptanceID, b.Identity.ApprovalSemanticRevision, b.Identity.Merchant, b.Identity.Live, b.Identity.APIVersion, b.Identity.TermsDigest, b.Identity.ProviderTermsDigest, b.CustomerID, b.UsageSubscriptionID, b.FeeSubscriptionID, b.FeeItemID, b.Anchor, b.FeeAnchor, b.StartsAt, b.EndsAt, payload, evidence, verifiedAt).Scan(&saved)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT binding FROM billing_contract_provider_binding WHERE contract_id=$1 AND binding=$2::jsonb`, b.ContractID, payload).Scan(&saved)
	}
	if err != nil {
		return ContractProviderBinding{}, err
	}
	return b, nil
}

func loadContractProviderBinding(ctx context.Context, reader db.DBTX, contract uuid.UUID) (ContractProviderBinding, error) {
	var b ContractProviderBinding
	var payload []byte
	err := reader.QueryRow(ctx, `SELECT binding FROM billing_contract_provider_binding WHERE contract_id=$1`, contract).Scan(&payload)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(payload, &b)
	return b, err
}

// PaidProviderPairEvidence is cash evidence for the fee sibling. A waived
// zero-dollar invoice can never become one of these receipts.
type PaidProviderPairEvidence struct {
	InvoiceID string          `json:"invoice_id"`
	Reference string          `json:"reference"`
	StartsAt  time.Time       `json:"starts_at"`
	EndsAt    time.Time       `json:"ends_at"`
	Evidence  json.RawMessage `json:"evidence"`
}

func (h *Handlers) VerifyProviderPairPayment(ctx context.Context, binding ContractProviderBinding, invoice string) (PaidProviderPairEvidence, error) {
	c, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return PaidProviderPairEvidence{}, errors.New("paired payment verifier unavailable")
	}
	ev, err := c.verifyProviderPairPayment(ctx, binding, invoice)
	if err != nil {
		return PaidProviderPairEvidence{}, err
	}
	return PaidProviderPairEvidence{InvoiceID: ev.Invoice.ID, Reference: ev.Reference, StartsAt: time.Unix(ev.Start, 0).UTC(), EndsAt: time.Unix(ev.End, 0).UTC(), Evidence: ev.Raw}, nil
}

func (c *stripeHTTPClient) verifyProviderPairPayment(ctx context.Context, b ContractProviderBinding, id string) (proPaymentEvidence, error) {
	var empty proPaymentEvidence
	if err := b.Terms.validate(); err != nil {
		return empty, err
	}
	digest, err := b.Terms.Digest()
	if err != nil || digest != b.Identity.ProviderTermsDigest || b.FeeSubscriptionID == "" || b.FeeSubscriptionID == b.UsageSubscriptionID || b.FeeItemID == "" || b.CustomerID == "" || b.Anchor.IsZero() || b.FeeAnchor.IsZero() || b.FeeAnchor.Nanosecond() != 0 || b.FeeAnchor.Before(b.Anchor) || b.FeeAnchor.After(b.StartsAt) || b.StartsAt.Before(b.Anchor) || c.apiVersion != b.Identity.APIVersion {
		return empty, errors.New("paired payment binding is incomplete")
	}
	var account struct{ ID string }
	if err = c.doForm(ctx, "GET", "/v1/account", nil, &account, ""); err != nil {
		return empty, err
	}
	if account.ID != b.Identity.Merchant {
		return empty, errors.New("paired payment merchant differs")
	}
	ev, found, err := c.verifyProInvoice(ctx, id, proOffer{Price: b.Terms.FeePriceID, Amount: b.Terms.FeeAmount, Months: b.Terms.FeeMonths}, b.CustomerID, b.FeeSubscriptionID)
	if err != nil {
		return empty, err
	}
	if !found || len(ev.Invoice.Lines.Data) != 1 || ev.Invoice.LiveMode != b.Identity.Live || len(ev.Invoice.Discounts) != 0 || len(ev.Invoice.DiscountAmounts) != 0 || len(ev.Invoice.PretaxCredits) != 0 || ev.Invoice.AmountPaid != b.Terms.FeeAmount || ev.Start < b.StartsAt.Unix() || b.EndsAt != nil && ev.End > b.EndsAt.Unix() {
		return empty, errors.New("paired payment does not cover the exact licensed fee")
	}
	l := ev.Invoice.Lines.Data[0]
	start := time.Unix(ev.Start, 0).UTC()
	months := (start.Year()-b.FeeAnchor.UTC().Year())*12 + int(start.Month()-b.FeeAnchor.UTC().Month())
	first := (b.StartsAt.UTC().Year()-b.FeeAnchor.UTC().Year())*12 + int(b.StartsAt.UTC().Month()-b.FeeAnchor.UTC().Month())
	if l.Parent.SubscriptionItemDetails == nil || l.Parent.SubscriptionItemDetails.SubscriptionItem != b.FeeItemID || l.Pricing.PriceDetails == nil || l.Pricing.PriceDetails.Product != b.Terms.FeeProductID || months < first || (months-first)%int(b.Terms.FeeMonths) != 0 || ev.Start != annualBoundary(b.FeeAnchor, months).Unix() || ev.End != annualBoundary(b.FeeAnchor, months+int(b.Terms.FeeMonths)).Unix() {
		return empty, errors.New("paired payment item or verified fee cadence differs")
	}
	return ev, nil
}
