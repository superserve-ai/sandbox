package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

// The original activation is the boundary authority even after a successor has
// become current. An acceptance timestamp never supplies a billing anniversary.
func loadRenewalChoicePair(ctx context.Context, reader db.DBTX, team, assignment uuid.UUID) (renewalChoiceKey, ContractProviderBinding, error) {
	var key renewalChoiceKey
	var contract uuid.UUID
	var anchor, boundary time.Time
	var merchant string
	var live bool
	if team == uuid.Nil || assignment == uuid.Nil {
		return key, ContractProviderBinding{}, errRenewalConflict
	}
	err := reader.QueryRow(ctx, `SELECT contract_id,anchor,ends_at,merchant_account,live_mode FROM billing_commercial_offer_activation WHERE team_id=$1 AND assignment_id=$2`, team, assignment).Scan(&contract, &anchor, &boundary, &merchant, &live)
	if err != nil {
		return key, ContractProviderBinding{}, err
	}
	b, err := loadContractProviderBinding(ctx, reader, contract)
	if err != nil {
		return key, b, err
	}
	key = renewalChoiceKey{Team: team, Assignment: assignment, Boundary: boundary.UTC()}
	digest, err := b.Terms.Digest()
	if err != nil || b.ContractID != contract || b.Identity.TeamID != team || b.Identity.AssignmentID != assignment || b.Identity.AcceptanceID == uuid.Nil || b.Identity.ApprovalSemanticRevision < 0 || b.Identity.APIVersion != renewalStripeVersion || digest != b.Identity.ProviderTermsDigest || b.Identity.Merchant != merchant || b.Identity.Live != live || !b.Anchor.Equal(anchor) || !b.StartsAt.Equal(anchor) || b.EndsAt == nil || !b.EndsAt.Equal(boundary) || !annualBoundary(anchor, 12).Equal(boundary) || b.Terms.FeeAmount != 1200000 || b.Terms.FeeMonths != 12 || b.FeeItemID == "" || !validRenewalBinding(renewalChoiceBindingFromPair(b), key) {
		return renewalChoiceKey{}, ContractProviderBinding{}, errRenewalConflict
	}
	var accountMatches bool
	if err = reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND stripe_customer_id=$2 AND stripe_subscription_id=$3 AND commercial_billing_anchor=$4)`, team, b.CustomerID, b.UsageSubscriptionID, b.Anchor).Scan(&accountMatches); err != nil {
		return renewalChoiceKey{}, ContractProviderBinding{}, err
	}
	if !accountMatches {
		return renewalChoiceKey{}, ContractProviderBinding{}, errRenewalConflict
	}
	return key, b, nil
}

func renewalChoiceBindingFromPair(b ContractProviderBinding) renewalChoiceBinding {
	// The provider binding is immutable and keyed by contract, not a separate UUID.
	return renewalChoiceBinding{Contract: b.ContractID, ProviderBinding: b.ContractID, Merchant: b.Identity.Merchant, Live: b.Identity.Live, Customer: b.CustomerID, Fee: b.FeeSubscriptionID, Usage: b.UsageSubscriptionID, Anchor: b.Anchor.UTC()}
}

// Provider terms must already have passed the paired-price verifier. This lookup
// matches that frozen mapping to an exact published catalog version; it performs
// no provider I/O and never chooses a newer catalog version on retry.
func loadRenewalChoiceTerms(ctx context.Context, reader db.DBTX, choice string, version int, mapping ProviderPairTerms) (*renewalChoiceTerms, error) {
	if choice == "free" {
		return nil, nil
	}
	if choice != "annual" && choice != "monthly" || version < 1 || mapping.validate() != nil {
		return nil, errRenewalConflict
	}
	var terms renewalChoiceTerms
	var termMonths int
	var waived, rollover, proration bool
	var payment, family, source string
	err := reader.QueryRow(ctx, `SELECT offer_key,version,rate_card_key,currency,charge_amount_cents,charge_interval_months,monthly_allowance_cents,term_months,initial_fee_waived,payment_requirement,default_successor_family,allowance_source,rollover,proration FROM billing_commercial_offer_version WHERE offer_key=$1 AND version=$2`, "pro_"+choice, version).Scan(&terms.Offer, &terms.Version, &terms.RateCard, &terms.Currency, &terms.Amount, &terms.Months, &terms.Allowances, &termMonths, &waived, &payment, &family, &source, &rollover, &proration)
	if err != nil {
		return nil, err
	}
	terms.Price, terms.Product = mapping.FeePriceID, mapping.FeeProductID
	if terms.Amount != mapping.FeeAmount || terms.Months != int(mapping.FeeMonths) || terms.Currency != mapping.Currency || termMonths != terms.Months || waived || rollover || proration || payment != "verified_payment" || family != terms.Offer || source != "usage_allowance" || validateRenewalTerms(choice, &terms) != nil {
		return nil, errRenewalConflict
	}
	return &terms, nil
}
