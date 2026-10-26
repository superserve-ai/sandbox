package api

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

func (a *offerProvisioningAuthority) Readiness(ctx context.Context, operation provisioning.Operation) (provisioning.Readiness, error) {
	var ready provisioning.Readiness
	binding, err := loadContractProviderBinding(ctx, a.h.Pool, operation.ID)
	if err != nil {
		return ready, err
	}
	input, err := offerPairInput(operation)
	if err != nil || binding.Identity != input.Identity || binding.CustomerID != input.CustomerID || binding.UsageSubscriptionID != input.UsageSubscriptionID {
		return ready, provisioning.ErrConflict
	}
	var validUntil pgtype.Timestamptz
	err = a.h.Pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM billing_commercial_offer_activation x WHERE x.assignment_id=$2 AND x.team_id=c.team_id AND x.contract_id=c.id),
 EXISTS(SELECT 1 FROM billing_invoice_account x JOIN billing_invoice_enrollment n USING(team_id)
 WHERE x.team_id=c.team_id AND x.customer_id=c.customer_id AND x.subscription_id=c.subscription_id AND n.completed_at IS NOT NULL AND x.enrolled_at=n.started_at),
 COALESCE(f.observed_generation=f.generation AND f.customer_id=c.customer_id AND f.subscription_id=c.subscription_id
 AND f.credit_checked_at IS NOT NULL AND f.credit_valid_until>clock_timestamp()
 AND f.provider_checked_at IS NOT NULL AND f.provider_valid_until>clock_timestamp(),false),
 COALESCE(c.collection_has_overdue_balance IS FALSE AND c.collection_valid_until>clock_timestamp(),false),
 EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=c.id AND e.team_id=c.team_id
 AND e.state='issued' AND e.stripe_credit_grant_id IS NOT NULL AND e.period_start<=clock_timestamp() AND e.period_end>clock_timestamp()
 AND billing_contract_eligible(c,e.period_start,e.period_end)),
 COALESCE(f.observe AND f.enforce AND f.observed_generation=f.generation AND f.customer_id=c.customer_id AND f.subscription_id=c.subscription_id
 AND f.credit_valid_until>clock_timestamp() AND f.provider_valid_until>clock_timestamp(),false),
 COALESCE(f.credit_usd>0,false),team_sandbox_billing_eligible(c.team_id),
 least(f.credit_valid_until,f.provider_valid_until,c.collection_valid_until,w.authority_valid_until,c.ends_at),
 COALESCE(w.revoked_at IS NULL AND w.authority_valid_until>clock_timestamp(),false)
 FROM billing_commercial_contract c
 LEFT JOIN billing_funding_account f ON f.team_id=c.team_id
 LEFT JOIN billing_provider_pair_waiver w ON w.contract_id=c.id
 WHERE c.id=$1 AND c.team_id=$3 AND c.customer_id=$4 AND c.subscription_id=$5 AND c.status='active'
 AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=c.id)`,
		operation.ID, operation.AssignmentID, operation.TeamID, input.CustomerID, input.UsageSubscriptionID).Scan(
		&ready.AssignmentMaterialized, &ready.InvoiceEnrolled, &ready.InventoryKnown, &ready.DebtClear,
		&ready.CurrentGrantEligible, &ready.FundingFresh, &ready.PositiveFunds, &ready.BillingEligible, &validUntil, &ready.PairVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return ready, nil
	}
	if err != nil {
		return ready, err
	}
	// Shared invalidity is read after regional observations; a valid historical
	// receipt alone must not turn pending revocation into readiness.
	if _, err = a.h.ReadProviderPairFinancialAuthority(ctx, binding); err != nil {
		return provisioning.Readiness{}, err
	}
	ready.AuthorityValid = true
	ready.Exhausted = ready.CurrentGrantEligible && ready.FundingFresh && !ready.PositiveFunds
	if validUntil.Valid {
		ready.ValidUntil = validUntil.Time
		if bound := time.Now().Add(time.Second); ready.ValidUntil.After(bound) {
			ready.ValidUntil = bound
		}
	}
	return ready, nil
}
