package api

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

// finalizeInitialOffer runs inside the caller's account/fence/operation locks.
// The operation UUID is also its stable initial contract UUID. Grant issuance
// remains the responsibility of the existing entitlement worker after commit.
func finalizeInitialOffer(ctx context.Context, tx pgx.Tx, operation provisioning.Operation, evidence provisioning.Verification) error {
	verified, ok := evidence.Proof.(VerifiedProviderPair)
	if !ok || tx == nil {
		return provisioning.ErrConflict
	}
	if err := verified.validateFresh(); err != nil {
		return err
	}
	expected, err := offerPairInput(operation)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, verified.Input) {
		return provisioning.ErrConflict
	}
	p := verified.Input
	// Do not overwrite a concurrent or previously associated billing identity.
	tag, err := tx.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2,
 stripe_subscription_id=$3,stripe_subscription_status='active',commercial_billing_anchor=$4,
 current_period_start=$4,current_period_end=$5,cancel_at_period_end=false
 WHERE team_id=$1 AND (stripe_customer_id IS NULL OR stripe_customer_id=$2)
 AND (stripe_subscription_id IS NULL OR stripe_subscription_id=$3)
 AND (commercial_billing_anchor IS NULL OR commercial_billing_anchor=$4)`,
		operation.TeamID, p.CustomerID, p.UsageSubscriptionID, p.Anchor, annualBoundary(p.Anchor, 1))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return provisioning.ErrConflict
	}
	if _, err = ActivateInitialProviderPair(ctx, tx, operation.ID, verified); err != nil {
		return err
	}
	if err = enrollInitialProviderPair(ctx, tx, operation.ID, verified); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id) VALUES($1)
 ON CONFLICT(contract_id) DO UPDATE SET next_check_at=least(billing_entitlement_work.next_check_at,clock_timestamp())`, operation.ID)
	return err
}
