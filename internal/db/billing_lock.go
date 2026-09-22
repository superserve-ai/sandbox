package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These methods keep webhook and recovery callers on the same per-team row
// lock while returning the billing projection used by activation.
const lockTeamBillingAccountSQL = `
SELECT team_id, stripe_customer_id, stripe_subscription_id,
       stripe_subscription_status, stripe_invoice_status,
       stripe_subscription_event_at, current_period_start, current_period_end,
       commercial_billing_anchor, cancel_at_period_end, created_at, updated_at,
       trial_ended_at, stripe_activation_credit_granted_at,
       stripe_activation_credit_grant_id, checkout_initializing_at,
       checkout_session_id
FROM team_billing_account
WHERE team_id = $1
FOR UPDATE`

const lockTeamBillingAccountByCustomerSQL = `
SELECT team_id, stripe_customer_id, stripe_subscription_id,
       stripe_subscription_status, stripe_invoice_status,
       stripe_subscription_event_at, current_period_start, current_period_end,
       commercial_billing_anchor, cancel_at_period_end, created_at, updated_at,
       trial_ended_at, stripe_activation_credit_granted_at,
       stripe_activation_credit_grant_id, checkout_initializing_at,
       checkout_session_id
FROM team_billing_account
WHERE stripe_customer_id = $1
FOR UPDATE`

func (q *Queries) LockTeamBillingAccount(ctx context.Context, teamID uuid.UUID) (TeamBillingAccount, error) {
	return scanTeamBillingAccount(q.db.QueryRow(ctx, lockTeamBillingAccountSQL, teamID))
}

func (q *Queries) LockTeamBillingAccountByStripeCustomerID(ctx context.Context, customerID *string) (TeamBillingAccount, error) {
	return scanTeamBillingAccount(q.db.QueryRow(ctx, lockTeamBillingAccountByCustomerSQL, customerID))
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTeamBillingAccount(row rowScanner) (TeamBillingAccount, error) {
	var account TeamBillingAccount
	var stripeInvoiceStatus *string
	var stripeSubscriptionEventAt pgtype.Timestamptz
	if err := row.Scan(
		&account.TeamID,
		&account.StripeCustomerID,
		&account.StripeSubscriptionID,
		&account.StripeSubscriptionStatus,
		&stripeInvoiceStatus,
		&stripeSubscriptionEventAt,
		&account.CurrentPeriodStart,
		&account.CurrentPeriodEnd,
		&account.CommercialBillingAnchor,
		&account.CancelAtPeriodEnd,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.TrialEndedAt,
		&account.StripeActivationCreditGrantedAt,
		&account.StripeActivationCreditGrantID,
		&account.CheckoutInitializingAt,
		&account.CheckoutSessionID,
	); err != nil {
		return TeamBillingAccount{}, err
	}
	account.StripeInvoiceStatus = stripeInvoiceStatus
	account.StripeSubscriptionEventAt = stripeSubscriptionEventAt
	return account, nil
}

// LockPendingStripeSubscriptionEvents returns deliveries that were retained
// for reconciliation while a checkout reservation was still being associated.
// Checkout callers hold the billing-account lock before acquiring these
// webhook-row locks, matching the order used by normal webhook processing.
func (q *Queries) LockPendingStripeSubscriptionEvents(ctx context.Context, customerID, subscriptionID string) ([]StripeWebhookEvent, error) {
	rows, err := q.db.Query(ctx, listPendingStripeSubscriptionEventsSQL, customerID, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []StripeWebhookEvent
	for rows.Next() {
		var event StripeWebhookEvent
		if err := rows.Scan(
			&event.EventID,
			&event.EventType,
			&event.Payload,
			&event.ReceivedAt,
			&event.ProcessedAt,
			&event.LastError,
			&event.UpdatedAt,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

const listPendingStripeSubscriptionEventsSQL = `
SELECT event_id, event_type, payload, received_at, processed_at, last_error, updated_at
FROM stripe_webhook_event
WHERE processed_at IS NULL
  AND event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                     'customer.subscription.deleted', 'customer.subscription.paused', 'customer.subscription.resumed')
  AND payload->'data'->'object'->>'customer' = $1
  AND payload->'data'->'object'->>'id' = $2
ORDER BY received_at, event_id
FOR UPDATE
`
