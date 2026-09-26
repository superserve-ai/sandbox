package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const StripeCheckoutAssociationPendingError = "Stripe checkout association is still being established"

type StripeCheckoutAssociationCandidate struct {
	EventID    string
	EventType  string
	Payload    []byte
	ReceivedAt time.Time
	ScanAt     time.Time
	Lane       int
	Eligible   bool
}

type StripeCheckoutAssociationCursor struct {
	ReadyAt time.Time
	EventID string
}

// Each lane pages its indexed source before joining the other table. The
// webhook cursor covers fresh due rows even when the trigger queued them;
// transactionally queued due rows start at the oldest due entry every tick.
func ListStripeCheckoutAssociationCandidates(ctx context.Context, pool *pgxpool.Pool, now time.Time, grace time.Duration, cursor StripeCheckoutAssociationCursor, limit int) ([]StripeCheckoutAssociationCandidate, error) {
	rows, err := pool.Query(ctx, `
WITH new_page AS MATERIALIZED (
    SELECT event_id, GREATEST((received_at AT TIME ZONE 'UTC') + interval '5 minutes', updated_at AT TIME ZONE 'UTC') AS scan_at
    FROM stripe_webhook_event
    WHERE processed_at IS NULL
      AND last_error = 'Stripe checkout association is still being established'
      AND event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                         'customer.subscription.deleted', 'customer.subscription.paused',
                         'customer.subscription.resumed')
      AND GREATEST((received_at AT TIME ZONE 'UTC') + interval '5 minutes', updated_at AT TIME ZONE 'UTC') <= ($1::timestamptz AT TIME ZONE 'UTC')
      AND (GREATEST((received_at AT TIME ZONE 'UTC') + interval '5 minutes', updated_at AT TIME ZONE 'UTC'), event_id) > ($2::timestamp, $3)
    ORDER BY GREATEST((received_at AT TIME ZONE 'UTC') + interval '5 minutes', updated_at AT TIME ZONE 'UTC'), event_id
    LIMIT $4
), due_page AS MATERIALIZED (
    SELECT event_id, next_check_at AT TIME ZONE 'UTC' AS scan_at
    FROM stripe_checkout_association_alert
    WHERE next_check_at <= $1
      AND NOT EXISTS (SELECT 1 FROM new_page n WHERE n.event_id = stripe_checkout_association_alert.event_id)
    ORDER BY next_check_at, event_id
    LIMIT $6
)
SELECT p.event_id, e.event_type, e.payload, e.received_at, p.scan_at, 0 AS lane,
       (a.event_id IS NULL OR a.next_check_at <= $1) AS eligible
FROM new_page p
JOIN stripe_webhook_event e USING (event_id)
LEFT JOIN stripe_checkout_association_alert a USING (event_id)
UNION ALL
SELECT p.event_id, e.event_type, e.payload, e.received_at, p.scan_at, 1 AS lane,
       COALESCE(e.processed_at IS NULL AND e.last_error = 'Stripe checkout association is still being established'
       AND e.event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                            'customer.subscription.deleted', 'customer.subscription.paused',
                            'customer.subscription.resumed') AND e.received_at <= $5, false) AS eligible
FROM due_page p
JOIN stripe_webhook_event e USING (event_id)
ORDER BY lane, scan_at, event_id`, now, stripeAssociationCursorTime(cursor.ReadyAt), cursor.EventID,
		(limit+1)/2, now.Add(-grace), limit/2)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []StripeCheckoutAssociationCandidate
	for rows.Next() {
		var c StripeCheckoutAssociationCandidate
		if err := rows.Scan(&c.EventID, &c.EventType, &c.Payload, &c.ReceivedAt, &c.ScanAt, &c.Lane, &c.Eligible); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

func stripeAssociationCursorTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return at
}

// Lock the webhook before moving stale bookkeeping. A concurrent retry's
// trigger inserts eligibility while holding this same webhook row lock.
func PostponeStripeCheckoutAssociationIneligible(ctx context.Context, pool *pgxpool.Pool, eventID string, now time.Time, grace, recheck time.Duration) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var unprocessed bool
	var lastError *string
	var eventType string
	var receivedAt time.Time
	err = tx.QueryRow(ctx, `SELECT processed_at IS NULL, last_error, event_type, received_at
FROM stripe_webhook_event WHERE event_id = $1 FOR UPDATE`, eventID).Scan(&unprocessed, &lastError, &eventType, &receivedAt)
	if err == pgx.ErrNoRows {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if unprocessed && lastError != nil && *lastError == StripeCheckoutAssociationPendingError &&
		stripeCheckoutAssociationEventType(eventType) && !receivedAt.Add(grace).After(now) {
		return tx.Commit(ctx)
	}
	next := now.Add(recheck)
	if unprocessed && lastError != nil && *lastError == StripeCheckoutAssociationPendingError &&
		stripeCheckoutAssociationEventType(eventType) && receivedAt.Add(grace).After(now) {
		next = receivedAt.Add(grace)
	}
	_, err = tx.Exec(ctx, `
UPDATE stripe_checkout_association_alert
SET next_check_at = $3
WHERE event_id = $1 AND next_check_at <= $2`, eventID, now, next)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func stripeCheckoutAssociationEventType(eventType string) bool {
	switch eventType {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted",
		"customer.subscription.paused", "customer.subscription.resumed":
		return true
	default:
		return false
	}
}

// ClaimStripeCheckoutAssociationAlert reserves a single event across replicas.
// Callers first lock its billing account and webhook row in the same transaction.
func ClaimStripeCheckoutAssociationAlert(ctx context.Context, tx pgx.Tx, eventID string, now, next time.Time) (bool, error) {
	var claimed string
	err := tx.QueryRow(ctx, `
INSERT INTO stripe_checkout_association_alert(event_id, lease_until, next_check_at)
VALUES ($1, $3, $3)
ON CONFLICT (event_id) DO UPDATE
SET lease_until = $3, next_check_at = $3
WHERE stripe_checkout_association_alert.next_check_at <= $2
RETURNING event_id`, eventID, now, next).Scan(&claimed)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// DeferStripeCheckoutAssociationInspectionFailure coalesces failures across
// replicas and restarts while keeping the retained webhook eligible for retry.
func DeferStripeCheckoutAssociationInspectionFailure(ctx context.Context, pool *pgxpool.Pool, eventID string, now, next time.Time) (bool, error) {
	var claimed string
	err := pool.QueryRow(ctx, `
INSERT INTO stripe_checkout_association_alert(event_id, next_check_at)
SELECT event_id, $3 FROM stripe_webhook_event
WHERE event_id = $1 AND processed_at IS NULL
  AND last_error = 'Stripe checkout association is still being established'
ON CONFLICT (event_id) DO UPDATE
SET lease_until = NULL, next_check_at = $3
WHERE stripe_checkout_association_alert.next_check_at <= $2
RETURNING event_id`, eventID, now, next).Scan(&claimed)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func FinishStripeCheckoutAssociationAlert(ctx context.Context, pool *pgxpool.Pool, eventID string, lease, next time.Time, alerted bool, now time.Time) error {
	_, err := pool.Exec(ctx, `
UPDATE stripe_checkout_association_alert
SET lease_until = NULL, next_check_at = $3,
    last_alert_at = CASE WHEN $4 THEN $5 ELSE last_alert_at END
WHERE event_id = $1 AND lease_until = $2`, eventID, lease, next, alerted, now)
	return err
}
