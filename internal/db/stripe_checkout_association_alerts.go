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
}

type StripeCheckoutAssociationCursor struct {
	ReceivedAt time.Time
	EventID    string
}

// ListStripeCheckoutAssociationCandidates bounds each poll. The due-time
// bookkeeping keeps repeatedly classified rows from hiding later receipts.
func ListStripeCheckoutAssociationCandidates(ctx context.Context, pool *pgxpool.Pool, now time.Time, grace time.Duration, cursor StripeCheckoutAssociationCursor, limit int) ([]StripeCheckoutAssociationCandidate, error) {
	rows, err := pool.Query(ctx, `
SELECT e.event_id, e.event_type, e.payload, e.received_at
FROM stripe_webhook_event e
LEFT JOIN stripe_checkout_association_alert a ON a.event_id = e.event_id
WHERE e.processed_at IS NULL
  AND e.last_error = 'Stripe checkout association is still being established'
  AND e.event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                       'customer.subscription.deleted', 'customer.subscription.paused',
                       'customer.subscription.resumed')
  AND e.received_at <= $1
  AND (a.next_check_at IS NULL OR a.next_check_at <= $2)
  AND ($3::timestamptz IS NULL OR (e.received_at, e.event_id) > ($3, $4))
ORDER BY e.received_at, e.event_id
LIMIT $5`, now.Add(-grace), now, nullableStripeAssociationCursorTime(cursor), cursor.EventID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []StripeCheckoutAssociationCandidate
	for rows.Next() {
		var c StripeCheckoutAssociationCandidate
		if err := rows.Scan(&c.EventID, &c.EventType, &c.Payload, &c.ReceivedAt); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

func nullableStripeAssociationCursorTime(cursor StripeCheckoutAssociationCursor) any {
	if cursor.ReceivedAt.IsZero() {
		return nil
	}
	return cursor.ReceivedAt
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

func FinishStripeCheckoutAssociationAlert(ctx context.Context, pool *pgxpool.Pool, eventID string, lease, next time.Time, alerted bool, now time.Time) error {
	_, err := pool.Exec(ctx, `
UPDATE stripe_checkout_association_alert
SET lease_until = NULL, next_check_at = $3,
    last_alert_at = CASE WHEN $4 THEN $5 ELSE last_alert_at END
WHERE event_id = $1 AND lease_until = $2`, eventID, lease, next, alerted, now)
	return err
}
