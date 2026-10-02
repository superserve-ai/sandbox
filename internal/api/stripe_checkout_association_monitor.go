package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

const (
	stripeAssociationGrace       = 5 * time.Minute
	stripeAssociationPoll        = time.Minute
	stripeAssociationLease       = 2 * time.Minute
	stripeAssociationCooldown    = 30 * time.Minute
	stripeAssociationRecheck     = 24 * time.Hour
	stripeAssociationBatchSize   = 100
	stripeAssociationTickTimeout = 20 * time.Second
)

type StripeAssociationAlert struct {
	EventID, EventType, CustomerID, SubscriptionID, CheckoutSessionID, TeamID string
	ReceivedAt                                                                time.Time
	Age                                                                       time.Duration
}

func stripeAssociationStillPending(account *db.TeamBillingAccount, subscriptionID string, expired bool) bool {
	if account == nil {
		return true // Missing authority does not prove the event obsolete.
	}
	if stripeSubscriptionMatchesCurrentAssociation(*account, subscriptionID) {
		return false
	}
	if expired {
		return false
	}
	checkoutSubscriptionID := strings.TrimSpace(derefString(account.CheckoutSubscriptionID))
	if checkoutSubscriptionID == "" || checkoutSubscriptionID == subscriptionID {
		return true
	}
	// Finalization clears the completion timestamp but preserves the accepted
	// checkout association. Beginning another checkout clears that association.
	finalized := !account.CheckoutInitializingAt.Valid && account.StripeSubscriptionEventAt.Valid &&
		stripeSubscriptionMatchesCurrentAssociation(*account, checkoutSubscriptionID)
	return !account.CheckoutCompletedAt.Valid && !finalized
}

func stripeAssociationExpired(ctx context.Context, tx pgx.Tx, account *db.TeamBillingAccount, customerID string, obj stripeSubscriptionObject) (bool, error) {
	// The signed subscription's generation must match a verified expiration;
	// a later reservation for the same customer does not identify this event.
	if account == nil || obj.Metadata["checkout_generation"] == "" {
		return false, nil
	}
	generation, err := time.Parse(time.RFC3339Nano, obj.Metadata["checkout_generation"])
	if err != nil {
		return false, nil
	}
	var expired bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM stripe_checkout_expiration_evidence
		WHERE team_id = $1 AND stripe_customer_id = $2 AND checkout_generation = $3
	)`, account.TeamID, customerID, generation).Scan(&expired)
	if err != nil || expired || (account.CheckoutInitializingAt.Valid && account.CheckoutInitializingAt.Time.Equal(generation)) {
		return expired, err
	}
	// Older webhook writers cleared the checkout without recording the new
	// evidence row. A processed, retained expiration for this generation
	// preserves that signed evidence across the rollout.
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM stripe_webhook_event
		WHERE event_type = 'checkout.session.expired' AND processed_at IS NOT NULL
		  AND payload #>> '{data,object,client_reference_id}' = $1::uuid::text
		  AND payload #>> '{data,object,customer}' = $2
		  AND payload #>> '{data,object,metadata,checkout_generation}' = $3
		  AND payload #>> '{data,object,id}' <> ''
		  AND payload ->> 'id' = event_id
		LIMIT 1
	)`, account.TeamID, customerID, generation.UTC().Format(time.RFC3339Nano)).Scan(&expired)
	return expired, err
}

func stripeAssociationPending(ctx context.Context, tx pgx.Tx, q *db.Queries, eventID string, account *db.TeamBillingAccount, obj stripeSubscriptionObject) (bool, error) {
	retired, err := q.IsStripeCheckoutAssociationRetired(ctx, eventID)
	if err != nil || retired {
		return false, err
	}
	expired, err := stripeAssociationExpired(ctx, tx, account, obj.Customer, obj)
	if err != nil {
		return false, err
	}
	pending := stripeAssociationStillPending(account, obj.ID, expired)
	if !pending && account != nil && (expired || !stripeSubscriptionMatchesCurrentAssociation(*account, obj.ID)) {
		// Later checkouts or migration can clear the account's obsolescence
		// evidence. Recovery alone remains recheckable.
		if err := q.RetireStripeCheckoutAssociation(ctx, eventID); err != nil {
			return false, err
		}
	}
	return pending, nil
}

func reportStripeAssociationOverdue(a StripeAssociationAlert) error {
	log.Error().Str("event_id", a.EventID).Str("event_type", a.EventType).
		Str("team_id", a.TeamID).Str("stripe_customer_id", a.CustomerID).
		Str("stripe_subscription_id", a.SubscriptionID).
		Str("checkout_session_id", a.CheckoutSessionID).
		Time("received_at", a.ReceivedAt).Dur("pending_age", a.Age).
		Msg("Stripe checkout association overdue")
	return nil
}

// StartStripeCheckoutAssociationMonitor runs independently of webhook traffic
// and incremental billing export. The first poll starts at the next minute.
func (h *Handlers) StartStripeCheckoutAssociationMonitor(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	startStripeCheckoutAssociationMonitor(ctx, func(interval time.Duration) (<-chan time.Time, func()) {
		ticker := time.NewTicker(interval)
		return ticker.C, ticker.Stop
	}, func(tickCtx context.Context, now time.Time, cursor db.StripeCheckoutAssociationCursor) (db.StripeCheckoutAssociationCursor, error) {
		return h.StripeCheckoutAssociationTick(tickCtx, now, cursor, reportStripeAssociationOverdue)
	})
}

func startStripeCheckoutAssociationMonitor(
	ctx context.Context,
	newTicker func(time.Duration) (<-chan time.Time, func()),
	tick func(context.Context, time.Time, db.StripeCheckoutAssociationCursor) (db.StripeCheckoutAssociationCursor, error),
) <-chan struct{} {
	ticks, stop := newTicker(stripeAssociationPoll)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stop()
		var cursor db.StripeCheckoutAssociationCursor
		var nextFailureReport time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticks:
				if ctx.Err() != nil {
					return
				}
				tickCtx, cancel := context.WithTimeout(ctx, stripeAssociationTickTimeout)
				sentrylog.RunSafe("stripe-checkout-association-monitor", func() {
					var err error
					cursor, err = tick(tickCtx, now, cursor)
					if err == nil {
						nextFailureReport = time.Time{}
					} else if ctx.Err() == nil && !now.Before(nextFailureReport) {
						log.Error().Err(err).Msg("Stripe checkout association monitor failed")
						nextFailureReport = now.Add(stripeAssociationCooldown)
					}
				})
				cancel()
			}
		}
	}()
	return done
}

func (h *Handlers) StripeCheckoutAssociationTick(ctx context.Context, now time.Time, cursor db.StripeCheckoutAssociationCursor, report func(StripeAssociationAlert) error) (db.StripeCheckoutAssociationCursor, error) {
	candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, h.Pool, now, stripeAssociationGrace, cursor, stripeAssociationBatchSize)
	if err != nil {
		return cursor, fmt.Errorf("discover pending Stripe checkout associations: %w", err)
	}
	for _, candidate := range candidates {
		if candidate.Eligible {
			if err := h.InspectStripeCheckoutAssociation(ctx, now, candidate, report); err != nil {
				claimed, claimErr := db.DeferStripeCheckoutAssociationInspectionFailure(ctx, h.Pool, candidate.EventID, now, now.Add(stripeAssociationCooldown))
				if claimErr != nil {
					return cursor, fmt.Errorf("defer failed Stripe checkout association inspection for %s: %w", candidate.EventID, claimErr)
				}
				if claimed {
					log.Error().Err(err).Str("event_id", candidate.EventID).Str("event_type", candidate.EventType).
						Msg("inspect Stripe checkout association failed")
				}
			}
		} else if candidate.Lane == 1 {
			if err := db.PostponeStripeCheckoutAssociationIneligible(ctx, h.Pool, candidate.EventID, now, stripeAssociationGrace, stripeAssociationRecheck); err != nil {
				return cursor, fmt.Errorf("postpone ineligible Stripe checkout association %s: %w", candidate.EventID, err)
			}
		}
		if candidate.Lane == 0 {
			cursor.ReadyAt, cursor.EventID = candidate.ScanAt, candidate.EventID
		}
	}
	return cursor, nil
}

func (h *Handlers) InspectStripeCheckoutAssociation(ctx context.Context, now time.Time, candidate db.StripeCheckoutAssociationCandidate, report func(StripeAssociationAlert) error) error {
	var event stripeEventEnvelope
	if err := json.Unmarshal(candidate.Payload, &event); err != nil {
		return fmt.Errorf("decode retained event: %w", err)
	}
	var obj stripeSubscriptionObject
	if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
		return fmt.Errorf("decode retained subscription: %w", err)
	}
	if obj.Customer == "" || obj.ID == "" {
		return errors.New("retained subscription lacks customer or subscription ID")
	}
	// Match checkout reconciliation's account-before-event lock order.
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := h.DB.WithTx(tx)
	var account *db.TeamBillingAccount
	locked, err := q.LockTeamBillingAccountByStripeCustomerID(ctx, &obj.Customer)
	if err == nil {
		account = &locked
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	current, err := q.GetStripeWebhookEventForUpdate(ctx, candidate.EventID)
	if err != nil {
		return err
	}
	if current.ProcessedAt.Valid || current.LastError == nil || *current.LastError != db.StripeCheckoutAssociationPendingError {
		return tx.Commit(ctx)
	}
	pending, err := stripeAssociationPending(ctx, tx, q, candidate.EventID, account, obj)
	if err != nil {
		return err
	}
	leaseUntil := now.Add(stripeAssociationLease)
	claimed, err := db.ClaimStripeCheckoutAssociationAlert(ctx, tx, candidate.EventID, now, leaseUntil)
	if err != nil {
		return err
	}
	if !claimed {
		return tx.Commit(ctx)
	}
	alert := StripeAssociationAlert{EventID: current.EventID, EventType: current.EventType,
		CustomerID: obj.Customer, SubscriptionID: obj.ID, ReceivedAt: current.ReceivedAt,
		Age: now.Sub(current.ReceivedAt)}
	if account != nil {
		alert.TeamID = account.TeamID.String()
		if account.CheckoutSessionID != nil {
			alert.CheckoutSessionID = *account.CheckoutSessionID
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if !pending {
		return db.FinishStripeCheckoutAssociationAlert(ctx, h.Pool, candidate.EventID, leaseUntil, now.Add(stripeAssociationRecheck), false, now)
	}
	stillPending, err := h.revalidateStripeCheckoutAssociation(ctx, candidate.EventID, obj.Customer, obj.ID)
	if err != nil {
		_ = db.FinishStripeCheckoutAssociationAlert(ctx, h.Pool, candidate.EventID, leaseUntil, now, false, now)
		return err
	}
	if !stillPending {
		return db.FinishStripeCheckoutAssociationAlert(ctx, h.Pool, candidate.EventID, leaseUntil, now.Add(stripeAssociationRecheck), false, now)
	}
	if err := report(alert); err != nil {
		// A failed reporter releases its lease. A crash leaves a two-minute lease.
		_ = db.FinishStripeCheckoutAssociationAlert(ctx, h.Pool, candidate.EventID, leaseUntil, now, false, now)
		return err
	}
	return db.FinishStripeCheckoutAssociationAlert(ctx, h.Pool, candidate.EventID, leaseUntil, now.Add(stripeAssociationCooldown), true, now)
}

func (h *Handlers) revalidateStripeCheckoutAssociation(ctx context.Context, eventID, customerID, subscriptionID string) (bool, error) {
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := h.DB.WithTx(tx)
	var account *db.TeamBillingAccount
	locked, err := q.LockTeamBillingAccountByStripeCustomerID(ctx, &customerID)
	if err == nil {
		account = &locked
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	event, err := q.GetStripeWebhookEventForUpdate(ctx, eventID)
	if err != nil {
		return false, err
	}
	var envelope stripeEventEnvelope
	if err := json.Unmarshal(event.Payload, &envelope); err != nil {
		return false, fmt.Errorf("decode retained event: %w", err)
	}
	var obj stripeSubscriptionObject
	if err := json.Unmarshal(envelope.Data.Object, &obj); err != nil {
		return false, fmt.Errorf("decode retained subscription: %w", err)
	}
	if obj.Customer != customerID || obj.ID != subscriptionID {
		return false, errors.New("retained subscription changed during revalidation")
	}
	pending := !event.ProcessedAt.Valid && event.LastError != nil &&
		*event.LastError == db.StripeCheckoutAssociationPendingError
	if pending {
		pending, err = stripeAssociationPending(ctx, tx, q, eventID, account, obj)
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return pending, nil
}

// RetireStripeCheckoutAssociationsBeforePurge preserves proven obsolescence in
// the transaction that removes the account and expiration evidence. It neither
// reports alerts nor acknowledges webhooks, and keeps unknown events inspectable.
func RetireStripeCheckoutAssociationsBeforePurge(ctx context.Context, tx pgx.Tx, teamID uuid.UUID) error {
	q := db.New(tx)
	account, err := q.LockTeamBillingAccount(ctx, teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil || account.StripeCustomerID == nil {
		return err
	}
	var after string
	for {
		rows, err := tx.Query(ctx, `SELECT event_id, payload FROM stripe_webhook_event
			WHERE processed_at IS NULL AND event_id > $1
			  AND payload #>> '{data,object,customer}' = $2
			  AND event_type IN ('customer.subscription.created', 'customer.subscription.updated',
			                     'customer.subscription.deleted', 'customer.subscription.paused',
			                     'customer.subscription.resumed')
			ORDER BY event_id LIMIT 100 FOR UPDATE`, after, *account.StripeCustomerID)
		if err != nil {
			return err
		}
		type retainedEvent struct {
			id      string
			payload []byte
		}
		events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (retainedEvent, error) {
			var event retainedEvent
			err := row.Scan(&event.id, &event.payload)
			return event, err
		})
		if err != nil {
			return err
		}
		for _, retained := range events {
			var event stripeEventEnvelope
			if err := json.Unmarshal(retained.payload, &event); err != nil {
				return err
			}
			var obj stripeSubscriptionObject
			if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
				return err
			}
			if obj.ID != "" {
				if _, err := stripeAssociationPending(ctx, tx, q, retained.id, &account, obj); err != nil {
					return err
				}
			}
			after = retained.id
		}
		if len(events) < 100 {
			return nil
		}
	}
}
