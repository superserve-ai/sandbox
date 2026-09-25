package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
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

type stripeAssociationAlert struct {
	EventID, EventType, CustomerID, SubscriptionID, CheckoutSessionID, TeamID string
	ReceivedAt                                                                time.Time
	Age                                                                       time.Duration
}

func stripeAssociationStillPending(account *db.TeamBillingAccount, subscriptionID string) bool {
	if account == nil {
		return true // Missing authority does not prove the event obsolete.
	}
	if stripeSubscriptionMatchesCurrentAssociation(*account, subscriptionID) {
		return false
	}
	if account.CheckoutInitializingAt.Valid {
		return true
	}
	// A different established subscription or a retained expired checkout
	// session proves that the old reservation can no longer associate.
	return strings.TrimSpace(derefString(account.StripeSubscriptionID)) == "" && account.CheckoutSessionID == nil
}

func reportStripeAssociationOverdue(a stripeAssociationAlert) error {
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
	go func() {
		ticker := time.NewTicker(stripeAssociationPoll)
		defer ticker.Stop()
		var cursor db.StripeCheckoutAssociationCursor
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				tickCtx, cancel := context.WithTimeout(ctx, stripeAssociationTickTimeout)
				var err error
				cursor, err = h.stripeCheckoutAssociationTick(tickCtx, now, cursor, reportStripeAssociationOverdue)
				if err != nil && ctx.Err() == nil {
					log.Error().Err(err).Msg("Stripe checkout association monitor failed")
				}
				cancel()
			}
		}
	}()
}

func (h *Handlers) stripeCheckoutAssociationTick(ctx context.Context, now time.Time, cursor db.StripeCheckoutAssociationCursor, report func(stripeAssociationAlert) error) (db.StripeCheckoutAssociationCursor, error) {
	candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, h.Pool, now, stripeAssociationGrace, cursor, stripeAssociationBatchSize)
	if err != nil {
		return cursor, fmt.Errorf("discover pending Stripe checkout associations: %w", err)
	}
	if len(candidates) == 0 && !cursor.ReceivedAt.IsZero() {
		cursor = db.StripeCheckoutAssociationCursor{}
		candidates, err = db.ListStripeCheckoutAssociationCandidates(ctx, h.Pool, now, stripeAssociationGrace, cursor, stripeAssociationBatchSize)
		if err != nil {
			return cursor, fmt.Errorf("restart pending Stripe checkout association scan: %w", err)
		}
	}
	for _, candidate := range candidates {
		cursor = db.StripeCheckoutAssociationCursor{ReceivedAt: candidate.ReceivedAt, EventID: candidate.EventID}
		if err := h.inspectStripeCheckoutAssociation(ctx, now, candidate, report); err != nil {
			log.Error().Err(err).Str("event_id", candidate.EventID).Msg("inspect Stripe checkout association failed")
		}
	}
	return cursor, nil
}

func (h *Handlers) inspectStripeCheckoutAssociation(ctx context.Context, now time.Time, candidate db.StripeCheckoutAssociationCandidate, report func(stripeAssociationAlert) error) error {
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
	pending := stripeAssociationStillPending(account, obj.ID)
	leaseUntil := now.Add(stripeAssociationLease)
	claimed, err := db.ClaimStripeCheckoutAssociationAlert(ctx, tx, candidate.EventID, now, leaseUntil)
	if err != nil {
		return err
	}
	if !claimed {
		return tx.Commit(ctx)
	}
	alert := stripeAssociationAlert{EventID: current.EventID, EventType: current.EventType,
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
	pending := !event.ProcessedAt.Valid && event.LastError != nil &&
		*event.LastError == db.StripeCheckoutAssociationPendingError &&
		stripeAssociationStillPending(account, subscriptionID)
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return pending, nil
}
