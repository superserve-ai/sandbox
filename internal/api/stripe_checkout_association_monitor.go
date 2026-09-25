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

func stripeAssociationStillPending(account *db.TeamBillingAccount, subscriptionID string, receivedAt time.Time) bool {
	if account == nil {
		return true // Missing authority does not prove the event obsolete.
	}
	if stripeSubscriptionMatchesCurrentAssociation(*account, subscriptionID) {
		return false
	}
	if account.CheckoutInitializingAt.Valid {
		// A reservation started after the webhook was received cannot be the
		// one that left this event pending.
		return !account.CheckoutInitializingAt.Time.After(receivedAt)
	}
	// A different established subscription or a retained expired checkout
	// session proves that the old reservation can no longer associate.
	return strings.TrimSpace(derefString(account.StripeSubscriptionID)) == "" && account.CheckoutSessionID == nil
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
	go func() {
		ticker := time.NewTicker(stripeAssociationPoll)
		defer ticker.Stop()
		var cursor db.StripeCheckoutAssociationCursor
		var nextFailureReport time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				tickCtx, cancel := context.WithTimeout(ctx, stripeAssociationTickTimeout)
				sentrylog.RunSafe("stripe-checkout-association-monitor", func() {
					var err error
					cursor, err = h.StripeCheckoutAssociationTick(tickCtx, now, cursor, reportStripeAssociationOverdue)
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
					log.Error().Err(err).Str("event_id", candidate.EventID).Msg("inspect Stripe checkout association failed")
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
	pending := stripeAssociationStillPending(account, obj.ID, current.ReceivedAt)
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
	pending := !event.ProcessedAt.Valid && event.LastError != nil &&
		*event.LastError == db.StripeCheckoutAssociationPendingError &&
		stripeAssociationStillPending(account, subscriptionID, event.ReceivedAt)
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return pending, nil
}
