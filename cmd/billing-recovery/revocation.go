package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func loadRevocationAccounts(ctx context.Context, pool *pgxpool.Pool, target, after *uuid.UUID, batchSize int) ([]billingAccount, error) {
	// Inspect Stripe even when the local projection predates cancellation-state
	// persistence. Activation completeness and user entitlements do not filter
	// this revocation-only scan.
	rows, err := pool.Query(ctx, `SELECT a.team_id, a.stripe_customer_id, a.stripe_subscription_id,
        a.stripe_subscription_status, a.stripe_activation_credit_grant_id, a.cancel_at_period_end,
        EXISTS (
            SELECT 1 FROM stripe_webhook_event e
            WHERE e.event_type IN ('customer.subscription.updated', 'customer.subscription.deleted')
              AND e.payload->'data'->'object'->>'customer' = a.stripe_customer_id
              AND (e.event_type = 'customer.subscription.deleted'
                   OR e.payload->'data'->'object'->>'cancel_at_period_end' = 'true'
                   OR lower(e.payload->'data'->'object'->>'status') = 'canceled')
        ),
        (r.team_id IS NOT NULL AND r.completed_at IS NULL), (r.completed_at IS NOT NULL)
        FROM team_billing_account a LEFT JOIN stripe_activation_credit_revocation r USING (team_id)
        WHERE ($1::uuid IS NULL OR a.team_id = $1)
          AND ($2::uuid IS NULL OR a.team_id > $2)
          AND a.stripe_customer_id IS NOT NULL
        ORDER BY a.team_id LIMIT $3`, target, after, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []billingAccount
	for rows.Next() {
		var a billingAccount
		if err := rows.Scan(&a.TeamID, &a.CustomerID, &a.SubscriptionID, &a.Status, &a.GrantID, &a.CancelAtPeriodEnd, &a.HistoricalCancellation, &a.RevocationPending, &a.RevocationComplete); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func auditRevocation(ctx context.Context, pool *pgxpool.Pool, stripe stripeClient, account billingAccount, excluded *uuid.UUID, apply bool) map[string]any {
	out := map[string]any{"team_id": account.TeamID.String(), "mode": "dry-run", "operation": "revoke_activation_credit"}
	if apply {
		out["mode"] = "apply"
	}
	unresolved := func(err error) map[string]any {
		out["outcome"], out["reason"], out["error"] = "unresolved", "activation_revocation_unresolved", err.Error()
		return out
	}
	if excluded != nil && *excluded == account.TeamID {
		out["outcome"], out["reason"] = "skipped", "operationally_excluded"
		return out
	}
	if account.RevocationComplete {
		out["outcome"], out["reason"] = "reconciled", "activation_revocation_complete"
		return out
	}
	if strings.TrimSpace(deref(account.CustomerID)) == "" {
		return unresolved(errors.New("Stripe customer identity missing"))
	}
	canceled := account.RevocationPending || account.CancelAtPeriodEnd || account.HistoricalCancellation || strings.EqualFold(deref(account.Status), "canceled")
	if !canceled {
		if strings.TrimSpace(deref(account.SubscriptionID)) == "" {
			return unresolved(errors.New("Stripe subscription identity missing"))
		}
		sub, err := stripe.subscription(ctx, *account.SubscriptionID)
		if err != nil {
			return unresolved(err)
		}
		if sub.ID != *account.SubscriptionID || sub.Customer != *account.CustomerID {
			return unresolved(errors.New("Stripe subscription ownership mismatch"))
		}
		canceled = sub.CancelAtPeriodEnd || strings.EqualFold(sub.Status, "canceled")
	}
	if !canceled {
		out["outcome"], out["reason"] = "skipped", "no_cancellation_evidence"
		return out
	}
	grant, err := billing.FindStripeActivationGrant(ctx, stripe.request, account.TeamID, *account.CustomerID, deref(account.GrantID))
	if err != nil {
		return unresolved(err)
	}
	out["grant_id"] = grant.ID
	if !apply {
		out["outcome"], out["reason"] = "candidate", "canceled_activation_credit"
		return out
	}
	if err := applyActivationRevocation(ctx, pool, stripe, account, grant.ID); err != nil {
		return unresolved(err)
	}
	out["outcome"], out["reason"] = "reconciled", "activation_credit_revoked"
	return out
}

func applyActivationRevocation(ctx context.Context, pool *pgxpool.Pool, stripe stripeClient, account billingAccount, grantID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	q := db.New(conn)
	token := uuid.New()
	if _, err := q.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: *account.CustomerID, Token: token}); err != nil {
		return err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.ReleaseStripeWebhookProcessingLease(releaseCtx, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: *account.CustomerID, Token: token})
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tq := q.WithTx(tx)
	if _, err := tq.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: *account.CustomerID, Token: token}); err != nil {
		return err
	}
	current, err := tq.LockTeamBillingAccount(ctx, account.TeamID)
	if err != nil {
		return err
	}
	if deref(current.StripeCustomerID) != *account.CustomerID || deref(current.StripeActivationCreditGrantID) != deref(account.GrantID) {
		return errors.New("activation grant association changed; rerun audit")
	}
	if err := tq.RequestStripeActivationCreditRevocation(ctx, account.TeamID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Intent survives a failure or reversal. No activation settlement or credit
	// creation is reachable from this path, including for user-scoped grants.
	if _, err := billing.RevokeStripeActivationGrant(ctx, stripe.request, account.TeamID, *account.CustomerID, grantID); err != nil {
		return err
	}
	finalTx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer finalTx.Rollback(ctx)
	fq := q.WithTx(finalTx)
	if _, err := fq.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: *account.CustomerID, Token: token}); err != nil {
		return err
	}
	current, err = fq.LockTeamBillingAccount(ctx, account.TeamID)
	if err != nil {
		return err
	}
	if current.StripeActivationCreditReservedAt.Valid && !current.StripeActivationUserID.Valid {
		return errors.New("pending Stripe promotion reservation has no user identity")
	}
	if current.StripeActivationUserID.Valid && current.StripeActivationCreditReservedAt.Valid &&
		!current.StripeActivationCreditGrantedAt.Valid && deref(current.StripeActivationCreditGrantID) == "" {
		// Stripe may have created the grant before the original response was
		// lost. Settle the pinned reservation before persisting its ID so the
		// user entitlement cannot remain pending behind a completed recovery.
		if err := fq.FinalizeStripePromotion(ctx, db.FinalizeStripePromotionParams{
			TeamID: account.TeamID, UserID: uuid.UUID(current.StripeActivationUserID.Bytes), StripeGrantID: grantID,
		}); err != nil {
			return err
		}
	}
	if _, err := fq.CompleteStripeActivationCreditRevocation(ctx, db.CompleteStripeActivationCreditRevocationParams{TeamID: account.TeamID, CustomerID: *account.CustomerID, GrantID: &grantID}); err != nil {
		return err
	}
	return finalTx.Commit(ctx)
}
