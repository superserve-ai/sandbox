package api

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
	"time"
)

func (h *Handlers) startSponsoredAnnualReconciliation(ctx context.Context) {
	go func() {
		for ctx.Err() == nil {
			tick, cancel := context.WithTimeout(ctx, 50*time.Second)
			token := uuid.New()
			rows, err := h.Pool.Query(tick, `WITH due AS (SELECT id FROM billing_sponsored_annual_authority WHERE state<>'ended' AND next_check_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_check_at,id FOR UPDATE SKIP LOCKED LIMIT 4) UPDATE billing_sponsored_annual_authority a SET lease_token=$1,lease_until=clock_timestamp()+interval '1 minute',next_check_at=clock_timestamp()+interval '1 minute' FROM due WHERE a.id=due.id RETURNING a.team_id`, token)
			var teams []uuid.UUID
			if err == nil {
				for rows.Next() {
					var team uuid.UUID
					if err = rows.Scan(&team); err != nil {
						break
					}
					teams = append(teams, team)
				}
				if err == nil {
					err = rows.Err()
				}
				rows.Close()
			}
			if err != nil {
				log.Warn().Err(err).Msg("annual sponsorship scheduler failed")
			}
			runYCReconciliationBatch(tick, teams, func(work context.Context, team uuid.UUID) {
				started := time.Now()
				e := h.reconcileSponsoredAnnual(work, team)
				var message *string
				if e != nil {
					s := e.Error()
					message = &s
					log.Warn().Err(e).Str("team_id", team.String()).Msg("annual sponsorship requires reconciliation")
				}
				currentBillingRecorder().RecordBillingWork(work, "sponsored_annual_reconciliation", e != nil, time.Since(started), 1)
				ack, done := context.WithTimeout(context.WithoutCancel(work), 3*time.Second)
				defer done()
				if _, e = h.Pool.Exec(ack, `UPDATE billing_sponsored_annual_authority SET last_error=$3,lease_token=NULL,lease_until=NULL,next_check_at=clock_timestamp()+interval '20 seconds' WHERE team_id=$1 AND lease_token=$2`, team, token, message); e != nil {
					log.Error().Err(e).Msg("annual sponsorship progress could not be saved")
				}
			})
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}
func (h *Handlers) reconcileSponsoredAnnual(ctx context.Context, team uuid.UUID) error {
	o, err := h.sponsoredAnnualAuthority(ctx, team, h.Pool)
	if err != nil {
		return err
	}
	if o.State == "ended" {
		return nil
	}
	if h.Config == nil || o.Region != h.Config.TeamCreationRegion {
		return errors.New("annual adoption belongs to another billing region")
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("billing provider unavailable")
	}
	token := uuid.New()
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	defer func() {
		ack, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token})
	}()
	if err = client.ycMerchant(ctx, ycApproval{Merchant: o.Request.Merchant}); err != nil {
		return err
	}
	sub, err := client.invoiceSubscription(ctx, o.Subscription)
	if err != nil {
		return err
	}
	var rounding string
	var current bool
	var now time.Time
	if err = h.Pool.QueryRow(ctx, `SELECT i.adjustment_price_id,a.stripe_customer_id=$2 AND a.stripe_subscription_id=$3 AND a.commercial_billing_anchor=$4,clock_timestamp() FROM team_billing_account a JOIN billing_invoice_account i ON i.team_id=a.team_id WHERE a.team_id=$1`, team, o.Customer, o.Subscription, o.Start).Scan(&rounding, &current, &now); err != nil {
		return err
	}
	if !current || sub.Customer != o.Customer || sub.ID != o.Subscription || sub.LiveMode != o.Live {
		return errors.New("annual adoption billing identity changed")
	}
	if sub.Status == "canceled" || sub.Status == "incomplete_expired" {
		tx, e := h.Pool.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		q := h.DB.WithTx(tx)
		if _, e = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); e != nil {
			return e
		}
		if _, e = q.LockTeamBillingAccount(ctx, team); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1 AND status<>'ended'`, o.Renewal); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET state='ended' WHERE id=$1`, o.ID); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if err = validateSponsoredAnnualSubscription(o, sub, rounding, false); err != nil {
		return err
	}
	if now.Before(o.End) {
		return nil
	}
	return h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token)
}
