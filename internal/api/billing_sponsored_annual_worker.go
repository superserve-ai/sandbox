package api

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
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

// Local benefit expiry cannot depend on provider availability or configuration.
func (h *Handlers) expireSponsoredAnnualBenefits(ctx context.Context, team uuid.UUID) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET state='renewal_pending' WHERE team_id=$1 AND state='active' AND waiver_ends_at<=clock_timestamp()`, team); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) reconcileSponsoredAnnual(ctx context.Context, team uuid.UUID) error {
	if err := h.expireSponsoredAnnualBenefits(ctx, team); err != nil {
		return err
	}
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
	// Project lifecycle evidence even if configuration now needs recovery. Periods
	// change only when the complete adopted resource calendar still validates.
	calendarErr := validateSponsoredAnnualSubscription(o, sub, rounding, false)
	var periodStart, periodEnd int64
	if calendarErr == nil {
		resources, _ := o.base().stripSubscription(sub)
		for _, item := range resources.Items.Data {
			if item.Price.ID != rounding {
				periodStart, periodEnd = item.Start, item.End
				break
			}
		}
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	if _, err = q.LockTeamBillingAccount(ctx, team); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status=$5,cancel_at_period_end=$6,current_period_start=CASE WHEN $7 THEN $8 ELSE current_period_start END,current_period_end=CASE WHEN $7 THEN $9 ELSE current_period_end END WHERE team_id=$1 AND stripe_customer_id=$2 AND stripe_subscription_id=$3 AND commercial_billing_anchor=$4`, team, o.Customer, o.Subscription, o.Start, sub.Status, sub.CancelAtPeriodEnd || sub.CancelAt > 0, calendarErr == nil && periodStart > 0, time.Unix(periodStart, 0), time.Unix(periodEnd, 0))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("annual adoption association changed during reconciliation")
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if calendarErr != nil {
		return calendarErr
	}
	if now.Before(o.End) && (sub.Status == "canceled" || sub.Status == "incomplete_expired") {
		return errors.New("sponsored annual subscription terminated during waived term; billing recovery requires support")
	}
	if now.Before(o.End) {
		return nil
	}
	return h.reconcileSponsoredAnnualRenewal(ctx, o, sub, client, token)
}
