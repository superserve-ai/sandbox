package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (h *Handlers) startSponsoredReconciliation(ctx context.Context) {
	go func() {
		for ctx.Err() == nil {
			tick, cancel := context.WithTimeout(ctx, 50*time.Second)
			var pending int64
			var age float64
			if e := h.Pool.QueryRow(tick, `SELECT count(*),COALESCE(extract(epoch FROM clock_timestamp()-min(approved_at)),0)::double precision FROM billing_sponsored_operation WHERE state='approved'`).Scan(&pending, &age); e != nil {
				log.Warn().Err(e).Msg("sponsorship activation backlog observation failed")
			} else {
				currentBillingRecorder().RecordBillingBacklog(tick, "sponsorship_activation", pending, age)
			}
			token := uuid.New()
			rows, err := h.Pool.Query(tick, `WITH due AS (SELECT id FROM billing_sponsored_operation WHERE state NOT IN ('revoked','expired') AND next_check_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_check_at,id FOR UPDATE SKIP LOCKED LIMIT 4) UPDATE billing_sponsored_operation o SET lease_token=$1,lease_until=clock_timestamp()+interval '1 minute',next_check_at=clock_timestamp()+interval '1 minute' FROM due WHERE o.id=due.id RETURNING o.id`, token)
			var ids []uuid.UUID
			if err == nil {
				for rows.Next() {
					var id uuid.UUID
					if err = rows.Scan(&id); err != nil {
						break
					}
					ids = append(ids, id)
				}
				if err == nil {
					err = rows.Err()
				}
				rows.Close()
			}
			if err != nil {
				log.Warn().Err(err).Msg("sponsorship scheduler failed")
			}
			runYCReconciliationBatch(tick, ids, func(work context.Context, id uuid.UUID) {
				started := time.Now()
				err := h.reconcileSponsored(work, id)
				var message *string
				currentBillingRecorder().RecordBillingWork(work, "sponsorship_reconciliation", err != nil, time.Since(started), 1)
				if err != nil {
					s := err.Error()
					message = &s
					log.Warn().Err(err).Str("operation_id", id.String()).Msg("sponsorship requires reconciliation")
				}
				ack, done := context.WithTimeout(context.WithoutCancel(work), 3*time.Second)
				defer done()
				_, save := h.Pool.Exec(ack, `UPDATE billing_sponsored_operation SET last_error=$3,lease_token=NULL,lease_until=NULL,next_check_at=clock_timestamp()+interval '20 seconds' WHERE id=$1 AND lease_token=$2`, id, token, message)
				if save != nil {
					log.Error().Err(save).Msg("sponsorship progress could not be saved")
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
func (h *Handlers) reconcileSponsored(ctx context.Context, id uuid.UUID) error {
	o, err := h.sponsoredOperation(ctx, id)
	if err != nil {
		return err
	}
	var region string
	if err = h.Pool.QueryRow(ctx, `SELECT home_region FROM team WHERE id=$1`, o.Team).Scan(&region); err != nil {
		return err
	}
	if h.Config == nil || region != h.Config.TeamCreationRegion {
		return errors.New("sponsorship belongs to another billing region")
	}
	if o.Revoked.Valid {
		// A lost bootstrap response is still an external obligation. Preserve the
		// operation until the original idempotent request has been recovered.
		if o.CustomerAttempt.Valid && o.Customer == "" {
			if err = h.ensureSponsoredCustomer(ctx, &o); err != nil {
				return err
			}
		}
		var attached bool
		if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account a JOIN billing_invoice_account i USING(team_id) WHERE a.team_id=$1 AND a.stripe_customer_id=$2 AND a.stripe_subscription_id=$3 AND i.customer_id=$2 AND i.subscription_id=$3)`, o.Team, o.Customer, o.Subscription).Scan(&attached); err != nil {
			return err
		}
		if o.ProviderAttempt.Valid && !attached {
			client, ok := h.Stripe.(*stripeHTTPClient)
			if !ok {
				return errors.New("billing provider unavailable")
			}
			sub, e := h.ensureSponsoredSubscription(ctx, &o, client)
			if e != nil {
				return e
			}
			if sub.Status != "canceled" && sub.Status != "incomplete_expired" {
				token := uuid.New()
				if _, e = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); e != nil {
					return e
				}
				defer func() {
					ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
					defer cancel()
					_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token})
				}()
				if e = h.bindSponsoredSubscription(ctx, &o, sub, token); e != nil {
					return e
				}
				if e = h.enrollInvoiceAccount(ctx, o.Team, nil); e != nil {
					return e
				}
			}
		}
		var unknown bool
		if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE sponsorship_id=$1 AND state='uncertain')`, id).Scan(&unknown); err != nil {
			return err
		}
		if unknown {
			return nil
		}
		// A current issued grant survives; the sponsorship contract remains available
		// to reconcile its closing invoice, but no future issuance can be authorized.
		tx, e := h.Pool.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		// Keep the invoice window of a recorded grant, and release only future authority.
		_, e = tx.Exec(ctx, `UPDATE billing_commercial_contract c SET status='ended',revision=revision+1,ends_at=LEAST(c.ends_at,GREATEST(c.starts_at+interval '1 microsecond',COALESCE((SELECT max(period_end) FROM billing_usage_entitlement WHERE contract_id=c.id),clock_timestamp()))) WHERE c.id=$1 AND c.status<>'ended'`, o.Contract)
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET state='revoked' WHERE id=$1`, id)
		}
		if e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if o.State == "active" {
		if o.End.Valid && !o.End.Time.After(time.Now()) {
			err = h.expireSponsorship(ctx, o)

		}
		return err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("billing provider unavailable")
	}
	if o.Customer == "" {
		if err = h.ensureSponsoredCustomer(ctx, &o); err != nil {
			return err
		}
	}
	token := uuid.New()
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token})
	}()
	debt, err := client.entitlementDebt(ctx, o.Customer)
	if err != nil {
		return err
	}
	if debt != "" {
		return errors.New("unpaid finalized invoice blocks sponsorship")
	}
	sub, err := h.ensureSponsoredSubscription(ctx, &o, client)
	if err != nil {
		return err
	}
	if err = h.bindSponsoredSubscription(ctx, &o, sub, token); err != nil {
		return err
	}
	if err = h.enrollInvoiceAccount(ctx, o.Team, nil); err != nil {
		return err
	}
	a, enrolled, err := h.invoiceAccount(ctx, o.Team)
	if err != nil {
		return err
	}
	if !enrolled {
		return errors.New("sponsored invoice enrollment is pending")
	}
	if _, err = client.ensureInvoiceSubscription(ctx, a, false, false); err != nil {
		return err
	}
	return h.activateSponsorship(ctx, o, token)
}

// The database clock decides both halves of expiration, including when an API
// host reaches the boundary first or the general reaper already ended it.
func (h *Handlers) expireSponsorship(ctx context.Context, o sponsoredOperation) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1 AND status<>'ended' AND ends_at<=clock_timestamp()`, o.Contract); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET state='expired' WHERE id=$1 AND state='active' AND ends_at<=clock_timestamp() AND EXISTS(SELECT 1 FROM billing_commercial_contract WHERE id=$2 AND status='ended')`, o.ID, o.Contract); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) ensureSponsoredCustomer(ctx context.Context, o *sponsoredOperation) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err := h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return err
	}
	if a.StripeCustomerID != nil && !o.CustomerAttempt.Valid {
		o.Customer = *a.StripeCustomerID
		if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET customer_id=$2 WHERE id=$1`, o.ID, o.Customer); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	err = tx.QueryRow(ctx, `UPDATE billing_sponsored_operation SET customer_attempt_at=COALESCE(customer_attempt_at,clock_timestamp()) WHERE id=$1 AND (revoked_at IS NULL OR customer_attempt_at IS NOT NULL) RETURNING customer_attempt_at`, o.ID).Scan(&o.CustomerAttempt)
	if err != nil {
		return err
	}
	if time.Since(o.CustomerAttempt.Time) >= 23*time.Hour {
		return errors.New("customer outcome unknown beyond safe replay window; operator recovery required")
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	customer, err := h.Stripe.CreateCustomer(ctx, StripeCreateCustomerParams{TeamID: o.Team, Name: o.CustomerName, IdempotencyKey: customerCreationIdempotencyKey(o.Team)})
	if err != nil {
		return err
	}
	if customer.ID == "" {
		return errors.New("provider returned no customer identity")
	}
	tx, err = h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return err
	}
	if a.StripeCustomerID != nil && *a.StripeCustomerID != customer.ID {
		return errors.New("customer mapping changed during sponsorship")
	}
	if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, o.Team, customer.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET customer_id=$2 WHERE id=$1`, o.ID, customer.ID); err != nil {
		return err
	}
	o.Customer = customer.ID
	return tx.Commit(ctx)
}
func (h *Handlers) ensureSponsoredSubscription(ctx context.Context, o *sponsoredOperation, c *stripeHTTPClient) (invoiceSubscription, error) {
	if o.Subscription != "" {
		return c.invoiceSubscription(ctx, o.Subscription)
	}
	var result invoiceSubscription
	var list struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {o.Customer}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &list, ""); err != nil {
		return result, err
	}
	if list.HasMore {
		return result, errors.New("subscription discovery incomplete")
	}
	for _, s := range list.Data {
		if s.Metadata["sponsored_operation"] == o.ID.String() {
			if result.ID != "" {
				return result, errors.New("duplicate sponsorship subscriptions")
			}
			result = s
		} else if s.Status != "canceled" && s.Status != "incomplete_expired" {
			return result, errors.New("competing subscription conflicts with sponsorship")
		}
	}
	if result.ID == "" {
		var hasAnchor bool
		if err := h.Pool.QueryRow(ctx, `SELECT commercial_billing_anchor IS NOT NULL FROM team_billing_account WHERE team_id=$1`, o.Team).Scan(&hasAnchor); err != nil {
			return result, err
		}
		if hasAnchor {
			return result, errors.New("existing anniversary has no aligned usage subscription; reconcile billing setup before sponsorship")
		}
		err := h.Pool.QueryRow(ctx, `UPDATE billing_sponsored_operation SET provider_attempt_at=COALESCE(provider_attempt_at,clock_timestamp()) WHERE id=$1 AND (revoked_at IS NULL OR provider_attempt_at IS NOT NULL) RETURNING provider_attempt_at`, o.ID).Scan(&o.ProviderAttempt)
		if err != nil {
			return result, err
		}
		if time.Since(o.ProviderAttempt.Time) >= 23*time.Hour {
			return result, errors.New("subscription outcome unknown beyond safe replay window")
		}
		form := url.Values{"customer": {o.Customer}, "collection_method": {"charge_automatically"}, "billing_mode[type]": {"flexible"}, "metadata[sponsored_operation]": {o.ID.String()}, "proration_behavior": {"none"}}
		for i, t := range o.Params.ResourceTerms {
			form.Set(fmt.Sprintf("items[%d][price]", i), t.PriceID)
		}
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions", form, &result, "sponsored-subscription:"+o.ID.String()); err != nil {
			return result, err
		}
	}
	if result.ID == "" || result.Customer != o.Customer || result.Metadata["sponsored_operation"] != o.ID.String() {
		return result, errors.New("subscription differs from sponsored operation")
	}
	_, err := h.Pool.Exec(ctx, `UPDATE billing_sponsored_operation SET subscription_id=$2 WHERE id=$1`, o.ID, result.ID)
	o.Subscription = result.ID
	return result, err
}
func (h *Handlers) bindSponsoredSubscription(ctx context.Context, o *sponsoredOperation, sub invoiceSubscription, token uuid.UUID) error {
	if sub.Customer != o.Customer || sub.ID != o.Subscription || sub.Status != "active" || sub.BillingCycleAnchor <= 0 || sub.Items.HasMore || sub.Schedule != "" || sub.PendingUpdate != nil || sub.CancelAtPeriodEnd || sub.CancelAt > 0 {
		return errors.New("sponsored usage subscription is not usable")
	}
	var rounding string
	if err := h.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1),'')`, o.Team).Scan(&rounding); err != nil {
		return err
	}
	if err := validateFrozenProResources(sub, o.Params.ResourceTerms, rounding); err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = h.DB.WithTx(tx).LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	a, err := h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return err
	}
	if derefString(a.StripeCustomerID) != o.Customer || a.StripeSubscriptionID != nil && *a.StripeSubscriptionID != o.Subscription {
		return errors.New("sponsored billing identity changed")
	}
	anchor := time.Unix(sub.BillingCycleAnchor, 0).UTC()
	if a.CommercialBillingAnchor.Valid && !a.CommercialBillingAnchor.Time.Equal(anchor) {
		return errors.New("existing billing anniversary differs; automatic reset is forbidden")
	}
	if err = invoiceCalendarCompatible(anchor, sub, rounding); err != nil {
		return err
	}
	at := o.Start
	if at.Before(anchor) {
		at = anchor
	}
	start, end, ok := billing.AnniversaryPeriod(anchor, at)
	if !ok {
		return errors.New("invalid sponsored anniversary")
	}
	amounts, err := o.Request.amounts()
	if err != nil {
		return err
	}
	for i := 1; i < len(amounts); i++ {
		_, end, _ = billing.AnniversaryPeriod(anchor, end)
	}
	// No trial/signup-choice state or payment evidence is manufactured here.
	if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status=$3,commercial_billing_anchor=COALESCE(commercial_billing_anchor,$4) WHERE team_id=$1`, o.Team, o.Subscription, sub.Status, anchor); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE billing_sponsored_operation SET anchor=$2,starts_at=$3,ends_at=$4 WHERE id=$1 AND (revoked_at IS NULL OR provider_attempt_at IS NOT NULL) AND (starts_at IS NULL OR (anchor=$2 AND starts_at=$3 AND ends_at=$4))`, o.ID, anchor, start, end)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("sponsorship revoked or calendar changed")
	}
	o.Anchor = pgtype.Timestamptz{Time: anchor, Valid: true}
	o.PeriodStart = pgtype.Timestamptz{Time: start, Valid: true}
	o.End = pgtype.Timestamptz{Time: end, Valid: true}
	return tx.Commit(ctx)
}
func (h *Handlers) activateSponsorship(ctx context.Context, o sponsoredOperation, token uuid.UUID) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = h.DB.WithTx(tx).LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	if _, err = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team); err != nil {
		return err
	}
	var revoked bool
	if err = tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM billing_sponsored_operation WHERE id=$1 FOR UPDATE`, o.ID).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return errors.New("sponsorship revoked")
	}
	amounts, err := o.Request.amounts()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_kind,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'sponsored_usage',$3,$4,$5,$6,'','sponsored_entitlement',0,1,'metered_usage',$7,'scheduled',$8) ON CONFLICT(id) DO NOTHING`, o.Contract, o.Team, o.PeriodStart.Time, o.End.Time, o.Customer, o.Subscription, amounts[0], o.Anchor.Time)
	if err != nil {
		return err
	}
	for i, amount := range amounts {
		if _, err = tx.Exec(ctx, `INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, o.Team, o.Contract, i, amount); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1 AND status='pending'`, o.Contract); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id) VALUES($1) ON CONFLICT(contract_id) DO UPDATE SET next_check_at=clock_timestamp()`, o.Contract); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET state='active' WHERE id=$1`, o.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Revocation cancels new grants, not a request already marked as dispatched.
// Recovery retains the shared worker's frozen request and finite replay window.
func (h *Handlers) finishSponsoredAttempt(ctx context.Context, c db.BillingCommercialContract, e db.BillingUsageEntitlement, client *stripeHTTPClient) error {
	if e.State != "uncertain" || !e.FirstAttemptAt.Valid || time.Since(e.FirstAttemptAt.Time) >= 23*time.Hour || !e.PeriodEnd.After(time.Now()) {
		return errors.New("revoked grant requires manual outcome recovery")
	}
	var raw struct {
		Applicability struct {
			Scope struct {
				Prices []map[string]string `json:"prices"`
			} `json:"scope"`
		} `json:"applicability_config"`
	}
	if err := json.Unmarshal(e.RequestPayload, &raw); err != nil {
		return err
	}
	token := uuid.New()
	if _, err := h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: c.CustomerID, Token: token}); err != nil {
		return err
	}
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: c.CustomerID, Token: token})
	}()
	return h.dispatchUsageEntitlement(ctx, c, e, client, raw.Applicability.Scope.Prices)
}
