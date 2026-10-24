package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (h *Handlers) reconcileYC(ctx context.Context, team uuid.UUID) error {
	var released bool
	if err := h.Pool.QueryRow(ctx, `SELECT billing_yc_released($1)`, team).Scan(&released); err != nil {
		return err
	}
	if released {
		return nil
	}
	o, err := h.ycOperation(ctx, team)
	if err != nil {
		return err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("Stripe verification unavailable")
	}
	if err = h.syncYCRevocation(ctx, &o); err != nil {
		return err
	}
	if !o.Revoked.Valid {
		if err = h.verifyYCAuthority(ctx, o); err != nil {
			return err
		}
	}
	if err = client.ycMerchant(ctx, o.Request); err != nil {
		return err
	}
	local, err := h.DB.GetTeam(ctx, team)
	if err != nil {
		return err
	}
	if h.Config == nil || local.HomeRegion != o.Request.Region || local.HomeRegion != h.Config.TeamCreationRegion {
		return errors.New("YC operation belongs to another billing region")
	}
	if o.Revoked.Valid && o.Subscription == "" && !o.Attempt.Valid {
		_, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET state='ended',next_check_at='infinity' WHERE team_id=$1`, team)
		return err
	}
	if !o.Revoked.Valid && o.State != "active" && o.State != "renewed" {
		authority, e := h.lockYCAuthority(ctx, o)
		if e != nil {
			return e
		}
		defer authority()
	}
	if o.Customer == "" {
		o.Customer, err = h.ensureYCCustomer(ctx, o)
		if err != nil {
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
	// Revocation prohibits new creation, but must recover a prior response loss.
	var sub invoiceSubscription
	if o.Revoked.Valid && o.Subscription == "" && o.Attempt.Valid {
		sub, err = h.createYCSubscription(ctx, o, client)
		if err != nil {
			return err
		}
		o.Subscription = sub.ID
	}
	if o.Subscription != "" {
		sub, err = client.invoiceSubscription(ctx, o.Subscription)
		if err != nil {
			return err
		}
	}
	if sub.ID != "" {
		if sub.Customer != o.Customer || sub.LiveMode != *o.Request.Live {
			return errors.New("subscription ownership or mode changed")
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status=$3,cancel_at_period_end=$4 WHERE team_id=$1 AND stripe_subscription_id=$2`, team, sub.ID, sub.Status, sub.CancelAtPeriodEnd || sub.CancelAt > 0); err != nil {
			return err
		}
	}
	ready, err := client.ycPaymentMethod(ctx, o.Customer, sub, *o.Request.Live)
	methodErr := err
	if methodErr != nil {
		ready = false
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET payment_method_ready=$2,payment_method_checked_at=clock_timestamp() WHERE team_id=$1`, team, ready); err != nil {
		return err
	}
	renewalDue := o.End.Valid && !time.Now().Before(o.End.Time)
	// The verified anniversary can be saved before contract adoption commits.
	// Reconcile that durable calendar independently of later billing checks.
	if o.Subscription != "" && o.Start.Valid {
		var reconciled bool
		if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE operation_id=$1 AND team_id=$2 AND anniversary=$3)`, o.ID, team, o.Start.Time).Scan(&reconciled); err != nil {
			return err
		}
		if !reconciled {
			if !o.Start.Valid || sub.ID != o.Subscription || sub.StartDate != o.Start.Time.Unix() || sub.BillingCycleAnchor != sub.StartDate {
				return errors.New("adopted subscription association or anniversary changed")
			}
			tx, err := h.Pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if err = h.lockAndReconcileYCCalendar(ctx, tx, o, token); err != nil {
				return err
			}
			if err = tx.Commit(ctx); err != nil {
				return err
			}
		}
	}
	if sub.LatestInvoice != "" {
		var latest StripeInvoiceAmounts
		if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(sub.LatestInvoice), nil, &latest, ""); err != nil {
			return err
		}
		if latest.ID != sub.LatestInvoice || latest.Customer != o.Customer || latest.Parent.SubscriptionDetails == nil || latest.Parent.SubscriptionDetails.Subscription != sub.ID || latest.Status == "" {
			return errors.New("latest invoice association differs")
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE team_billing_account SET stripe_invoice_status=$3 WHERE team_id=$1 AND stripe_customer_id=$2`, team, o.Customer, latest.Status); err != nil {
			return err
		}
	}
	if methodErr != nil {
		return methodErr
	}
	if !ready {
		return errors.New("payment_method_required: resource usage remains blocked")
	}
	if o.State == "ended" {
		return nil
	}
	if renewalDue {
		return h.reconcileYCRenewal(ctx, o, sub, client, token)
	}
	if o.Subscription == "" {
		sub, err = h.createYCSubscription(ctx, o, client)
		if err != nil {
			return err
		}
		o.Subscription = sub.ID
	}
	// Re-read durable values after recovering a possibly successful creation.
	o, err = h.ycOperation(ctx, team)
	if err != nil {
		return err
	}
	in := o.Request
	in.Customer = o.Customer
	if o.State != "active" {
		original := sub
		original.LatestInvoice = o.FirstInvoice
		if err = client.verifyYCFirstInvoice(ctx, original, o.Params.BasePriceID); err != nil {
			return err
		}
	}
	if !o.Start.Valid {
		if err = validateYCSubscription(sub, o.Params, in); err != nil {
			return err
		}
		var end int64
		for _, item := range sub.Items.Data {
			if item.Price.ID == o.Params.BasePriceID {
				end = item.End
			}
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET starts_at=$2,ends_at=$3 WHERE team_id=$1 AND starts_at IS NULL`, team, time.Unix(sub.StartDate, 0), time.Unix(end, 0)); err != nil {
			return err
		}
		o.Start = pgtype.Timestamptz{Time: time.Unix(sub.StartDate, 0), Valid: true}
		o.End = pgtype.Timestamptz{Time: time.Unix(end, 0), Valid: true}
	}
	if sub.Customer != o.Customer || sub.LiveMode != *o.Request.Live || sub.StartDate != o.Start.Time.Unix() || sub.BillingCycleAnchor != sub.StartDate {
		return errors.New("adopted subscription association or anniversary changed")
	}
	if sub.Status != "active" && sub.Status != "past_due" {
		return errors.New("subscription is not usable; operator recovery required")
	}
	sub, err = h.normalizeYCCancellation(ctx, o, sub, client)
	if err != nil {
		return err
	}
	if o.State == "active" {
		_, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET last_error=NULL,next_check_at=clock_timestamp()+interval '30 seconds' WHERE team_id=$1`, team)
		return err
	}
	if err = client.ycSubscriptionInventory(ctx, o.Customer, o.Subscription, o.ID.String()); err != nil {
		return err
	}
	if o.currentApprovedGrant() != "" {
		if _, err = client.validateYCExistingGrant(ctx, sub, o.Params, o.currentApprovedGrant()); err != nil {
			return err
		}
	}
	if err = client.ycGrantPreflight(ctx, o.Customer, o.Contract.String(), o.currentApprovedGrant()); err != nil {
		return err
	}
	sub, err = h.ensureYCResources(ctx, o, sub, client)
	if err != nil {
		return err
	}
	if err = h.persistYCContract(ctx, o, sub, token); err != nil {
		return err
	}
	if err = h.enrollInvoiceAccount(ctx, team, nil); err != nil {
		return err
	}
	sub, err = client.invoiceSubscription(ctx, o.Subscription)
	if err != nil {
		return err
	}
	a, enrolled, err := h.invoiceAccount(ctx, team)
	if err != nil {
		return err
	}
	if !enrolled {
		return errors.New("YC invoice enrollment pending")
	}
	if _, err = client.ensureInvoiceSubscription(ctx, a, false, false); err != nil {
		return err
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
	contract, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: o.Contract})
	if err != nil {
		return err
	}
	if contract.Status == "pending" {
		// Inventory before activation uses the shared resumable scanner, allowing a
		// matching pre-existing grant to be adopted before the issuer can run.
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		if err = h.adoptYCGrant(ctx, o, contract, a, client); err != nil {
			return err
		}
		tx, err = h.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		q = h.DB.WithTx(tx)
		if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
			return err
		}
		contract, err = q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: o.Contract})
		if err != nil {
			return err
		}
		if contract.Status == "pending" {
			_, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: team, ContractID: o.Contract, ExpectedRevision: contract.Revision})
			if err != nil {
				return err
			}
		}
	}
	var reconciled bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE operation_id=$1 AND team_id=$2 AND anniversary=$3)`, o.ID, team, o.Start.Time).Scan(&reconciled); err != nil {
		return err
	}
	if !reconciled {
		return errors.New("YC billing calendar reconciliation is required before activation")
	}
	if err = q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: team, StripeGrantID: ""}); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET state='active',last_error=NULL,next_check_at=clock_timestamp()+interval '30 seconds' WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (h *Handlers) createYCSubscription(ctx context.Context, o ycOperation, c *stripeHTTPClient) (invoiceSubscription, error) {
	var sub invoiceSubscription
	var list struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	query := url.Values{"customer": {o.Customer}, "status": {"all"}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+query.Encode(), nil, &list, ""); err != nil {
		return sub, err
	}
	if list.HasMore {
		return sub, errors.New("YC subscription discovery exceeds bound")
	}
	for _, s := range list.Data {
		if s.Metadata["yc_operation"] == o.ID.String() {
			if sub.ID != "" {
				return sub, errors.New("duplicate YC provider operation")
			}
			sub = s
		} else if s.Status != "canceled" && s.Status != "incomplete_expired" {
			return sub, errors.New("conflicting customer subscription")
		}
	}
	if sub.ID == "" {
		if o.Revoked.Valid {
			return sub, errors.New("revoked provider attempt has no confirmed subscription; operator reconciliation required")
		}
		if o.Attempt.Valid && time.Since(o.Attempt.Time) >= 23*time.Hour {
			return sub, errors.New("subscription creation outcome unknown beyond replay window; operator recovery required")
		}
		var price storagePrice
		if err := c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(o.Params.BasePriceID), nil, &price, ""); err != nil {
			return sub, err
		}
		coupon := "yc-first-year-" + o.ID.String()
		var existing struct {
			ID       string  `json:"id"`
			Duration string  `json:"duration"`
			Percent  float64 `json:"percent_off"`
			Applies  struct {
				Products []string `json:"products"`
			} `json:"applies_to"`
		}
		couponPath := "/v1/coupons/" + coupon + "?" + url.Values{"expand[]": {"applies_to"}}.Encode()
		err := c.doForm(ctx, http.MethodGet, couponPath, nil, &existing, "")
		if err != nil {
			if !strings.HasPrefix(err.Error(), "stripe GET "+couponPath+" returned 404:") {
				return sub, err
			}
			form := url.Values{"id": {coupon}, "duration": {"once"}, "percent_off": {"100"}, "applies_to[products][0]": {price.Product}}
			if err = c.doForm(ctx, http.MethodPost, "/v1/coupons", form, nil, coupon); err != nil {
				return sub, err
			}
			// Read restriction evidence explicitly without changing the replayable creation payload.
			if err = c.doForm(ctx, http.MethodGet, couponPath, nil, &existing, ""); err != nil {
				return sub, err
			}
		}
		if existing.ID != coupon || existing.Duration != "once" || existing.Percent != 100 || len(existing.Applies.Products) != 1 || existing.Applies.Products[0] != price.Product {
			return sub, errors.New("YC coupon differs from approved base-only waiver")
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET state='provider_pending',provider_attempt_at=COALESCE(provider_attempt_at,clock_timestamp()) WHERE team_id=$1`, o.Team); err != nil {
			return sub, err
		}
		form := url.Values{"customer": {o.Customer}, "items[0][price]": {o.Params.BasePriceID}, "items[0][quantity]": {"1"}, "discounts[0][coupon]": {coupon}, "collection_method": {"charge_automatically"}, "billing_mode[type]": {"flexible"}, "metadata[yc_operation]": {o.ID.String()}}
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions", form, &sub, "yc-subscription:"+o.ID.String()); err != nil {
			return sub, err
		}
	}
	if sub.Customer != o.Customer || sub.ID == "" || sub.Metadata["yc_operation"] != o.ID.String() {
		return sub, errors.New("created subscription differs from saved operation")
	}
	var err error
	sub, err = c.clearYCFirstInvoiceDiscount(ctx, o, sub)
	if err != nil {
		return sub, err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET subscription_id=$2,first_invoice_id=COALESCE(first_invoice_id,NULLIF($3,'')) WHERE team_id=$1`, o.Team, sub.ID, sub.LatestInvoice)
	return sub, err
}
func (h *Handlers) ensureYCResources(ctx context.Context, o ycOperation, sub invoiceSubscription, c *stripeHTTPClient) (invoiceSubscription, error) {
	base := invoiceBase{Price: o.Params.BasePriceID, Amount: 1200000, Months: 12}
	resources, err := base.stripSubscription(sub)
	if err != nil {
		return sub, err
	}
	var rounding string
	err = h.Pool.QueryRow(ctx, `SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1 AND subscription_id=$2`, o.Team, sub.ID).Scan(&rounding)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return sub, err
	}
	if len(resources.Items.Data) > 0 {
		return sub, validateFrozenProResources(resources, o.Params.ResourceTerms, rounding)
	}
	if sub.Metadata["yc_usage_attached"] != "" {
		return sub, errors.New("previously attached usage items disappeared")
	}
	if sub.CancelAtPeriodEnd {
		return sub, errors.New("normalize cancellation to the verified absolute annual boundary before adoption")
	}
	var candidate invoiceSubscription
	for _, term := range o.Params.ResourceTerms {
		var price storagePrice
		if err = c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(term.PriceID), nil, &price, ""); err != nil {
			return sub, err
		}
		if !price.Active {
			return sub, errors.New("resource price became inactive")
		}
		candidate.Items.Data = append(candidate.Items.Data, invoiceSubscriptionItem{Price: price})
	}
	if err = validateFrozenProResources(candidate, o.Params.ResourceTerms, ""); err != nil {
		return sub, err
	}
	fresh, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return sub, err
	}
	if err = validateProUsageUpdate(sub, fresh, o.Params.BasePriceID); err != nil {
		return sub, err
	}
	if fresh.CancelAtPeriodEnd != sub.CancelAtPeriodEnd || len(fresh.Items.Data) != len(sub.Items.Data) || len(fresh.Discounts) != 0 || fresh.PendingUpdate != nil || fresh.Schedule != "" {
		return sub, errors.New("subscription changed before resource attachment")
	}
	form := url.Values{"proration_behavior": {"none"}, "metadata[yc_usage_attached]": {o.ID.String()}}
	for i, t := range o.Params.ResourceTerms {
		form.Set(fmt.Sprintf("items[%d][price]", i), t.PriceID)
	}
	if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), form, nil, "yc-usage:"+o.ID.String()); err != nil {
		return sub, err
	}
	updated, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return sub, err
	}
	if err = validateProUsageUpdate(sub, updated, o.Params.BasePriceID); err != nil {
		return sub, err
	}
	resources, err = base.stripSubscription(updated)
	if err != nil {
		return sub, err
	}
	return updated, validateFrozenProResources(resources, o.Params.ResourceTerms, rounding)
}
func (h *Handlers) lockAndReconcileYCCalendar(ctx context.Context, tx pgx.Tx, o ycOperation, token uuid.UUID) error {
	q := h.DB.WithTx(tx)
	if _, err := q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	// Match invoice enrollment's advisory-before-account order. The webhook
	// lease still fences subscription association changes and stale retries.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+o.Team.String()); err != nil {
		return err
	}
	a, err := q.LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return err
	}
	if derefString(a.StripeCustomerID) != o.Customer || (a.StripeSubscriptionID != nil && *a.StripeSubscriptionID != o.Subscription) || (o.State == "ended" && derefString(a.StripeSubscriptionID) != o.Subscription) {
		return errors.New("billing binding changed during adoption")
	}
	if _, err = tx.Exec(ctx, `SELECT reconcile_yc_billing_calendar($1,$2)`, o.Team, o.ID); err != nil {
		return err
	}
	return nil
}
func (h *Handlers) persistYCContract(ctx context.Context, o ycOperation, sub invoiceSubscription, token uuid.UUID) error {
	start, end, err := proMeteredPeriod(sub, proOffer{Key: "pro_annual", Price: o.Params.BasePriceID, Amount: 1200000, Months: 12})
	if err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = h.lockAndReconcileYCCalendar(ctx, tx, o, token); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET state=CASE WHEN state='active' THEN state ELSE 'enrolling' END WHERE team_id=$1`, o.Team)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status=$3,commercial_billing_anchor=$4,current_period_start=$5,current_period_end=$6,cancel_at_period_end=$7 WHERE team_id=$1`, o.Team, o.Subscription, sub.Status, o.Start.Time, time.Unix(start, 0), time.Unix(end, 0), sub.CancelAtPeriodEnd || sub.CancelAt > 0)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'yc_2026',$3,$4,$5,$6,$7,1200000,12,'metered_usage',100000,'scheduled',$3) ON CONFLICT(id) DO NOTHING`, o.Contract, o.Team, o.Start.Time, o.End.Time, o.Customer, o.Subscription, o.Params.BasePriceID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,CASE WHEN m<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) m WHERE NOT EXISTS(SELECT 1 FROM billing_contract_entitlement_schedule WHERE contract_id=$2)`, o.Team, o.Contract)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_contract_waiver(id,team_id,contract_id,offer_key,offer_version,customer_id,subscription_id,starts_at,ends_at,collectible_base_cents) SELECT $1,$2,$3,'yc_2026',1,$4,$5,$6,$7,0 WHERE NOT EXISTS(SELECT 1 FROM billing_contract_waiver WHERE id=$1)`, o.ID, o.Team, o.Contract, o.Customer, o.Subscription, o.Start.Time, o.End.Time)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_entitlement_work(contract_id) VALUES($1) ON CONFLICT DO NOTHING`, o.Contract)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (h *Handlers) adoptYCGrant(ctx context.Context, o ycOperation, c db.BillingCommercialContract, a invoiceAccount, client *stripeHTTPClient) error {
	if err := h.syncCreditInventory(ctx, c.ID, c.CustomerID, client); err != nil {
		return err
	}
	start, end, ok := billing.AnniversaryPeriod(c.EntitlementAnchor, time.Now())
	if !ok {
		return errors.New("YC current period unavailable")
	}
	p := billing.ExportPeriod{TeamID: c.TeamID, Start: start, End: end}
	if _, err := h.DB.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{TeamID: c.TeamID, PeriodStart: start, PeriodEnd: end, Status: "open"}); err != nil {
		return err
	}
	mapped, err := h.ensureInvoiceCalendar(ctx, p, a, client)
	if err != nil {
		return err
	}
	prices := []string{a.Price}
	for _, t := range o.Params.ResourceTerms {
		prices = append(prices, t.PriceID)
	}
	grants, err := h.eligibleInvoiceCredits(ctx, c.CustomerID, mapped.End.Unix(), prices, client)
	if err != nil {
		return err
	}
	if grants, err = h.withoutMatchingGrants(ctx, grants); err != nil {
		return err
	}
	grantID := ""
	balance := int64(0)
	if o.currentApprovedGrant() != "" {
		grantID = o.currentApprovedGrant()
		for _, g := range grants {
			if g.ID != grantID {
				return errors.New("another grant conflicts with approved adoption")
			}
		}
		balance, err = client.grantLedgerBalance(ctx, c.CustomerID, grantID)
		if err != nil {
			return err
		}
	} else {
		if len(grants) == 0 {
			return nil
		}
		if len(grants) != 1 {
			return errors.New("multiple existing credits require operator review")
		}
		grantID, balance = grants[0].ID, grants[0].Before
	}
	g, err := client.retrieveEntitlementGrant(ctx, grantID)
	if err != nil {
		return err
	}
	// The SQL adoption guard checks amount, full price scope, period, owner,
	// balance and metadata; no cash receipt is fabricated.
	raw, _ := json.Marshal(g)
	var evidence map[string]any
	_ = json.Unmarshal(raw, &evidence)
	evidence["available_balance_cents"] = balance
	raw, _ = json.Marshal(evidence)
	_, err = h.DB.AdoptUsageEntitlement(ctx, db.AdoptUsageEntitlementParams{TeamID: c.TeamID, ContractID: c.ID, GrantID: &g.ID, Evidence: raw, ProviderCreatedAt: time.Unix(g.Created, 0), AvailableBalanceCents: balance, InvoiceStart: mapped.Start, InvoiceEnd: mapped.End})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}
func (h *Handlers) ycSaveError(ctx context.Context, team uuid.UUID, err error) {
	ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, saveErr := h.Pool.Exec(ack, `UPDATE billing_yc_operation SET last_error=$2,next_check_at=clock_timestamp()+interval '1 minute' WHERE team_id=$1`, team, err.Error())
	log.Warn().Err(errors.Join(err, saveErr)).Str("team_id", team.String()).Msg("YC activation or renewal requires reconciliation")
}
func (h *Handlers) startYCReconciliation(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		return
	}
	go func() {
		for ctx.Err() == nil {
			tick, cancel := context.WithTimeout(ctx, 50*time.Second)
			rows, err := h.Pool.Query(tick, `WITH due AS (SELECT team_id FROM billing_yc_operation WHERE state<>'ended' AND next_check_at<=clock_timestamp() ORDER BY next_check_at,team_id FOR UPDATE SKIP LOCKED LIMIT 4) UPDATE billing_yc_operation o SET next_check_at=clock_timestamp()+interval '1 minute' FROM due WHERE o.team_id=due.team_id RETURNING o.team_id`)
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
				log.Warn().Err(err).Msg("YC scheduler failed")
			}
			cancel()
			runYCReconciliationBatch(ctx, teams, func(tick context.Context, team uuid.UUID) {
				started := time.Now()
				err := h.reconcileYC(tick, team)
				if err != nil {
					h.ycSaveError(tick, team, err)
				}
				currentBillingRecorder().RecordBillingWork(tick, "yc_reconciliation", err != nil, time.Since(started), 1)
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// Claims are bounded to four; a slow provider request gets its own deadline and
// cannot consume another team's payment-method refresh budget.
func runYCReconciliationBatch(ctx context.Context, teams []uuid.UUID, reconcile func(context.Context, uuid.UUID)) {
	var workers sync.WaitGroup
	for _, team := range teams {
		workers.Add(1)
		go func() {
			defer workers.Done()
			tick, cancel := context.WithTimeout(ctx, 50*time.Second)
			defer cancel()
			reconcile(tick, team)
		}()
	}
	workers.Wait()
}

func (h *Handlers) ensureYCCustomer(ctx context.Context, o ycOperation) (string, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	a, err := h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return "", err
	}
	if a.StripeCustomerID != nil {
		if _, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET customer_id=$2 WHERE team_id=$1`, o.Team, *a.StripeCustomerID); err != nil {
			return "", err
		}
		return *a.StripeCustomerID, tx.Commit(ctx)
	}
	var attempt pgtype.Timestamptz
	if err = tx.QueryRow(ctx, `UPDATE billing_yc_operation SET customer_attempt_at=COALESCE(customer_attempt_at,clock_timestamp()) WHERE team_id=$1 RETURNING customer_attempt_at`, o.Team).Scan(&attempt); err != nil {
		return "", err
	}
	if time.Since(attempt.Time) >= 23*time.Hour {
		return "", errors.New("customer creation outcome unknown beyond replay window; operator recovery required")
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	customer, err := h.Stripe.CreateCustomer(ctx, StripeCreateCustomerParams{TeamID: o.Team, Name: "YC team " + o.Team.String(), IdempotencyKey: "yc-customer:" + o.ID.String()})
	if err != nil {
		return "", err
	}
	tx, err = h.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	a, err = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, o.Team)
	if err != nil {
		return "", err
	}
	if a.StripeCustomerID != nil && *a.StripeCustomerID != customer.ID {
		return "", errors.New("customer binding changed during creation")
	}
	if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, o.Team, customer.ID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET customer_id=$2 WHERE team_id=$1`, o.Team, customer.ID); err != nil {
		return "", err
	}
	return customer.ID, tx.Commit(ctx)
}
