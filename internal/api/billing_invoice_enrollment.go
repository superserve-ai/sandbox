package api

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

const invoiceRoundingEvent = "invoice_rounding_cents_v1"
const invoiceRoundingLookup = "invoice_rounding_usd_monthly_v1"
const invoiceRoundingProduct = "prod_invoice_rounding_v1"

// Stable provider identities work across regions and beyond Stripe's request
// idempotency retention. Conflicts are retried through a fresh lookup.
func (c *stripeHTTPClient) ensureInvoiceCatalog(ctx context.Context) (invoiceAccount, error) {
	a := invoiceAccount{Event: invoiceRoundingEvent}
	var prices struct {
		Data    []storagePrice `json:"data"`
		HasMore bool           `json:"has_more"`
	}
	query := url.Values{"lookup_keys[]": {invoiceRoundingLookup}, "limit": {"2"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices?"+query.Encode(), nil, &prices, ""); err != nil {
		return a, err
	}
	if prices.HasMore || len(prices.Data) > 1 {
		return a, fmt.Errorf("ambiguous invoice rounding price")
	}
	if len(prices.Data) == 1 {
		a.Price = prices.Data[0].ID
		return a, nil
	}
	// The event name is unique at Stripe, including when a creation response is lost.
	meter, err := c.ActiveMeterID(ctx, a.Event)
	if err != nil {
		if err.Error() != "configured meter was not found within bounded lookup" {
			return a, err
		}
		var created struct {
			ID string `json:"id"`
		}
		form := url.Values{"display_name": {"Invoice rounding"}, "event_name": {a.Event}, "default_aggregation[formula]": {"sum"}, "customer_mapping[type]": {"by_id"}, "customer_mapping[event_payload_key]": {"stripe_customer_id"}, "value_settings[event_payload_key]": {"value"}}
		if err = c.doForm(ctx, http.MethodPost, "/v1/billing/meters", form, &created, "invoice-rounding-meter-v1"); err != nil {
			return a, err
		}
		meter = created.ID
	}
	if meter == "" {
		return a, fmt.Errorf("rounding meter identity missing")
	}
	var product struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	err = c.doForm(ctx, http.MethodGet, "/v1/products/"+invoiceRoundingProduct, nil, &product, "")
	if err != nil {
		if !strings.HasPrefix(err.Error(), "stripe GET /v1/products/"+invoiceRoundingProduct+" returned 404:") {
			return a, err
		}
		if err = c.doForm(ctx, http.MethodPost, "/v1/products", url.Values{"id": {invoiceRoundingProduct}, "name": {"Rounding adjustment"}}, &product, "invoice-rounding-product-v1"); err != nil {
			return a, err
		}
	}
	if product.ID != invoiceRoundingProduct || !product.Active {
		return a, fmt.Errorf("rounding product is unavailable")
	}
	var price storagePrice
	form := url.Values{"product": {product.ID}, "currency": {"usd"}, "unit_amount": {"1"}, "lookup_key": {invoiceRoundingLookup}, "recurring[interval]": {"month"}, "recurring[usage_type]": {"metered"}, "recurring[meter]": {meter}}
	if err = c.doForm(ctx, http.MethodPost, "/v1/prices", form, &price, "invoice-rounding-price-v1"); err != nil {
		return a, err
	}
	if price.ID == "" {
		return a, fmt.Errorf("rounding price identity missing")
	}
	a.Price, a.Meter = price.ID, meter
	return a, nil
}

// The account row serializes enrollment with association changes and other
// replicas. A failed provider request rolls back enrollment, not its retry job.
func (h *Handlers) enrollInvoiceAccount(ctx context.Context, team uuid.UUID, requested *invoiceAccount) error {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return fmt.Errorf("Stripe invoice reconciliation is unavailable")
	}
	// Persist a tentative boundary for response-loss recovery. Actual invoices
	// confirm or advance it after the provider hold exists, before enrollment commits.
	_, err := h.Pool.Exec(ctx, `INSERT INTO billing_invoice_enrollment(team_id,customer_id,subscription_id,started_at)
        SELECT team_id,stripe_customer_id,stripe_subscription_id,clock_timestamp() FROM team_billing_account WHERE team_id=$1 AND stripe_subscription_status='active' AND stripe_customer_id IS NOT NULL AND stripe_subscription_id IS NOT NULL AND commercial_billing_anchor IS NOT NULL AND feature_enabled('billing_export_enabled',team_id)
        ON CONFLICT(team_id) DO UPDATE SET started_at=COALESCE(billing_invoice_enrollment.started_at,EXCLUDED.started_at)`, team)
	if err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Association transitions must not race a close using the previous enrollment.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String()); err != nil {
		return err
	}
	var a invoiceAccount
	var anchored bool
	err = tx.QueryRow(ctx, `SELECT stripe_customer_id,stripe_subscription_id,commercial_billing_anchor IS NOT NULL FROM team_billing_account WHERE team_id=$1 AND stripe_subscription_status='active' AND feature_enabled('billing_export_enabled',team_id) FOR UPDATE`, team).Scan(&a.Customer, &a.Subscription, &anchored)
	if err != nil {
		return err
	}
	if !anchored {
		return fmt.Errorf("commercial billing anchor is required before invoice enrollment")
	}
	var existing invoiceAccount
	err = tx.QueryRow(ctx, `SELECT customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at FROM billing_invoice_account WHERE team_id=$1`, team).Scan(&existing.Customer, &existing.Subscription, &existing.Price, &existing.Event, &existing.Meter, &existing.EnrolledAt)
	enrolled := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	replacement := enrolled && (existing.Customer != a.Customer || existing.Subscription != a.Subscription)
	if enrolled {
		if requested != nil && (requested.Price != existing.Price || requested.Event != existing.Event) {
			return fmt.Errorf("existing rounding configuration differs; explicit recovery required")
		}
		a.Price, a.Event, a.Meter = existing.Price, existing.Event, existing.Meter
		if replacement {
			old, e := client.invoiceSubscription(ctx, existing.Subscription)
			if e != nil {
				return e
			}
			if old.Customer != existing.Customer || (old.Status != "canceled" && old.Status != "incomplete_expired") {
				return fmt.Errorf("previous subscription must be terminated before replacement enrollment")
			}
		}
	} else {
		catalog := invoiceAccount{}
		if requested != nil {
			catalog = *requested
		} else {
			catalog, err = client.ensureInvoiceCatalog(ctx)
			if err != nil {
				return err
			}
		}
		a.Price, a.Event, a.Meter = catalog.Price, catalog.Event, catalog.Meter
	}
	for _, resource := range h.billingResourceStates(true) {
		if a.Price == resource.StripePriceID || a.Event == resource.StripeEventName {
			return fmt.Errorf("rounding price and event must be separate from resource usage")
		}
	}
	if !enrolled || replacement {
		if err = h.validateInvoiceEnrollment(ctx, team, a, client); err != nil {
			return err
		}
	}
	// Fail before changing collection for unsupported credit configurations.
	if !enrolled || replacement {
		if _, err = client.invoiceCreditLedger(ctx, a.Customer, time.Now().Unix()); err != nil {
			return err
		}
	}
	var validate func(invoiceSubscription) error
	if !enrolled || replacement {
		validate = func(sub invoiceSubscription) error {
			return h.validateInvoiceEnrollmentSubscription(ctx, team, a, client, sub)
		}
	}
	a, err = client.ensureInvoiceSubscriptionValidated(ctx, a, !enrolled || replacement, false, validate)
	if err != nil {
		return err
	}
	if !enrolled || replacement {
		var attempt time.Time
		if err = tx.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&attempt); err != nil {
			return err
		}
		boundary, e := client.invoiceEnrollmentBoundary(ctx, a, attempt)
		if e != nil {
			return e
		}
		if _, err = tx.Exec(ctx, `UPDATE billing_invoice_enrollment SET started_at=$2 WHERE team_id=$1`, team, boundary); err != nil {
			return err
		}
		if _, err = client.ensureInvoiceSubscriptionValidated(ctx, a, false, false, validate); err != nil {
			return err
		}
	}
	if replacement {
		// Keep the replacement held even when old periods still need recovery.
		// Never reinterpret their immutable plans or usage as the new subscription.
		var pending bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_period p JOIN billing_invoice_enrollment w USING(team_id) LEFT JOIN billing_invoice_close j USING(team_id,period_start,period_end)
            WHERE p.team_id=$1 AND p.period_end>$2 AND p.period_start<w.requested_at
              AND (p.period_end<=w.requested_at OR p.created_at<w.requested_at)
              AND (p.finalized_at IS NULL OR COALESCE(j.state,'')<>'released'))`, team, existing.EnrolledAt).Scan(&pending)
		if err != nil {
			return err
		}
		if pending {
			return fmt.Errorf("replacement is held; previous invoice periods require recovery before association transition")
		}
		_, err = tx.Exec(ctx, `UPDATE billing_invoice_account SET customer_id=$2,subscription_id=$3,adjustment_meter_id=$4,
            enrolled_at=(SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1),last_attempt_at=NULL,last_error=NULL WHERE team_id=$1`, team, a.Customer, a.Subscription, a.Meter)
		if err != nil {
			return err
		}
	} else if !enrolled {
		_, err = tx.Exec(ctx, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) SELECT $1,$2,$3,$4,$5,$6,started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team, a.Customer, a.Subscription, a.Price, a.Event, a.Meter)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE billing_invoice_enrollment SET completed_at=clock_timestamp(),last_error=NULL WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) invoiceEnrollmentTick(ctx context.Context) (bool, error) {
	started := time.Now()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var team uuid.UUID
	err = tx.QueryRow(ctx, `SELECT w.team_id FROM billing_invoice_enrollment w JOIN team_billing_account a USING(team_id)
 WHERE w.completed_at IS NULL AND w.next_attempt_at<=now() AND a.stripe_subscription_status='active'
 AND a.stripe_customer_id IS NOT NULL AND a.stripe_subscription_id IS NOT NULL AND feature_enabled('billing_export_enabled',w.team_id)
 ORDER BY w.next_attempt_at,w.team_id LIMIT 1 FOR UPDATE OF w SKIP LOCKED`).Scan(&team)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// This persisted reservation outlives the bounded request and avoids a failed
	// account starving the queue. The account lock handles lease overruns safely.
	_, err = tx.Exec(ctx, `UPDATE billing_invoice_enrollment SET attempt_count=attempt_count+1,next_attempt_at=clock_timestamp()+interval '2 minutes' WHERE team_id=$1`, team)
	if err != nil {
		return true, err
	}
	if err = tx.Commit(ctx); err != nil {
		return true, err
	}
	err = h.enrollInvoiceAccount(ctx, team, nil)
	if err != nil {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, _ = h.Pool.Exec(ack, `UPDATE billing_invoice_enrollment SET last_error=$2 WHERE team_id=$1 AND completed_at IS NULL`, team, err.Error())
	}
	currentBillingRecorder().RecordBillingWork(ctx, "invoice_enrollment", err != nil, time.Since(started), 1)
	return true, err
}

func (h *Handlers) StartInvoiceEnrollmentService(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			work, cancel := context.WithTimeout(ctx, 45*time.Second)
			_, err := h.invoiceEnrollmentTick(work)
			cancel()
			if err != nil {
				log.Warn().Err(err).Msg("automatic invoice enrollment pending")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (h *Handlers) validateInvoiceEnrollment(ctx context.Context, team uuid.UUID, a invoiceAccount, c *stripeHTTPClient) error {
	sub, err := c.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return err
	}
	return h.validateInvoiceEnrollmentSubscription(ctx, team, a, c, sub)
}

func (h *Handlers) validateInvoiceEnrollmentSubscription(ctx context.Context, team uuid.UUID, a invoiceAccount, c *stripeHTTPClient, sub invoiceSubscription) error {
	var anchor time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, team).Scan(&anchor); err != nil {
		return err
	}
	if err := invoiceCalendarCompatible(anchor, sub, a.Price); err != nil {
		return err
	}
	storage, err := h.billingStorageBillingEnabledForWindow(ctx, team, time.Now())
	if err != nil {
		return err
	}
	rates, err := h.DB.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: team, EffectiveAt: time.Now()})
	if err != nil {
		return err
	}
	expected := map[string]*big.Rat{}
	events := map[string]string{}
	required := map[string]bool{}
	for _, resource := range h.billingResourceStates(storage) {
		if !resource.SubscriptionIncluded() {
			continue
		}
		if _, duplicate := events[resource.StripePriceID]; duplicate || resource.StripeEventName == "" {
			return fmt.Errorf("resource price/event configuration is ambiguous")
		}
		for _, event := range events {
			if event == resource.StripeEventName {
				return fmt.Errorf("resource price/event configuration is ambiguous")
			}
		}
		events[resource.StripePriceID] = resource.StripeEventName
		for _, rate := range rates {
			if rate.Resource == resource.ResourceKey && rate.Unit == "second" {
				value, e := rate.PriceUsd.Value()
				if e != nil {
					return e
				}
				r, ok := new(big.Rat).SetString(fmt.Sprint(value))
				if !ok {
					return fmt.Errorf("invalid resource rate")
				}
				expected[resource.StripePriceID] = new(big.Rat).Mul(r, big.NewRat(360000, 1))
			}
		}
		if resource.Billable {
			required[resource.StripePriceID] = true
		}
	}
	seen := map[string]bool{}
	for _, item := range sub.Items.Data {
		p := item.Price
		if p.ID == a.Price {
			continue
		}
		rate, ok := expected[p.ID]
		amount, e := meterDecimal(p.UnitAmountDecimal)
		if !ok || e != nil || seen[p.ID] || !p.Active || amount.Cmp(rate) != 0 || p.Currency != "usd" || p.BillingScheme != "per_unit" || p.TransformQuantity != nil || p.Recurring.UsageType != "metered" || p.Recurring.Interval != "month" || p.Recurring.IntervalCount != 1 {
			return fmt.Errorf("subscription resource pricing is not supported for automatic enrollment")
		}
		meter, e := c.ActiveMeterID(ctx, events[p.ID])
		if e != nil {
			return e
		}
		if meter != p.Recurring.Meter {
			return fmt.Errorf("resource event meter differs from subscription price meter")
		}
		seen[p.ID] = true
		delete(required, p.ID)
	}
	if len(required) != 0 || len(seen) == 0 {
		return fmt.Errorf("subscription is missing configured billable resource items")
	}
	return nil
}
