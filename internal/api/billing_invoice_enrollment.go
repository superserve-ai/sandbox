package api

import (
	"context"
	"encoding/json"
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

// invoiceEnrollmentPlan is what the provider work decided, computed without
// the account lock from a snapshot of the team's billing rows.
type invoiceEnrollmentPlan struct {
	account     invoiceAccount
	existing    invoiceAccount
	enrolled    bool
	replacement bool
	attempt     time.Time
	boundary    time.Time
	fingerprint string
}

var errInvoiceEnrollmentChanged = errors.New("billing account changed during enrollment; retrying")

// The account lock serializes enrollment with association changes and other
// replicas, but never spans a provider round trip: planInvoiceEnrollment does
// the Stripe work against a snapshot of the rows, then recordInvoiceEnrollment
// takes the lock, confirms the snapshot still holds, and writes. A change in
// between fails this attempt and the retry job runs it again. A failed
// provider request rolls back enrollment, not its retry job.
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
	plan, err := h.planInvoiceEnrollment(ctx, team, requested, client)
	if err != nil {
		return err
	}
	return h.recordInvoiceEnrollment(ctx, team, plan)
}

// planInvoiceEnrollment reads the team's billing rows in one read-only
// transaction and consults the provider. It holds no advisory lock, so a
// slow provider call blocks no other billing work on the team.
func (h *Handlers) planInvoiceEnrollment(ctx context.Context, team uuid.UUID, requested *invoiceAccount, client *stripeHTTPClient) (invoiceEnrollmentPlan, error) {
	var p invoiceEnrollmentPlan
	// One snapshot for every read, so the fingerprint covers exactly the
	// rows the provider validation below was computed from.
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	if p.fingerprint, err = invoiceEnrollmentFingerprint(ctx, tx, team, true); err != nil {
		return p, err
	}
	var a invoiceAccount
	var anchored bool
	err = tx.QueryRow(ctx, `SELECT stripe_customer_id,stripe_subscription_id,commercial_billing_anchor IS NOT NULL FROM team_billing_account WHERE team_id=$1 AND stripe_subscription_status='active' AND feature_enabled('billing_export_enabled',team_id)`, team).Scan(&a.Customer, &a.Subscription, &anchored)
	if err != nil {
		return p, err
	}
	if err = h.requireInvoiceCalendarReconciled(ctx, tx, team, a); err != nil {
		return p, err
	}
	if err = h.loadInvoiceBase(ctx, team, &a, tx); err != nil {
		return p, err
	}
	var firstCycle bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND request_payload->>'FirstPaidProCycle'='true')`, team, a.Customer, a.Subscription).Scan(&firstCycle); err != nil {
		return p, err
	}
	if firstCycle {
		sub, e := client.invoiceSubscription(ctx, a.Subscription)
		if e != nil {
			return p, e
		}
		if e = h.verifyFirstProCycleProviderCalendar(ctx, tx, sub); e != nil {
			return p, e
		}
	}

	if !anchored {
		return p, fmt.Errorf("commercial billing anchor is required before invoice enrollment")
	}
	existing, enrolled, err := readInvoiceAccount(ctx, tx, team)
	if err != nil {
		return p, err
	}
	replacement := enrolled && (existing.Customer != a.Customer || existing.Subscription != a.Subscription)
	if enrolled {
		if requested != nil && (requested.Price != existing.Price || requested.Event != existing.Event) {
			return p, fmt.Errorf("existing rounding configuration differs; explicit recovery required")
		}
		a.Price, a.Event, a.Meter = existing.Price, existing.Event, existing.Meter
		if replacement {
			old, e := client.invoiceSubscription(ctx, existing.Subscription)
			if e != nil {
				return p, e
			}
			if old.Customer != existing.Customer || (old.Status != "canceled" && old.Status != "incomplete_expired") {
				return p, fmt.Errorf("previous subscription must be terminated before replacement enrollment")
			}
		}
	} else {
		catalog := invoiceAccount{}
		if requested != nil {
			catalog = *requested
		} else {
			catalog, err = client.ensureInvoiceCatalog(ctx)
			if err != nil {
				return p, err
			}
		}
		a.Price, a.Event, a.Meter = catalog.Price, catalog.Event, catalog.Meter
	}
	for _, resource := range h.billingResourceStates(true) {
		if a.Base.Price == "" && (a.Price == resource.StripePriceID || a.Event == resource.StripeEventName) {
			return p, fmt.Errorf("rounding price and event must be separate from resource usage")
		}
	}
	if !enrolled || replacement {
		if err = h.validateInvoiceEnrollment(ctx, team, a, client, tx); err != nil {
			return p, err
		}
	}
	// Fail before changing collection for unsupported credit configurations.
	if !enrolled || replacement {
		var ycContract, ycGrant string
		ycErr := tx.QueryRow(ctx, `SELECT contract_id::text,COALESCE(request->>'existing_grant_id','') FROM billing_yc_operation WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3`, team, a.Customer, a.Subscription).Scan(&ycContract, &ycGrant)
		if ycErr == nil {
			err = client.ycGrantPreflight(ctx, a.Customer, ycContract, ycGrant)
		} else if errors.Is(ycErr, pgx.ErrNoRows) {
			var released bool
			released, err = h.preflightFirstProCycleCredits(ctx, team, a, client, tx)
			if err == nil && !released {
				released, err = h.preflightReleasedFundingCredits(ctx, team, a, client, tx)
			}
			if err == nil && !released {
				_, err = client.invoiceCreditLedger(ctx, a.Customer, time.Now().Unix())
			}
		} else {
			err = ycErr
		}
		if err != nil {
			return p, err
		}
	}
	var validate func(invoiceSubscription) error
	if !enrolled || replacement {
		validate = func(sub invoiceSubscription) error {
			return h.validateInvoiceEnrollmentSubscription(ctx, team, a, client, sub, tx)
		}
	}
	a, err = client.ensureInvoiceSubscriptionValidated(ctx, a, !enrolled || replacement, false, validate)
	if err != nil {
		return p, err
	}
	var attempt time.Time
	if err = tx.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&attempt); err != nil {
		return p, err
	}
	boundary := attempt
	if !enrolled || replacement {
		if boundary, err = client.invoiceEnrollmentBoundary(ctx, a, attempt); err != nil {
			return p, err
		}
		if _, err = client.ensureInvoiceSubscriptionValidated(ctx, a, false, false, validate); err != nil {
			return p, err
		}
	}
	p.account, p.existing, p.enrolled, p.replacement, p.attempt, p.boundary = a, existing, enrolled, replacement, attempt, boundary
	return p, nil
}

// recordInvoiceEnrollment takes the account lock, confirms the rows the plan
// was computed from are unchanged, and records the enrollment.
func (h *Handlers) recordInvoiceEnrollment(ctx context.Context, team uuid.UUID, p invoiceEnrollmentPlan) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Association transitions must not race a close using the previous enrollment.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String()); err != nil {
		return err
	}
	var current invoiceAccount
	var anchored bool
	err = tx.QueryRow(ctx, `SELECT stripe_customer_id,stripe_subscription_id,commercial_billing_anchor IS NOT NULL FROM team_billing_account WHERE team_id=$1 AND stripe_subscription_status='active' AND feature_enabled('billing_export_enabled',team_id) FOR UPDATE`, team).Scan(&current.Customer, &current.Subscription, &anchored)
	if errors.Is(err, pgx.ErrNoRows) {
		return errInvoiceEnrollmentChanged
	}
	if err != nil {
		return err
	}
	if err = h.requireInvoiceCalendarReconciled(ctx, tx, team, current); err != nil {
		return err
	}
	existing, enrolled, err := readInvoiceAccount(ctx, tx, team)
	if err != nil {
		return err
	}
	// An association change clears the attempt, so it is read as nullable.
	var attempt *time.Time
	if err = tx.QueryRow(ctx, `SELECT started_at FROM billing_invoice_enrollment WHERE team_id=$1`, team).Scan(&attempt); err != nil {
		return err
	}
	fingerprint, err := invoiceEnrollmentFingerprint(ctx, tx, team, true)
	if err != nil {
		return err
	}
	if fingerprint != p.fingerprint ||
		current.Customer != p.account.Customer || current.Subscription != p.account.Subscription || !anchored ||
		enrolled != p.enrolled || attempt == nil || !attempt.Equal(p.attempt) ||
		existing.Customer != p.existing.Customer || existing.Subscription != p.existing.Subscription ||
		existing.Price != p.existing.Price || existing.Event != p.existing.Event || existing.Meter != p.existing.Meter ||
		!existing.EnrolledAt.Equal(p.existing.EnrolledAt) {
		return errInvoiceEnrollmentChanged
	}
	a := p.account
	if !enrolled || p.replacement {
		if _, err = tx.Exec(ctx, `UPDATE billing_invoice_enrollment SET started_at=$2 WHERE team_id=$1`, team, p.boundary); err != nil {
			return err
		}
	}
	if p.replacement {
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

// invoiceEnrollmentFingerprint hashes the versions of every row the plan
// reads: the team's account, contracts, upgrades, credits, plan and pricing
// assignments, storage activation, sponsored or YC operations, and the pricing
// catalog, plus whether each time-bound pricing or storage row is in effect
// now. A transition that keeps the customer and subscription IDs but changes
// any of that state, or an effective boundary that passes meanwhile, still
// changes the hash, so the record step refuses a plan validated against the
// previous state. The plan judges the windows at its snapshot's now(); the
// record step, whose transaction began before its lock wait, judges them at
// the statement after the lock, since the wait may have spanned a boundary.
// Checkout recovery rewrites retry bookkeeping on every poll; enrollment never
// reads those columns, so they are left out rather than invalidating the plan.
func invoiceEnrollmentFingerprint(ctx context.Context, reader db.DBTX, team uuid.UUID, afterLockWait bool) (string, error) {
	var fingerprint string
	err := reader.QueryRow(ctx, `WITH t AS (SELECT CASE WHEN $2 THEN statement_timestamp() ELSE now() END AS at)
        SELECT md5(COALESCE(string_agg(v,',' ORDER BY v),'')) FROM (
        SELECT 'a'||xmin::text FROM team_billing_account WHERE team_id=$1
        UNION ALL SELECT 'i'||xmin::text FROM billing_invoice_account WHERE team_id=$1
        UNION ALL SELECT 'c'||id::text||xmin::text FROM billing_commercial_contract WHERE team_id=$1
        UNION ALL SELECT 'p'||id::text||xmin::text FROM billing_contract_payment WHERE team_id=$1
        UNION ALL SELECT 'r'||id::text||xmin::text FROM billing_plan_release WHERE team_id=$1
        UNION ALL SELECT 'u'||id::text||md5((to_jsonb(u)-'{next_check_at,last_error}'::text[])::text) FROM billing_pro_upgrade u WHERE team_id=$1
        UNION ALL SELECT 'k'||c.id::text||c.xmin::text FROM billing_pro_upgrade_catchup c JOIN billing_pro_upgrade u ON u.id=c.upgrade_id WHERE u.team_id=$1
        UNION ALL SELECT 's'||offer_key||md5((to_jsonb(s)-'{next_check_at,last_error,paid_observed_at,paid_observed_until,invoice_cursor}'::text[])::text) FROM billing_signup_choice s WHERE team_id=$1
        UNION ALL SELECT 'n'||id::text||xmin::text FROM billing_sponsored_annual_authority WHERE team_id=$1
        UNION ALL SELECT 'o'||id::text||xmin::text FROM billing_sponsored_operation WHERE team_id=$1
        UNION ALL SELECT 't'||operation_id::text||xmin::text FROM billing_yc_calendar_transition WHERE team_id=$1
        UNION ALL SELECT 'y'||id::text||xmin::text FROM billing_yc_operation WHERE team_id=$1
        UNION ALL SELECT 'l'||id::text||xmin::text FROM team_plan_assignment WHERE team_id=$1
        UNION ALL SELECT 'g'||plan_key||xmin::text||(effective_from<=t.at AND (effective_to IS NULL OR effective_to>t.at))::text FROM team_pricing_plan, t WHERE team_id=$1
        UNION ALL SELECT 'b'||effective_at::text||xmin::text||(effective_at<t.at)::text FROM team_storage_billing_activation, t WHERE team_id=$1
        UNION ALL SELECT 'q'||key||xmin::text FROM pricing_plan
        UNION ALL SELECT 'e'||id::text||xmin::text||(effective_from<=t.at AND (effective_to IS NULL OR effective_to>t.at))::text FROM pricing_rate, t) s(v)`, team, afterLockWait).Scan(&fingerprint)
	return fingerprint, err
}

// requireInvoiceCalendarReconciled refuses enrollment while a YC operation
// still owes a calendar transition for this association.
func (h *Handlers) requireInvoiceCalendarReconciled(ctx context.Context, reader db.DBTX, team uuid.UUID, a invoiceAccount) error {
	var calendarPending bool
	if err := reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_yc_operation o
        WHERE o.team_id=$1 AND (o.state IN ('approved','provider_pending','enrolling','active','renewal_pending','renewed')
        OR (o.state='ended' AND o.starts_at IS NOT NULL AND o.customer_id=$2 AND o.subscription_id=$3))
        AND NOT EXISTS(SELECT 1 FROM billing_yc_calendar_transition r WHERE r.operation_id=o.id))`, team, a.Customer, a.Subscription).Scan(&calendarPending); err != nil {
		return err
	}
	if calendarPending {
		return fmt.Errorf("YC calendar reconciliation is required before invoice enrollment; retry YC activation and follow the Billing plans, entitlements and calendar recovery runbook on conflict")
	}
	return nil
}

// readInvoiceAccount returns the team's recorded enrollment, if any.
func readInvoiceAccount(ctx context.Context, reader db.DBTX, team uuid.UUID) (invoiceAccount, bool, error) {
	var existing invoiceAccount
	err := reader.QueryRow(ctx, `SELECT customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at FROM billing_invoice_account WHERE team_id=$1`, team).Scan(&existing.Customer, &existing.Subscription, &existing.Price, &existing.Event, &existing.Meter, &existing.EnrolledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return invoiceAccount{}, false, nil
	}
	return existing, err == nil, err
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

func (h *Handlers) validateInvoiceEnrollment(ctx context.Context, team uuid.UUID, a invoiceAccount, c *stripeHTTPClient, reader db.DBTX) error {
	sub, err := c.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return err
	}
	return h.validateInvoiceEnrollmentSubscription(ctx, team, a, c, sub, reader)
}

func (h *Handlers) validateInvoiceEnrollmentSubscription(ctx context.Context, team uuid.UUID, a invoiceAccount, c *stripeHTTPClient, sub invoiceSubscription, reader db.DBTX) error {
	if err := h.verifyFirstProCycleProviderCalendar(ctx, reader, sub); err != nil {
		return err
	}
	if a.Base.Item != "" {
		o, err := h.sponsoredAnnualAuthority(ctx, team, reader)
		if err != nil {
			return err
		}
		return validateSponsoredAnnualSubscription(o, sub, a.Price, false)
	}
	var stripErr error
	sub, stripErr = a.Base.stripSubscription(sub)
	if stripErr != nil {
		return stripErr
	}
	if a.Base.Price != "" {
		var payload []byte
		if err := reader.QueryRow(ctx, `SELECT request_payload FROM billing_pro_upgrade WHERE team_id=$1 AND subscription_id=$2 AND state<>'expired' UNION ALL SELECT request_payload FROM billing_signup_choice WHERE team_id=$1 AND subscription_id=$2 AND NOT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=$1 AND subscription_id=$2 AND state<>'expired') UNION ALL SELECT resource_terms || jsonb_build_object('CustomerID',customer_id) FROM billing_yc_operation WHERE team_id=$1 AND subscription_id=$2`, team, a.Subscription).Scan(&payload); err != nil {
			return err
		}
		var params StripeCreateCheckoutSessionParams
		if err := json.Unmarshal(payload, &params); err != nil {
			return err
		}
		if params.CustomerID != a.Customer || params.BasePriceID != a.Base.Price {
			return fmt.Errorf("frozen Pro enrollment association differs")
		}
		for _, term := range params.ResourceTerms {
			if term.PriceID == a.Price || term.EventName == a.Event || (a.Meter != "" && term.MeterID == a.Meter) {
				return fmt.Errorf("rounding configuration overlaps frozen resource terms")
			}
		}
		if err := invoiceCalendarCompatible(a.Base.Anchor, sub, a.Price); err != nil {
			return err
		}
		return validateFrozenProResources(sub, params.ResourceTerms, a.Price)
	}
	var anchor time.Time
	if err := reader.QueryRow(ctx, `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, team).Scan(&anchor); err != nil {
		return err
	}
	var frozen []byte
	err := reader.QueryRow(ctx, `SELECT resource_terms FROM billing_sponsored_operation WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 ORDER BY approved_at DESC,id DESC LIMIT 1`, team, a.Customer, a.Subscription).Scan(&frozen)
	if err == nil {
		var params StripeCreateCheckoutSessionParams
		if err = json.Unmarshal(frozen, &params); err != nil {
			return err
		}
		if err = validateEntitlementResourceTerms(params.ResourceTerms, "", "", "", false); err != nil {
			return err
		}
		for _, term := range params.ResourceTerms {
			if term.PriceID == a.Price || term.EventName == a.Event || a.Meter != "" && term.MeterID == a.Meter {
				return errors.New("rounding configuration overlaps frozen sponsored resources")
			}
		}
		if err = invoiceCalendarCompatible(anchor, sub, a.Price); err != nil {
			return err
		}
		return validateFrozenProResources(sub, params.ResourceTerms, a.Price)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return h.validateInvoiceResourceSubscription(ctx, team, a, c, sub, anchor, reader)
}

func (h *Handlers) validateInvoiceResourceSubscription(ctx context.Context, team uuid.UUID, a invoiceAccount, c *stripeHTTPClient, sub invoiceSubscription, anchor time.Time, reader db.DBTX) error {
	if err := h.verifyFirstProCycleProviderCalendar(ctx, reader, sub); err != nil {
		return err
	}
	if err := invoiceCalendarCompatible(anchor, sub, a.Price); err != nil {
		return err
	}
	queries := db.New(reader)
	storage, err := queries.IsStorageBillingActivatedForWindow(ctx, db.IsStorageBillingActivatedForWindowParams{TeamID: team, PeriodEnd: time.Now()})
	if err != nil {
		return err
	}
	rates, err := queries.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: team, EffectiveAt: time.Now()})
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
