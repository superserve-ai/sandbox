package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errInvoiceAssociationChanged = errors.New("invoice account association changed")

func (h *Handlers) invoiceAccount(ctx context.Context, team uuid.UUID) (invoiceAccount, bool, error) {
	var a invoiceAccount
	var currentCustomer, currentSubscription *string
	err := h.Pool.QueryRow(ctx, `SELECT i.customer_id,i.subscription_id,i.adjustment_price_id,i.adjustment_event_name,i.adjustment_meter_id,i.enrolled_at,b.stripe_customer_id,b.stripe_subscription_id FROM billing_invoice_account i JOIN team_billing_account b USING(team_id) WHERE team_id=$1`, team).Scan(&a.Customer, &a.Subscription, &a.Price, &a.Event, &a.Meter, &a.EnrolledAt, &currentCustomer, &currentSubscription)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return a, false, err
	}
	if currentCustomer == nil || currentSubscription == nil || *currentCustomer != a.Customer || *currentSubscription != a.Subscription {
		return a, true, errInvoiceAssociationChanged
	}
	return a, true, nil
}

// A queued replacement cannot take ownership of a previously frozen period.
// Retain the saved association until those invoices are settled and released.
func (h *Handlers) invoiceAccountForPeriod(ctx context.Context, p billing.ExportPeriod) (invoiceAccount, bool, error) {
	a, enrolled, err := h.invoiceAccount(ctx, p.TeamID)
	if !errors.Is(err, errInvoiceAssociationChanged) || !a.EnrolledAt.Before(p.End) {
		return a, enrolled, err
	}
	err = h.Pool.QueryRow(ctx, `SELECT b.stripe_customer_id,b.stripe_subscription_id
        FROM team_billing_period p JOIN billing_incremental_period i USING(team_id,period_start,period_end)
        JOIN billing_invoice_enrollment w USING(team_id) JOIN team_billing_account b USING(team_id)
        WHERE p.team_id=$1 AND p.period_start=$2 AND p.period_end=$3
          AND (p.status IN ('exporting','exported') OR p.finalized_at IS NOT NULL)
		  AND p.period_end<=w.requested_at AND w.completed_at IS NULL
		  AND w.customer_id=b.stripe_customer_id AND w.subscription_id=b.stripe_subscription_id
          AND b.stripe_subscription_status='active' AND b.stripe_customer_id IS NOT NULL AND b.stripe_subscription_id IS NOT NULL`, p.TeamID, p.Start, p.End).Scan(&a.ReplacementCustomer, &a.ReplacementSubscription)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, enrolled, errInvoiceAssociationChanged
	}
	return a, enrolled, err
}

func (h *Handlers) EnrollInvoiceReconciliation(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingWritePermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	var input struct {
		Price string `json:"adjustment_price_id"`
		Event string `json:"adjustment_event_name"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err = c.ShouldBindJSON(&input); err != nil || input.Price == "" || input.Event == "" {
		respondErrorMsg(c, "bad_request", "adjustment_price_id and adjustment_event_name are required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	err = h.enrollInvoiceAccount(ctx, team, &invoiceAccount{Price: input.Price, Event: input.Event})
	if err != nil {
		respondErrorMsg(c, "invoice_reconciliation_unavailable", err.Error(), http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "enrolled", "collection": "held"})
}

// Scheduled reconciliation is independent of webhook delivery and of the
// hourly export lease. It never runs on sandbox lifecycle request paths.
func (h *Handlers) StartInvoiceReconciliationService(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			workCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
			_, err := h.invoiceReconciliationTick(workCtx)
			if err != nil {
				log.Warn().Err(err).Msg("invoice cent reconciliation held")
			}
			cancel()
		}
	}()
}

func (h *Handlers) invoiceReconciliationTick(ctx context.Context) (bool, error) {
	var p billing.ExportPeriod
	err := h.Pool.QueryRow(ctx, `SELECT p.team_id,p.period_start,p.period_end FROM team_billing_period p JOIN billing_invoice_account a USING(team_id) LEFT JOIN billing_invoice_close j USING(team_id,period_start,period_end)
     WHERE a.enrolled_at<p.period_end AND p.period_end<=now() AND p.status IN ('exporting','exported','finalized') AND COALESCE(j.state,'')<>'released'
     ORDER BY a.last_attempt_at NULLS FIRST,p.period_end LIMIT 1`).Scan(&p.TeamID, &p.Start, &p.End)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = h.reconcileInvoicePeriod(ctx, p)
	if err != nil {
		return true, fmt.Errorf("team %s: %w", p.TeamID, err)
	}
	return true, nil
}

func invoicePlanKey(invoiceID string) string { return "invoice-cent:" + invoiceID }

func (h *Handlers) reconcileInvoicePeriod(ctx context.Context, p billing.ExportPeriod) (resultErr error) {
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		var message *string
		if resultErr != nil {
			v := resultErr.Error()
			message = &v
		}
		_, _ = h.Pool.Exec(ack, `UPDATE billing_invoice_account SET last_attempt_at=clock_timestamp(),last_error=$2 WHERE team_id=$1`, p.TeamID, message)
		if resultErr != nil {
			_, _ = h.Pool.Exec(ack, `UPDATE billing_invoice_close SET last_error=$4,updated_at=clock_timestamp() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End, resultErr.Error())
		}
	}()
	a, enrolled, err := h.invoiceAccountForPeriod(ctx, p)
	if err != nil {
		return err
	}
	if !enrolled || !a.EnrolledAt.Before(p.End) {
		return nil
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return fmt.Errorf("invoice provider unavailable")
	}
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, "invoice:"+p.TeamID.String()).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("invoice reconciliation already running")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, e := conn.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, "invoice:"+p.TeamID.String())
		if e != nil {
			conn.Conn().Close(cleanup)
		}
	}()
	if _, err = client.ensureInvoiceSubscription(ctx, a, false, true); err != nil {
		return err
	}
	// Older held periods have first claim on credits and must finish first.
	var older bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_period p JOIN billing_invoice_account a USING(team_id) LEFT JOIN billing_invoice_close j USING(team_id,period_start,period_end) WHERE p.team_id=$1 AND p.period_end>$2 AND p.period_end<=$3 AND COALESCE(j.state,'')<>'released')`, p.TeamID, a.EnrolledAt, p.Start).Scan(&older); err != nil {
		return err
	}
	if older {
		return fmt.Errorf("earlier invoice period remains held")
	}
	var invoiceID, state string
	var raw []byte
	var firstAdjustment *time.Time
	err = h.Pool.QueryRow(ctx, `SELECT invoice_id,state,plan,first_adjustment_at FROM billing_invoice_close WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&invoiceID, &state, &raw, &firstAdjustment)
	var plan billing.InvoiceClosePlan
	if errors.Is(err, pgx.ErrNoRows) {
		invoicePeriod, e := h.ensureInvoiceCalendar(ctx, p, a, client)
		if e != nil {
			return e
		}
		inv, e := client.billingCycleInvoice(ctx, a, invoicePeriod.Start.Unix(), invoicePeriod.End.Unix())
		if e != nil {
			return e
		}
		if inv.Status != "draft" || inv.AutoAdvance {
			return fmt.Errorf("cycle invoice must already be held in draft")
		}
		plan, e = h.prepareInvoicePlan(ctx, p, a, inv, client)
		if e != nil {
			return e
		}
		raw, e = json.Marshal(plan)
		if e != nil {
			return e
		}
		invoiceID = inv.ID
		_, err = h.Pool.Exec(ctx, `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan) VALUES($1,$2,$3,$4,$5)`, p.TeamID, p.Start, p.End, invoiceID, raw)
		if err != nil {
			return err
		}
		state = "prepared"
	} else if err != nil {
		return err
	} else if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	invoicePeriod := invoicePlanPeriod(p, plan)
	if plan.Customer != a.Customer || plan.Subscription != a.Subscription {
		return fmt.Errorf("saved invoice scope differs")
	}
	if err = h.validateInvoicePlan(ctx, p, a, plan, client); err != nil {
		return err
	}
	advance := func(next string) error {
		_, e := h.Pool.Exec(ctx, `UPDATE billing_invoice_close SET state=$4,last_error=NULL,updated_at=clock_timestamp() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End, next)
		if e == nil {
			state = next
		}
		return e
	}
	if state == "released" {
		return nil
	}
	if state == "verified" {
		var localFinal bool
		if err = h.Pool.QueryRow(ctx, `SELECT finalized_at IS NOT NULL AND billing_invoice_close_matches(team_id,period_start,period_end) FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&localFinal); err != nil {
			return err
		}
		if !localFinal {
			return nil
		}
		final, e := client.RetrieveBillingInvoice(ctx, invoiceID)
		if e != nil {
			return e
		}
		if e = validateInvoiceDocument(final, invoicePeriod, a, plan); e != nil {
			return e
		}
		remaining, e := client.invoiceCreditLedger(ctx, a.Customer, invoicePeriod.End.Unix())
		if e != nil {
			return e
		}
		// A lost release response can leave auto_advance enabled. Verify the
		// immutable settlement again before acknowledging that same invoice.
		alreadyReleased := final.AutoAdvance
		final.AutoAdvance = false
		if e = VerifyBillingInvoiceSettlement(final, plan.ExpectedCents, plan.CreditBeforeCents, remaining); e != nil {
			return e
		}
		if alreadyReleased {
			return advance("released")
		}
		if err = client.releaseBillingInvoice(ctx, invoiceID); err != nil {
			return err
		}
		return advance("released")
	}
	inv, err := client.RetrieveBillingInvoice(ctx, invoiceID)
	if err != nil {
		return err
	}
	if err = validateInvoiceDocument(inv, invoicePeriod, a, plan); err != nil {
		return err
	}
	if inv.AutoAdvance || inv.Customer != a.Customer || inv.BillingReason != "subscription_cycle" {
		return fmt.Errorf("invoice no longer matches held cycle")
	}
	if state == "prepared" {
		if inv.Status != "draft" {
			return fmt.Errorf("invoice finalized before its correction plan was applied")
		}
		if plan.AdjustmentCents > 0 {
			counted, e := client.CountedMeterUsage(ctx, a.Event, a.Customer, invoicePeriod.Start, invoicePeriod.End)
			if e != nil {
				return e
			}
			qty, e := meterDecimal(counted)
			if e != nil {
				return e
			}
			expected := big.NewRat(plan.AdjustmentCents, 1)
			if qty.Cmp(expected) != 0 {
				if qty.Sign() != 0 {
					return fmt.Errorf("rounding meter differs from the immutable plan")
				}
				if firstAdjustment != nil && time.Since(*firstAdjustment) >= 23*time.Hour {
					return fmt.Errorf("rounding event replay window expired; collection remains held")
				}
				_, e = h.Pool.Exec(ctx, `UPDATE billing_invoice_close SET first_adjustment_at=COALESCE(first_adjustment_at,clock_timestamp()) WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
				if e != nil {
					return e
				}
				e = client.ReportMeterEvent(ctx, StripeReportMeterEventParams{EventName: a.Event, CustomerID: a.Customer, Value: strconv.FormatInt(plan.AdjustmentCents, 10), Timestamp: plan.AdjustmentTimestamp, Identifier: invoicePlanKey(invoiceID), IdempotencyKey: invoicePlanKey(invoiceID)})
				if e != nil {
					return e
				}
				return fmt.Errorf("waiting for rounding event aggregation")
			}
		} else if plan.AdjustmentCents < 0 {
			if err = client.applyInvoiceDiscount(ctx, invoiceID, -plan.AdjustmentCents, invoicePlanKey(invoiceID)); err != nil {
				return err
			}
		}
		if err = advance("adjusted"); err != nil {
			return err
		}
	}
	if state == "adjusted" {
		credits, e := client.invoiceCreditLedger(ctx, a.Customer, invoicePeriod.End.Unix())
		if e != nil {
			return e
		}
		if credits != plan.CreditBeforeCents {
			return fmt.Errorf("credit ledger changed before finalization")
		}
		if err = h.validateInvoicePlan(ctx, p, a, plan, client); err != nil {
			return err
		}
		_, err = h.Pool.Exec(ctx, `UPDATE billing_invoice_close SET state='finalizing',first_finalize_at=clock_timestamp(),updated_at=clock_timestamp() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
		if err != nil {
			return err
		}
		state = "finalizing"
	}
	if state == "finalizing" {
		// The process may have stopped after saving finalizing but before the
		// provider write. Recheck credit authority whenever it is still draft.
		current, e := client.RetrieveBillingInvoice(ctx, invoiceID)
		if e != nil {
			return e
		}
		if e = validateInvoiceDocument(current, invoicePeriod, a, plan); e != nil {
			return e
		}
		if current.Status == "draft" {
			credits, e := client.invoiceCreditLedger(ctx, a.Customer, invoicePeriod.End.Unix())
			if e != nil {
				return e
			}
			if credits != plan.CreditBeforeCents {
				return fmt.Errorf("credit ledger changed before finalization")
			}
			if plan.AdjustmentCents < 0 && len(current.Discounts) != 1 {
				return fmt.Errorf("rounding discount missing before finalization")
			}
			counted, e := client.CountedMeterUsage(ctx, a.Event, a.Customer, invoicePeriod.Start, invoicePeriod.End)
			if e != nil {
				return e
			}
			qty, e := meterDecimal(counted)
			if e != nil || qty.Cmp(big.NewRat(max(plan.AdjustmentCents, 0), 1)) != 0 {
				return fmt.Errorf("rounding meter changed before finalization")
			}
		}
		final, e := client.FinalizeHeldBillingInvoice(ctx, invoiceID, true, invoicePlanKey(invoiceID)+":finalize")
		if e != nil {
			return e
		}
		remaining, e := client.invoiceCreditLedger(ctx, a.Customer, invoicePeriod.End.Unix())
		if e != nil {
			return e
		}
		if e = validateInvoiceDocument(final, invoicePeriod, a, plan); e != nil {
			return e
		}
		if e = VerifyBillingInvoiceSettlement(final, plan.ExpectedCents, plan.CreditBeforeCents, remaining); e != nil {
			return e
		}
		if e = h.validateInvoicePlan(ctx, p, a, plan, client); e != nil {
			return e
		}
		applied := int64(0)
		for _, credit := range final.PretaxCredits {
			if credit.Type == "credit_balance_transaction" {
				applied += credit.Amount
			}
		}
		invoiceJSON, _ := json.Marshal(final)
		evidence, _ := json.Marshal(billing.InvoiceCloseSettlement{CreditAppliedCents: applied, CreditRemainingCents: remaining, NetCents: final.Total, Invoice: invoiceJSON})
		_, err = h.Pool.Exec(ctx, `UPDATE billing_invoice_close SET state='verified',verified_at=clock_timestamp(),finalized_evidence=$4,last_error=NULL,updated_at=clock_timestamp() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End, evidence)
		return err
	}
	return nil
}

func (h *Handlers) validateInvoicePlan(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, plan billing.InvoiceClosePlan, client *stripeHTTPClient) error {
	invoicePeriod := invoicePlanPeriod(p, plan)
	current, ok, err := h.invoiceAccountForPeriod(ctx, p)
	if err != nil {
		return err
	}
	if !ok || current != a {
		return fmt.Errorf("invoice account changed")
	}
	if _, err = client.ensureInvoiceSubscription(ctx, a, false, true); err != nil {
		return err
	}
	sub, err := client.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return err
	}
	if plan.InvoiceStart != 0 || plan.InvoiceEnd != 0 {
		var matches bool
		if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_invoice_calendar WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND customer_id=$4 AND subscription_id=$5 AND invoice_start=$6 AND invoice_end=$7 AND billing_cycle_anchor=$8)`, p.TeamID, p.Start, p.End, a.Customer, a.Subscription, invoicePeriod.Start, invoicePeriod.End, sub.BillingCycleAnchor).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("invoice calendar changed after planning")
		}
	}
	prices := map[string]string{a.Price: a.Meter}
	for _, r := range plan.Resources {
		prices[r.PriceID] = r.MeterID
	}
	if len(sub.Items.Data) != len(prices) {
		return fmt.Errorf("subscription resource set changed")
	}
	for _, item := range sub.Items.Data {
		meter, ok := prices[item.Price.ID]
		if !ok || item.Price.Recurring.Meter != meter {
			return fmt.Errorf("subscription price mapping changed")
		}
		delete(prices, item.Price.ID)
	}
	for _, r := range plan.Resources {
		snapshot, _, err := h.meterAccountingSnapshot(ctx, p, r.Resource)
		if err != nil {
			return err
		}
		var equal bool
		if err = h.Pool.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, snapshot, []byte(r.Snapshot)).Scan(&equal); err != nil {
			return err
		}
		if !equal {
			return fmt.Errorf("invoice usage snapshot changed")
		}
		meter, err := client.ActiveMeterID(ctx, r.EventName)
		if err != nil {
			return err
		}
		if meter != r.MeterID {
			return fmt.Errorf("invoice resource meter changed")
		}
		quantity, err := client.CountedMeterUsage(ctx, r.EventName, a.Customer, invoicePeriod.Start, invoicePeriod.End)
		if err != nil {
			return err
		}
		before, e1 := meterDecimal(r.ProviderQuantity)
		after, e2 := meterDecimal(quantity)
		if e1 != nil || e2 != nil || before.Cmp(after) != 0 {
			return fmt.Errorf("provider resource quantity changed after invoice planning")
		}
	}
	return nil
}

func (h *Handlers) prepareInvoicePlan(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, inv StripeInvoiceAmounts, client *stripeHTTPClient) (billing.InvoiceClosePlan, error) {
	plan := billing.InvoiceClosePlan{Customer: a.Customer, Subscription: a.Subscription, InvoiceStart: inv.PeriodStart, InvoiceEnd: inv.PeriodEnd}
	invoicePeriod := invoicePlanPeriod(p, plan)
	var closed bool
	if err := h.Pool.QueryRow(ctx, `SELECT status='exporting' AND period_end<=now() AND finalized_at IS NULL FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&closed); err != nil {
		return plan, err
	}
	if !closed {
		return plan, fmt.Errorf("invoice usage period has not been frozen for export")
	}
	if len(inv.Discounts) != 0 || len(inv.Taxes) != 0 || inv.AmountShipping != 0 || inv.Lines.HasMore {
		return plan, fmt.Errorf("invoice has unsupported non-usage charges or discounts")
	}
	usage, err := h.DB.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
	if err != nil {
		return plan, err
	}
	storage, err := h.billingStorageBillingEnabledForWindow(ctx, p.TeamID, p.End)
	if err != nil {
		return plan, err
	}
	states := h.billingResourceStates(storage)
	items, err := incrementalExportItems(usage, states)
	if err != nil {
		return plan, err
	}
	rates, err := h.DB.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: p.TeamID, EffectiveAt: p.End.Add(-time.Nanosecond)})
	if err != nil {
		return plan, err
	}
	// Preloaded, inactive resources still appear as zero-value subscription
	// lines. Include them in the proof without making their measured usage billable.
	invoicePrices := map[string]bool{}
	for _, line := range inv.Lines.Data {
		if line.Pricing.PriceDetails != nil {
			invoicePrices[line.Pricing.PriceDetails.Price] = true
		}
	}
	for _, state := range states {
		if !state.Billable && state.SubscriptionIncluded() && invoicePrices[state.StripePriceID] {
			items = append(items, incrementalExportItem{ResourceType: billingExportResourceType(state.ResourceKey), EventName: state.StripeEventName, Quantity: "0"})
		}
	}
	providerCents := int64(0)
	_, queryEnd := meterObservationWindow(p.Start, p.End)
	plan.AdjustmentTimestamp = queryEnd.Add(-time.Second).Unix()
	for _, item := range items {
		priceID, resourceKey := "", ""
		billable := false
		for _, s := range states {
			if billingExportResourceType(s.ResourceKey) == item.ResourceType {
				priceID, resourceKey = s.StripePriceID, s.ResourceKey
				billable = s.Billable
			}
		}
		if priceID == "" {
			return plan, fmt.Errorf("resource invoice price is missing")
		}
		var price storagePrice
		if err = client.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(priceID), nil, &price, ""); err != nil {
			return plan, err
		}
		var rate *big.Rat
		for _, r := range rates {
			if r.Resource == resourceKey && r.Unit == "second" {
				v, e := r.PriceUsd.Value()
				if e != nil {
					return plan, e
				}
				rate, _ = new(big.Rat).SetString(fmt.Sprint(v))
			}
		}
		providerPrice, e := meterDecimal(price.UnitAmountDecimal)
		if e != nil || rate == nil {
			return plan, fmt.Errorf("invoice pricing unavailable")
		}
		expectedPrice := new(big.Rat).Mul(rate, big.NewRat(360000, 1))
		if price.ID != priceID || !price.Active || price.Recurring.Interval != "month" || price.Recurring.IntervalCount != 1 || price.Currency != "usd" || price.BillingScheme != "per_unit" || price.TransformQuantity != nil || price.Recurring.UsageType != "metered" || providerPrice.Cmp(expectedPrice) != 0 {
			return plan, fmt.Errorf("invoice price differs from authoritative resource pricing")
		}
		unitUSD := new(big.Rat).Quo(providerPrice, big.NewRat(100, 1)).FloatString(14)
		totals, e := (billing.ExportStore{Pool: h.Pool}).Totals(ctx, p, item.ResourceType)
		if e != nil {
			return plan, e
		}
		target, e := (billing.ExportStore{Pool: h.Pool}).CorrectionTarget(ctx, p, item.ResourceType, item.Quantity)
		if e != nil {
			return plan, e
		}
		if target != totals.Reserved {
			x, _ := meterDecimal(target)
			y, _ := meterDecimal(totals.Reserved)
			if x == nil || y == nil || x.Cmp(y) != 0 {
				return plan, fmt.Errorf("invoice usage is not fully reserved")
			}
		}
		x, e := meterDecimal(totals.Submitted)
		if e != nil {
			return plan, e
		}
		y, e := meterDecimal(target)
		if e != nil || x.Cmp(y) != 0 {
			return plan, fmt.Errorf("invoice usage is not fully submitted")
		}
		event, e := (billing.ExportStore{Pool: h.Pool}).MeterEventName(ctx, p, item.ResourceType, item.EventName)
		if e != nil {
			return plan, e
		}
		var invalid bool
		if e = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_export_allocation x LEFT JOIN billing_export_event v ON v.allocation_id=x.id AND v.active WHERE x.team_id=$1 AND x.period_start=$2 AND x.period_end=$3 AND x.resource_type=$4 AND (v.id IS NULL OR v.status NOT IN ('submitted','adopted') OR v.customer_id<>$5 OR v.event_name<>$6 OR v.event_timestamp<$7 OR v.event_timestamp>=$8))`, p.TeamID, p.Start, p.End, item.ResourceType, a.Customer, event, invoicePeriod.Start.Unix(), invoicePeriod.End.Unix()).Scan(&invalid); e != nil {
			return plan, e
		}
		if invalid {
			return plan, fmt.Errorf("invoice event scope or acceptance is incomplete")
		}
		meter, e := client.ActiveMeterID(ctx, event)
		if e != nil {
			return plan, e
		}
		if meter != price.Recurring.Meter {
			return plan, fmt.Errorf("invoice price meter mismatch")
		}
		counted, e := client.CountedMeterUsage(ctx, event, a.Customer, invoicePeriod.Start, invoicePeriod.End)
		if e != nil {
			return plan, e
		}
		provider, e := meterDecimal(counted)
		if e != nil {
			return plan, e
		}
		if !invoiceQuantityEquivalent(provider, y) {
			return plan, fmt.Errorf("provider usage is incomplete or materially different")
		}
		expected, e := billing.InvoiceLineCents(target, unitUSD)
		if e != nil {
			return plan, e
		}
		// Preserve raw exact usage at the cent boundary unless an explicit approved
		// correction replaced the original usage target.
		baseTarget, _ := meterDecimal(item.Quantity)
		if baseTarget.Cmp(y) == 0 && billable {
			var value any
			switch resourceKey {
			case "vcpu":
				value, e = usage.VcpuSeconds.Value()
			case "memory_gib":
				value, e = usage.MemoryMibSeconds.Value()
			case "storage_gib":
				value, e = usage.StorageMibSeconds.Value()
			}
			if e != nil {
				return plan, e
			}
			seconds, ok := new(big.Rat).SetString(fmt.Sprint(value))
			if !ok {
				return plan, fmt.Errorf("invalid exact resource usage")
			}
			if resourceKey != "vcpu" {
				seconds.Quo(seconds, big.NewRat(1024, 1))
			}
			exactCost := new(big.Rat).Mul(seconds, rate)
			cost := exactCost.FloatString(40)
			reparsed, _ := new(big.Rat).SetString(cost)
			if reparsed.Cmp(exactCost) != 0 {
				return plan, fmt.Errorf("resource cost exceeds supported decimal scale")
			}
			expected, e = billing.InvoiceLineCents(cost, "1")
			if e != nil {
				return plan, e
			}
		}
		actual, e := billing.InvoiceLineCents(counted, unitUSD)
		if e != nil {
			return plan, e
		}
		snapshot, _, e := h.meterAccountingSnapshot(ctx, p, item.ResourceType)
		if e != nil {
			return plan, e
		}
		if expected > math.MaxInt64-plan.ExpectedCents || actual > math.MaxInt64-providerCents {
			return plan, fmt.Errorf("invoice total overflow")
		}
		plan.ExpectedCents += expected
		providerCents += actual
		plan.Resources = append(plan.Resources, billing.InvoiceCloseResource{Resource: item.ResourceType, EventName: event, MeterID: meter, PriceID: priceID, Quantity: target, ProviderQuantity: counted, UnitUSD: unitUSD, ExpectedCents: expected, ProviderCents: actual, Snapshot: json.RawMessage(snapshot)})
	}
	if len(plan.Resources) == 0 || len(plan.Resources) > 3 {
		return plan, fmt.Errorf("unsupported invoice resource set")
	}
	if err = validateInvoiceDocument(inv, invoicePeriod, a, plan); err != nil {
		return plan, err
	}
	adjustment, e := client.CountedMeterUsage(ctx, a.Event, a.Customer, invoicePeriod.Start, invoicePeriod.End)
	if e != nil {
		return plan, e
	}
	q, e := meterDecimal(adjustment)
	if e != nil || q.Sign() != 0 {
		return plan, fmt.Errorf("unplanned rounding usage already exists")
	}
	plan.AdjustmentCents = plan.ExpectedCents - providerCents
	if plan.AdjustmentCents > int64(len(items)) || plan.AdjustmentCents < -int64(len(items)) {
		return plan, fmt.Errorf("invoice difference exceeds supported rounding correction")
	}
	plan.CreditBeforeCents, err = client.invoiceCreditLedger(ctx, a.Customer, invoicePeriod.End.Unix())
	return plan, err
}

// Quantity drift is provisional only for accounts under a durable invoice hold.
// The final charge is reconciled independently; this is never close evidence.
func invoiceQuantityEquivalent(provider, local *big.Rat) bool {
	if provider == nil || local == nil || provider.Sign() < 0 || local.Sign() < 0 {
		return false
	}
	if provider.Cmp(local) == 0 {
		return true
	}
	if local.Cmp(big.NewRat(1, 1_000_000_000_000)) < 0 || local.Cmp(big.NewRat(1_000_000_000, 1)) > 0 {
		return false
	}
	bound := new(big.Rat).Quo(local, big.NewRat(1_000_000_000, 1))
	return new(big.Rat).Abs(new(big.Rat).Sub(provider, local)).Cmp(bound) <= 0
}

func (h *Handlers) verifyInvoiceExportHold(ctx context.Context, p billing.ExportPeriod) error {
	a, enrolled, err := h.invoiceAccountForPeriod(ctx, p)
	if err != nil {
		return err
	}
	if !enrolled {
		if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
			return nil
		}
		// Historical shadow handoffs predate commercial enrollment and retain
		// their existing exact-quantity close gate.
		var legacyHandoff bool
		if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account b JOIN billing_usage_export x USING(team_id)
            WHERE b.team_id=$1 AND b.commercial_billing_anchor IS NULL AND x.period_start=$2 AND x.period_end=$3
              AND x.status='skipped_shadow' AND x.period_end<=now())`, p.TeamID, p.Start, p.End).Scan(&legacyHandoff); err != nil {
			return err
		}
		if legacyHandoff {
			return nil
		}
		if err = h.enrollInvoiceAccount(ctx, p.TeamID, nil); err != nil {
			return err
		}
		a, enrolled, err = h.invoiceAccountForPeriod(ctx, p)
		if err != nil {
			return err
		}
	}
	if !enrolled || !a.EnrolledAt.Before(p.End) {
		return nil
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return fmt.Errorf("invoice provider unavailable")
	}
	var frozen bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_incremental_period i JOIN team_billing_period p USING(team_id,period_start,period_end) WHERE i.team_id=$1 AND i.period_start=$2 AND i.period_end=$3 AND (p.status IN ('exporting','exported') OR p.finalized_at IS NOT NULL))`, p.TeamID, p.Start, p.End).Scan(&frozen); err != nil {
		return err
	}
	_, err = client.ensureInvoiceSubscription(ctx, a, false, frozen)
	if err != nil {
		return err
	}
	mapped, err := h.ensureInvoiceCalendar(ctx, p, a, client)
	if err != nil {
		return err
	}
	queryStart, _ := meterObservationWindow(mapped.Start, mapped.End)
	if !h.nowUTC().Truncate(time.Hour).After(queryStart) {
		return fmt.Errorf("waiting for mapped invoice cycle to begin before exporting usage")
	}
	return nil
}

func validateInvoiceDocument(inv StripeInvoiceAmounts, p billing.ExportPeriod, a invoiceAccount, plan billing.InvoiceClosePlan) error {
	if inv.Customer != a.Customer || inv.Currency != "usd" || inv.BillingReason != "subscription_cycle" || inv.PeriodStart != p.Start.Unix() || inv.PeriodEnd != p.End.Unix() || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != a.Subscription || inv.Lines.HasMore || len(inv.Taxes) != 0 || inv.AmountShipping != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 {
		return fmt.Errorf("invoice scope or accounting configuration changed")
	}
	if len(inv.Discounts) > 1 || (len(inv.Discounts) == 1 && (plan.AdjustmentCents >= 0 || inv.Discounts[0].Coupon != "rounding_"+inv.ID)) {
		return fmt.Errorf("invoice has an unplanned discount")
	}
	if inv.Status != "draft" && plan.AdjustmentCents < 0 {
		if len(inv.Discounts) != 1 || len(inv.DiscountAmounts) != 1 || inv.DiscountAmounts[0].Amount != -plan.AdjustmentCents {
			return fmt.Errorf("finalized rounding discount differs from plan")
		}
	}
	allowed := map[string]string{a.Price: "1"}
	amounts := map[string]int64{a.Price: max(plan.AdjustmentCents, 0)}
	for _, resource := range plan.Resources {
		if _, exists := allowed[resource.PriceID]; exists {
			return fmt.Errorf("duplicate invoice resource price")
		}
		v, err := meterDecimal(resource.UnitUSD)
		if err != nil {
			return err
		}
		allowed[resource.PriceID] = new(big.Rat).Mul(v, big.NewRat(100, 1)).RatString()
		amounts[resource.PriceID] = resource.ProviderCents
	}
	start, end := meterObservationWindow(p.Start, p.End)
	seen := map[string]bool{}
	for _, line := range inv.Lines.Data {
		d, parent := line.Pricing.PriceDetails, line.Parent.SubscriptionItemDetails
		if d == nil || parent == nil || parent.Proration || parent.Subscription != a.Subscription || line.Currency != "usd" || len(line.Discounts) != 0 {
			return fmt.Errorf("invoice line does not match supported resource set")
		}
		expected, ok := new(big.Rat).SetString(allowed[d.Price])
		actual, err := meterDecimal(line.Pricing.UnitAmountDecimal)
		if !ok || err != nil || expected.Cmp(actual) != 0 || seen[d.Price] {
			return fmt.Errorf("invoice price changed or duplicated")
		}
		if inv.Status != "draft" && line.Amount != amounts[d.Price] {
			return fmt.Errorf("finalized resource or rounding line amount differs from plan")
		}
		seen[d.Price] = true
		latestStart := start.Unix()
		if d.Price == a.Price {
			latestStart = plan.AdjustmentTimestamp
		}
		if line.Period.Start > latestStart || line.Period.End < end.Unix() {
			return fmt.Errorf("invoice line does not cover usage window")
		}
	}
	if len(seen) != len(allowed) {
		return fmt.Errorf("invoice is missing resource or rounding lines")
	}
	return nil
}
