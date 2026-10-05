package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
)

// Usage keeps its commercial anniversary. A separate, immutable mapping assigns
// it to the provider cycle containing its final export timestamp. New exports
// wait for that cycle to begin; already accepted events are never moved.
func invoiceCalendarPeriod(p billing.ExportPeriod, sub invoiceSubscription, roundingPrice string) (billing.ExportPeriod, error) {
	result := p
	if sub.BillingCycleAnchor <= 0 {
		return result, fmt.Errorf("subscription billing cycle anchor is missing")
	}
	anchor := time.Unix(sub.BillingCycleAnchor, 0).UTC()
	var start, end int64
	for _, item := range sub.Items.Data {
		if item.Price.ID == roundingPrice {
			continue
		}
		if item.Start <= 0 || item.End <= item.Start {
			return result, fmt.Errorf("subscription item period is missing")
		}
		if start != 0 && (start != item.Start || end != item.End) {
			return result, fmt.Errorf("subscription resource calendars differ")
		}
		start, end = item.Start, item.End
	}
	actualStart, actualEnd, ok := billing.AnniversaryPeriod(anchor, time.Unix(start, 0))
	if !ok || actualStart.Unix() != start || actualEnd.Unix() != end {
		return result, fmt.Errorf("subscription calendar is not a regular monthly cycle")
	}
	_, last := meterObservationWindow(p.Start, p.End)
	result.Start, result.End, ok = billing.AnniversaryPeriod(anchor, last.Add(-time.Second))
	if !ok || !result.Start.Before(p.End) || result.End.Before(p.End) {
		return result, fmt.Errorf("commercial period cannot be assigned to this subscription calendar")
	}
	queryStart, queryEnd := meterObservationWindow(result.Start, result.End)
	finalTimestamp := last.Add(-time.Second)
	if finalTimestamp.Before(queryStart) || !finalTimestamp.Before(queryEnd) {
		return result, fmt.Errorf("commercial close timestamp is outside observable invoice window")
	}
	return result, nil
}

// Different month-end anchors can collapse two commercial periods onto one
// invoice (or skip a cycle). Reject that schedule before taking collection
// responsibility rather than discovering the collision after accepting usage.
func invoiceCalendarCompatible(anchor time.Time, sub invoiceSubscription, roundingPrice string) error {
	at := anchor
	if provider := time.Unix(sub.BillingCycleAnchor, 0); provider.After(at) {
		at = provider
	}
	var previousEnd time.Time
	for month := 0; month < 48; month++ {
		start, end, ok := billing.AnniversaryPeriod(anchor, at)
		if !ok {
			return fmt.Errorf("commercial calendar is unavailable")
		}
		mapped, err := invoiceCalendarPeriod(billing.ExportPeriod{Start: start, End: end}, sub, roundingPrice)
		if err != nil {
			return err
		}
		if !previousEnd.IsZero() && !previousEnd.Equal(mapped.Start) {
			return fmt.Errorf("commercial and provider month-end calendars require explicit settlement recovery")
		}
		previousEnd, at = mapped.End, end
	}
	return nil
}

func invoicePlanPeriod(p billing.ExportPeriod, plan billing.InvoiceClosePlan) billing.ExportPeriod {
	if plan.InvoiceStart != 0 && plan.InvoiceEnd != 0 {
		p.Start, p.End = time.Unix(plan.InvoiceStart, 0).UTC(), time.Unix(plan.InvoiceEnd, 0).UTC()
	}
	return p
}

func (h *Handlers) ensureInvoiceCalendar(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, client *stripeHTTPClient) (billing.ExportPeriod, error) {
	// Old immutable plans retain their original exact-calendar interpretation.
	var rawStart, rawEnd int64
	err := h.Pool.QueryRow(ctx, `SELECT COALESCE((plan->>'invoice_start')::bigint,extract(epoch from period_start)::bigint),COALESCE((plan->>'invoice_end')::bigint,extract(epoch from period_end)::bigint) FROM billing_invoice_close WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&rawStart, &rawEnd)
	if err == nil {
		return billing.ExportPeriod{TeamID: p.TeamID, Start: time.Unix(rawStart, 0).UTC(), End: time.Unix(rawEnd, 0).UTC()}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return p, err
	}
	sub, err := client.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return p, err
	}
	if sub.Customer != a.Customer {
		return p, fmt.Errorf("invoice calendar customer changed")
	}
	var anchor time.Time
	if err = h.Pool.QueryRow(ctx, `SELECT COALESCE(commercial_billing_anchor,$2) FROM team_billing_account WHERE team_id=$1`, p.TeamID, p.Start).Scan(&anchor); err != nil {
		return p, err
	}
	if a.ReplacementSubscription != "" {
		anchor = p.Start
	}
	if err = invoiceCalendarCompatible(anchor, sub, a.Price); err != nil {
		return p, err
	}
	mapped, err := invoiceCalendarPeriod(p, sub, a.Price)
	if err != nil {
		return p, err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	// Serialize with allocation, including old replicas that do not know about
	// the calendar map. The event trigger enforces the same window for them.
	if _, err = tx.Exec(ctx, `SELECT 1 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3 FOR UPDATE`, p.TeamID, p.Start, p.End); err != nil {
		return p, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(team_id,period_start,period_end) DO NOTHING`, p.TeamID, p.Start, p.End, a.Customer, a.Subscription, mapped.Start, mapped.End, sub.BillingCycleAnchor)
	if err != nil {
		return p, err
	}
	var matches bool
	err = tx.QueryRow(ctx, `SELECT customer_id=$4 AND subscription_id=$5 AND invoice_start=$6 AND invoice_end=$7 AND billing_cycle_anchor=$8 FROM billing_invoice_calendar WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End, a.Customer, a.Subscription, mapped.Start, mapped.End, sub.BillingCycleAnchor).Scan(&matches)
	if err != nil {
		return p, err
	}
	if !matches {
		return p, fmt.Errorf("saved invoice calendar differs from subscription")
	}
	return mapped, tx.Commit(ctx)
}
