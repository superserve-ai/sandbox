package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type invoiceBase struct {
	Product      string
	Live         bool
	Item         string
	WaiverEnd    int64
	Price        string
	Amount       int64
	Months       int32
	Anchor       time.Time
	TerminatedAt int64
	StartsAt     int64
	SeparateFees [12]int64
}

func (h *Handlers) loadInvoiceBase(ctx context.Context, team uuid.UUID, a *invoiceAccount, readers ...db.DBTX) error {
	var reader db.DBTX = h.Pool
	if len(readers) > 0 {
		reader = readers[0]
	}
	var contract uuid.UUID
	err := reader.QueryRow(ctx, `SELECT id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_anchor,extract(epoch from starts_at)::bigint FROM billing_commercial_contract WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND (offer_key='yc_2026' OR offer_key IN `+paidPlanOffers+`) ORDER BY created_at DESC LIMIT 1`, team, a.Customer, a.Subscription).Scan(&contract, &a.Base.Price, &a.Base.Amount, &a.Base.Months, &a.Base.Anchor, &a.Base.StartsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return err
	}
	if contract != uuid.Nil {
		var review bool
		if err = reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE contract_id=$1 AND payment_review_required)`, contract).Scan(&review); err != nil {
			return err
		}
		if review {
			return errors.New("one-off upgrade payment requires review before invoice close")
		}
		rows, e := reader.Query(ctx, `SELECT extract(epoch from j.period_start)::bigint FROM billing_pro_upgrade_catchup j JOIN billing_pro_upgrade u ON u.id=j.upgrade_id JOIN billing_contract_payment p ON p.contract_id=u.contract_id AND p.invoice_id=j.invoice_id AND p.service_period_start=j.period_start AND p.service_period_end=j.period_end WHERE u.contract_id=$1`, contract)
		if e != nil {
			return e
		}
		index := 0
		for rows.Next() {
			var boundary int64
			if e = rows.Scan(&boundary); e != nil {
				rows.Close()
				return e
			}
			if index >= len(a.Base.SeparateFees) {
				rows.Close()
				return errors.New("too many separately paid upgrade periods")
			}
			a.Base.SeparateFees[index] = boundary
			index++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	return h.loadSponsoredAnnualBase(ctx, team, a, reader)
}
func (b invoiceBase) stripSubscription(sub invoiceSubscription) (invoiceSubscription, error) {
	if b.Price == "" {
		return sub, nil
	}
	if b.Item != "" {
		if err := validateSponsoredAnnualTiming(sub); err != nil {
			return sub, err
		}
	}
	// Copy before filtering; callers may retain the original provider evidence.
	items := sub.Items.Data[:0:0]
	found := false
	for _, item := range sub.Items.Data {
		if item.Price.ID != b.Price {
			items = append(items, item)
			continue
		}
		interval := "month"
		if b.Months == 12 {
			interval = "year"
		}
		if (b.Item != "" && item.ID != b.Item) || found || sub.BillingMode.Type != "flexible" || item.Quantity != 1 || item.Price.Currency != "usd" || item.Price.UnitAmountDecimal != fmt.Sprint(b.Amount) || item.Price.Recurring.UsageType != "licensed" || item.Price.Recurring.Interval != interval || item.Price.Recurring.IntervalCount != 1 || item.Price.TransformQuantity != nil || item.Price.BillingScheme != "per_unit" {
			return sub, errors.New("licensed subscription terms changed")
		}
		if b.Item != "" {
			start := time.Unix(item.Start, 0).UTC()
			months := (start.Year()-b.Anchor.UTC().Year())*12 + int(start.Month()-b.Anchor.UTC().Month())
			if item.Price.Product != b.Product || item.Price.LiveMode != b.Live || sub.LiveMode != b.Live || months < 0 || months%12 != 0 || item.Start != annualBoundary(b.Anchor, months).Unix() || item.End != annualBoundary(b.Anchor, months+12).Unix() {
				return sub, errors.New("adopted annual item period or product changed")
			}
		}
		found = true
	}
	if !found {
		return sub, errors.New("licensed base item is missing")
	}
	sub.Items.Data = items
	return sub, nil
}
func (b invoiceBase) separatelyPaid(boundary int64) bool {
	for _, paid := range b.SeparateFees {
		if paid != 0 && paid == boundary {
			return true
		}
	}
	return false
}

func (b invoiceBase) expectedFee(boundary time.Time) (int64, int64, int64, error) {
	b.Anchor = b.Anchor.UTC()
	boundary = boundary.UTC()
	if b.separatelyPaid(boundary.Unix()) || b.Price == "" || (b.StartsAt > 0 && boundary.Unix() < b.StartsAt) || (b.TerminatedAt > 0 && boundary.Unix() >= b.TerminatedAt) {
		return 0, 0, 0, nil
	}
	start, _, ok := billing.AnniversaryPeriod(b.Anchor, boundary)
	if !ok || !start.Equal(boundary) || b.Months <= 0 {
		return 0, 0, 0, errors.New("base invoice boundary is not a contract anniversary")
	}
	if b.WaiverEnd > 0 && boundary.Unix() < b.WaiverEnd {
		return 0, 0, 0, nil
	}
	months := (boundary.UTC().Year()-b.Anchor.UTC().Year())*12 + int(boundary.UTC().Month()-b.Anchor.UTC().Month())
	if months%int(b.Months) != 0 {
		return 0, 0, 0, nil
	}
	// Find the future boundary from the original anniversary, preserving month-end clamping.
	first := time.Date(b.Anchor.Year(), b.Anchor.Month(), 1, b.Anchor.Hour(), b.Anchor.Minute(), b.Anchor.Second(), 0, time.UTC).AddDate(0, months+int(b.Months), 0)
	last := first.AddDate(0, 1, -1).Day()
	day := b.Anchor.Day()
	if day > last {
		day = last
	}
	end := time.Date(first.Year(), first.Month(), day, first.Hour(), first.Minute(), first.Second(), 0, time.UTC)
	return b.Amount, boundary.Unix(), end.Unix(), nil
}
func (b invoiceBase) validateLine(line StripeInvoiceAmountLine, subscription string, start, end int64) error {
	parent := line.Parent.SubscriptionItemDetails
	if parent == nil || (b.Item != "" && parent.SubscriptionItem != b.Item) || parent.Subscription != subscription || parent.Proration || line.Currency != "usd" || line.Amount != b.Amount || line.Quantity != 1 || line.Pricing.UnitAmountDecimal != fmt.Sprint(b.Amount) || baseLineHasCredits(line) || line.Period.Start != start || line.Period.End != end {
		return errors.New("licensed invoice line differs from contract")
	}
	return nil
}

// Product-scoped invoice discounts can leave zero-valued discount entries on
// excluded lines. They do not reduce the licensed fee.
func baseLineHasCredits(line StripeInvoiceAmountLine) bool {
	if len(line.Discounts) != 0 {
		return true
	}
	for _, credit := range line.PretaxCredits {
		if credit.Type != "discount" || credit.Amount != 0 {
			return true
		}
	}
	return false
}

func verifyInvoicePlanSettlement(inv StripeInvoiceAmounts, plan billing.InvoiceClosePlan, before, after int64) error {
	if plan.BaseCents == 0 {
		return VerifyBillingInvoiceSettlement(inv, plan.ExpectedCents, before, after)
	}
	if inv.Subtotal < plan.BaseCents || inv.Total < plan.BaseCents || inv.EndingBalance == nil || *inv.EndingBalance < math.MinInt64+plan.BaseCents {
		return errors.New("invoice cannot cover licensed fee")
	}
	// Keep the existing usage-only conservation check, including customer balances.
	inv.Subtotal -= plan.BaseCents
	inv.Total -= plan.BaseCents
	ending := *inv.EndingBalance - plan.BaseCents
	inv.EndingBalance = &ending
	return VerifyBillingInvoiceSettlement(inv, plan.ExpectedCents, before, after)
}

func proRoundingProducts(inv StripeInvoiceAmounts, basePrice string) ([]string, error) {
	baseProduct := ""
	products := map[string]bool{}
	for _, line := range inv.Lines.Data {
		d := line.Pricing.PriceDetails
		if d == nil || d.Product == "" {
			return nil, errors.New("invoice product evidence is missing")
		}
		if d.Price == basePrice {
			baseProduct = d.Product
		} else {
			products[d.Product] = true
		}
	}
	if baseProduct == "" || products[baseProduct] || len(products) == 0 {
		return nil, errors.New("Pro fee and usage must use separate products for rounding")
	}
	result := make([]string, 0, len(products))
	for product := range products {
		result = append(result, product)
	}
	sort.Strings(result)
	return result, nil
}
