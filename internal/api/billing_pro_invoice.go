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
	Price        string
	Amount       int64
	Months       int32
	Anchor       time.Time
	TerminatedAt int64
}

func (h *Handlers) loadInvoiceBase(ctx context.Context, team uuid.UUID, a *invoiceAccount, readers ...db.DBTX) error {
	var reader db.DBTX = h.Pool
	if len(readers) > 0 {
		reader = readers[0]
	}
	err := reader.QueryRow(ctx, `SELECT base_price_id,charge_amount_cents,charge_interval_months,entitlement_anchor FROM billing_commercial_contract WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND offer_key IN ('pro_monthly','pro_annual') ORDER BY created_at DESC LIMIT 1`, team, a.Customer, a.Subscription).Scan(&a.Base.Price, &a.Base.Amount, &a.Base.Months, &a.Base.Anchor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}
func (b invoiceBase) stripSubscription(sub invoiceSubscription) (invoiceSubscription, error) {
	if b.Price == "" {
		return sub, nil
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
		if found || sub.BillingMode.Type != "flexible" || item.Quantity != 1 || item.Price.Currency != "usd" || item.Price.UnitAmountDecimal != fmt.Sprint(b.Amount) || item.Price.Recurring.UsageType != "licensed" || item.Price.Recurring.Interval != interval || item.Price.Recurring.IntervalCount != 1 || item.Price.TransformQuantity != nil || item.Price.BillingScheme != "per_unit" {
			return sub, errors.New("licensed subscription terms changed")
		}
		found = true
	}
	if !found {
		return sub, errors.New("licensed base item is missing")
	}
	sub.Items.Data = items
	return sub, nil
}
func (b invoiceBase) expectedFee(boundary time.Time) (int64, int64, int64, error) {
	if b.Price == "" || (b.TerminatedAt > 0 && boundary.Unix() >= b.TerminatedAt) {
		return 0, 0, 0, nil
	}
	start, _, ok := billing.AnniversaryPeriod(b.Anchor, boundary)
	if !ok || !start.Equal(boundary) || b.Months <= 0 {
		return 0, 0, 0, errors.New("base invoice boundary is not a contract anniversary")
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
	if parent == nil || parent.Subscription != subscription || parent.Proration || line.Currency != "usd" || line.Amount != b.Amount || line.Quantity != 1 || line.Pricing.UnitAmountDecimal != fmt.Sprint(b.Amount) || len(line.Discounts) != 0 || len(line.PretaxCredits) != 0 || line.Period.Start != start || line.Period.End != end {
		return errors.New("licensed invoice line differs from contract")
	}
	return nil
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
