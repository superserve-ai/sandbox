package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var errProResourcesUnpaid = errors.New("annual usage attachment awaits verified payment")

// Attach all monthly resources together after annual Checkout has collected the
// base fee. A complete provider inventory recovers success even after request
// idempotency expires; partial or removed inventories require explicit recovery.
func (c *stripeHTTPClient) ensureProDeferredResources(ctx context.Context, sub invoiceSubscription, params StripeCreateCheckoutSessionParams, receipts []proPaymentEvidence) (invoiceSubscription, error) {
	offer, err := frozenProOffer(params.Metadata["commercial_offer"], params)
	if err != nil || offer.Months != 12 || len(params.PriceIDs) != 0 || !params.Flexible || params.BasePriceID == "" || params.IdempotencyKey == "" || params.Metadata["checkout_generation"] == "" {
		return sub, errors.New("invalid deferred annual checkout terms")
	}
	offer.Price = params.BasePriceID
	if sub.Customer != params.CustomerID || sub.Metadata["checkout_generation"] != params.Metadata["checkout_generation"] || sub.Metadata["commercial_offer"] != offer.Key || sub.Items.HasMore || sub.AutomaticTax.Enabled || len(sub.Discounts) != 0 || sub.BillingThresholds != nil || sub.StartDate <= 0 || sub.BillingCycleAnchor != sub.StartDate {
		return sub, errors.New("annual subscription differs from frozen purchase")
	}
	base := invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: offer.Months}
	resources, err := base.stripSubscription(sub)
	if err != nil {
		return sub, err
	}
	expected := map[string]bool{}
	for _, id := range params.DeferredResourcePriceIDs {
		if id == "" || id == offer.Price || expected[id] {
			return sub, errors.New("invalid deferred resource inventory")
		}
		expected[id] = true
	}
	if len(expected) == 0 || len(expected) != len(params.ResourceTerms) {
		return sub, errors.New("incomplete deferred resource terms")
	}
	for _, term := range params.ResourceTerms {
		if !expected[term.PriceID] {
			return sub, errors.New("deferred resource differs from frozen terms")
		}
	}
	found := 0
	for _, item := range resources.Items.Data {
		if expected[item.Price.ID] {
			found++
		}
	}
	if found == len(expected) {
		// Existing rounding enrollment may have added its own monthly item. The
		// caller validates that identity against the durable enrollment record.
		return sub, nil
	}
	if len(resources.Items.Data) != 0 || sub.Metadata["pro_usage_attached"] != "" {
		return sub, errors.New("annual usage inventory changed; explicit recovery required")
	}
	now := time.Now().Unix()
	paid := false
	for _, receipt := range receipts {
		if receipt.Start <= now && receipt.End > now {
			paid = true
		}
	}
	if !paid {
		return sub, errProResourcesUnpaid
	}
	if sub.Status != "active" {
		return sub, errors.New("paid annual subscription cannot enroll usage")
	}
	candidate := invoiceSubscription{}
	for _, id := range params.DeferredResourcePriceIDs {
		var price storagePrice
		if err = c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(id), nil, &price, ""); err != nil {
			return sub, err
		}
		if price.ID != id || !price.Active {
			return sub, errors.New("deferred resource price unavailable")
		}
		candidate.Items.Data = append(candidate.Items.Data, invoiceSubscriptionItem{Price: price})
	}
	if err = validateFrozenProResources(candidate, params.ResourceTerms, ""); err != nil {
		return sub, err
	}
	// Payment and price reads may take time. Recheck before every attachment so
	// both newly scheduled and removed cancellation are respected on retry.
	fresh, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return sub, err
	}
	if fresh.CancelAtPeriodEnd != sub.CancelAtPeriodEnd || fresh.Items.HasMore || len(fresh.Items.Data) != len(sub.Items.Data) {
		return sub, errors.New("annual subscription changed before usage preparation")
	}
	if err = validateProUsageUpdate(sub, fresh, offer.Price); err != nil {
		return sub, err
	}
	sub = fresh
	if sub.CancelAtPeriodEnd {
		// Adding monthly items changes the relative cancellation boundary. Freeze
		// its existing absolute deadline first, keeping the attachment replay fixed.
		if sub.CancelAt <= now {
			return sub, errors.New("annual cancellation deadline is missing or elapsed")
		}
		deadline := strconv.FormatInt(sub.CancelAt, 10)
		cancelForm := url.Values{"cancel_at": {deadline}, "proration_behavior": {"none"}}
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), cancelForm, nil, "pro-usage-cancel:"+sub.ID+":"+deadline); err != nil {
			return sub, err
		}
		normalized, err := c.invoiceSubscription(ctx, sub.ID)
		if err != nil {
			return sub, err
		}
		if normalized.CancelAtPeriodEnd {
			return sub, errors.New("annual cancellation deadline is still relative")
		}
		if err = validateProUsageUpdate(sub, normalized, offer.Price); err != nil {
			return sub, err
		}
		sub = normalized
	}
	form := url.Values{"proration_behavior": {"none"}, "metadata[pro_usage_attached]": {params.Metadata["checkout_generation"]}}
	for i, id := range params.DeferredResourcePriceIDs {
		form.Set(fmt.Sprintf("items[%d][price]", i), id)
	}
	// Omit billing_cycle_anchor: flexible mode preserves the existing annual
	// anniversary and aligns added monthly items to it without another base fee.
	if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), form, nil, "pro-usage:"+params.IdempotencyKey); err != nil {
		return sub, err
	}
	updated, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return sub, err
	}
	if updated.Metadata["pro_usage_attached"] != params.Metadata["checkout_generation"] {
		return sub, errors.New("annual subscription changed during usage attachment")
	}
	if err = validateProUsageUpdate(sub, updated, offer.Price); err != nil {
		return sub, err
	}
	return updated, nil
}

func validateProUsageUpdate(sub, updated invoiceSubscription, basePrice string) error {
	if updated.ID != sub.ID || updated.Customer != sub.Customer || updated.Status != sub.Status || updated.StartDate != sub.StartDate || updated.BillingCycleAnchor != sub.BillingCycleAnchor || updated.CancelAt != sub.CancelAt || updated.Metadata["checkout_generation"] != sub.Metadata["checkout_generation"] || updated.Metadata["commercial_offer"] != sub.Metadata["commercial_offer"] {
		return errors.New("annual subscription changed during usage preparation")
	}
	for _, before := range sub.Items.Data {
		if before.Price.ID != basePrice {
			continue
		}
		matched := false
		for _, after := range updated.Items.Data {
			if after.ID == before.ID && after.Price.ID == before.Price.ID && after.Start == before.Start && after.End == before.End {
				matched = true
			}
		}
		if !matched {
			return errors.New("annual base period changed during usage preparation")
		}
	}
	return nil
}
