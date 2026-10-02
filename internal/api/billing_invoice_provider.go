package api

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type invoiceSubscription struct {
	BillingCycleAnchor int64  `json:"billing_cycle_anchor"`
	ID                 string `json:"id"`
	Customer           string `json:"customer"`
	Status             string `json:"status"`
	PauseCollection    *struct {
		Behavior  string `json:"behavior"`
		ResumesAt int64  `json:"resumes_at"`
	} `json:"pause_collection"`
	Discounts    []string `json:"discounts"`
	AutomaticTax struct {
		Enabled bool `json:"enabled"`
	} `json:"automatic_tax"`
	BillingThresholds any `json:"billing_thresholds"`
	Items             struct {
		Data []struct {
			ID    string       `json:"id"`
			Price storagePrice `json:"price"`
			Start int64        `json:"current_period_start"`
			End   int64        `json:"current_period_end"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	} `json:"items"`
}

type invoiceAccount struct {
	Customer, Subscription, Price, Event, Meter  string
	EnrolledAt                                   time.Time
	ReplacementCustomer, ReplacementSubscription string
}

func (c *stripeHTTPClient) invoiceSubscription(ctx context.Context, id string) (invoiceSubscription, error) {
	var s invoiceSubscription
	err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(id), nil, &s, "")
	if err == nil && (s.ID != id || s.Items.HasMore || s.Customer == "" || len(s.Items.Data) == 0) {
		err = fmt.Errorf("incomplete invoice subscription")
	}
	return s, err
}

func (c *stripeHTTPClient) ensureInvoiceSubscription(ctx context.Context, a invoiceAccount, add, frozen bool) (invoiceAccount, error) {
	return c.ensureInvoiceSubscriptionValidated(ctx, a, add, frozen, nil)
}

func (c *stripeHTTPClient) ensureInvoiceSubscriptionValidated(ctx context.Context, a invoiceAccount, add, frozen bool, validate func(invoiceSubscription) error) (invoiceAccount, error) {
	var price storagePrice
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(a.Price), nil, &price, ""); err != nil {
		return a, err
	}
	amount, amountOK := new(big.Rat).SetString(price.UnitAmountDecimal)
	if !amountOK || amount.Cmp(big.NewRat(1, 1)) != 0 || price.ID != a.Price || !price.Active || price.Currency != "usd" || price.BillingScheme != "per_unit" || price.TransformQuantity != nil || price.Recurring.UsageType != "metered" || price.Recurring.Interval != "month" || price.Recurring.IntervalCount != 1 || price.Recurring.Meter == "" {
		return a, fmt.Errorf("adjustment price must be a USD monthly metered one-cent price")
	}
	meter, err := c.ActiveMeterID(ctx, a.Event)
	if err != nil {
		return a, err
	}
	if meter != price.Recurring.Meter || (a.Meter != "" && a.Meter != meter) {
		return a, fmt.Errorf("adjustment meter mapping changed")
	}
	a.Meter = meter
	s, err := c.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return a, err
	}
	statusOK := s.Status == "active" || (!add && frozen && s.Status == "canceled")
	if s.Customer != a.Customer || !statusOK || s.AutomaticTax.Enabled || len(s.Discounts) != 0 || s.BillingThresholds != nil {
		return a, fmt.Errorf("invoice reconciliation requires an eligible, undiscounted metered subscription without tax or thresholds")
	}
	if a.ReplacementSubscription != "" {
		replacement, e := c.invoiceSubscription(ctx, a.ReplacementSubscription)
		if e != nil {
			return a, e
		}
		if !frozen || add || replacement.Customer != a.ReplacementCustomer || replacement.Status != "active" || replacement.PauseCollection == nil || replacement.PauseCollection.Behavior != "keep_as_draft" || replacement.PauseCollection.ResumesAt != 0 {
			return a, fmt.Errorf("historical recovery requires the replacement subscription to remain held")
		}
	}
	var subscriptions struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {a.Customer}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &subscriptions, ""); err != nil {
		return a, err
	}
	if subscriptions.HasMore {
		return a, fmt.Errorf("subscription inventory exceeds reconciliation limit")
	}
	found := false
	for _, other := range subscriptions.Data {
		if other.ID == a.Subscription {
			found = true
			continue
		}
		if other.Status != "canceled" && other.Status != "incomplete_expired" && other.ID != a.ReplacementSubscription {
			return a, fmt.Errorf("another subscription can consume this customer's credits")
		}
	}
	if !found {
		return a, fmt.Errorf("subscription is absent from customer inventory")
	}
	refresh := func() error {
		var e error
		s, e = c.invoiceSubscription(ctx, a.Subscription)
		if e != nil {
			return e
		}
		if s.Customer != a.Customer || s.Status != "active" || s.AutomaticTax.Enabled || len(s.Discounts) != 0 || s.BillingThresholds != nil {
			return fmt.Errorf("subscription changed during enrollment")
		}
		if validate != nil {
			return validate(s)
		}
		return nil
	}
	countItems := func(s invoiceSubscription) int {
		count := 0
		for _, item := range s.Items.Data {
			if item.Price.ID == a.Price {
				count++
			}
		}
		return count
	}
	// Install the price before holding future renewals, so every invoice created
	// under our hold can carry a credit-eligible positive adjustment.
	if add {
		if err = refresh(); err != nil {
			return a, err
		}
	}
	if countItems(s) == 0 && add {
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscription_items", url.Values{"subscription": {a.Subscription}, "price": {a.Price}, "proration_behavior": {"none"}}, nil, "invoice-rounding-item:"+a.Subscription+":"+a.Price); err != nil {
			return a, err
		}
		if err = refresh(); err != nil {
			return a, err
		}
	}
	if countItems(s) != 1 {
		return a, fmt.Errorf("subscription must include exactly one rounding adjustment item")
	}
	if s.PauseCollection == nil || s.PauseCollection.Behavior != "keep_as_draft" || s.PauseCollection.ResumesAt != 0 {
		if !add {
			return a, fmt.Errorf("subscription collection hold is missing")
		}
		if err = refresh(); err != nil {
			return a, err
		}
		if countItems(s) != 1 {
			return a, fmt.Errorf("rounding item changed before collection hold")
		}
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(a.Subscription), url.Values{"pause_collection[behavior]": {"keep_as_draft"}}, nil, ""); err != nil {
			return a, err
		}
		s, err = c.invoiceSubscription(ctx, a.Subscription)
		if err != nil {
			return a, err
		}
		if s.Customer != a.Customer || s.Status != "active" || s.PauseCollection == nil || s.PauseCollection.Behavior != "keep_as_draft" || s.PauseCollection.ResumesAt != 0 {
			return a, fmt.Errorf("subscription collection hold was not retained")
		}
	}
	if countItems(s) != 1 {
		return a, fmt.Errorf("rounding item changed while establishing collection hold")
	}
	if validate != nil {
		if err = refresh(); err != nil {
			return a, err
		}
		if countItems(s) != 1 || s.PauseCollection == nil || s.PauseCollection.Behavior != "keep_as_draft" || s.PauseCollection.ResumesAt != 0 {
			return a, fmt.Errorf("enrollment protection changed during validation")
		}
	}
	return a, nil
}

func (c *stripeHTTPClient) billingCycleInvoice(ctx context.Context, a invoiceAccount, start, end int64) (StripeInvoiceAmounts, error) {
	var list struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	query := url.Values{"subscription": {a.Subscription}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+query.Encode(), nil, &list, ""); err != nil {
		return StripeInvoiceAmounts{}, err
	}
	var match *StripeInvoiceAmounts
	for _, candidate := range list.Data {
		if candidate.BillingReason != "subscription_cycle" || candidate.Status == "void" || candidate.PeriodStart != start || candidate.PeriodEnd != end {
			continue
		}
		invoice, err := c.RetrieveBillingInvoice(ctx, candidate.ID)
		if err != nil {
			return invoice, err
		}
		found := invoice.PeriodStart == start && invoice.PeriodEnd == end
		if found {
			if match != nil {
				return invoice, fmt.Errorf("multiple cycle invoices for period")
			}
			v := invoice
			match = &v
		}
	}
	if match == nil {
		return StripeInvoiceAmounts{}, fmt.Errorf("waiting for the scheduled renewal invoice")
	}
	if list.HasMore {
		return *match, fmt.Errorf("invoice inventory exceeds reconciliation scan limit")
	}
	if match.Customer != a.Customer || match.Currency != "usd" || match.Parent.SubscriptionDetails == nil || match.Parent.SubscriptionDetails.Subscription != a.Subscription {
		return *match, fmt.Errorf("invoice association changed")
	}
	return *match, nil
}

// A tentative attempt timestamp is not proof that collection was held. Rescue
// eligible drafts and exclude renewals that were already outside our protection.
func (c *stripeHTTPClient) invoiceEnrollmentBoundary(ctx context.Context, a invoiceAccount, attempt time.Time) (time.Time, error) {
	var list struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	query := url.Values{"subscription": {a.Subscription}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+query.Encode(), nil, &list, ""); err != nil {
		return attempt, err
	}
	if list.HasMore {
		return attempt, fmt.Errorf("enrollment invoice inventory exceeds reconciliation limit")
	}
	boundary := attempt
	var protected []time.Time
	for _, candidate := range list.Data {
		end := time.Unix(candidate.PeriodEnd, 0)
		if candidate.BillingReason != "subscription_cycle" || !end.After(attempt) {
			continue
		}
		inv, err := c.RetrieveBillingInvoice(ctx, candidate.ID)
		if err != nil {
			return attempt, err
		}
		if inv.Customer != a.Customer || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != a.Subscription || inv.PeriodEnd != candidate.PeriodEnd || inv.Lines.HasMore {
			return attempt, fmt.Errorf("enrollment invoice scope is incomplete or changed")
		}
		roundingLines := 0
		for _, line := range inv.Lines.Data {
			if line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price == a.Price {
				roundingLines++
			}
		}
		if inv.Status != "draft" || (roundingLines == 0 && inv.AutoAdvance) {
			if end.After(boundary) {
				boundary = end
			}
			continue
		}
		if roundingLines != 1 {
			return attempt, fmt.Errorf("held renewal lacks its rounding item; recovery required")
		}
		if _, err = c.HoldBillingInvoice(ctx, inv.ID); err != nil {
			return attempt, err
		}
		protected = append(protected, end)
	}
	for _, end := range protected {
		if !end.After(boundary) {
			return attempt, fmt.Errorf("enrollment boundary would orphan a held renewal; recovery required")
		}
	}
	return boundary, nil
}

// The first version supports the non-expiring, all-metered USD grants issued by
// the application. An incompatible grant is held for reconciliation, not guessed.
func (c *stripeHTTPClient) invoiceCreditLedger(ctx context.Context, customer string, periodEnd int64) (int64, error) {
	var grants struct {
		Data []struct {
			ID          string `json:"id"`
			VoidedAt    int64  `json:"voided_at"`
			ExpiresAt   int64  `json:"expires_at"`
			EffectiveAt int64  `json:"effective_at"`
			Scope       struct {
				Scope struct {
					PriceType string `json:"price_type"`
				} `json:"scope"`
			} `json:"applicability_config"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+url.Values{"customer": {customer}, "limit": {"100"}}.Encode(), nil, &grants, ""); err != nil {
		return 0, err
	}
	if grants.HasMore {
		return 0, fmt.Errorf("credit grant inventory exceeds reconciliation limit")
	}
	var total int64
	for _, g := range grants.Data {
		if g.VoidedAt != 0 {
			continue
		}
		var balance struct {
			Balances []struct {
				Ledger struct {
					Monetary *struct {
						Currency string `json:"currency"`
						Value    int64  `json:"value"`
					} `json:"monetary"`
				} `json:"ledger_balance"`
			} `json:"balances"`
		}
		query := url.Values{"customer": {customer}, "filter[type]": {"credit_grant"}, "filter[credit_grant]": {g.ID}}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_balance_summary?"+query.Encode(), nil, &balance, ""); err != nil {
			return 0, err
		}
		if len(balance.Balances) != 1 || balance.Balances[0].Ledger.Monetary == nil {
			return 0, fmt.Errorf("incomplete grant ledger")
		}
		m := balance.Balances[0].Ledger.Monetary
		if m.Value == 0 {
			continue
		}
		if m.Currency != "usd" || m.Value < 0 || m.Value > math.MaxInt64-total || g.ExpiresAt != 0 || g.EffectiveAt > periodEnd || g.Scope.Scope.PriceType != "metered" {
			return 0, fmt.Errorf("credit grant requires unsupported eligibility reconciliation")
		}
		total += m.Value
	}
	return total, nil
}

func (c *stripeHTTPClient) applyInvoiceDiscount(ctx context.Context, invoiceID string, cents int64, key string) error {
	if cents <= 0 {
		return fmt.Errorf("invalid invoice discount")
	}
	couponID := "rounding_" + invoiceID
	invoice, err := c.RetrieveBillingInvoice(ctx, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != "draft" || invoice.AutoAdvance {
		return fmt.Errorf("rounding discount requires a held draft")
	}
	attached := len(invoice.Discounts) == 1 && invoice.Discounts[0].Coupon == couponID
	if len(invoice.Discounts) != 0 && !attached {
		return fmt.Errorf("existing invoice discount differs from rounding plan")
	}
	var coupon struct {
		ID        string `json:"id"`
		AmountOff int64  `json:"amount_off"`
		Currency  string `json:"currency"`
	}
	// A deterministic coupon ID makes creation recoverable after Stripe expires
	// request idempotency. Never replace an existing coupon with another amount.
	err = c.doForm(ctx, http.MethodGet, "/v1/coupons/"+url.PathEscape(couponID), nil, &coupon, "")
	if err != nil {
		if !strings.HasPrefix(err.Error(), "stripe GET /v1/coupons/"+url.PathEscape(couponID)+" returned 404:") {
			return err
		}
		form := url.Values{"id": {couponID}, "amount_off": {strconv.FormatInt(cents, 10)}, "currency": {"usd"}, "duration": {"once"}, "name": {"Rounding adjustment"}}
		if err = c.doForm(ctx, http.MethodPost, "/v1/coupons", form, &coupon, key+":coupon"); err != nil {
			return err
		}
	}
	if coupon.ID != couponID || coupon.AmountOff != cents || coupon.Currency != "usd" {
		return fmt.Errorf("invoice rounding coupon differs from saved plan")
	}
	if attached {
		return nil
	}
	return c.doForm(ctx, http.MethodPost, "/v1/invoices/"+url.PathEscape(invoiceID), url.Values{"discounts[0][coupon]": {couponID}}, nil, key+":discount")
}

func (c *stripeHTTPClient) releaseBillingInvoice(ctx context.Context, id string) error {
	invoice, err := c.RetrieveBillingInvoice(ctx, id)
	if err != nil {
		return err
	}
	if invoice.Status == "paid" {
		return nil
	}
	if invoice.Status != "open" {
		return fmt.Errorf("verified invoice is not open for collection")
	}
	return c.doForm(ctx, http.MethodPost, "/v1/invoices/"+url.PathEscape(id), url.Values{"auto_advance": {"true"}}, nil, "")
}
