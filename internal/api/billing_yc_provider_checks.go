package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/superserve-ai/sandbox/internal/billing"
	"net/http"
	"net/url"
	"time"
)

// No unrelated live grant can silently become an additional YC allowance.
// Historical expired/voided grants are retained and do not block adoption.
func (c *stripeHTTPClient) ycGrantPreflight(ctx context.Context, customer, contract, approved string) error {
	var list struct {
		Data    []entitlementGrant `json:"data"`
		HasMore bool               `json:"has_more"`
	}
	q := url.Values{"customer": {customer}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+q.Encode(), nil, &list, ""); err != nil {
		return err
	}
	if list.HasMore {
		return errors.New("grant inventory exceeds preflight bound; operator reconciliation required")
	}
	live := 0
	for _, g := range list.Data {
		if g.Customer != customer {
			return errors.New("grant inventory customer differs")
		}
		if g.VoidedAt != 0 || (g.ExpiresAt > 0 && g.ExpiresAt <= time.Now().Unix()) {
			continue
		}
		live++
		if live > 1 {
			return errors.New("multiple live grants conflict with a single monthly allowance")
		}
		if g.ID != approved && (contract == "" || g.Metadata["superserve_contract_id"] != contract) {
			return errors.New("existing credit grant conflicts with YC approval; reconcile before provider writes")
		}
	}
	return nil
}

// Once monthly items exist Stripe's relative cancellation may refer to their
// shorter period. Preserve the covered annual term with an absolute boundary.
func (h *Handlers) normalizeYCCancellation(ctx context.Context, o ycOperation, sub invoiceSubscription, c *stripeHTTPClient) (invoiceSubscription, error) {
	if !sub.CancelAtPeriodEnd {
		_, err := h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET cancel_pending=false WHERE team_id=$1 AND cancel_pending`, o.Team)
		return sub, err
	}
	boundary := o.End.Time
	if o.End.Valid && !time.Now().Before(o.End.Time) {
		// Annual product access after the waiver requires actual paid coverage.
		if err := h.Pool.QueryRow(ctx, `SELECT service_period_end FROM billing_contract_payment p WHERE contract_id=$1 AND service_period_start<=clock_timestamp() AND service_period_end>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)`, o.Renewal).Scan(&boundary); err != nil {
			return sub, err
		}
	}
	if !o.End.Valid || !time.Now().Before(boundary) {
		return sub, errors.New("cannot normalize cancellation without a future covered annual boundary")
	}
	var generation int64
	err := h.Pool.QueryRow(ctx, `UPDATE billing_yc_operation SET cancel_generation=CASE WHEN cancel_pending AND cancel_requested_at=$2 AND cancel_boundary=$3 THEN cancel_generation ELSE cancel_generation+1 END,cancel_pending=true,cancel_requested_at=$2,cancel_boundary=$3 WHERE team_id=$1 RETURNING cancel_generation`, o.Team, sub.CanceledAt, boundary).Scan(&generation)
	if err != nil {
		return sub, err
	}
	form := url.Values{"cancel_at_period_end": {"false"}, "cancel_at": {fmt.Sprint(boundary.Unix())}, "proration_behavior": {"none"}}
	if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), form, nil, fmt.Sprintf("yc-cancel:%s:%d", o.ID, generation)); err != nil {
		return sub, err
	}
	updated, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return sub, err
	}
	if updated.Customer != sub.Customer || updated.CancelAtPeriodEnd || updated.CancelAt != boundary.Unix() || updated.BillingCycleAnchor != sub.BillingCycleAnchor {
		return sub, errors.New("annual nonrenewal could not be verified")
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET cancel_pending=false WHERE team_id=$1 AND cancel_generation=$2`, o.Team, generation)
	return updated, err
}

func (c *stripeHTTPClient) clearYCFirstInvoiceDiscount(ctx context.Context, o ycOperation, sub invoiceSubscription) (invoiceSubscription, error) {
	if len(sub.Discounts) == 0 {
		return sub, nil
	}
	if sub.Metadata["yc_operation"] != o.ID.String() {
		return sub, errors.New("cannot change a discount on an unowned subscription")
	}
	if err := c.verifyYCFirstInvoice(ctx, sub, o.Params.BasePriceID); err != nil {
		return sub, err
	}
	var expanded struct {
		Discounts []struct {
			ID     string `json:"id"`
			Source struct {
				Coupon struct {
					ID       string  `json:"id"`
					Duration string  `json:"duration"`
					Percent  float64 `json:"percent_off"`
				} `json:"coupon"`
			} `json:"source"`
		} `json:"discounts"`
	}
	q := url.Values{"expand[]": {"discounts.source.coupon"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(sub.ID)+"?"+q.Encode(), nil, &expanded, ""); err != nil {
		return sub, err
	}
	if len(expanded.Discounts) != 1 || len(sub.Discounts) != 1 || expanded.Discounts[0].ID != sub.Discounts[0] || expanded.Discounts[0].Source.Coupon.ID != "yc-first-year-"+o.ID.String() || expanded.Discounts[0].Source.Coupon.Duration != "once" || expanded.Discounts[0].Source.Coupon.Percent != 100 {
		return sub, errors.New("unexpected subscription discount; operator review required")
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), url.Values{"discounts": {""}, "proration_behavior": {"none"}}, nil, "yc-discount-consumed:"+o.ID.String()); err != nil {
		return sub, err
	}
	return c.invoiceSubscription(ctx, sub.ID)
}

func (c *stripeHTTPClient) validateYCExistingGrant(ctx context.Context, sub invoiceSubscription, p StripeCreateCheckoutSessionParams, id string) (entitlementGrant, error) {
	g, err := c.retrieveEntitlementGrant(ctx, id)
	if err != nil {
		return g, err
	}
	anchor := time.Unix(sub.StartDate, 0).UTC()
	start, end, ok := billing.AnniversaryPeriod(anchor, time.Now())
	if !ok || !start.Before(ycAnnualEnd(anchor)) {
		return g, errors.New("existing grant is outside the waived year")
	}
	months := (start.Year()-anchor.Year())*12 + int(start.Month()) - int(anchor.Month())
	amount := int64(100000)
	if months < 3 {
		amount = 3000000
	}
	var prices struct {
		Data    []storagePrice `json:"data"`
		HasMore bool           `json:"has_more"`
	}
	q := url.Values{"lookup_keys[]": {invoiceRoundingLookup}, "limit": {"2"}}
	if err = c.doForm(ctx, http.MethodGet, "/v1/prices?"+q.Encode(), nil, &prices, ""); err != nil {
		return g, err
	}
	if prices.HasMore || len(prices.Data) != 1 {
		return g, errors.New("existing grant requires a unique rounding price")
	}
	if err = validateEntitlementResourceTerms(p.ResourceTerms, prices.Data[0].ID, invoiceRoundingEvent, prices.Data[0].Recurring.Meter, false); err != nil {
		return g, err
	}
	scope := []string{prices.Data[0].ID}
	for _, t := range p.ResourceTerms {
		scope = append(scope, t.PriceID)
	}
	if err = creditScope(g, sub.Customer, end.Unix(), scope); err != nil {
		return g, err
	}
	if g.Category != "promotional" || g.Amount.Monetary.Value != amount || g.EffectiveAt < start.Unix()+1 || g.EffectiveAt > time.Now().Unix() || g.Created < sub.StartDate || g.Created > g.EffectiveAt || g.ExpiresAt != end.Unix()+1 || g.Applicability.Scope.PriceType != "" || len(g.Applicability.Scope.Prices) != len(scope) {
		return g, errors.New("existing grant does not match the current full YC allowance")
	}
	balance, err := c.grantLedgerBalance(ctx, sub.Customer, id)
	if err != nil {
		return g, err
	}
	if balance > amount {
		return g, errors.New("existing grant balance exceeds its allowance")
	}
	return g, nil
}
