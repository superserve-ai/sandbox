package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"
)

type fundingProviderObservation struct {
	PaymentMethodID          string
	PaymentMethodFingerprint string
	PaymentMethodReusable    bool
	CashChargeID             string
	CashCollected            bool
	CollectionReady          bool
	DebtInvoiceID            string
	UnpaidRenewalInvoiceID   string
	ChargeScanComplete       bool
	NextChargeCursor         string
	Subscription             invoiceSubscription
	ValidUntil               time.Time
	Evidence                 []byte `json:"-"`
}

type fundingCharge struct {
	ID             string `json:"id"`
	Customer       string `json:"customer"`
	Live           bool   `json:"livemode"`
	Currency       string `json:"currency"`
	Status         string `json:"status"`
	Paid           bool   `json:"paid"`
	Captured       bool   `json:"captured"`
	AmountCaptured int64  `json:"amount_captured"`
	AmountRefunded int64  `json:"amount_refunded"`
	Refunded       bool   `json:"refunded"`
	Disputed       bool   `json:"disputed"`
	PaymentMethod  string `json:"payment_method"`
	PaymentIntent  string `json:"payment_intent"`
}

func (ch fundingCharge) collected(customer string, live bool) bool {
	return ch.ID != "" && ch.Customer == customer && ch.Live == live && ch.Currency == "usd" && ch.Status == "succeeded" && ch.Paid && ch.Captured && ch.AmountCaptured > 0 && ch.AmountRefunded == 0 && !ch.Refunded && !ch.Disputed
}

func (c *stripeHTTPClient) observeFunding(ctx context.Context, customer, subscription string, live bool, previousChargeID string) (fundingProviderObservation, error) {
	return c.observeFundingPage(ctx, customer, subscription, live, previousChargeID, "")
}

// This background observation performs at most one charge-history page per run.
// The caller persists the cursor, binds Subscription to its enrolled usage
// prices, and expires all authorizing evidence when a refresh fails.
func (c *stripeHTTPClient) observeFundingPage(ctx context.Context, customer, subscription string, live bool, previousChargeID, cursor string) (fundingProviderObservation, error) {
	var out fundingProviderObservation
	out.ValidUntil = time.Now().UTC().Add(5 * time.Minute)
	if customer == "" {
		return out, errors.New("funding customer is required")
	}
	var cust ycCustomer
	if err := c.doForm(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(customer), nil, &cust, ""); err != nil {
		return out, err
	}
	if cust.ID != customer || cust.Deleted || cust.Live != live {
		return out, errors.New("funding customer identity or mode changed")
	}
	if subscription != "" {
		sub, err := c.invoiceSubscription(ctx, subscription)
		if err != nil {
			return out, err
		}
		if sub.Customer != customer || sub.LiveMode != live {
			return out, errors.New("funding subscription owner or mode changed")
		}
		out.Subscription = sub
		out.CollectionReady = fundingCollectionReady(sub)
	}
	out.PaymentMethodID = out.Subscription.DefaultPaymentMethod
	if out.PaymentMethodID == "" {
		out.PaymentMethodID = cust.InvoiceSettings.DefaultPaymentMethod
	}
	methodUsable := false
	if out.PaymentMethodID != "" {
		var method struct {
			ID       string `json:"id"`
			Customer string `json:"customer"`
			Live     bool   `json:"livemode"`
			Type     string `json:"type"`
			Card     *struct {
				Month       int    `json:"exp_month"`
				Year        int    `json:"exp_year"`
				Fingerprint string `json:"fingerprint"`
			} `json:"card"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_methods/"+url.PathEscape(out.PaymentMethodID), nil, &method, ""); err != nil {
			return out, err
		}
		if method.ID != out.PaymentMethodID || method.Customer != customer || method.Live != live {
			return out, errors.New("funding payment method ownership or mode changed")
		}
		if types := out.Subscription.PaymentSettings.PaymentMethodTypes; len(types) == 0 || slices.Contains(types, method.Type) {
			if method.Type == "card" && method.Card != nil {
				now := time.Now().UTC()
				methodUsable = method.Card.Month >= 1 && method.Card.Month <= 12 && (method.Card.Year > now.Year() || method.Card.Year == now.Year() && method.Card.Month >= int(now.Month()))
				out.PaymentMethodFingerprint = method.Card.Fingerprint
				if methodUsable {
					expiry := time.Date(method.Card.Year, time.Month(method.Card.Month)+1, 1, 0, 0, 0, 0, time.UTC)
					if expiry.Before(out.ValidUntil) {
						out.ValidUntil = expiry
					}
				}
			} else if method.Type == "link" {
				methodUsable = true
			}
		}
		if methodUsable {
			ready, err := c.fundingOffSessionSetup(ctx, customer, out.PaymentMethodID, live)
			if err != nil {
				return out, err
			}
			out.PaymentMethodReusable = ready
		}
	}
	var saved fundingCharge
	if previousChargeID != "" {
		if err := c.doForm(ctx, http.MethodGet, "/v1/charges/"+url.PathEscape(previousChargeID), nil, &saved, ""); err != nil {
			return out, err
		}
		if saved.ID != previousChargeID || saved.Customer != customer || saved.Live != live {
			return out, errors.New("funding charge identity, owner or mode changed")
		}
		out.CashCollected = saved.collected(customer, live)
		if out.CashCollected {
			out.CashChargeID = saved.ID
		}
	}
	checkReuse := func(ch fundingCharge) error {
		if out.PaymentMethodReusable || !methodUsable || !ch.collected(customer, live) || ch.PaymentMethod != out.PaymentMethodID || ch.PaymentIntent == "" {
			return nil
		}
		ready, err := c.fundingPaymentReuse(ctx, ch, live)
		out.PaymentMethodReusable = ready
		return err
	}
	if err := checkReuse(saved); err != nil {
		return out, err
	}
	if !out.CashCollected || methodUsable && !out.PaymentMethodReusable {
		var page struct {
			Data    []fundingCharge `json:"data"`
			HasMore bool            `json:"has_more"`
		}
		q := url.Values{"customer": {customer}, "limit": {"100"}}
		if cursor != "" {
			q.Set("starting_after", cursor)
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/charges?"+q.Encode(), nil, &page, ""); err != nil {
			return out, err
		}
		if page.HasMore && len(page.Data) == 0 {
			return out, errors.New("empty incomplete funding charge inventory")
		}
		out.ChargeScanComplete = !page.HasMore
		if page.HasMore {
			out.NextChargeCursor = page.Data[len(page.Data)-1].ID
		}
		// Only one PaymentIntent candidate is retrieved per page, preventing
		// provider calls from scaling with a customer's charge history.
		checkedReuse := false
		seen := map[string]bool{}
		for i, ch := range page.Data {
			if ch.ID == "" || ch.Customer != customer || ch.Live != live || seen[ch.ID] || ch.ID == cursor {
				return out, errors.New("funding charge inventory identity mismatch")
			}
			seen[ch.ID] = true
			if !ch.collected(customer, live) {
				continue
			}
			if !out.CashCollected {
				out.CashCollected, out.CashChargeID = true, ch.ID
			}
			if !checkedReuse && ch.PaymentMethod == out.PaymentMethodID && ch.PaymentIntent != "" {
				if err := checkReuse(ch); err != nil {
					return out, err
				}
				checkedReuse = true
				if methodUsable && !out.PaymentMethodReusable && i < len(page.Data)-1 {
					out.NextChargeCursor = ch.ID
					out.ChargeScanComplete = false
				}
			}
		}
	}
	debt, err := c.entitlementDebt(ctx, customer)
	if err != nil {
		return out, err
	}
	out.DebtInvoiceID = debt
	out.Evidence, err = json.Marshal(out)
	return out, err
}

func fundingCollectionReady(sub invoiceSubscription) bool {
	if sub.ID == "" || !slices.Contains([]string{"active", "trialing", "past_due"}, sub.Status) || sub.EndedAt != 0 || sub.Items.HasMore || sub.CollectionMethod != "charge_automatically" {
		return false
	}
	if sub.PauseCollection != nil && (sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0) {
		return false
	}
	meters := map[string]bool{}
	for _, item := range sub.Items.Data {
		p := item.Price
		if p.Recurring.UsageType != "metered" {
			continue
		}
		amount, err := meterDecimal(p.UnitAmountDecimal)
		if item.ID == "" || p.ID == "" || p.Product == "" || p.LiveMode != sub.LiveMode || !proResourceShape(p) || p.Recurring.Meter == "" || meters[p.Recurring.Meter] || err != nil || amount.Sign() < 0 {
			return false
		}
		meters[p.Recurring.Meter] = true
	}
	return len(meters) >= 2
}

func (c *stripeHTTPClient) fundingOffSessionSetup(ctx context.Context, customer, method string, live bool) (bool, error) {
	var page struct {
		Data []struct {
			ID               string `json:"id"`
			Customer         string `json:"customer"`
			PaymentMethod    string `json:"payment_method"`
			Status           string `json:"status"`
			Usage            string `json:"usage"`
			Live             bool   `json:"livemode"`
			Mandate          string `json:"mandate"`
			SingleUseMandate string `json:"single_use_mandate"`
			OnBehalfOf       string `json:"on_behalf_of"`
		} `json:"data"`
	}
	q := url.Values{"payment_method": {method}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/setup_intents?"+q.Encode(), nil, &page, ""); err != nil {
		return false, err
	}
	for _, setup := range page.Data {
		if setup.ID == "" || setup.Customer != customer || setup.PaymentMethod != method || setup.Live != live || setup.Status != "succeeded" || setup.Usage != "off_session" || setup.SingleUseMandate != "" || setup.OnBehalfOf != "" {
			continue
		}
		if setup.Mandate == "" {
			return true, nil
		}
		var mandate struct {
			ID            string `json:"id"`
			PaymentMethod string `json:"payment_method"`
			Status        string `json:"status"`
			Type          string `json:"type"`
			Live          bool   `json:"livemode"`
			OnBehalfOf    string `json:"on_behalf_of"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/mandates/"+url.PathEscape(setup.Mandate), nil, &mandate, ""); err != nil {
			return false, err
		}
		return mandate.ID == setup.Mandate && mandate.PaymentMethod == method && mandate.Status == "active" && mandate.Type == "multi_use" && mandate.Live == live && mandate.OnBehalfOf == "", nil
	}
	return false, nil
}

func (c *stripeHTTPClient) fundingPaymentReuse(ctx context.Context, ch fundingCharge, live bool) (bool, error) {
	var pi struct {
		ID               string `json:"id"`
		Customer         string `json:"customer"`
		PaymentMethod    string `json:"payment_method"`
		LatestCharge     string `json:"latest_charge"`
		Status           string `json:"status"`
		Currency         string `json:"currency"`
		AmountReceived   int64  `json:"amount_received"`
		SetupFutureUsage string `json:"setup_future_usage"`
		Live             bool   `json:"livemode"`
		OnBehalfOf       string `json:"on_behalf_of"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(ch.PaymentIntent), nil, &pi, ""); err != nil {
		return false, err
	}
	return pi.ID == ch.PaymentIntent && pi.Customer == ch.Customer && pi.PaymentMethod == ch.PaymentMethod && pi.LatestCharge == ch.ID && pi.Live == live && pi.Status == "succeeded" && pi.Currency == "usd" && pi.AmountReceived > 0 && pi.SetupFutureUsage == "off_session" && pi.OnBehalfOf == "", nil
}
