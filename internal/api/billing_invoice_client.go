package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"net/http"
	"net/url"
	"strings"

	"github.com/superserve-ai/sandbox/internal/billing"
)

// StripeInvoiceAmounts keeps provider money in its integer minor units. A
// preview has status=draft too; its upcoming_ ID does not identify an invoice
// that can be held or finalized.
type StripeInvoiceAmounts struct {
	PeriodStart     int64             `json:"period_start"`
	PeriodEnd       int64             `json:"period_end"`
	Discounts       []invoiceDiscount `json:"discounts"`
	ID              string            `json:"id"`
	Customer        string            `json:"customer"`
	Currency        string            `json:"currency"`
	Status          string            `json:"status"`
	BillingReason   string            `json:"billing_reason"`
	AutoAdvance     bool              `json:"auto_advance"`
	Subtotal        int64             `json:"subtotal"`
	Total           int64             `json:"total"`
	AmountDue       int64             `json:"amount_due"`
	StartingBalance int64             `json:"starting_balance"`
	EndingBalance   *int64            `json:"ending_balance"`
	Parent          struct {
		SubscriptionDetails *struct {
			Subscription string `json:"subscription"`
		} `json:"subscription_details"`
	} `json:"parent"`
	PretaxCredits   []StripeInvoicePretaxCredit `json:"total_pretax_credit_amounts"`
	DiscountAmounts []struct {
		Amount int64 `json:"amount"`
	} `json:"total_discount_amounts"`
	Taxes                  []json.RawMessage `json:"total_taxes"`
	AmountShipping         int64             `json:"amount_shipping"`
	PrePaymentCreditNotes  int64             `json:"pre_payment_credit_notes_amount"`
	PostPaymentCreditNotes int64             `json:"post_payment_credit_notes_amount"`
	Lines                  struct {
		Data    []StripeInvoiceAmountLine `json:"data"`
		HasMore bool                      `json:"has_more"`
	} `json:"lines"`
}

type StripeInvoicePretaxCredit struct {
	Type                     string `json:"type"`
	Amount                   int64  `json:"amount"`
	CreditBalanceTransaction string `json:"credit_balance_transaction"`
}

type StripeInvoiceAmountLine struct {
	Discounts       []json.RawMessage `json:"discounts"`
	ID              string            `json:"id"`
	Amount          int64             `json:"amount"`
	Currency        string            `json:"currency"`
	QuantityDecimal string            `json:"quantity_decimal"`
	Period          struct {
		Start int64 `json:"start"`
		End   int64 `json:"end"`
	} `json:"period"`
	Pricing struct {
		Type              string `json:"type"`
		UnitAmountDecimal string `json:"unit_amount_decimal"`
		PriceDetails      *struct {
			Price   string `json:"price"`
			Product string `json:"product"`
		} `json:"price_details"`
	} `json:"pricing"`
	Parent struct {
		SubscriptionItemDetails *struct {
			Subscription     string `json:"subscription"`
			SubscriptionItem string `json:"subscription_item"`
			Proration        bool   `json:"proration"`
		} `json:"subscription_item_details"`
	} `json:"parent"`
	PretaxCredits []StripeInvoicePretaxCredit `json:"pretax_credit_amounts"`
}

// PreviewBillingInvoice must always request a fresh preview. Stripe processes
// meter events asynchronously; caching this response can hide a correction.
func (c *stripeHTTPClient) PreviewBillingInvoice(ctx context.Context, subscriptionID string) (StripeInvoiceAmounts, error) {
	var invoice StripeInvoiceAmounts
	if !strings.HasPrefix(subscriptionID, "sub_") {
		return invoice, fmt.Errorf("a subscription is required for invoice preview")
	}
	err := c.doForm(ctx, http.MethodPost, "/v1/invoices/create_preview", url.Values{
		"subscription": {subscriptionID},
	}, &invoice, "")
	if err != nil {
		return invoice, err
	}
	if !strings.HasPrefix(invoice.ID, "upcoming_in_") {
		return invoice, fmt.Errorf("Stripe returned an invalid invoice preview")
	}
	if invoice.Lines.HasMore {
		return invoice, fmt.Errorf("invoice preview has incomplete line evidence")
	}
	return invoice, nil
}

func (c *stripeHTTPClient) RetrieveBillingInvoice(ctx context.Context, invoiceID string) (StripeInvoiceAmounts, error) {
	var invoice StripeInvoiceAmounts
	if !strings.HasPrefix(invoiceID, "in_") {
		return invoice, fmt.Errorf("a persisted invoice ID is required")
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(invoiceID)+"?expand[]=discounts", nil, &invoice, ""); err != nil {
		return invoice, err
	}
	if invoice.ID != invoiceID {
		return invoice, fmt.Errorf("Stripe returned a different invoice")
	}
	// Do not silently verify only the first page of a multi-line invoice.
	if invoice.Lines.HasMore {
		var lines []StripeInvoiceAmountLine
		cursor := ""
		for {
			query := url.Values{"limit": {"100"}}
			if cursor != "" {
				query.Set("starting_after", cursor)
			}
			var page struct {
				Data    []StripeInvoiceAmountLine `json:"data"`
				HasMore bool                      `json:"has_more"`
			}
			if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(invoiceID)+"/lines?"+query.Encode(), nil, &page, ""); err != nil {
				return invoice, err
			}
			lines = append(lines, page.Data...)
			if !page.HasMore {
				break
			}
			if len(page.Data) == 0 || page.Data[len(page.Data)-1].ID == cursor || len(lines) > 10000 {
				return invoice, fmt.Errorf("Stripe invoice line pagination did not complete")
			}
			cursor = page.Data[len(page.Data)-1].ID
		}
		invoice.Lines.Data, invoice.Lines.HasMore = lines, false
	}
	return invoice, nil
}

// VerifyBillingInvoiceSettlement supports the USD metered charge contract only.
// Taxes, shipping, and credit notes need separate accounting before collection
// can be released. Credit balances must come from actual ledger observations,
// not a preview's provisional credit reservation.
func VerifyBillingInvoiceSettlement(invoice StripeInvoiceAmounts, expectedChargeCents, creditBeforeCents, creditAfterCents int64) error {
	if !strings.HasPrefix(invoice.ID, "in_") || (invoice.Status != "open" && invoice.Status != "paid") || invoice.AutoAdvance {
		return fmt.Errorf("invoice is not finalized under collection hold")
	}
	if invoice.Currency != "usd" || invoice.Lines.HasMore || invoice.EndingBalance == nil {
		return fmt.Errorf("invoice currency or settlement evidence is unsupported")
	}
	if len(invoice.Taxes) != 0 || invoice.AmountShipping != 0 || invoice.PrePaymentCreditNotes != 0 || invoice.PostPaymentCreditNotes != 0 {
		return fmt.Errorf("invoice includes unsupported taxes, shipping, or credit notes")
	}
	gross := invoice.Subtotal
	for _, discount := range invoice.DiscountAmounts {
		if discount.Amount < 0 || discount.Amount > gross {
			return fmt.Errorf("invalid invoice discount")
		}
		gross -= discount.Amount
	}
	var applied int64
	for _, credit := range invoice.PretaxCredits {
		switch credit.Type {
		case "credit_balance_transaction":
			if credit.CreditBalanceTransaction == "" || credit.Amount < 0 || credit.Amount > math.MaxInt64-applied {
				return fmt.Errorf("invalid finalized billing credit evidence")
			}
			applied += credit.Amount
		case "discount": // Already included in total_discount_amounts above.
		default:
			return fmt.Errorf("unsupported invoice pretax credit type")
		}
	}
	return billing.VerifyInvoiceSettlement(expectedChargeCents, creditBeforeCents, billing.InvoiceSettlement{
		GrossCents: gross, CreditAppliedCents: applied, CreditRemainingCents: creditAfterCents,
		TotalCents: invoice.Total, AmountDueCents: invoice.AmountDue,
		StartingInvoiceBalance: invoice.StartingBalance, EndingInvoiceBalance: *invoice.EndingBalance,
	})
}

// HoldBillingInvoice stops automatic finalization and collection. Enrollment
// must separately hold the subscription before renewal; a webhook-only hold
// cannot protect an invoice when delivery or the worker is unavailable.
func (c *stripeHTTPClient) HoldBillingInvoice(ctx context.Context, invoiceID string) (StripeInvoiceAmounts, error) {
	invoice, err := c.RetrieveBillingInvoice(ctx, invoiceID)
	if err != nil {
		return invoice, err
	}
	if invoice.Status != "draft" {
		return invoice, fmt.Errorf("invoice was already finalized before collection hold")
	}
	if !invoice.AutoAdvance {
		return invoice, nil
	}
	var held StripeInvoiceAmounts
	if err := c.doForm(ctx, http.MethodPost, "/v1/invoices/"+url.PathEscape(invoiceID), url.Values{"auto_advance": {"false"}}, &held, ""); err != nil {
		return held, err
	}
	if held.ID != invoiceID || held.Status != "draft" || held.AutoAdvance {
		return held, fmt.Errorf("Stripe did not retain the draft collection hold")
	}
	return held, nil
}

// FinalizeHeldBillingInvoice never enables collection. The caller must verify
// its finalized charge and credit ledger before separately releasing payment.
// Late meter events are only recomputed for supported renewal invoices whose
// subscription prices have not changed during the service period.
func (c *stripeHTTPClient) FinalizeHeldBillingInvoice(ctx context.Context, invoiceID string, fullPeriodPricesVerified bool, idempotencyKey string) (StripeInvoiceAmounts, error) {
	invoice, err := c.RetrieveBillingInvoice(ctx, invoiceID)
	if err != nil {
		return invoice, err
	}
	if idempotencyKey == "" || !fullPeriodPricesVerified || invoice.BillingReason != "subscription_cycle" || invoice.AutoAdvance || invoice.Currency != "usd" {
		return invoice, fmt.Errorf("invoice is not an eligible held renewal")
	}
	if invoice.Status == "open" || invoice.Status == "paid" {
		// A lost finalize response must not cause another debit or a new invoice.
		return invoice, nil
	}
	if invoice.Status != "draft" {
		return invoice, fmt.Errorf("invoice cannot be finalized from status %q", invoice.Status)
	}
	var finalized StripeInvoiceAmounts
	if err := c.doForm(ctx, http.MethodPost, "/v1/invoices/"+url.PathEscape(invoiceID)+"/finalize", url.Values{"auto_advance": {"false"}}, &finalized, idempotencyKey); err != nil {
		return finalized, err
	}
	// Fetch every line again, and observe the persisted outcome of recomputation.
	invoice, err = c.RetrieveBillingInvoice(ctx, invoiceID)
	if err != nil {
		return invoice, err
	}
	if invoice.AutoAdvance || (invoice.Status != "open" && invoice.Status != "paid") {
		return invoice, fmt.Errorf("Stripe did not finalize the invoice under collection hold")
	}
	return invoice, nil
}

// Expanded discounts bind a recovery retry to its deterministic coupon.
type invoiceDiscount struct{ ID, Coupon string }

func (d *invoiceDiscount) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &d.ID)
	}
	var v struct {
		ID     string          `json:"id"`
		Coupon json.RawMessage `json:"coupon"`
		Source struct {
			Coupon json.RawMessage `json:"coupon"`
		} `json:"source"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	d.ID = v.ID
	if len(v.Source.Coupon) == 0 {
		v.Source.Coupon = v.Coupon
	}
	if len(v.Source.Coupon) > 0 && v.Source.Coupon[0] == '"' {
		return json.Unmarshal(v.Source.Coupon, &d.Coupon)
	}
	var coupon struct {
		ID string `json:"id"`
	}
	if len(v.Source.Coupon) > 0 {
		if err := json.Unmarshal(v.Source.Coupon, &coupon); err != nil {
			return err
		}
	}
	d.Coupon = coupon.ID
	return nil
}
