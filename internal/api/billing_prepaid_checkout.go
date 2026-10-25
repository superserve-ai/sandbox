package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var prepaidCheckoutNamespace = uuid.MustParse("6f1c8f55-3c4e-4f62-9d55-6a8b0c1f2e47")

type prepaidCheckoutLine struct {
	AmountCents int64
}

type prepaidCheckoutRequest struct {
	Customer    string `json:"customer"`
	Team        string `json:"team"`
	AmountCents int64  `json:"amount_cents"`
	SuccessURL  string `json:"success_url"`
	CancelURL   string `json:"cancel_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

type prepaidCheckoutSession struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	Mode          string            `json:"mode"`
	Status        string            `json:"status"`
	PaymentStatus string            `json:"payment_status"`
	Customer      string            `json:"customer"`
	PaymentIntent string            `json:"payment_intent"`
	Invoice       string            `json:"invoice"`
	Subscription  string            `json:"subscription"`
	Metadata      map[string]string `json:"metadata"`
}

// A replayed first-purchase checkout reuses its lease, so the purchase identity
// is derived from the lease rather than generated per request.
func prepaidCheckoutPurchaseID(team uuid.UUID, lease time.Time, amount int64) uuid.UUID {
	return uuid.NewSHA1(prepaidCheckoutNamespace, []byte(fmt.Sprintf("%s|%s|%d", team, lease.UTC().Format(time.RFC3339Nano), amount)))
}

func prepaidCheckoutOneTimeLine(id uuid.UUID, amount int64) StripeCheckoutOneTimeLine {
	return StripeCheckoutOneTimeLine{AmountCents: amount, Name: "Superserve prepaid credit", Metadata: map[string]string{"prepaid_purchase_id": id.String()}}
}

func validPrepaidAmount(amount int64) bool {
	return amount >= 500 && amount%500 == 0 && amount <= 100000000
}

func (h *Handlers) recordCheckoutPurchase(ctx context.Context, id, team uuid.UUID, customer string, actor uuid.UUID, amount int64, session string) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = h.preparePrepaidPurchase(ctx, tx, id, team, customer, actor, amount); err != nil {
		return err
	}
	if session == "" {
		if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_state='uncertain',payment_first_attempt_at=clock_timestamp(),next_attempt_at=clock_timestamp()+interval '2 minutes' WHERE id=$1 AND payment_state='pending'`, id); err != nil {
			return err
		}
	} else {
		var recorded *string
		err = tx.QueryRow(ctx, `UPDATE billing_prepaid_purchase SET checkout_session_id=COALESCE(checkout_session_id,$2),payment_state=CASE WHEN payment_state IN ('pending','uncertain') THEN 'processing' ELSE payment_state END,
   payment_first_attempt_at=COALESCE(payment_first_attempt_at,clock_timestamp()) WHERE id=$1 AND team_id=$3 AND customer_id=$4 AND amount_cents=$5 RETURNING checkout_session_id`, id, session, team, customer, amount).Scan(&recorded)
		if err != nil {
			return err
		}
		if recorded == nil || *recorded != session {
			return errors.New("prepaid purchase is bound to a different checkout session")
		}
	}
	return tx.Commit(ctx)
}

// Later purchases pay once in Checkout and save the card for auto-recharge.
func (h *Handlers) startPrepaidPaymentCheckout(ctx context.Context, client *stripeHTTPClient, team, actor uuid.UUID, customer string, amount int64, successURL, cancelURL string) (prepaidCheckoutSession, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return prepaidCheckoutSession{}, err
	}
	defer tx.Rollback(ctx)
	id := uuid.New()
	if err = h.preparePrepaidPurchase(ctx, tx, id, team, customer, actor, amount); err != nil {
		return prepaidCheckoutSession{}, err
	}
	request, err := json.Marshal(prepaidCheckoutRequest{Customer: customer, Team: team.String(), AmountCents: amount, SuccessURL: successURL, CancelURL: cancelURL, ExpiresAt: time.Now().Add(23 * time.Hour).Unix()})
	if err != nil {
		return prepaidCheckoutSession{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_request=$2,payment_state='uncertain',payment_first_attempt_at=clock_timestamp(),next_attempt_at=clock_timestamp()+interval '2 minutes' WHERE id=$1`, id, request); err != nil {
		return prepaidCheckoutSession{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return prepaidCheckoutSession{}, err
	}
	return h.dispatchPrepaidPaymentCheckout(ctx, client, id)
}

func (h *Handlers) dispatchPrepaidPaymentCheckout(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) (prepaidCheckoutSession, error) {
	var raw []byte
	var key string
	if err := h.Pool.QueryRow(ctx, `SELECT payment_request,payment_idempotency_key FROM billing_prepaid_purchase WHERE id=$1 AND source='checkout'`, id).Scan(&raw, &key); err != nil {
		return prepaidCheckoutSession{}, err
	}
	var req prepaidCheckoutRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return prepaidCheckoutSession{}, err
	}
	form := url.Values{
		"mode": {"payment"}, "customer": {req.Customer}, "client_reference_id": {req.Team},
		"success_url": {req.SuccessURL}, "cancel_url": {req.CancelURL}, "expires_at": {strconv.FormatInt(req.ExpiresAt, 10)},
		"line_items[0][price_data][currency]":                                    {"usd"},
		"line_items[0][price_data][unit_amount]":                                 {strconv.FormatInt(req.AmountCents, 10)},
		"line_items[0][price_data][product_data][name]":                          {"Superserve prepaid credit"},
		"line_items[0][price_data][product_data][metadata][prepaid_purchase_id]": {id.String()},
		"line_items[0][quantity]":                                                {"1"},
		"payment_intent_data[setup_future_usage]":                                {"off_session"},
		"payment_intent_data[metadata][prepaid_purchase_id]":                     {id.String()},
		"metadata[prepaid_purchase_id]":                                          {id.String()},
	}
	var session prepaidCheckoutSession
	if err := client.doForm(ctx, http.MethodPost, "/v1/checkout/sessions", form, &session, key); err != nil {
		return session, err
	}
	if session.ID == "" || session.Metadata["prepaid_purchase_id"] != id.String() {
		return session, errors.New("checkout session does not carry this purchase")
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET checkout_session_id=$2,payment_state='processing' WHERE id=$1 AND payment_state IN ('uncertain','processing') AND (checkout_session_id IS NULL OR checkout_session_id=$2)`, id, session.ID); err != nil {
		return session, err
	}
	return session, nil
}

func (c *stripeHTTPClient) retrievePrepaidCheckout(ctx context.Context, id string) (prepaidCheckoutSession, error) {
	var s prepaidCheckoutSession
	err := c.doForm(ctx, http.MethodGet, "/v1/checkout/sessions/"+url.PathEscape(id), nil, &s, "")
	if err == nil && s.ID != id {
		err = errors.New("checkout session identity changed")
	}
	return s, err
}

// Payment is proven only by re-reading Stripe: the paid PaymentIntent for a
// payment-mode checkout, or the paid first invoice carrying the credit line.
func (h *Handlers) settleCheckoutPurchase(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) error {
	var team uuid.UUID
	var customer, state string
	var amount int64
	var session *string
	var request []byte
	var first *time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,customer_id,amount_cents,payment_state,checkout_session_id,payment_request,payment_first_attempt_at FROM billing_prepaid_purchase WHERE id=$1`, id).
		Scan(&team, &customer, &amount, &state, &session, &request, &first); err != nil {
		return err
	}
	if session == nil {
		if first == nil {
			return h.failPrepaidPayment(ctx, id, "", "the checkout was never opened", false)
		}
		if request == nil || time.Since(*first) >= 23*time.Hour {
			found, err := client.findPrepaidCheckout(ctx, customer, id)
			if err != nil {
				return err
			}
			if found == "" {
				if time.Since(*first) < 23*time.Hour {
					return errPrepaidPaymentPending
				}
				return h.failPrepaidPayment(ctx, id, "", "the checkout was never opened", false)
			}
			if _, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET checkout_session_id=$2,payment_state='processing' WHERE id=$1 AND checkout_session_id IS NULL AND payment_state='uncertain'`, id, found); err != nil {
				return err
			}
			return errPrepaidPaymentPending
		}
		if _, err := h.dispatchPrepaidPaymentCheckout(ctx, client, id); err != nil {
			return err
		}
		return errPrepaidPaymentPending
	}
	s, err := client.retrievePrepaidCheckout(ctx, *session)
	if err != nil {
		return err
	}
	if s.Customer != customer {
		return errors.New("checkout session customer differs from the purchase")
	}
	switch s.Status {
	case "expired":
		return h.failPrepaidPayment(ctx, id, "", "the checkout was not completed", false)
	case "open":
		return errPrepaidPaymentPending
	case "complete":
	default:
		return fmt.Errorf("unexpected checkout status %q", s.Status)
	}
	var evidence []byte
	switch s.Mode {
	case "payment":
		if s.Metadata["prepaid_purchase_id"] != id.String() || s.PaymentIntent == "" {
			return errors.New("payment checkout does not carry this purchase")
		}
		pi, err := client.retrievePrepaidPaymentIntent(ctx, s.PaymentIntent)
		if err != nil {
			return err
		}
		if pi.Customer != customer || pi.Currency != "usd" || pi.Amount != amount || pi.Metadata["prepaid_purchase_id"] != id.String() {
			return errors.New("payment intent does not match the purchase")
		}
		if pi.Status == "processing" || pi.Status == "requires_action" {
			return errPrepaidPaymentPending
		}
		if pi.Status == "canceled" {
			return h.failPrepaidPayment(ctx, id, "", "the payment did not succeed", false)
		}
		if pi.Status != "succeeded" || pi.AmountReceived != amount {
			return errPrepaidPaymentPending
		}
		evidence, _ = json.Marshal(map[string]any{"amount_cents": pi.AmountReceived, "customer": pi.Customer, "checkout_session": s, "payment_intent": pi})
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_intent_id=$2 WHERE id=$1 AND payment_intent_id IS NULL`, id, pi.ID); err != nil {
			return err
		}
	case "subscription":
		if s.Invoice == "" {
			return errPrepaidPaymentPending
		}
		inv, err := client.RetrieveBillingInvoice(ctx, s.Invoice)
		if err != nil {
			return err
		}
		if inv.Customer != customer {
			return errors.New("first invoice customer differs from the purchase")
		}
		if inv.Status == "void" {
			return h.failPrepaidPayment(ctx, id, "", "the first invoice was voided", false)
		}
		if inv.Status != "paid" || inv.AmountRemaining == nil || *inv.AmountRemaining != 0 {
			return errPrepaidPaymentPending
		}
		line, err := client.prepaidInvoiceLine(ctx, inv, id)
		if err != nil {
			return err
		}
		if line.Amount != amount || line.Currency != "usd" || len(line.PretaxCredits) != 0 {
			return errors.New("first invoice credit line differs from the purchase")
		}
		evidence, _ = json.Marshal(map[string]any{"amount_cents": line.Amount, "customer": inv.Customer, "checkout_session": s, "invoice": inv})
		intents, err := client.invoicePaymentIntents(ctx, inv.ID)
		if err != nil {
			return err
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET invoice_id=COALESCE(invoice_id,$2),
 reversal_payment_intents=ARRAY(SELECT DISTINCT unnest(reversal_payment_intents||$3::text[]) ORDER BY 1) WHERE id=$1`, id, inv.ID, intents); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected checkout mode %q", s.Mode)
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_state='succeeded',payment_evidence=$2,paid_at=clock_timestamp() WHERE id=$1 AND payment_state IN ('uncertain','processing')`, id, evidence)
	return err
}

func (c *stripeHTTPClient) prepaidInvoiceLine(ctx context.Context, inv StripeInvoiceAmounts, id uuid.UUID) (StripeInvoiceAmountLine, error) {
	var found []StripeInvoiceAmountLine
	for _, line := range inv.Lines.Data {
		if line.Pricing.PriceDetails == nil || line.Pricing.PriceDetails.Product == "" || line.Parent.SubscriptionItemDetails != nil {
			continue
		}
		var product struct {
			ID       string            `json:"id"`
			Metadata map[string]string `json:"metadata"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/products/"+url.PathEscape(line.Pricing.PriceDetails.Product), nil, &product, ""); err != nil {
			return StripeInvoiceAmountLine{}, err
		}
		if product.ID == line.Pricing.PriceDetails.Product && product.Metadata["prepaid_purchase_id"] == id.String() {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		return StripeInvoiceAmountLine{}, fmt.Errorf("first invoice carries %d credit lines for this purchase", len(found))
	}
	return found[0], nil
}

func (c *stripeHTTPClient) findPrepaidCheckout(ctx context.Context, customer string, id uuid.UUID) (string, error) {
	cursor := ""
	var found []string
	for page := 0; page < 20; page++ {
		q := url.Values{"customer": {customer}, "limit": {"100"}}
		if cursor != "" {
			q.Set("starting_after", cursor)
		}
		var list struct {
			Data    []prepaidCheckoutSession `json:"data"`
			HasMore bool                     `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/checkout/sessions?"+q.Encode(), nil, &list, ""); err != nil {
			return "", err
		}
		for _, s := range list.Data {
			if s.Metadata["prepaid_purchase_id"] == id.String() {
				found = append(found, s.ID)
			}
		}
		if !list.HasMore {
			if len(found) > 1 {
				return "", errors.New("multiple checkouts carry one purchase identity; operator recovery required")
			}
			if len(found) == 1 {
				return found[0], nil
			}
			return "", nil
		}
		if len(list.Data) == 0 {
			return "", errors.New("empty incomplete checkout page")
		}
		cursor = list.Data[len(list.Data)-1].ID
	}
	return "", errors.New("checkout inventory exceeds the discovery bound")
}
