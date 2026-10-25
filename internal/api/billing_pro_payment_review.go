package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

type proPaymentReviewError struct {
	reason   string
	evidence json.RawMessage
}

func (e *proPaymentReviewError) Error() string { return e.reason }

// Credit notes linked exclusively to usage lines do not change the licensed fee.
func (c *stripeHTTPClient) verifyProCreditNotes(ctx context.Context, inv proPaidInvoice, base string) error {
	if inv.PrePaymentCreditNotes == 0 && inv.PostPaymentCreditNotes == 0 {
		return nil
	}
	review := &proPaymentReviewError{reason: "base payment credit-note allocation requires review"}
	if inv.PrePaymentCreditNotes != 0 {
		return review
	}
	usage := map[string]bool{}
	for _, line := range inv.Lines.Data {
		if line.ID != "" && line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price != base {
			usage[line.ID] = true
		}
	}
	var notes struct {
		HasMore bool `json:"has_more"`
		Data    []struct {
			Invoice, Customer, Currency, Status string
			PostPaymentAmount                   int64 `json:"post_payment_amount"`
			Lines                               struct {
				HasMore bool `json:"has_more"`
				Data    []struct {
					Type            string
					InvoiceLineItem string `json:"invoice_line_item"`
				} `json:"data"`
			} `json:"lines"`
		} `json:"data"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/credit_notes?"+url.Values{"invoice": {inv.ID}, "limit": {"100"}}.Encode(), nil, &notes, ""); err != nil {
		return err
	}
	review.evidence, _ = json.Marshal(notes)
	if notes.HasMore {
		return review
	}
	var total int64
	for _, note := range notes.Data {
		if note.Status == "void" {
			continue
		}
		if note.Status != "issued" || note.Invoice != inv.ID || note.Customer != inv.Customer || note.Currency != "usd" || note.Lines.HasMore || len(note.Lines.Data) == 0 || note.PostPaymentAmount < 0 || note.PostPaymentAmount > inv.PostPaymentCreditNotes-total {
			return review
		}
		for _, line := range note.Lines.Data {
			if line.Type != "invoice_line_item" || !usage[line.InvoiceLineItem] {
				return review
			}
		}
		total += note.PostPaymentAmount
	}
	if total != inv.PostPaymentCreditNotes {
		return review
	}
	return nil
}

func (c *stripeHTTPClient) verifyProCharge(ctx context.Context, id, intent, customer string, amount int64) (json.RawMessage, error) {
	if id == "" {
		return nil, &proPaymentReviewError{reason: "paid intent is missing its charge"}
	}
	var charge struct {
		ID, Customer, Currency   string
		PaymentIntent            string `json:"payment_intent"`
		Paid, Captured, Disputed bool
		AmountCaptured           int64 `json:"amount_captured"`
		AmountRefunded           int64 `json:"amount_refunded"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/charges/"+url.PathEscape(id), nil, &charge, ""); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(charge)
	if charge.ID != id || charge.Customer != customer || charge.PaymentIntent != intent || charge.Currency != "usd" || !charge.Paid || !charge.Captured || charge.AmountCaptured < amount {
		return raw, &proPaymentReviewError{reason: "charge does not prove owned captured payment", evidence: raw}
	}
	if charge.AmountRefunded != 0 || charge.Disputed {
		return raw, &proPaymentReviewError{reason: "base payment charge was refunded or disputed; allocation requires review", evidence: raw}
	}
	return raw, nil
}

// Receipt history remains immutable. A separate observation can temporarily stop
// new authorization without revoking grants or deciding refund economics.
func (h *Handlers) observeProPaymentReview(ctx context.Context, team uuid.UUID, invoice string, ev proPaymentEvidence, verificationErr error) error {
	var review *proPaymentReviewError
	if verificationErr != nil && !errors.As(verificationErr, &review) {
		return nil
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var contract uuid.UUID
	err = tx.QueryRow(ctx, `SELECT c.id FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE p.team_id=$1 AND p.invoice_id=$2 FOR UPDATE OF c`, team, invoice).Scan(&contract)
	if err != nil {
		return err
	}
	evidence, _ := json.Marshal(struct {
		Invoice  proPaidInvoice
		Error    string
		Provider json.RawMessage
	}{ev.Invoice, func() string {
		if verificationErr != nil {
			return verificationErr.Error()
		}
		return ""
	}(), func() json.RawMessage {
		if review != nil {
			return review.evidence
		}
		return nil
	}()})
	_, err = tx.Exec(ctx, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) VALUES($1,$2,$3) ON CONFLICT(invoice_id) DO UPDATE SET review_required=EXCLUDED.review_required,evidence=EXCLUDED.evidence,observed_at=clock_timestamp()`, invoice, review != nil, evidence)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
