package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (h *Handlers) verifyProContractInvoice(ctx context.Context, c *stripeHTTPClient, contract uuid.UUID, invoice string, o proOffer, customer, subscription string) (proPaymentEvidence, bool, error) {
	var review bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE contract_id=$1 AND payment_review_required)`, contract).Scan(&review); err != nil {
		return proPaymentEvidence{}, false, err
	}
	if review {
		return proPaymentEvidence{}, false, &proPaymentReviewError{reason: "one-off upgrade payment requires review"}
	}
	var id uuid.UUID
	var start, end time.Time
	var amount int64
	err := h.Pool.QueryRow(ctx, `SELECT j.id,j.period_start,j.period_end,j.amount_cents FROM billing_pro_upgrade_catchup j JOIN billing_pro_upgrade u ON u.id=j.upgrade_id WHERE j.invoice_id=$1 AND u.contract_id=$2 AND u.customer_id=$3 AND u.subscription_id=$4`, invoice, contract, customer, subscription).Scan(&id, &start, &end, &amount)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.verifyProInvoice(ctx, invoice, o, customer, subscription)
	}
	if err != nil {
		return proPaymentEvidence{}, false, err
	}
	if amount != o.Amount {
		return proPaymentEvidence{}, false, errors.New("upgrade catch-up fee differs from contract")
	}
	return c.verifyProCatchupInvoice(ctx, invoice, id, customer, amount, start, end)
}

func (c *stripeHTTPClient) verifyProCatchupInvoice(ctx context.Context, invoice string, id uuid.UUID, customer string, amount int64, start, end time.Time) (proPaymentEvidence, bool, error) {
	var inv proPaidInvoice
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(invoice), nil, &inv, ""); err != nil {
		return proPaymentEvidence{}, false, err
	}
	ev := proPaymentEvidence{Invoice: inv, Start: start.Unix(), End: end.Unix()}
	if inv.ID != invoice || inv.Metadata["pro_upgrade_catchup_id"] != id.String() || inv.Customer != customer || inv.Parent.SubscriptionDetails != nil || inv.Currency != "usd" || inv.Status != "paid" || inv.Lines.HasMore || len(inv.Lines.Data) != 1 || inv.Lines.Data[0].Amount != amount || inv.Lines.Data[0].Currency != "usd" || inv.Lines.Data[0].Period.Start != start.Unix() || inv.Lines.Data[0].Period.End != end.Unix() || baseLineHasCredits(inv.Lines.Data[0]) || len(inv.Discounts) != 0 || len(inv.DiscountAmounts) != 0 || len(inv.Taxes) != 0 || inv.StartingBalance != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 || inv.AmountPaid != amount || inv.AmountDue != amount || inv.AmountRemaining != 0 || inv.PaidOutOfBand || inv.EndingBalance == nil || *inv.EndingBalance != 0 || inv.StatusTransitions.PaidAt <= 0 {
		return ev, false, &proPaymentReviewError{reason: "upgrade catch-up invoice differs from frozen standalone fee"}
	}
	return c.verifyProInvoiceCash(ctx, ev)
}
