package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Fee renewals may precede the corresponding original-calendar allowance. Select
// by allowance ordinal, never by the currently running provider fee period.
func pairPaymentCoversAllowance(b ContractProviderBinding, start, end time.Time, feeStart, feeEnd int64) bool {
	if b.Terms.FeeMonths != 1 {
		return feeStart <= start.Unix() && feeEnd >= end.Unix()
	}
	s := time.Unix(feeStart, 0).UTC()
	a := b.Anchor.UTC()
	m := (s.Year()-a.Year())*12 + int(s.Month()-a.Month())
	return annualBoundary(a, m).Equal(start) && annualBoundary(a, m+1).Equal(end)
}

// Missing receipts are discovered a bounded page at a time. Cash verification is
// outside the financial transaction; adoption and the one-to-one mapping are
// committed under the same current authority fence as grant issuance.
func (h *Handlers) discoverProviderPairReceipt(ctx context.Context, b ContractProviderBinding, c db.BillingCommercialContract, start, end time.Time, token uuid.UUID, client *stripeHTTPClient) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var cursor string
	if err := h.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT paired_invoice_cursor FROM billing_entitlement_work WHERE contract_id=$1 AND paired_invoice_period_start=$2),'')`, b.ContractID, start).Scan(&cursor); err != nil {
		return false, err
	}
	ids, next, err := client.proInvoices(ctx, b.CustomerID, b.FeeSubscriptionID, cursor)
	if err != nil {
		return false, err
	}
	var receipt *proPaymentEvidence
	for _, id := range ids {
		var invoice proPaidInvoice
		if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(id), nil, &invoice, ""); err != nil {
			return false, err
		}
		// Historical waived invoices and other periods cannot authorize this grant.
		candidate := false
		for _, line := range invoice.Lines.Data {
			candidate = candidate || pairPaymentCoversAllowance(b, start, end, line.Period.Start, line.Period.End)
		}
		if !candidate {
			continue
		}
		verified, verifyErr := client.verifyProviderPairPayment(ctx, b, id)
		if verifyErr != nil {
			if err = h.observeProPaymentReview(ctx, b.Identity.TeamID, id, verified, verifyErr); err != nil {
				return false, err
			}
			return false, verifyErr
		}
		if !pairPaymentCoversAllowance(b, start, end, verified.Start, verified.End) {
			return false, errors.New("paired invoice period changed during discovery")
		}
		if receipt != nil {
			return false, errors.New("multiple paired invoices claim the current allowance")
		}
		receipt = &verified
	}
	debt, err := client.entitlementDebt(ctx, b.CustomerID)
	if err != nil {
		return false, err
	}
	if debt != "" {
		return false, h.observeProviderPairDebt(ctx, c, debt)
	}
	err = h.withProviderPairEntitlementAuthority(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		q := h.DB.WithTx(tx)
		if _, err := q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: b.CustomerID, Token: token}); err != nil {
			return err
		}
		var current bool
		var observed time.Time
		if err := tx.QueryRow(ctx, `SELECT p.period_start=$2 AND p.period_end=$3,clock_timestamp() FROM billing_commercial_contract c CROSS JOIN LATERAL billing_contract_entitlement(c,clock_timestamp()) p WHERE c.id=$1`, b.ContractID, start, end).Scan(&current, &observed); err != nil {
			return err
		}
		if !current {
			return errors.New("paired allowance changed during receipt discovery")
		}
		if receipt != nil {
			r := *receipt
			p, err := q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID, InvoiceID: r.Invoice.ID, PaymentReference: r.Reference, CustomerID: b.CustomerID, SubscriptionID: &b.FeeSubscriptionID, BasePriceID: b.Terms.FeePriceID, ServicePeriodStart: time.Unix(r.Start, 0), ServicePeriodEnd: time.Unix(r.End, 0), BaseAmountPaidCents: b.Terms.FeeAmount, InvoiceAmountPaidCents: r.Invoice.AmountPaid, Currency: b.Terms.Currency, PaidAt: time.Unix(r.Invoice.StatusTransitions.PaidAt, 0), VerifiedAt: observed, Evidence: r.Raw})
			if errors.Is(err, pgx.ErrNoRows) {
				p, err = q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID, InvoiceID: r.Invoice.ID})
			}
			if err != nil {
				return err
			}
			if p.PaymentReference != r.Reference || p.CustomerID != b.CustomerID || derefString(p.SubscriptionID) != b.FeeSubscriptionID || p.BasePriceID != b.Terms.FeePriceID || !p.ServicePeriodStart.Equal(time.Unix(r.Start, 0)) || !p.ServicePeriodEnd.Equal(time.Unix(r.End, 0)) || p.BaseAmountPaidCents != b.Terms.FeeAmount || p.InvoiceAmountPaidCents != r.Invoice.AmountPaid || p.InvoiceAmountRemainingCents != 0 || p.Currency != b.Terms.Currency || !p.PaidAt.Equal(time.Unix(r.Invoice.StatusTransitions.PaidAt, 0)) {
				return errors.New("paired discovery differs from immutable cash receipt")
			}
			if err = observeProPaymentReviewTx(ctx, tx, b.Identity.TeamID, r.Invoice.ID, r, nil); err != nil {
				return err
			}
			if b.Terms.FeeMonths == 1 {
				m, err := ConfirmProviderPairMonthlyPayment(ctx, tx, b.ContractID, b.Identity, p.ID)
				if err != nil {
					return err
				}
				if !m.PeriodStart.Equal(start) || !m.PeriodEnd.Equal(end) {
					return errors.New("paired payment mapping differs from current allowance")
				}
			}
			next = ""
		}
		updated, err := tx.Exec(ctx, `UPDATE billing_entitlement_work SET paired_invoice_cursor=NULLIF($2,''),paired_invoice_period_start=$3 WHERE contract_id=$1`, b.ContractID, next, start)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return errors.New("paired receipt discovery has no durable work row")
		}
		return nil
	})
	return receipt != nil && err == nil, err
}
