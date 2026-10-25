package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (h *Handlers) catchUpProUpgrade(ctx context.Context, conn *pgxpool.Conn, u proUpgrade, o proOffer, c *stripeHTTPClient) error {
	if u.BaseCreated == nil || !u.BaseCreated.After(u.End) {
		return nil
	}
	sub, err := c.invoiceSubscription(ctx, derefString(u.Subscription))
	if err != nil {
		return err
	}
	if sub.Customer != u.Customer || sub.Status != "active" || sub.CancelAtPeriodEnd || sub.CancelAt != 0 {
		return errors.New("upgrade catch-up is blocked by subscription cancellation or collection state")
	}
	var inventory struct {
		Data    []proPaidInvoice `json:"data"`
		HasMore bool             `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {u.Customer}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
		return err
	}
	if inventory.HasMore {
		return errors.New("upgrade catch-up invoice inventory exceeds supported bound")
	}
	at := u.End
	for count := 0; at.Before(*u.BaseCreated); count++ {
		if count >= 12 {
			return errors.New("upgrade catch-up exceeds twelve billing periods")
		}
		start, end, ok := billing.AnniversaryPeriod(u.Anchor, at)
		if !ok || !start.Equal(at) {
			return errors.New("upgrade catch-up calendar differs")
		}
		regular := false
		for _, invoice := range inventory.Data {
			if invoice.Parent.SubscriptionDetails == nil || invoice.Parent.SubscriptionDetails.Subscription != derefString(u.Subscription) || invoice.Status == "void" {
				continue
			}
			if invoice.Lines.HasMore {
				return errors.New("upgrade catch-up invoice lines exceed supported bound")
			}
			for _, line := range invoice.Lines.Data {
				if line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price == o.Price && line.Period.Start == start.Unix() && line.Period.End == end.Unix() {
					if line.Amount != o.Amount || line.Quantity != 1 || line.Currency != "usd" {
						return errors.New("upgrade catch-up conflicts with regular base invoice")
					}
					regular = true
				}
			}
		}
		if !regular {
			if err := h.collectProUpgradeCatchup(ctx, conn, u, o, start, end, inventory.Data, c); err != nil {
				return err
			}
		}
		at = end
	}
	return nil
}

func (h *Handlers) collectProUpgradeCatchup(ctx context.Context, conn *pgxpool.Conn, u proUpgrade, o proOffer, start, end time.Time, inventory []proPaidInvoice, c *stripeHTTPClient) error {
	id := uuid.New()
	if _, err := conn.Exec(ctx, `INSERT INTO billing_pro_upgrade_catchup(id,upgrade_id,period_start,period_end,amount_cents,created_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(upgrade_id,period_start) DO NOTHING`, id, u.ID, start, end, o.Amount, h.nowUTC()); err != nil {
		return err
	}
	var invoiceID *string
	var created time.Time
	if err := conn.QueryRow(ctx, `SELECT id,invoice_id,created_at FROM billing_pro_upgrade_catchup WHERE upgrade_id=$1 AND period_start=$2`, u.ID, start).Scan(&id, &invoiceID, &created); err != nil {
		return err
	}
	if invoiceID == nil {
		for _, inv := range inventory {
			if inv.Metadata["pro_upgrade_catchup_id"] == id.String() {
				if invoiceID != nil {
					return errors.New("ambiguous upgrade catch-up invoices")
				}
				invoiceID = stringPtr(inv.ID)
			}
		}
		if invoiceID == nil {
			if h.nowUTC().Sub(created) >= 23*time.Hour {
				return errors.New("upgrade catch-up invoice creation replay expired")
			}
			form := url.Values{"customer": {u.Customer}, "currency": {"usd"}, "collection_method": {"charge_automatically"}, "auto_advance": {"false"}, "pending_invoice_items_behavior": {"exclude"}, "discounts": {""}, "default_payment_method": {derefString(u.PaymentMethod)}, "metadata[pro_upgrade_catchup_id]": {id.String()}, "description": {fmt.Sprintf("%s monthly fee, %s to %s", o.Name, start.Format("2006-01-02"), end.Format("2006-01-02"))}}
			var inv proPaidInvoice
			if err := c.doForm(ctx, http.MethodPost, "/v1/invoices", form, &inv, "pro-upgrade-catchup:"+id.String()); err != nil {
				return err
			}
			if inv.ID == "" {
				return errors.New("missing upgrade catch-up invoice identity")
			}
			invoiceID = &inv.ID
		}
		if _, err := conn.Exec(ctx, `UPDATE billing_pro_upgrade_catchup SET invoice_id=$2 WHERE id=$1`, id, *invoiceID); err != nil {
			return err
		}
	}
	path := "/v1/invoices/" + url.PathEscape(*invoiceID)
	var inv proPaidInvoice
	if err := c.doForm(ctx, http.MethodGet, path, nil, &inv, ""); err != nil {
		return err
	}
	if inv.ID != *invoiceID || inv.Customer != u.Customer || inv.Currency != "usd" || inv.Metadata["pro_upgrade_catchup_id"] != id.String() || inv.Lines.HasMore || len(inv.Lines.Data) > 1 {
		return errors.New("upgrade catch-up invoice association differs")
	}
	if len(inv.Lines.Data) == 0 {
		if inv.Status != "draft" || h.nowUTC().Sub(created) >= 23*time.Hour {
			return errors.New("upgrade catch-up invoice line requires reconciliation")
		}
		form := url.Values{"customer": {u.Customer}, "invoice": {inv.ID}, "currency": {"usd"}, "amount": {strconv.FormatInt(o.Amount, 10)}, "discountable": {"false"}, "description": {o.Name + " monthly fee"}, "period[start]": {strconv.FormatInt(start.Unix(), 10)}, "period[end]": {strconv.FormatInt(end.Unix(), 10)}, "metadata[pro_upgrade_catchup_id]": {id.String()}}
		if err := c.doForm(ctx, http.MethodPost, "/v1/invoiceitems", form, nil, "pro-upgrade-catchup-line:"+id.String()); err != nil {
			return err
		}
		if err := c.doForm(ctx, http.MethodGet, path, nil, &inv, ""); err != nil {
			return err
		}
	}
	if len(inv.Lines.Data) != 1 || inv.Lines.Data[0].Amount != o.Amount || inv.Lines.Data[0].Currency != "usd" || inv.Lines.Data[0].Period.Start != start.Unix() || inv.Lines.Data[0].Period.End != end.Unix() || len(inv.Discounts) != 0 || len(inv.DiscountAmounts) != 0 || len(inv.Taxes) != 0 || inv.StartingBalance != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 {
		return errors.New("upgrade catch-up invoice terms differ")
	}
	if inv.Status == "draft" {
		if err := c.doForm(ctx, http.MethodPost, path+"/finalize", url.Values{"auto_advance": {"false"}}, &inv, "pro-upgrade-catchup-finalize:"+id.String()); err != nil {
			return err
		}
	}
	if inv.Status == "open" {
		if err := c.doForm(ctx, http.MethodPost, path+"/pay", url.Values{"off_session": {"true"}, "payment_method": {derefString(u.PaymentMethod)}}, &inv, "pro-upgrade-catchup-pay:"+id.String()); err != nil {
			return err
		}
	}
	if inv.Status != "paid" || inv.AmountPaid != o.Amount || inv.AmountDue != o.Amount || inv.AmountRemaining != 0 || inv.PaidOutOfBand || inv.EndingBalance == nil || *inv.EndingBalance != 0 || inv.StatusTransitions.PaidAt <= 0 {
		return errors.New("upgrade catch-up fee is awaiting verified payment")
	}
	receipt, _, err := c.verifyProCatchupInvoice(ctx, inv.ID, id, u.Customer, o.Amount, start, end)
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	_, err = q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: u.Team, ContractID: *u.Contract, InvoiceID: inv.ID, PaymentReference: receipt.Reference, CustomerID: u.Customer, SubscriptionID: u.Subscription, BasePriceID: o.Price, ServicePeriodStart: start, ServicePeriodEnd: end, BaseAmountPaidCents: o.Amount, InvoiceAmountPaidCents: inv.AmountPaid, Currency: "usd", PaidAt: time.Unix(inv.StatusTransitions.PaidAt, 0), VerifiedAt: h.nowUTC(), Evidence: receipt.Raw})
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: u.Team, ContractID: *u.Contract, InvoiceID: inv.ID})
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) VALUES($1,false,$2) ON CONFLICT(invoice_id) DO UPDATE SET review_required=false,evidence=EXCLUDED.evidence,observed_at=clock_timestamp()`, inv.ID, receipt.Raw); err != nil {
		return err
	}
	contract, err := q.GetCurrentCommercialContract(ctx, u.Team)
	if err != nil {
		return err
	}
	if contract.ID == *u.Contract && contract.Status == "pending" && !h.nowUTC().Before(start) && h.nowUTC().Before(end) {
		if _, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: u.Team, ContractID: *u.Contract, ExpectedRevision: contract.Revision}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
