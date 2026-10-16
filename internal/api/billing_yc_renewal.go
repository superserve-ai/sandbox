package api

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Stripe owns renewal collection. This path only adopts verified receipts and
// never creates an invoice, payment intent or second subscription.
func (h *Handlers) reconcileYCRenewal(ctx context.Context, o ycOperation, sub invoiceSubscription, client *stripeHTTPClient, token uuid.UUID) error {
	if sub.ID != o.Subscription || sub.Customer != o.Customer || sub.LiveMode != *o.Request.Live {
		return errors.New("renewal subscription ownership changed")
	}
	if sub.Status == "canceled" || sub.Status == "incomplete_expired" {
		_, err := h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET state='ended',last_error=NULL,next_check_at='infinity' WHERE team_id=$1`, o.Team)
		return err
	}
	if sub.Status != "active" && sub.Status != "past_due" {
		return errors.New("annual renewal is awaiting a usable subscription")
	}
	offer := proOffer{Key: "pro_annual", Price: o.Params.BasePriceID, Amount: 1200000, Months: 12}
	if _, err := (invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: 12}).stripSubscription(sub); err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	if _, err = q.LockTeamBillingAccount(ctx, o.Team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1 AND status<>'ended'`, o.Contract); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_annual',$3,$4,$5,$6,1200000,12,'metered_usage',100000,'monthly',$7) ON CONFLICT(id) DO NOTHING`, o.Renewal, o.Team, o.End.Time, o.Customer, o.Subscription, o.Params.BasePriceID, o.Start.Time); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET state=CASE WHEN state='renewed' THEN state ELSE 'renewal_pending' END WHERE team_id=$1`, o.Team); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	var cursor string
	if err = h.Pool.QueryRow(ctx, `SELECT COALESCE(invoice_cursor,'') FROM billing_yc_operation WHERE team_id=$1`, o.Team).Scan(&cursor); err != nil {
		return err
	}
	ids, next, err := client.proInvoices(ctx, o.Customer, o.Subscription, cursor)
	if err != nil {
		return err
	}
	var current string
	err = h.Pool.QueryRow(ctx, `SELECT invoice_id FROM billing_contract_payment WHERE contract_id=$1 AND service_period_start<=clock_timestamp() AND service_period_end>clock_timestamp()`, o.Renewal).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if current != "" {
		ids = append(ids, current)
	}
	var verified []proPaymentEvidence
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		receipt, paid, e := client.verifyProInvoice(ctx, id, offer, o.Customer, o.Subscription)
		if id == current {
			if observe := h.observeProPaymentReview(ctx, o.Team, id, receipt, e); observe != nil {
				return observe
			}
			if e != nil {
				return e
			}
		}
		// The first discounted invoice is historical waiver evidence, never a receipt.
		if e != nil {
			if id == sub.LatestInvoice {
				return e
			}
			continue
		}
		if paid && receipt.Start >= o.End.Time.Unix() {
			verified = append(verified, receipt)
		}
	}
	tx, err = h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q = h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
		return err
	}
	contract, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: o.Team, ContractID: o.Renewal})
	if err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	covered := false
	for _, receipt := range verified {
		_, err = q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: o.Team, ContractID: o.Renewal, InvoiceID: receipt.Invoice.ID, PaymentReference: receipt.Reference, CustomerID: o.Customer, SubscriptionID: &o.Subscription, BasePriceID: offer.Price, ServicePeriodStart: time.Unix(receipt.Start, 0), ServicePeriodEnd: time.Unix(receipt.End, 0), BaseAmountPaidCents: 1200000, InvoiceAmountPaidCents: receipt.Invoice.AmountPaid, InvoiceAmountRemainingCents: 0, Currency: "usd", PaidAt: time.Unix(receipt.Invoice.StatusTransitions.PaidAt, 0), VerifiedAt: now, Evidence: receipt.Raw})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) VALUES($1,false,$2) ON CONFLICT(invoice_id) DO UPDATE SET review_required=false,evidence=EXCLUDED.evidence`, receipt.Invoice.ID, receipt.Raw); err != nil {
			return err
		}
		covered = covered || (receipt.Start <= now.Unix() && receipt.End > now.Unix())
	}
	if covered && contract.Status == "pending" {
		if _, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: o.Team, ContractID: o.Renewal, ExpectedRevision: contract.Revision}); err != nil {
			return err
		}
	}
	// Persist the paid authority before normalizing cancellation against its end.
	state := "renewal_pending"
	if covered {
		state = "renewed"
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_yc_operation SET state=$2,invoice_cursor=NULLIF($3,''),last_error=NULL,next_check_at=clock_timestamp()+interval '30 seconds' WHERE team_id=$1`, o.Team, state, next); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if covered {
		_, err = h.normalizeYCCancellation(ctx, o, sub, client)
	}
	return err
}
