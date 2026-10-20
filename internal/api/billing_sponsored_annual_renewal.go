package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Stripe owns renewal collection. This path only adopts verified receipts and
// never creates an invoice, payment intent or second subscription.
func (h *Handlers) reconcileSponsoredAnnualRenewal(ctx context.Context, o sponsoredAnnualAuthority, sub invoiceSubscription, client *stripeHTTPClient, token uuid.UUID) error {
	if sub.ID != o.Subscription || sub.Customer != o.Customer || sub.LiveMode != o.Live {
		return errors.New("renewal subscription ownership changed")
	}
	terminal := sub.Status == "canceled" || sub.Status == "incomplete_expired"
	if sub.Status != "active" && sub.Status != "past_due" && !terminal {
		return errors.New("annual renewal is awaiting a usable subscription")
	}
	offer := proOffer{Key: "pro_annual", Price: o.Price, Amount: 1200000, Months: 12}
	if _, err := o.base().stripSubscription(sub); err != nil {
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
	var expired bool
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()>=$2 AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE contract_id=$1 AND (state='uncertain' OR period_end>$2))`, o.Contract, o.End).Scan(&expired); err != nil {
		return err
	}
	if !expired {
		return errors.New("sponsored annual renewal awaits original expiry and grant reconciliation")
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1 AND status<>'ended' AND ends_at<=clock_timestamp()`, o.Contract); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_operation SET state='expired' WHERE id=$1 AND state='active' AND ends_at<=clock_timestamp()`, o.Sponsorship); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_annual',$3,$4,$5,$6,1200000,12,'metered_usage',100000,'monthly',$7) ON CONFLICT(id) DO NOTHING`, o.Renewal, o.Team, o.End, o.Customer, o.Subscription, o.Price, o.Start); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET state=CASE WHEN state='renewed' THEN state ELSE 'renewal_pending' END WHERE id=$1`, o.ID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	var cursor string
	if err = h.Pool.QueryRow(ctx, `SELECT COALESCE(invoice_cursor,'') FROM billing_sponsored_annual_authority WHERE id=$1`, o.ID).Scan(&cursor); err != nil {
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
	var historicalRaw []byte
	if err = h.Pool.QueryRow(ctx, `SELECT COALESCE(provider_evidence->'waiver_inventory','[]'::jsonb) FROM billing_sponsored_annual_authority WHERE id=$1`, o.ID).Scan(&historicalRaw); err != nil {
		return err
	}
	var historical []StripeInvoiceAmounts
	if err = json.Unmarshal(historicalRaw, &historical); err != nil {
		return err
	}
	var verified []proPaymentEvidence
	var verifiedIDs []string
	verificationFailed := false
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		// Completed zero-fee history remains closure evidence, never cash coverage.
		knownWaiver := false
		for _, old := range historical {
			if old.ID != id || old.Status != "paid" {
				continue
			}
			var fresh StripeInvoiceAmounts
			if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(id), nil, &fresh, ""); err != nil {
				return err
			}
			if !reflect.DeepEqual(old, fresh) {
				return errors.New("adopted invoice history changed; financial reconciliation required")
			}
			knownWaiver = true
			break
		}
		if knownWaiver {
			verifiedIDs = append(verifiedIDs, id)
			continue
		}
		receipt, paid, e := client.verifyProInvoice(ctx, id, offer, o.Customer, o.Subscription)
		if e == nil && paid && !validAnnualReceipt(o, receipt) {
			e = &proPaymentReviewError{reason: "annual receipt differs from adopted item or service year"}
		}
		if id == current {
			if e == nil && !paid {
				e = &proPaymentReviewError{reason: "annual receipt no longer proves cash payment"}
			}
			if observe := h.observeProPaymentReview(ctx, o.Team, id, receipt, e); observe != nil {
				return observe
			}
			if e != nil {
				return e
			}
		}
		// The first discounted invoice is historical waiver evidence, never a receipt.
		if e != nil {
			verificationFailed = true
			if id == sub.LatestInvoice {
				return e
			}
			continue
		}
		verifiedIDs = append(verifiedIDs, id)
		if paid && receipt.Start >= o.End.Unix() && annualReceiptPeriod(o, receipt) {
			verified = append(verified, receipt)
		}
	}
	terminalClosed := false
	if terminal && next == "" && !verificationFailed {
		terminalClosed, err = h.proInvoicesClosed(ctx, client, o.Team, o.Customer, o.Subscription, verifiedIDs)
		if err != nil {
			return err
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
		if errors.Is(err, pgx.ErrNoRows) {
			saved, e := q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: o.Team, ContractID: o.Renewal, InvoiceID: receipt.Invoice.ID})
			if e != nil {
				return e
			}
			if saved.ServicePeriodStart.Unix() != receipt.Start || saved.ServicePeriodEnd.Unix() != receipt.End || saved.PaymentReference != receipt.Reference || saved.InvoiceAmountPaidCents != receipt.Invoice.AmountPaid {
				return errors.New("renewal receipt changed after it was recorded")
			}
			err = nil
		}
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) VALUES($1,false,$2) ON CONFLICT(invoice_id) DO UPDATE SET review_required=false,evidence=EXCLUDED.evidence`, receipt.Invoice.ID, receipt.Raw); err != nil {
			return err
		}
		covered = covered || (receipt.Start <= now.Unix() && receipt.End > now.Unix())
	}
	var unexpired bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_contract_payment WHERE contract_id=$1 AND service_period_end>clock_timestamp())`, o.Renewal).Scan(&unexpired); err != nil {
		return err
	}
	var recoveryErr error
	if terminal && contract.Status == "pending" {
		recoveryErr = errors.New("paid subscription terminated before activation; billing recovery requires support")
	}
	if covered && contract.Status == "pending" && !terminal {
		if _, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: o.Team, ContractID: o.Renewal, ExpectedRevision: contract.Revision}); err != nil {
			return err
		}
	}
	// A renewal receipt cannot authorize an allowance before its service term.
	state := "renewal_pending"
	if covered && recoveryErr == nil {
		state = "renewed"
	}
	if terminal && contract.Status != "pending" && !unexpired && terminalClosed {
		if _, err = q.EndCommercialContract(ctx, db.EndCommercialContractParams{TeamID: o.Team, ContractID: o.Renewal, ExpectedRevision: contract.Revision}); err != nil {
			return err
		}
		state = "ended"
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET state=$2,invoice_cursor=NULLIF($3,''),last_error=NULL,next_check_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, o.ID, state, next); err != nil {
		return err
	}
	// Verification survives bounded pagination; it does not authorize cash coverage.
	if _, err = tx.Exec(ctx, `INSERT INTO billing_pro_invoice_seen(team_id,invoice_id) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, o.Team, verifiedIDs); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return recoveryErr
}

func annualReceiptPeriod(o sponsoredAnnualAuthority, r proPaymentEvidence) bool {
	start := time.Unix(r.Start, 0).UTC()
	months := (start.Year()-o.Start.UTC().Year())*12 + int(start.Month()-o.Start.UTC().Month())
	return months >= 12 && months%12 == 0 && start.Equal(annualBoundary(o.Start, months)) && r.End == annualBoundary(o.Start, months+12).Unix()
}

func validAnnualReceipt(o sponsoredAnnualAuthority, r proPaymentEvidence) bool {
	if r.Invoice.LiveMode != o.Live || !annualReceiptPeriod(o, r) {
		return false
	}
	for _, line := range r.Invoice.Lines.Data {
		if line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price == o.Price {
			return line.Pricing.PriceDetails.Product == o.Product && o.base().validateLine(line, o.Subscription, r.Start, r.End) == nil
		}
	}
	return false
}
