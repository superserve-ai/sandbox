package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (h *Handlers) enqueueReleasedProInvoice(ctx context.Context, event stripeEventEnvelope, customer, subscription, invoice string) (bool, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var release, contract uuid.UUID
	err = tx.QueryRow(ctx, `SELECT r.id,c.id FROM billing_plan_release r
 JOIN team_plan_change ch ON ch.id=r.plan_change_id AND ch.team_id=r.team_id
 JOIN team_plan_assignment a ON a.id=ch.from_assignment_id AND a.team_id=r.team_id
 JOIN billing_commercial_contract c ON c.id=a.contract_id AND c.team_id=r.team_id
 WHERE r.customer_id=$1 AND r.subscription_id=$2 AND r.yc_operation_id IS NULL
 AND c.status='ended' AND c.customer_id=r.customer_id AND c.subscription_id=r.subscription_id`, customer, subscription).Scan(&release, &contract)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var bound bool
	err = tx.QueryRow(ctx, `INSERT INTO billing_pro_released_invoice(release_id,invoice_id,contract_id) VALUES($1,$2,$3)
 ON CONFLICT(invoice_id) DO UPDATE SET next_check_at=clock_timestamp(),revision=billing_pro_released_invoice.revision+1
 WHERE billing_pro_released_invoice.release_id=EXCLUDED.release_id AND billing_pro_released_invoice.contract_id=EXCLUDED.contract_id
 RETURNING true`, release, invoice, contract).Scan(&bound)
	if err != nil {
		return true, err
	}
	if _, err = h.DB.WithTx(tx).MarkStripeWebhookEventProcessed(ctx, event.ID); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}

func (h *Handlers) releasedProInvoiceTick(ctx context.Context) (int, error) {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return 0, nil
	}
	rows, err := h.Pool.Query(ctx, `WITH due AS (SELECT invoice_id FROM billing_pro_released_invoice
 WHERE next_check_at<=clock_timestamp() AND (verified_revision<revision OR state<>'recorded' OR credit_state='pending')
 ORDER BY next_check_at,invoice_id LIMIT 4 FOR UPDATE SKIP LOCKED)
 UPDATE billing_pro_released_invoice j SET next_check_at=clock_timestamp()+interval '2 minutes'
 FROM due WHERE j.invoice_id=due.invoice_id RETURNING j.invoice_id,j.revision`)
	if err != nil {
		return 0, err
	}
	var invoices []struct {
		ID       string
		Revision int64
	}
	for rows.Next() {
		var job struct {
			ID       string
			Revision int64
		}
		if err = rows.Scan(&job.ID, &job.Revision); err != nil {
			rows.Close()
			return 0, err
		}
		invoices = append(invoices, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, job := range invoices {
		e := h.reconcileReleasedProInvoice(ctx, client, job.ID)
		var message *string
		if e != nil {
			s := e.Error()
			message = &s
			log.Warn().Err(e).Str("invoice_id", job.ID).Msg("released Pro invoice requires reconciliation")
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_pro_released_invoice SET last_error=$2,updated_at=clock_timestamp(),next_check_at=clock_timestamp()+interval '1 hour' WHERE invoice_id=$1 AND revision=$3`, job.ID, message, job.Revision); err != nil {
			return len(invoices), err
		}
	}
	return len(invoices), nil
}

func (h *Handlers) reconcileReleasedProInvoice(ctx context.Context, client *stripeHTTPClient, invoice string) error {
	var team, contract uuid.UUID
	var customer, subscription, offerKey, price string
	var payload []byte
	var releasedAt time.Time
	var revision int64
	err := h.Pool.QueryRow(ctx, `SELECT r.team_id,c.id,r.customer_id,r.subscription_id,c.offer_key,c.base_price_id,
 COALESCE(u.request_payload,r.previous_choice->'request_payload'),r.released_at,j.revision
 FROM billing_pro_released_invoice j JOIN billing_plan_release r ON r.id=j.release_id
 JOIN billing_commercial_contract c ON c.id=j.contract_id AND c.team_id=r.team_id
 LEFT JOIN billing_pro_upgrade u ON u.contract_id=c.id
 WHERE j.invoice_id=$1 AND c.status='ended' AND c.customer_id=r.customer_id AND c.subscription_id=r.subscription_id`, invoice).
		Scan(&team, &contract, &customer, &subscription, &offerKey, &price, &payload, &releasedAt, &revision)
	if err != nil {
		return err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(payload, &params); err != nil {
		return err
	}
	offer, err := frozenProOffer(offerKey, params)
	if err != nil {
		return err
	}
	offer.Price = price
	offer.Promotion, err = contractPromotion(ctx, h.Pool, contract)
	if err != nil {
		return err
	}
	var inv proPaidInvoice
	if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(invoice), nil, &inv, ""); err != nil {
		return err
	}
	if inv.ID != invoice || inv.Customer != customer || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != subscription {
		return errors.New("released invoice ownership differs from immutable source")
	}
	if inv.Status != "paid" {
		return errors.New("released invoice awaits verified settlement; collection requires its frozen close plan")
	}
	receipt, found, err := h.verifyProContractInvoice(ctx, client, contract, invoice, offer, customer, subscription)
	if err != nil {
		return err
	}
	if !found {
		return h.reconcileReleasedUsageInvoice(ctx, client, invoice, team, revision, inv)
	}
	if receipt.Start >= releasedAt.Unix() {
		return errors.New("released invoice service starts after purchase release")
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var prior []byte
	if err = tx.QueryRow(ctx, `SELECT receipt FROM billing_pro_released_invoice WHERE invoice_id=$1 FOR UPDATE`, invoice).Scan(&prior); err != nil {
		return err
	}
	if len(prior) == 0 {
		if _, err = tx.Exec(ctx, `UPDATE billing_pro_released_invoice SET receipt=$2,payment_reference=$3 WHERE invoice_id=$1`, invoice, receipt.Raw, receipt.Reference); err != nil {
			return err
		}
	}
	if err = recordPaymentPromotion(ctx, tx, team, contract, receipt); err != nil {
		return err
	}
	q := h.DB.WithTx(tx)
	existing, existingErr := q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: team, ContractID: contract, InvoiceID: invoice})
	if existingErr == nil {
		if existing.PaymentReference != receipt.Reference {
			return errors.New("released invoice payment identity changed")
		}
	} else if !errors.Is(existingErr, pgx.ErrNoRows) {
		return existingErr
	} else {
		_, err = q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: team, ContractID: contract, InvoiceID: invoice, PaymentReference: receipt.Reference, CustomerID: customer, SubscriptionID: &subscription, BasePriceID: price, ServicePeriodStart: time.Unix(receipt.Start, 0), ServicePeriodEnd: time.Unix(receipt.End, 0), BaseAmountPaidCents: offer.Amount, InvoiceAmountPaidCents: receipt.Invoice.AmountPaid, Currency: "usd", PaidAt: time.Unix(receipt.Invoice.StatusTransitions.PaidAt, 0), VerifiedAt: h.nowUTC(), Evidence: receipt.Raw})
		if errors.Is(err, pgx.ErrNoRows) {
			var same bool
			err = tx.QueryRow(ctx, `SELECT contract_id=$2 AND evidence=$3 AND payment_reference=$4 FROM billing_contract_payment WHERE invoice_id=$1`, invoice, contract, receipt.Raw, receipt.Reference).Scan(&same)
			if err == nil && !same {
				err = errors.New("released invoice receipt identity changed")
			}
		}
	}

	if err != nil {
		return err
	}
	covered, expiredMissing, err := releasedProCreditCoverage(ctx, tx, contract, time.Unix(receipt.Start, 0), offer.Months, h.nowUTC())
	if err != nil {
		return err
	}

	creditState := "pending"
	var liability *string
	if covered {
		creditState = "covered"
	} else {
		reason := "released payment recorded; original credit remains pending resolution"
		if expiredMissing {
			creditState = "review_required"
			reason = "released payment recorded; expired original monthly credit was not issued and requires operator resolution; original terms preserved"
		}
		liability = &reason
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_pro_released_invoice SET state='recorded',credit_state=$2,verified_revision=$3,last_error=$4 WHERE invoice_id=$1`, invoice, creditState, revision, liability); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if !covered {
		return errors.New(*liability)
	}
	return nil
}

func (h *Handlers) reconcileReleasedUsageInvoice(ctx context.Context, client *stripeHTTPClient, invoice string, team uuid.UUID, revision int64, inv proPaidInvoice) error {
	var raw, accountRaw []byte
	var period billing.ExportPeriod
	period.TeamID = team
	err := h.Pool.QueryRow(ctx, `SELECT c.period_start,c.period_end,c.plan,r.provider_evidence->'invoice_account'
 FROM billing_pro_released_invoice j JOIN billing_plan_release r ON r.id=j.release_id
 JOIN billing_invoice_close c ON c.team_id=r.team_id AND c.invoice_id=j.invoice_id
 WHERE j.invoice_id=$1 AND c.state IN ('verified','released')`, invoice).Scan(&period.Start, &period.End, &raw, &accountRaw)
	if err != nil {
		return fmt.Errorf("released invoice awaits its verified frozen close plan: %w", err)
	}
	var plan billing.InvoiceClosePlan
	var account invoiceAccount
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if len(accountRaw) == 0 || string(accountRaw) == "null" {
		return errors.New("released invoice has no frozen invoice-account snapshot")
	}
	if err = json.Unmarshal(accountRaw, &account); err != nil {
		return err
	}
	if plan.Customer != account.Customer || plan.Subscription != account.Subscription {
		return errors.New("released invoice plan ownership differs")
	}
	if err = validateInvoiceDocument(inv.StripeInvoiceAmounts, invoicePlanPeriod(period, plan), account, plan); err != nil {
		return err
	}
	remaining, err := client.verifyInvoiceCreditTransactions(ctx, inv.StripeInvoiceAmounts, plan)
	if err != nil {
		return err
	}
	if err = verifyInvoicePlanSettlement(inv.StripeInvoiceAmounts, plan, plan.CreditBeforeCents, remaining); err != nil {
		return err
	}
	if inv.PaidOutOfBand || inv.AmountRemaining != 0 || inv.AmountPaid != inv.AmountDue {
		return errors.New("released usage invoice lacks cash settlement")
	}
	receipt, _, err := client.verifyProInvoiceCash(ctx, proPaymentEvidence{Invoice: inv})
	if err != nil {
		return err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_pro_released_invoice SET receipt=COALESCE(receipt,$2),payment_reference=COALESCE(payment_reference,$3),state='recorded',credit_state='covered',verified_revision=$4 WHERE invoice_id=$1`, invoice, receipt.Raw, receipt.Reference, revision)
	return err
}

func releasedProCreditCoverage(ctx context.Context, q db.DBTX, contract uuid.UUID, start time.Time, months int32, now time.Time) (bool, bool, error) {
	if months != 1 && months != 12 {
		return false, false, errors.New("unsupported frozen payment cadence")
	}
	var covered, expiredMissing bool
	err := q.QueryRow(ctx, `WITH windows AS (
 SELECT p.period_start,p.period_end,p.amount_cents
 FROM billing_commercial_contract c CROSS JOIN generate_series(0,$3::integer-1) offset_month
 CROSS JOIN LATERAL billing_contract_entitlement(c,billing_anniversary_boundary(c.entitlement_anchor,
 (extract(year FROM $2::timestamptz AT TIME ZONE 'UTC')::integer-extract(year FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer)*12
 +extract(month FROM $2::timestamptz AT TIME ZONE 'UTC')::integer-extract(month FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer+offset_month)) p
 WHERE c.id=$1), coverage AS (
 SELECT w.*,EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=$1 AND e.period_start=w.period_start AND e.period_end=w.period_end AND e.amount_cents=w.amount_cents AND e.state='issued') issued FROM windows w)
 SELECT count(*)=$3 AND COALESCE(bool_and(issued),false),COALESCE(bool_or(period_end<=$4 AND NOT issued),false) FROM coverage`, contract, start, months, now).Scan(&covered, &expiredMissing)
	return covered, expiredMissing, err
}
