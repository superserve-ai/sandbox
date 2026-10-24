package api

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProviderPairMonthlyPayment links actual cash dates to one original-calendar
// allowance. It does not change the receipt or create a provider credit grant.
type ProviderPairMonthlyPayment struct {
	PaymentID      uuid.UUID
	ContractID     uuid.UUID
	InvoiceID      string
	FeeItemID      string
	FeePeriodStart time.Time
	FeePeriodEnd   time.Time
	PeriodStart    time.Time
	PeriodEnd      time.Time
	AmountCents    int64
}

// ConfirmProviderPairMonthlyPayment requires current paid-choice authority and
// team/account -> regional fence -> contract locks in the caller's transaction.
// The caller records verified cash and fresh payment review before this call.
func ConfirmProviderPairMonthlyPayment(ctx context.Context, tx pgx.Tx, contract uuid.UUID, identity ProviderPairIdentity, payment uuid.UUID) (ProviderPairMonthlyPayment, error) {
	var out ProviderPairMonthlyPayment
	if tx == nil || contract == uuid.Nil || payment == uuid.Nil || identity.TeamID == uuid.Nil {
		return out, errors.New("monthly mapping requires its financial authority transaction")
	}
	if err := lockCommercialOfferAccount(ctx, tx, identity.TeamID); err != nil {
		return out, err
	}
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM billing_commercial_contract WHERE id=$1 AND team_id=$2 FOR UPDATE`, contract, identity.TeamID).Scan(&locked); err != nil {
		return out, err
	}
	b, err := loadContractProviderBinding(ctx, tx, contract)
	if err != nil {
		return out, err
	}
	if b.Identity != identity || b.Terms.FeeMonths != 1 || b.Terms.FeeAmount != 120000 {
		return out, errors.New("monthly mapping differs from effective paid-choice binding")
	}
	var allowed bool
	if err = tx.QueryRow(ctx, `SELECT c.status<>'ended' AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=c.id) FROM billing_commercial_contract c WHERE c.id=$1`, contract).Scan(&allowed); err != nil {
		return out, err
	}
	if !allowed {
		return out, errors.New("monthly mapping authority is ended or revoked")
	}
	read := func() error {
		return tx.QueryRow(ctx, `SELECT payment_id,contract_id,invoice_id,fee_item_id,fee_period_start,fee_period_end,period_start,period_end,amount_cents FROM billing_provider_pair_monthly_payment WHERE payment_id=$1 AND contract_id=$2 AND team_id=$3`, payment, contract, identity.TeamID).Scan(&out.PaymentID, &out.ContractID, &out.InvoiceID, &out.FeeItemID, &out.FeePeriodStart, &out.FeePeriodEnd, &out.PeriodStart, &out.PeriodEnd, &out.AmountCents)
	}
	if err = read(); err == nil {
		return out, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_provider_pair_monthly_payment(payment_id,team_id,contract_id,invoice_id,fee_item_id,fee_period_start,fee_period_end,period_start,period_end,amount_cents)
 SELECT p.id,p.team_id,p.contract_id,p.invoice_id,b.fee_item_id,p.service_period_start,p.service_period_end,
 billing_anniversary_boundary(b.anchor,((extract(year FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(year FROM b.anchor AT TIME ZONE 'UTC')::integer)*12+extract(month FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(month FROM b.anchor AT TIME ZONE 'UTC')::integer)),
 billing_anniversary_boundary(b.anchor,((extract(year FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(year FROM b.anchor AT TIME ZONE 'UTC')::integer)*12+extract(month FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(month FROM b.anchor AT TIME ZONE 'UTC')::integer)+1),100000
 FROM billing_contract_payment p JOIN billing_contract_provider_binding b ON b.contract_id=p.contract_id AND b.team_id=p.team_id
 WHERE p.id=$1 AND p.contract_id=$2 AND p.team_id=$3`, payment, contract, identity.TeamID)
	if err != nil {
		return out, err
	}
	err = read()
	return out, err
}
