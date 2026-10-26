package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditEvidence is a durable audit copy, not a replacement for this typed value.
// Serialization deliberately drops the private verification seal.
func (v VerifiedProviderPair) AuditEvidence() json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ActivateInitialProviderPair requires the caller's durable activation authority
// and regional fence through commit; a shared approval lock alone is insufficient.
// The caller associates the usage account first, then enrolls collection
// and wakes the existing grant issuer before committing this same transaction.
// This helper neither commits nor performs provider I/O.
func ActivateInitialProviderPair(ctx context.Context, tx pgx.Tx, contract uuid.UUID, verified VerifiedProviderPair) (ContractProviderBinding, error) {
	var empty ContractProviderBinding
	if tx == nil || contract == uuid.Nil {
		return empty, errors.New("paired activation requires an admission transaction and contract")
	}
	if err := verified.validateFresh(); err != nil {
		return empty, err
	}
	p := verified.Input
	if err := lockCommercialOfferAccount(ctx, tx, p.Identity.TeamID); err != nil {
		return empty, err
	}
	if err := commercialOfferEnabled(ctx, tx, p.Identity.TeamID); err != nil {
		return empty, err
	}
	// A committed activation is immutable; recovery must not insert into a
	// pending-only guard or manufacture a new observation of current authority.
	var existing uuid.UUID
	err := tx.QueryRow(ctx, `SELECT contract_id FROM billing_commercial_offer_activation WHERE assignment_id=$1 AND team_id=$2`, p.Identity.AssignmentID, p.Identity.TeamID).Scan(&existing)
	if err == nil {
		if existing != contract {
			return empty, errors.New("assignment already activated another contract")
		}
		return ConfirmContractProviderBinding(ctx, tx, contract, verified)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return empty, err
	}
	end := annualBoundary(p.Anchor, 12)
	_, err = tx.Exec(ctx, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor)
 VALUES($1,$2,'yc_2026',$3,$4,$5,$6,$7,1200000,12,'metered_usage',100000,'scheduled',$3)`, contract, p.Identity.TeamID, p.Anchor, end, p.CustomerID, p.UsageSubscriptionID, p.Terms.FeePriceID)
	if err != nil {
		return empty, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents)
 SELECT a.team_id,$1,n-1,amount FROM billing_commercial_offer_assignment a
 JOIN billing_commercial_offer_version v ON v.offer_key=a.offer_key AND v.version=a.offer_version
 CROSS JOIN LATERAL unnest(v.monthly_allowance_cents) WITH ORDINALITY AS schedule(amount,n)
 WHERE a.id=$2 AND a.team_id=$3 AND a.offer_key='yc_2026'`, contract, p.Identity.AssignmentID, p.Identity.TeamID)
	if err != nil {
		return empty, err
	}
	b, err := ConfirmContractProviderBinding(ctx, tx, contract, verified)
	if err != nil {
		return empty, err
	}
	var evidence struct{ Invoice json.RawMessage }
	if err = json.Unmarshal(verified.Evidence, &evidence); err != nil {
		return empty, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_provider_pair_waiver(team_id,contract_id,invoice_id,coupon_id,starts_at,ends_at,evidence,authority_checked_at,authority_valid_until)
 VALUES($1,$2,$3,$4,$5,$6,$7,statement_timestamp(),statement_timestamp()+interval '1 minute')`, p.Identity.TeamID, contract, p.WaiverInvoiceID, p.WaiverCouponID, p.Anchor, end, evidence.Invoice)
	if err != nil {
		return empty, err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1 AND team_id=$2 AND status='pending'`, contract, p.Identity.TeamID); err != nil {
		return empty, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_commercial_offer_activation(assignment_id,team_id,contract_id,anchor,ends_at,merchant_account,live_mode)
 VALUES($1,$2,$3,$4,$5,$6,$7)`, p.Identity.AssignmentID, p.Identity.TeamID, contract, p.Anchor, end, p.Identity.Merchant, p.Identity.Live)
	if err != nil {
		return empty, err
	}
	return b, nil
}
