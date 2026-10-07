package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

type InvoiceCloseResource struct {
	Resource         string          `json:"resource"`
	EventName        string          `json:"event_name"`
	MeterID          string          `json:"meter_id"`
	PriceID          string          `json:"price_id"`
	Quantity         string          `json:"quantity"`
	ProviderQuantity string          `json:"provider_quantity"`
	UnitUSD          string          `json:"unit_usd"`
	ExpectedCents    int64           `json:"expected_cents"`
	ProviderCents    int64           `json:"provider_cents"`
	Snapshot         json.RawMessage `json:"snapshot"`
}

type InvoiceClosePlan struct {
	InvoiceStart        int64                  `json:"invoice_start,omitempty"`
	InvoiceEnd          int64                  `json:"invoice_end,omitempty"`
	Customer            string                 `json:"customer"`
	Subscription        string                 `json:"subscription"`
	ExpectedCents       int64                  `json:"expected_cents"`
	AdjustmentCents     int64                  `json:"adjustment_cents"`
	AdjustmentTimestamp int64                  `json:"adjustment_timestamp"`
	CreditBeforeCents   int64                  `json:"credit_before_cents"`
	Resources           []InvoiceCloseResource `json:"resources"`
}

type InvoiceCloseSettlement struct {
	CreditAppliedCents   int64           `json:"credit_applied_cents"`
	CreditRemainingCents int64           `json:"credit_remaining_cents"`
	NetCents             int64           `json:"net_cents"`
	Invoice              json.RawMessage `json:"invoice"`
}

// Provider credits have their own ledger. Live periods verified against Stripe
// must not also debit the independent local/shadow credit-grant ledger.
func finalizeVerifiedInvoice(ctx context.Context, tx pgx.Tx, p ExportPeriod, usage db.TeamBillingUsage) (FinalizeTeamBillingPeriodResult, bool, error) {
	var enrolled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1 AND enrolled_at<$2)`, p.TeamID, p.End).Scan(&enrolled); err != nil {
		return FinalizeTeamBillingPeriodResult{}, false, err
	}
	if !enrolled {
		return FinalizeTeamBillingPeriodResult{}, false, nil
	}
	var rawPlan, rawSettlement []byte
	err := tx.QueryRow(ctx, `SELECT plan,finalized_evidence FROM billing_invoice_close WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND billing_invoice_close_matches($1,$2,$3) FOR UPDATE`, p.TeamID, p.Start, p.End).Scan(&rawPlan, &rawSettlement)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, true, fmt.Errorf("verified invoice settlement unavailable: %w", err)
	}
	var plan InvoiceClosePlan
	var settlement InvoiceCloseSettlement
	if err = json.Unmarshal(rawPlan, &plan); err != nil {
		return FinalizeTeamBillingPeriodResult{}, true, err
	}
	if err = json.Unmarshal(rawSettlement, &settlement); err != nil {
		return FinalizeTeamBillingPeriodResult{}, true, err
	}
	money := func(c int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(c), Exp: -2, Valid: true} }
	period, err := finalizeBillingPeriod(ctx, tx, p.TeamID, p.Start, p.End, money(plan.ExpectedCents), money(settlement.CreditAppliedCents), money(settlement.NetCents))
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, true, err
	}
	_, err = tx.Exec(ctx, `UPDATE team_billing_usage SET finalized_at=now(),updated_at=now() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, true, err
	}
	var breakdown SummaryBreakdown
	for _, resource := range plan.Resources {
		value := float64(resource.ExpectedCents) / 100
		switch resource.Resource {
		case "cpu":
			breakdown.ComputeUSD = value
		case "memory":
			breakdown.MemoryUSD = value
		case "storage":
			breakdown.StorageUSD = value
		}
	}
	return FinalizeTeamBillingPeriodResult{Period: period, Usage: usage, Charges: SummaryCharges{Breakdown: breakdown, CurrentChargesUSD: float64(plan.ExpectedCents) / 100, CreditsAppliedUSD: float64(settlement.CreditAppliedCents) / 100, ExpectedInvoiceAmountUSD: float64(settlement.NetCents) / 100, CreditsRemainingUSD: float64(settlement.CreditRemainingCents) / 100}}, true, nil
}
