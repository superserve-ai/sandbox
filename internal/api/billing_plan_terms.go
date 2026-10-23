package api

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var errUnknownPlan = errors.New("unsupported offer")

// planTerms are a catalog plan's current terms. Contracts freeze their own
// copy at assignment, so these only apply to new purchases and reporting.
type planTerms struct {
	OfferKey           string
	DisplayName        string
	FeeCents           int64
	IntervalMonths     int32
	MonthlyCreditCents int64
}

// planTerms is the single reader of billing_plan terms for Go code.
func (h *Handlers) planTerms(ctx context.Context, offerKey string) (planTerms, error) {
	if h.Pool == nil {
		return planTerms{}, errors.New("billing is not configured")
	}
	t := planTerms{OfferKey: offerKey}
	err := h.Pool.QueryRow(ctx, `SELECT display_name,charge_amount_cents,charge_interval_months,monthly_credit_cents FROM billing_plan WHERE offer_key=$1`, offerKey).
		Scan(&t.DisplayName, &t.FeeCents, &t.IntervalMonths, &t.MonthlyCreditCents)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, errUnknownPlan
	}
	return t, err
}
