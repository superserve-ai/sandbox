package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

func loadInvoiceProviderPair(ctx context.Context, reader db.DBTX, team uuid.UUID, a *invoiceAccount) (bool, error) {
	var raw []byte
	err := reader.QueryRow(ctx, `SELECT binding FROM billing_contract_provider_binding WHERE team_id=$1 AND customer_id=$2 AND usage_subscription_id=$3 ORDER BY starts_at DESC LIMIT 1`, team, a.Customer, a.Subscription).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var b ContractProviderBinding
	if err = json.Unmarshal(raw, &b); err != nil {
		return false, err
	}
	if b.Identity.TeamID != team || b.CustomerID != a.Customer || b.UsageSubscriptionID != a.Subscription {
		return false, errors.New("paired invoice account identity differs")
	}
	if err = b.Terms.validate(); err != nil {
		return false, err
	}
	a.Pair = &b
	a.Base = invoiceBase{}
	a.Price, a.Meter, a.Event = b.Terms.Rounding.PriceID, b.Terms.Rounding.MeterID, b.Terms.Rounding.EventName
	return true, nil
}

// Collection only needs to prove that the exact fee sibling cannot consume
// metered credits. Its current economics are checked separately for payment
// authority; a renewal must not block closing the preceding usage period.
func validatePairFeeSibling(b ContractProviderBinding, s invoiceSubscription) error {
	if s.ID != b.FeeSubscriptionID || s.Customer != b.CustomerID || s.LiveMode != b.Identity.Live || s.Items.HasMore || len(s.Items.Data) != 1 {
		return errors.New("paired fee sibling inventory differs")
	}
	for _, i := range s.Items.Data {
		if i.ID == "" || i.Price.ID == "" || i.Price.Recurring.UsageType != "licensed" || i.Price.Recurring.Meter != "" {
			return errors.New("paired fee sibling can consume metered credits")
		}
	}
	return nil
}

func validatePairUsageSubscription(b ContractProviderBinding, a invoiceAccount, sub invoiceSubscription) error {
	if sub.ID != b.UsageSubscriptionID || sub.Customer != b.CustomerID || sub.LiveMode != b.Identity.Live || a.Price != b.Terms.Rounding.PriceID || a.Meter != b.Terms.Rounding.MeterID || a.Event != b.Terms.Rounding.EventName || len(sub.DefaultTaxRates) != 0 {
		return errors.New("paired usage identity or rounding terms differ")
	}
	for _, i := range sub.Items.Data {
		if i.Price.LiveMode != b.Identity.Live || len(i.TaxRates) != 0 || len(i.Discounts) != 0 {
			return errors.New("paired usage item mode or modifiers differ")
		}
	}
	if err := invoiceCalendarCompatible(b.Anchor, sub, a.Price); err != nil {
		return err
	}
	return validateFrozenProResources(sub, append(append([]StripeCheckoutResourceTerms{}, b.Terms.Resources...), b.Terms.Rounding), "")
}
