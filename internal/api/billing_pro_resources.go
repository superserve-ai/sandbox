package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// These backend-validated terms travel with the immutable Checkout request.
// Later configuration changes cannot reinterpret a purchase already in flight.
type StripeCheckoutResourceTerms struct {
	ResourceKey, PriceID, UnitAmountDecimal, MeterID, EventName string
}

func (h *Handlers) freezeProResourceTerms(ctx context.Context, team uuid.UUID, prices []string, client *stripeHTTPClient) ([]StripeCheckoutResourceTerms, error) {
	rates, err := h.DB.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: team, EffectiveAt: time.Now()})
	if err != nil {
		return nil, err
	}
	var terms []StripeCheckoutResourceTerms
	seenPrices, seenEvents, seenMeters := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, id := range prices {
		var resource, event string
		for _, r := range h.billingConfiguredResources() {
			if r.StripePriceID == id {
				resource, event = r.ResourceKey, r.StripeEventName
			}
		}
		if resource == "" || event == "" {
			return nil, errors.New("resource mapping is incomplete")
		}
		var expected *big.Rat
		for _, rate := range rates {
			if rate.Resource == resource && rate.Unit == "second" {
				v, e := rate.PriceUsd.Value()
				if e != nil {
					return nil, e
				}
				value, ok := new(big.Rat).SetString(fmt.Sprint(v))
				if !ok {
					return nil, errors.New("invalid usage rate")
				}
				expected = new(big.Rat).Mul(value, big.NewRat(360000, 1))
			}
		}
		var p storagePrice
		if err = client.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(id), nil, &p, ""); err != nil {
			return nil, err
		}
		actual, e := meterDecimal(p.UnitAmountDecimal)
		if p.ID != id || !p.Active || expected == nil || e != nil || actual.Cmp(expected) != 0 || !proResourceShape(p) {
			return nil, errors.New("configured Pro resource price differs from PAYG terms")
		}
		meter, e := client.ActiveMeterID(ctx, event)
		if e != nil {
			return nil, e
		}
		if meter != p.Recurring.Meter {
			return nil, errors.New("configured resource meter differs from its price")
		}
		if seenPrices[id] || seenEvents[event] || seenMeters[meter] {
			return nil, errors.New("configured resource prices, events, and meters must be unique")
		}
		seenPrices[id], seenEvents[event], seenMeters[meter] = true, true, true
		terms = append(terms, StripeCheckoutResourceTerms{ResourceKey: resource, PriceID: id, UnitAmountDecimal: p.UnitAmountDecimal, MeterID: meter, EventName: event})
	}
	return terms, nil
}
func proResourceShape(p storagePrice) bool {
	return p.Currency == "usd" && p.BillingScheme == "per_unit" && p.TransformQuantity == nil && p.Recurring.UsageType == "metered" && p.Recurring.Interval == "month" && p.Recurring.IntervalCount == 1
}
func validateFrozenProResources(sub invoiceSubscription, terms []StripeCheckoutResourceTerms, rounding string) error {
	expected := map[string]StripeCheckoutResourceTerms{}
	seenEvents, seenMeters := map[string]bool{}, map[string]bool{}
	for _, term := range terms {
		if term.PriceID == "" || term.MeterID == "" || term.EventName == "" || expected[term.PriceID].PriceID != "" || seenEvents[term.EventName] || seenMeters[term.MeterID] {
			return errors.New("frozen resource evidence is incomplete")
		}
		expected[term.PriceID] = term
		seenEvents[term.EventName], seenMeters[term.MeterID] = true, true
	}
	if len(expected) == 0 {
		return errors.New("frozen resource evidence is missing")
	}
	for _, item := range sub.Items.Data {
		p := item.Price
		if p.ID == rounding && rounding != "" {
			continue
		}
		term, ok := expected[p.ID]
		actual, e := meterDecimal(p.UnitAmountDecimal)
		want, werr := meterDecimal(term.UnitAmountDecimal)
		if !ok || e != nil || werr != nil || actual.Cmp(want) != 0 || !proResourceShape(p) || p.Recurring.Meter != term.MeterID {
			return errors.New("subscription resource differs from frozen Checkout terms")
		}
		delete(expected, p.ID)
	}
	if len(expected) != 0 {
		return errors.New("subscription is missing frozen resource items")
	}
	return nil
}

// Keep provider identities attached to their purchased subscription. Quantity,
// billability, and historical monetary rates remain owned by the usage ledger.
func (h *Handlers) billingSubscriptionResourceStates(ctx context.Context, team uuid.UUID, subscription string, storage bool, readers ...db.DBTX) ([]billingResourceState, error) {
	states := h.billingResourceStates(storage)
	var payload []byte
	var reader db.DBTX = h.Pool
	if len(readers) > 0 {
		reader = readers[0]
	}
	err := reader.QueryRow(ctx, `SELECT s.request_payload FROM billing_signup_choice s
        WHERE s.team_id=$1 AND s.offer_key IN ('pro_monthly','pro_annual')
        AND s.subscription_id=COALESCE(NULLIF($2,''),(SELECT stripe_subscription_id FROM team_billing_account WHERE team_id=$1))`, team, subscription).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return states, nil
	}
	if err != nil {
		return nil, err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(payload, &params); err != nil {
		return nil, err
	}
	result := make([]billingResourceState, 0, len(params.ResourceTerms))
	seen := map[string]bool{}
	for _, term := range params.ResourceTerms {
		if term.ResourceKey == "" || term.PriceID == "" || term.EventName == "" || term.MeterID == "" || seen[term.ResourceKey] {
			return nil, errors.New("frozen resource mapping is incomplete")
		}
		seen[term.ResourceKey] = true
		state := billingResourceState{BillingResourceConfig: config.BillingResourceConfig{ResourceKey: term.ResourceKey}}
		for _, current := range states {
			if current.ResourceKey == term.ResourceKey {
				state = current
				break
			}
		}
		state.StripePriceID, state.StripeEventName = term.PriceID, term.EventName
		state.PurchasedTerms = &term
		state.CheckoutEnabled = true
		state.SubscriptionEnabled = nil
		result = append(result, state)
	}
	if len(result) == 0 {
		return nil, errors.New("frozen resource mapping is missing")
	}
	return result, nil
}
