package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

func ycResourcePriceIDs(states []billingResourceState, storageRequired bool) ([]string, error) {
	seen := map[string]bool{}
	prices := []string{}
	for _, s := range states {
		if seen[s.ResourceKey] {
			return nil, errors.New("YC resource configuration contains duplicate resource identities")
		}
		seen[s.ResourceKey] = true
		switch s.ResourceKey {
		case "vcpu", "memory_gib", "storage_gib":
			if s.ResourceKey == "storage_gib" && !s.SubscriptionIncluded() && !storageRequired {
				continue
			}
			if !s.SubscriptionIncluded() || s.StripePriceID == "" || s.StripeEventName == "" || s.UsageUnit != "second" {
				return nil, fmt.Errorf("YC credits require a configured subscription price and meter for %s; storage billability may remain disabled", s.ResourceKey)
			}
			prices = append(prices, s.StripePriceID)
		default:
			if s.SubscriptionIncluded() {
				return nil, errors.New("YC credit scope contains an unsupported resource")
			}
		}
	}
	if !seen["vcpu"] || !seen["memory_gib"] || storageRequired && !seen["storage_gib"] {
		return nil, errors.New("YC credits require CPU and memory mappings, plus storage when storage billing is activated")
	}
	return prices, nil
}

func validateEntitlementResourceTerms(terms []StripeCheckoutResourceTerms, rounding, event, meter string, storageRequired bool) error {
	resources, prices, events, meters := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	if rounding != "" || event != "" || meter != "" {
		if rounding == "" || event == "" || meter == "" {
			return errors.New("entitlement rounding evidence is incomplete")
		}
		prices[rounding], events[event], meters[meter] = true, true, true
	}
	for _, t := range terms {
		if t.ResourceKey != "vcpu" && t.ResourceKey != "memory_gib" && t.ResourceKey != "storage_gib" {
			return errors.New("entitlement resource identity is unsupported")
		}
		amount, err := meterDecimal(t.UnitAmountDecimal)
		if resources[t.ResourceKey] || t.PriceID == "" || t.EventName == "" || t.MeterID == "" || prices[t.PriceID] || events[t.EventName] || meters[t.MeterID] || err != nil || amount.Sign() < 0 {
			return errors.New("entitlement resource identities, prices, meters and events must be complete and unique")
		}
		resources[t.ResourceKey], prices[t.PriceID], events[t.EventName], meters[t.MeterID] = true, true, true, true
	}
	if !resources["vcpu"] || !resources["memory_gib"] || storageRequired && !resources["storage_gib"] {
		return errors.New("credit_scope_incomplete: frozen terms must cover CPU, memory and any activated storage billing")
	}
	return nil
}

func (c *stripeHTTPClient) validateYCResourcePrices(ctx context.Context, terms []StripeCheckoutResourceTerms, live bool) error {
	for _, t := range terms {
		var p storagePrice
		if err := c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(t.PriceID), nil, &p, ""); err != nil {
			return err
		}
		actual, err := meterDecimal(p.UnitAmountDecimal)
		want, werr := meterDecimal(t.UnitAmountDecimal)
		if p.ID != t.PriceID || p.Product == "" || p.LiveMode != live || !p.Active || !proResourceShape(p) || err != nil || werr != nil || actual.Cmp(want) != 0 || p.Recurring.Meter != t.MeterID {
			return errors.New("YC resource price, currency, mode or frozen terms differ")
		}
		meter, err := c.ActiveMeterID(ctx, t.EventName)
		if err != nil {
			return err
		}
		if meter != t.MeterID {
			return errors.New("YC resource meter differs from frozen mapping")
		}
	}
	return nil
}

func (c *stripeHTTPClient) ycRoundingPreflight(ctx context.Context, terms []StripeCheckoutResourceTerms, live bool) error {
	var list struct {
		Data    []storagePrice `json:"data"`
		HasMore bool           `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices?"+url.Values{"lookup_keys[]": {invoiceRoundingLookup}, "limit": {"2"}}.Encode(), nil, &list, ""); err != nil {
		return err
	}
	// Invoice enrollment provisions a missing rounding catalog before issuance.
	if !list.HasMore && len(list.Data) == 0 {
		return nil
	}
	if list.HasMore || len(list.Data) != 1 {
		return errors.New("YC approval requires an unambiguous invoice rounding price")
	}
	p := list.Data[0]
	t := StripeCheckoutResourceTerms{PriceID: p.ID, MeterID: p.Recurring.Meter, EventName: invoiceRoundingEvent, UnitAmountDecimal: "1"}
	if err := validateEntitlementResourceTerms(terms, t.PriceID, t.EventName, t.MeterID, false); err != nil {
		return err
	}
	return c.validateYCResourcePrices(ctx, []StripeCheckoutResourceTerms{t}, live)
}
