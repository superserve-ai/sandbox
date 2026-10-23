package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// VerifyProviderPairTerms checks server-pinned mappings before request creation.
// It does not resolve prices from configuration or grant acceptance authority.
func (h *Handlers) VerifyProviderPairTerms(ctx context.Context, identity ProviderPairIdentity, terms ProviderPairTerms) error {
	c, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("paired price verifier unavailable")
	}
	digest, err := terms.Digest()
	if err != nil {
		return err
	}
	if digest != identity.ProviderTermsDigest || c.apiVersion != identity.APIVersion || identity.Merchant == "" {
		return errors.New("paired provider scope or price digest differs")
	}
	var account struct{ ID string }
	if err = c.doForm(ctx, http.MethodGet, "/v1/account", nil, &account, ""); err != nil {
		return err
	}
	if account.ID != identity.Merchant {
		return errors.New("paired price merchant differs")
	}
	var fee storagePrice
	if err = c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(terms.FeePriceID), nil, &fee, ""); err != nil {
		return err
	}
	if !fee.Active {
		return errors.New("paired fee price is inactive")
	}
	if err = validatePairFeeItem(terms, identity.Live, invoiceSubscriptionItem{ID: "price-validation", Quantity: 1, Price: fee}); err != nil {
		return err
	}
	for _, term := range append(append([]StripeCheckoutResourceTerms{}, terms.Resources...), terms.Rounding) {
		var price storagePrice
		if err = c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(term.PriceID), nil, &price, ""); err != nil {
			return err
		}
		actual, e := meterDecimal(price.UnitAmountDecimal)
		want, werr := meterDecimal(term.UnitAmountDecimal)
		if e != nil || werr != nil || actual.Cmp(want) != 0 || price.ID != term.PriceID || !price.Active || price.LiveMode != identity.Live || !proResourceShape(price) || price.Recurring.Meter != term.MeterID {
			return errors.New("paired metered price differs from frozen mapping")
		}
		meter, e := c.ActiveMeterID(ctx, term.EventName)
		if e != nil {
			return e
		}
		if meter != term.MeterID {
			return errors.New("paired metered event mapping differs")
		}
	}
	return nil
}

func (h *Handlers) ContractProviderBinding(ctx context.Context, team, contract uuid.UUID) (ContractProviderBinding, error) {
	b, err := loadContractProviderBinding(ctx, h.Pool, contract)
	if err != nil {
		return b, err
	}
	if b.Identity.TeamID != team {
		return ContractProviderBinding{}, errors.New("provider binding belongs to another team")
	}
	return b, nil
}
