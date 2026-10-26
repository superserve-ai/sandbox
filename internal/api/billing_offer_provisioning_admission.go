package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
	"github.com/superserve-ai/sandbox/internal/db"
)

func savedOfferProvisioningTerms(ctx context.Context, q db.DBTX, team, assignment uuid.UUID) (provisioning.AcceptedOffer, error) {
	var raw json.RawMessage
	var offer provisioning.AcceptedOffer
	if err := q.QueryRow(ctx, `SELECT accepted_offer FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2`, team, assignment).Scan(&raw); err != nil {
		return offer, err
	}
	err := json.Unmarshal(raw, &offer)
	return offer, err
}

func enrichOfferProvisioning(current, pinned provisioning.AcceptedOffer) provisioning.AcceptedOffer {
	current.Merchant, current.Live, current.APIVersion, current.ProviderTerms = pinned.Merchant, pinned.Live, pinned.APIVersion, pinned.ProviderTerms
	return current
}

func (a *offerProvisioningAuthority) WithAcceptedOffer(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error) error {
	if err := offerProvisioningExportEnabled(ctx, a.h.Pool, team); err != nil {
		return err
	}
	pinned, err := savedOfferProvisioningTerms(ctx, a.h.Pool, team, assignment)
	if errors.Is(err, pgx.ErrNoRows) {
		r, e := a.admission.record(ctx, a.h.Pool, team, assignment)
		if e != nil {
			return e
		}
		pinned, err = a.freezeProviderTerms(ctx, r)
	}
	if err != nil {
		return err
	}
	return a.admission.WithAcceptedOffer(ctx, team, assignment, func(ctx context.Context, tx pgx.Tx, offer provisioning.AcceptedOffer) error {
		if err := offerProvisioningExportEnabled(ctx, tx, team); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO billing_funding_account(team_id) VALUES($1) ON CONFLICT(team_id) DO NOTHING`, team); err != nil {
			return err
		}
		// Reserve bounded observation capacity before any provider write. The
		// existing cohort trigger rejects exhaustion atomically with admission.
		if _, err := tx.Exec(ctx, `UPDATE billing_funding_account SET observe=true,enforce=true,next_check_at=clock_timestamp() WHERE team_id=$1 AND (NOT observe OR NOT enforce)`, team); err != nil {
			return err
		}
		// A concurrent admission may have won while catalog GETs were in flight.
		// Its saved mapping wins; neither retry nor configuration drift replaces it.
		saved, err := savedOfferProvisioningTerms(ctx, tx, team, assignment)
		if err == nil {
			pinned = saved
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		} else if !bytes.Equal(offer.Snapshot, pinned.Snapshot) {
			return provisioning.ErrConflict
		}
		return f(ctx, tx, enrichOfferProvisioning(offer, pinned))
	})
}

func (a *offerProvisioningAuthority) WithDispatchGuard(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, provisioning.AcceptedOffer) error) error {
	if err := offerProvisioningExportEnabled(ctx, a.h.Pool, team); err != nil {
		return err
	}
	pinned, err := savedOfferProvisioningTerms(ctx, a.h.Pool, team, assignment)
	if err != nil {
		return err
	}
	return a.admission.WithDispatchGuard(ctx, team, assignment, func(ctx context.Context, offer provisioning.AcceptedOffer) error {
		return f(ctx, enrichOfferProvisioning(offer, pinned))
	})
}

func offerProvisioningExportEnabled(ctx context.Context, q db.DBTX, team uuid.UUID) error {
	var enabled bool
	if err := q.QueryRow(ctx, `SELECT feature_enabled('billing_export_enabled',$1)`, team).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return provisioning.ErrUnavailable
	}
	return nil
}

// freezeProviderTerms reads catalog objects before admission locks. Prices must
// match the accepted historical rates, never the currently active rate card.
func (a *offerProvisioningAuthority) freezeProviderTerms(ctx context.Context, r YCAcceptanceRecord) (provisioning.AcceptedOffer, error) {
	offer, err := acceptedProvisioningSnapshot(r)
	if err != nil {
		return offer, err
	}
	if a.client == nil || a.client.apiVersion == "" || a.h.Config == nil || r.Terms.ChargeAmountCents != 1200000 || r.Terms.ChargeIntervalMonths != 12 || !r.Terms.InitialFeeWaived || len(r.Terms.ResourceRates) != 3 {
		return offer, provisioning.ErrUnavailable
	}
	get := func(path string, dst any) error {
		raw, err := a.client.offerProviderHTTP(ctx, http.MethodGet, path, "", "", a.client.apiVersion)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, dst)
	}
	var account struct{ ID string }
	var balance struct {
		Live *bool `json:"livemode"`
	}
	if err = get("/v1/account", &account); err != nil {
		return offer, err
	}
	if err = get("/v1/balance", &balance); err != nil {
		return offer, err
	}
	if account.ID == "" || balance.Live == nil {
		return offer, provisioning.ErrConflict
	}
	offer.Merchant, offer.Live, offer.APIVersion = account.ID, *balance.Live, a.client.apiVersion
	readPrice := func(id string) (storagePrice, error) {
		var p struct {
			storagePrice
			Mode *bool `json:"livemode"`
		}
		err := get("/v1/prices/"+url.PathEscape(id), &p)
		if err == nil && (id == "" || p.ID != id || !p.Active || p.Product == "" || p.Mode == nil || *p.Mode != offer.Live) {
			err = provisioning.ErrConflict
		}
		return p.storagePrice, err
	}
	fee, err := readPrice(a.h.Config.StripeProAnnualPriceID)
	if err != nil {
		return offer, err
	}
	if fee.Currency != "usd" || fee.BillingScheme != "per_unit" || fee.TransformQuantity != nil || fee.Recurring.UsageType != "licensed" || fee.Recurring.Interval != "year" || fee.Recurring.IntervalCount != 1 || fee.UnitAmountDecimal != "1200000" {
		return offer, provisioning.ErrConflict
	}
	terms := ProviderPairTerms{FeePriceID: fee.ID, FeeProductID: fee.Product, FeeAmount: 1200000, Currency: "usd", FeeMonths: 12}
	resources := a.h.billingConfiguredResources()
	for _, rate := range r.Terms.ResourceRates {
		var id, event string
		for _, configured := range resources {
			if configured.ResourceKey == rate.Resource {
				if id != "" || configured.UsageUnit != "second" {
					return offer, provisioning.ErrConflict
				}
				id, event = configured.StripePriceID, configured.StripeEventName
			}
		}
		price, err := readPrice(id)
		if err != nil {
			return offer, err
		}
		accepted, ok := new(big.Rat).SetString(rate.PriceUSD)
		actual, amountErr := meterDecimal(price.UnitAmountDecimal)
		if !ok || amountErr != nil || rate.Unit != "second" || rate.Currency != "USD" || !proResourceShape(price) || event == "" || actual.Cmp(new(big.Rat).Mul(accepted, big.NewRat(360000, 1))) != 0 {
			return offer, provisioning.ErrConflict
		}
		meter, err := a.client.ActiveMeterID(ctx, event)
		if err != nil {
			return offer, err
		}
		if meter != price.Recurring.Meter {
			return offer, provisioning.ErrConflict
		}
		terms.Resources = append(terms.Resources, StripeCheckoutResourceTerms{ResourceKey: rate.Resource, PriceID: price.ID, UnitAmountDecimal: price.UnitAmountDecimal, MeterID: meter, EventName: event})
	}
	var rounding struct {
		Data    []struct{ ID string } `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = get("/v1/prices?"+url.Values{"lookup_keys[]": {invoiceRoundingLookup}, "limit": {"2"}}.Encode(), &rounding); err != nil {
		return offer, err
	}
	// The catalog is provisioned separately. Admission never creates shared
	// merchant objects outside the operation's five durable requests.
	if rounding.HasMore || len(rounding.Data) != 1 {
		return offer, provisioning.ErrUnavailable
	}
	price, err := readPrice(rounding.Data[0].ID)
	if err != nil {
		return offer, err
	}
	meter, err := a.client.ActiveMeterID(ctx, invoiceRoundingEvent)
	if err != nil {
		return offer, err
	}
	if !proResourceShape(price) || price.UnitAmountDecimal != "1" || price.Recurring.Meter != meter {
		return offer, provisioning.ErrConflict
	}
	terms.Rounding = StripeCheckoutResourceTerms{ResourceKey: "rounding", PriceID: price.ID, UnitAmountDecimal: "1", MeterID: meter, EventName: invoiceRoundingEvent}
	if _, err = terms.Digest(); err != nil {
		return offer, err
	}
	offer.ProviderTerms, err = json.Marshal(terms)
	return offer, err
}
