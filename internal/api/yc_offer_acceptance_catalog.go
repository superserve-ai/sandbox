package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type ycAcceptedCatalog struct {
	h *Handlers
	s *YCOfferAcceptanceService
}

func (c ycAcceptedCatalog) Resolve(ctx context.Context, a YCAcceptanceAuthority) (YCAcceptanceDisclosure, error) {
	var d YCAcceptanceDisclosure
	if a.HomeRegion != c.s.Region {
		return d, errYCAcceptanceConflict
	}
	if err := commercialOfferEnabled(ctx, c.s.Pool, a.TeamID); err != nil {
		return d, err
	}
	load := func(key string, version int) (YCAcceptanceTerms, error) {
		var t YCAcceptanceTerms
		var raw json.RawMessage
		err := c.s.Pool.QueryRow(ctx, `SELECT to_jsonb(v)||jsonb_build_object('offer_version',version) FROM billing_commercial_offer_version v WHERE offer_key=$1 AND version=$2`, key, version).Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &t)
		}
		return t, err
	}
	var err error
	d.Terms, err = load(a.OfferKey, a.OfferVersion)
	if err != nil {
		return d, err
	}
	// This published renewal version is explicit. Future versions require a new
	// disclosure contract; retries never select MAX(version) or current defaults.
	d.RenewalTerms, err = load(d.Terms.DefaultSuccessorFamily, 1)
	if err != nil {
		return d, err
	}
	var card string
	var ids []uuid.UUID
	var raw json.RawMessage
	if err = c.s.Pool.QueryRow(ctx, commercialOfferPricingSQL, a.TeamID, a.OfferKey, a.OfferVersion).Scan(&card, &ids, &d.PricingAt, &raw); err != nil {
		return d, err
	}
	var rates []struct {
		ID       uuid.UUID   `json:"id"`
		Resource string      `json:"resource"`
		Unit     string      `json:"unit"`
		Price    json.Number `json:"price_usd"`
		Currency string      `json:"currency"`
	}
	if err = json.Unmarshal(raw, &rates); err != nil {
		return d, err
	}
	if card != d.Terms.RateCardKey || card != d.RenewalTerms.RateCardKey {
		return d, errYCAcceptanceConflict
	}
	for _, rate := range rates {
		d.Terms.ResourceRates = append(d.Terms.ResourceRates, YCAcceptanceRate{ID: rate.ID, Resource: rate.Resource, Unit: rate.Unit, PriceUSD: rate.Price.String(), Currency: rate.Currency})
	}
	d.RenewalTerms.ResourceRates = append([]YCAcceptanceRate(nil), d.Terms.ResourceRates...)
	return d, d.validate(a)
}

func (c ycAcceptedCatalog) Assign(ctx context.Context, input YCAcceptanceRecord) (uuid.UUID, error) {
	r, err := loadYCAcceptance(ctx, c.s.Pool, input.TeamID, input.ClaimID)
	if err != nil {
		return uuid.Nil, err
	}
	if r.ID != input.ID || r.AcceptedAt == nil || r.TermsDigest != input.TermsDigest || r.RenewalTermsDigest != input.RenewalTermsDigest {
		return uuid.Nil, errYCAcceptanceConflict
	}
	var id uuid.UUID
	err = c.s.withGuard(ctx, r, "admit", func(guardCtx context.Context) error {
		request := CommercialOfferRequest{Key: "acceptance/" + r.ID.String(), OfferKey: r.OfferKey, Version: r.OfferVersion, ApprovalID: r.ApprovalID, Company: r.Company, Region: r.HomeRegion, Reason: "Customer accepted exact published terms", Reference: r.ID.String() + "/" + r.TermsDigest + "/" + r.RenewalTermsDigest + "/" + r.PricingAt.UTC().Format(time.RFC3339Nano)}
		raw, err := c.h.assignCommercialOfferRegional(guardCtx, r.TeamID, r.UserID, request, true, &r)
		if err != nil {
			return err
		}
		var out struct {
			Assignment struct {
				ID uuid.UUID `json:"id"`
			} `json:"assignment"`
		}
		if err = json.Unmarshal(raw, &out); err != nil {
			return err
		}
		id = out.Assignment.ID
		if id == uuid.Nil {
			return errYCAcceptanceConflict
		}
		return nil
	})
	return id, err
}

func acceptedResourceSnapshot(r YCAcceptanceRecord) ([]uuid.UUID, json.RawMessage, error) {
	ids := make([]uuid.UUID, 0, len(r.Terms.ResourceRates))
	rates := make([]map[string]any, 0, len(r.Terms.ResourceRates))
	for _, rate := range r.Terms.ResourceRates {
		ids = append(ids, rate.ID)
		rates = append(rates, map[string]any{"id": rate.ID, "plan_key": r.Terms.RateCardKey, "resource": rate.Resource, "unit": rate.Unit, "price_usd": json.Number(rate.PriceUSD), "currency": rate.Currency})
	}
	raw, err := json.Marshal(rates)
	return ids, raw, err
}

func verifyAcceptedAssignment(ctx context.Context, q db.DBTX, r YCAcceptanceRecord, id uuid.UUID) error {
	ids, raw, err := acceptedResourceSnapshot(r)
	if err != nil {
		return err
	}
	var same bool
	err = q.QueryRow(ctx, `SELECT team_id=$2 AND approval_id=$3 AND company_identity=$4 AND home_region=$5 AND offer_key=$6 AND offer_version=$7
 AND rate_card_key=$8 AND rate_ids=$9 AND pricing_at=$10 AND resource_rates=$11::jsonb FROM billing_commercial_offer_assignment WHERE id=$1`,
		id, r.TeamID, r.ApprovalID, r.Company, r.HomeRegion, r.OfferKey, r.OfferVersion, r.Terms.RateCardKey, ids, r.PricingAt, raw).Scan(&same)
	if err == nil && !same {
		err = errYCAcceptanceConflict
	}
	return err
}

func acceptedOfferPricing(ctx context.Context, tx pgx.Tx, r YCAcceptanceRecord) (string, []uuid.UUID, time.Time, json.RawMessage, error) {
	fail := func(err error) (string, []uuid.UUID, time.Time, json.RawMessage, error) {
		return "", nil, time.Time{}, nil, err
	}
	if err := (YCAcceptanceDisclosure{Terms: r.Terms, RenewalTerms: r.RenewalTerms, PricingAt: r.PricingAt}).validate(r.YCAcceptanceAuthority); err != nil {
		return fail(err)
	}
	// Lock the exact historical rows through assignment commit. Publishing a new
	// version may close the old interval, but cannot change prices accepted within it.
	for _, terms := range []YCAcceptanceTerms{r.Terms, r.RenewalTerms} {
		var raw json.RawMessage
		if err := tx.QueryRow(ctx, `SELECT to_jsonb(v)||jsonb_build_object('offer_version',version) FROM billing_commercial_offer_version v WHERE offer_key=$1 AND version=$2`, terms.OfferKey, terms.OfferVersion).Scan(&raw); err != nil {
			return fail(err)
		}
		var current YCAcceptanceTerms
		if err := json.Unmarshal(raw, &current); err != nil {
			return fail(err)
		}
		current.ResourceRates = terms.ResourceRates
		if ycAcceptanceDigest(current) != ycAcceptanceDigest(terms) {
			return fail(errYCAcceptanceConflict)
		}
	}
	ids, raw, err := acceptedResourceSnapshot(r)
	if err != nil {
		return fail(err)
	}
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT public.lock_yc_accepted_offer_rates($1)`, r.ID).Scan(&valid); err != nil {
		return fail(err)
	}
	if !valid {
		return fail(errYCAcceptanceConflict)
	}
	return r.Terms.RateCardKey, ids, r.PricingAt, raw, nil
}
