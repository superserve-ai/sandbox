package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// planGrant is one timed-grant rule: starting StartMonths after the contract
// anchor, AmountCents is issued Repeat times (nil means indefinitely), every
// EveryMonths months, and each issue expires ExpiresAfterMonths later.
type planGrant struct {
	StartMonths        int32  `json:"start_months"`
	Repeat             *int32 `json:"repeat"`
	EveryMonths        int32  `json:"every_months"`
	AmountCents        int64  `json:"amount_cents"`
	ExpiresAfterMonths int32  `json:"expires_after_months"`
}

// planMatching credits MatchingBps basis points of customer-paid usage until
// CapCents of matched credit has been issued over the contract.
type planMatching struct {
	MatchingBps int32 `json:"matching_bps"`
	CapCents    int64 `json:"cap_cents"`
}

// planLimits are the limits a plan grants. MaxConcurrent is the number of
// sandboxes a team may run at once (paused ones do not count); the size caps
// bound each sandbox's template.
type planLimits struct {
	MaxConcurrent *int32 `json:"max_concurrent"`
	MaxVCPU       *int32 `json:"max_vcpu"`
	MaxMemoryMiB  *int32 `json:"max_memory_mib"`
	MaxDiskMiB    *int32 `json:"max_disk_mib"`
	MaxTemplates  *int32 `json:"max_templates"`
}

// planCompute prices an allowance as Seconds of a sandbox with VCPU vCPUs and
// MemoryGiB of memory at the current rate card.
type planCompute struct {
	Seconds   int32 `json:"seconds"`
	VCPU      int32 `json:"vcpu"`
	MemoryGiB int32 `json:"memory_gib"`
}

// planAllowance is the usage included in each period. Period is "day_window"
// (24 hours from the first start) or "month"; OnExhausted is "pause" or
// "payg". A version stores either AmountCents or Compute; planTerms resolves
// both to AmountUSD, an exact decimal string, and Compute to AmountCents
// rounded to the cent for display.
type planAllowance struct {
	AmountCents int64        `json:"amount_cents"`
	AmountUSD   string       `json:"amount_usd,omitempty"`
	Period      string       `json:"period"`
	OnExhausted string       `json:"on_exhausted"`
	Compute     *planCompute `json:"compute,omitempty"`
}

var planKinds = map[string]bool{"free": true, "prepaid": true, "subscription": true, "legacy_payg": true, "custom": true}

type planVersion struct {
	ID              uuid.UUID      `json:"id"`
	PricingVersion  string         `json:"pricing_version"`
	Family          string         `json:"family"`
	Version         int32          `json:"version"`
	State           string         `json:"state"`
	Kind            string         `json:"kind"`
	Public          bool           `json:"public"`
	DisplayName     string         `json:"display_name"`
	PriceLabel      string         `json:"price_label"`
	Tagline         string         `json:"tagline"`
	Features        []string       `json:"features"`
	SortOrder       int32          `json:"sort_order"`
	DisplayOnly     bool           `json:"display_only"`
	SelfServe       bool           `json:"self_serve"`
	MonthlyFeeCents *int64         `json:"monthly_fee_cents"`
	AnnualFeeCents  *int64         `json:"annual_fee_cents"`
	CreditSchedule  []planGrant    `json:"credit_schedule"`
	Matching        *planMatching  `json:"matching"`
	Allowance       *planAllowance `json:"allowance"`
	Limits          planLimits     `json:"limits"`
	CreatedBy       *uuid.UUID     `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	PublishedBy     *uuid.UUID     `json:"published_by"`
	PublishedAt     *time.Time     `json:"published_at"`
	RetiredBy       *uuid.UUID     `json:"retired_by"`
	RetiredAt       *time.Time     `json:"retired_at"`
}

const planVersionColumns = `id,pricing_version,family,version,state,kind,public,display_name,price_label,tagline,features,sort_order,display_only,self_serve,
monthly_fee_cents,annual_fee_cents,credit_schedule,matching_bps,cap_cents,
allowance_period,allowance_on_exhausted,allowance_cents,allowance_compute_seconds,allowance_compute_vcpu,allowance_compute_memory_gib,
max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates,
created_by,created_at,updated_at,published_by,published_at,retired_by,retired_at`

func scanPlanVersion(row pgx.Row) (planVersion, error) {
	var v planVersion
	var schedule []byte
	var bps *int32
	var capCents, allowanceCents *int64
	var period, onExhausted *string
	var seconds, vcpu, memory *int32
	err := row.Scan(&v.ID, &v.PricingVersion, &v.Family, &v.Version, &v.State, &v.Kind, &v.Public, &v.DisplayName, &v.PriceLabel, &v.Tagline, &v.Features,
		&v.SortOrder, &v.DisplayOnly, &v.SelfServe, &v.MonthlyFeeCents, &v.AnnualFeeCents, &schedule, &bps, &capCents,
		&period, &onExhausted, &allowanceCents, &seconds, &vcpu, &memory,
		&v.Limits.MaxConcurrent, &v.Limits.MaxVCPU, &v.Limits.MaxMemoryMiB, &v.Limits.MaxDiskMiB, &v.Limits.MaxTemplates,
		&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt, &v.PublishedBy, &v.PublishedAt, &v.RetiredBy, &v.RetiredAt)
	if err != nil {
		return v, err
	}
	if err = json.Unmarshal(schedule, &v.CreditSchedule); err != nil {
		return v, err
	}
	if bps != nil && capCents != nil {
		v.Matching = &planMatching{MatchingBps: *bps, CapCents: *capCents}
	}
	if period != nil && onExhausted != nil {
		v.Allowance = &planAllowance{Period: *period, OnExhausted: *onExhausted}
		if allowanceCents != nil {
			v.Allowance.AmountCents = *allowanceCents
		}
		if seconds != nil && vcpu != nil && memory != nil {
			v.Allowance.Compute = &planCompute{Seconds: *seconds, VCPU: *vcpu, MemoryGiB: *memory}
		}
	}
	return v, nil
}

// sellable reports whether new customers may check the version out: it is a
// public self-serve subscription whose contract can deliver its terms, one
// monthly credit and no matching rule.
func (v planVersion) sellable() bool {
	_, uniform := uniformMonthlyCredit(v.CreditSchedule)
	return v.SelfServe && v.Public && v.Kind == "subscription" && !v.DisplayOnly && v.hasFee() && uniform && v.Matching == nil
}

func (v planVersion) feeCents(months int32) *int64 {
	if months == 12 {
		return v.AnnualFeeCents
	}
	return v.MonthlyFeeCents
}

// validate mirrors the database constraints so staff see a precise error
// before a write is attempted.
func (v planVersion) validate() error {
	if !planFamilyPattern(v.Family) {
		return errors.New("family must be lowercase letters and digits joined by single underscores, starting with a letter")
	}
	if v.PricingVersion != "legacy" && v.PricingVersion != "v2" {
		return errors.New("pricing version must be legacy or v2")
	}
	if !planKinds[v.Kind] {
		return errors.New("kind must be free, prepaid, subscription, legacy_payg or custom")
	}
	if v.SortOrder < 0 || v.SortOrder > 1000 {
		return errors.New("card order must be between 0 and 1000")
	}
	if strings.ContainsRune(v.DisplayName+v.PriceLabel+v.Tagline+strings.Join(v.Features, ""), 0) {
		return errors.New("text may not contain NUL characters")
	}
	if strings.TrimSpace(v.DisplayName) == "" || len(v.DisplayName) > 80 || len(v.PriceLabel) > 80 || len(v.Tagline) > 200 || len(v.Features) > 20 {
		return errors.New("display name is required; name, price label, tagline and features have length limits")
	}
	for _, f := range v.Features {
		if strings.TrimSpace(f) == "" || len(f) > 200 {
			return errors.New("feature bullets must be non-empty and at most 200 characters")
		}
	}
	if err := validatePlanSchedule(v.CreditSchedule); err != nil {
		return err
	}
	if m := v.Matching; m != nil && (m.MatchingBps < 1 || m.MatchingBps > 10000 || m.CapCents <= 0) {
		return errors.New("matching must be 1-10000 basis points with a positive cap")
	}
	for _, fee := range []*int64{v.MonthlyFeeCents, v.AnnualFeeCents} {
		if fee != nil && *fee <= 0 {
			return errors.New("fees must be positive")
		}
	}
	for _, limit := range []*int32{v.Limits.MaxConcurrent, v.Limits.MaxVCPU, v.Limits.MaxMemoryMiB, v.Limits.MaxDiskMiB} {
		if limit != nil && *limit <= 0 {
			return errors.New("limits must be positive")
		}
	}
	if v.Limits.MaxTemplates != nil && *v.Limits.MaxTemplates < 0 {
		return errors.New("max_templates must be nonnegative")
	}
	if v.Limits.MaxVCPU != nil && *v.Limits.MaxVCPU > absoluteMaxVcpu {
		return fmt.Errorf("max_vcpu must not exceed %d", absoluteMaxVcpu)
	}
	if v.Limits.MaxMemoryMiB != nil && (*v.Limits.MaxMemoryMiB < minimumTemplateMemoryMiB || *v.Limits.MaxMemoryMiB > absoluteMaxMemoryMib) {
		return fmt.Errorf("max_memory_mib must be between %d and %d", minimumTemplateMemoryMiB, absoluteMaxMemoryMib)
	}
	if v.Limits.MaxDiskMiB != nil && (*v.Limits.MaxDiskMiB < minimumTemplateDiskMiB || *v.Limits.MaxDiskMiB > absoluteMaxDiskMib) {
		return fmt.Errorf("max_disk_mib must be between %d and %d", minimumTemplateDiskMiB, absoluteMaxDiskMib)
	}
	if v.Kind == "legacy_payg" && (v.Limits.MaxVCPU == nil || v.Limits.MaxMemoryMiB == nil || v.Limits.MaxDiskMiB == nil || v.Limits.MaxTemplates == nil) {
		return errors.New("pay as you go needs every template limit: teams without their own limits use it")
	}
	if a := v.Allowance; a != nil {
		if (a.Period != "day_window" && a.Period != "month") || (a.OnExhausted != "pause" && a.OnExhausted != "payg") {
			return errors.New("an allowance needs a period (day_window or month) and what happens when it runs out (pause or payg)")
		}
		if (a.AmountCents > 0) == (a.Compute != nil) {
			return errors.New("an allowance is either a fixed amount or a compute basis")
		}
		if a.AmountCents < 0 || (a.Compute != nil && (a.Compute.Seconds <= 0 || a.Compute.VCPU <= 0 || a.Compute.MemoryGiB <= 0)) {
			return errors.New("allowance amounts must be positive")
		}
	}
	if v.DisplayOnly {
		if v.hasFee() || v.SelfServe || len(v.CreditSchedule) != 0 || v.Matching != nil || v.Allowance != nil {
			return errors.New("display-only plans carry no fees, credits, matching, allowance or self-serve checkout")
		}
		return nil
	}
	if v.hasFee() != (v.Kind == "subscription") && v.Kind != "custom" {
		return errors.New("subscription plans charge a fee and no other kind does")
	}
	if v.SelfServe && !v.sellable() {
		return errors.New("self-serve checkout sells only public subscriptions with a fee, one ongoing monthly credit grant expiring after a month, and no matching rule")
	}
	if v.hasFee() && strings.Contains(v.Family, "_") {
		return errors.New("plans with fees use a family without underscores")
	}
	if v.Limits.MaxConcurrent == nil && v.Kind != "custom" {
		return errors.New("max running sandboxes is required")
	}
	if v.Kind == "custom" && !v.hasFee() && len(v.CreditSchedule) == 0 && v.Matching == nil && v.Allowance == nil && v.Limits.MaxConcurrent == nil {
		return errors.New("a custom plan needs a fee, credits, matching, an allowance or limits")
	}
	return nil
}

func (v planVersion) hasFee() bool {
	return v.MonthlyFeeCents != nil || v.AnnualFeeCents != nil
}

// planFamilyPattern accepts lowercase words of letters and digits joined by
// single underscores, never ending like an offer key's interval.
func planFamilyPattern(family string) bool {
	if family == "" || len(family) > 63 || family[0] < 'a' || family[0] > 'z' ||
		strings.HasSuffix(family, "_monthly") || strings.HasSuffix(family, "_annual") {
		return false
	}
	for _, word := range strings.Split(family, "_") {
		if word == "" {
			return false
		}
		for _, r := range word {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}

func validatePlanSchedule(grants []planGrant) error {
	if len(grants) > 24 {
		return errors.New("a credit schedule has at most 24 grant rules")
	}
	for i, g := range grants {
		if g.StartMonths < 0 || g.StartMonths > 120 || g.EveryMonths < 1 || g.EveryMonths > 12 || g.ExpiresAfterMonths < 1 || g.ExpiresAfterMonths > 12 ||
			g.AmountCents < 1 || g.AmountCents > 100000000 || (g.Repeat != nil && (*g.Repeat < 1 || *g.Repeat > 120)) {
			return fmt.Errorf("credit grant %d: start 0-120 months, every and expiry 1-12 months, repeat 1-120 or ongoing, amount up to $1,000,000", i+1)
		}
	}
	return nil
}

// planGrantIssue is one expanded grant, at a month offset from the anchor.
type planGrantIssue struct {
	MonthOffset        int32 `json:"month_offset"`
	AmountCents        int64 `json:"amount_cents"`
	ExpiresAfterMonths int32 `json:"expires_after_months"`
}

// expandPlanSchedule lists every grant issued before horizonMonths, ordered by
// offset. It is the single expansion used by previews and materialisation.
func expandPlanSchedule(grants []planGrant, horizonMonths int32) []planGrantIssue {
	issues := []planGrantIssue{}
	for _, g := range grants {
		for n := int32(0); g.Repeat == nil || n < *g.Repeat; n++ {
			offset := g.StartMonths + n*g.EveryMonths
			if offset >= horizonMonths {
				break
			}
			issues = append(issues, planGrantIssue{MonthOffset: offset, AmountCents: g.AmountCents, ExpiresAfterMonths: g.ExpiresAfterMonths})
		}
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].MonthOffset < issues[j].MonthOffset })
	return issues
}

// uniformMonthlyCredit reports the amount of a schedule that issues the same
// one-month grant every month from the anchor, the shape self-serve
// subscription contracts represent.
func uniformMonthlyCredit(grants []planGrant) (int64, bool) {
	if len(grants) != 1 {
		return 0, false
	}
	g := grants[0]
	if g.StartMonths != 0 || g.Repeat != nil || g.EveryMonths != 1 || g.ExpiresAfterMonths != 1 {
		return 0, false
	}
	return g.AmountCents, true
}

// planPriceLookupKey names the Stripe price of a version's fee for one
// interval. Version ids are the same in every region, so every region and
// every caller finds the same price instead of creating another.
func planPriceLookupKey(versionID uuid.UUID, months int32) string {
	interval := "monthly"
	if months == 12 {
		interval = "annual"
	}
	return "superserve_plan_" + versionID.String() + "_" + interval
}

// ensurePlanPrice is the one source of Stripe prices for catalog plan fees.
// A configured price wins while it charges t's fee on t's interval, so a plan
// keeps one price whichever path sells it; otherwise the version's own price
// is found by lookup key or created once. Versions that do not own a price
// (see ownsPrice) are sold only on the configured price. It reads only t's
// VersionID, Version, PricingVersion, OfferKey, DisplayName, FeeCents and
// IntervalMonths, so callers may pass frozen terms.
func (h *Handlers) ensurePlanPrice(ctx context.Context, c *stripeHTTPClient, t planTerms) (storagePrice, error) {
	if configured := h.Config.PlanPriceID(t.OfferKey); configured != "" {
		p, err := c.verifiedPlanPrice(ctx, proOffer{Key: t.OfferKey, Price: configured, Amount: t.FeeCents, Months: t.IntervalMonths})
		if !errors.Is(err, errProPriceMismatch) || !t.ownsPrice() {
			return p, err
		}
	}
	if !t.ownsPrice() {
		return storagePrice{}, errProPriceMismatch
	}
	return c.versionPlanPrice(ctx, t)
}

// versionPlanPrice finds or creates the price keyed by t's version.
func (c *stripeHTTPClient) versionPlanPrice(ctx context.Context, t planTerms) (storagePrice, error) {
	if t.VersionID == uuid.Nil || t.FeeCents <= 0 || (t.IntervalMonths != 1 && t.IntervalMonths != 12) {
		return storagePrice{}, errors.New("plan terms have no fee to price")
	}
	o := proOffer{Key: t.OfferKey, Amount: t.FeeCents, Months: t.IntervalMonths, VersionID: t.VersionID}
	key := planPriceLookupKey(t.VersionID, t.IntervalMonths)
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices?"+url.Values{"lookup_keys[]": {key}, "limit": {"2"}}.Encode(), nil, &list, ""); err != nil {
		return storagePrice{}, err
	}
	if len(list.Data) > 1 {
		return storagePrice{}, errors.New("multiple Stripe prices share a plan lookup key")
	}
	if len(list.Data) == 1 {
		o.Price = list.Data[0].ID
		p, err := c.verifiedPlanPrice(ctx, o)
		if err != nil {
			return p, fmt.Errorf("plan price %s is archived or differs from the version: %w", o.Price, err)
		}
		return p, nil
	}
	interval := "month"
	if t.IntervalMonths == 12 {
		interval = "year"
	}
	form := url.Values{}
	form.Set("currency", "usd")
	form.Set("unit_amount", fmt.Sprint(t.FeeCents))
	form.Set("recurring[interval]", interval)
	form.Set("recurring[interval_count]", "1")
	form.Set("recurring[usage_type]", "licensed")
	form.Set("lookup_key", key)
	form.Set("product_data[name]", "Superserve "+catalogPlanName(t.DisplayName, t.IntervalMonths))
	form.Set("metadata[plan_version_id]", t.VersionID.String())
	form.Set("metadata[commercial_offer]", t.OfferKey)
	var created struct {
		ID string `json:"id"`
	}
	if err := c.doForm(ctx, http.MethodPost, "/v1/prices", form, &created, "plan-price-"+key); err != nil {
		return storagePrice{}, err
	}
	o.Price = created.ID
	return c.verifiedPlanPrice(ctx, o)
}
