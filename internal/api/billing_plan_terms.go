package api

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

// planTerms are a catalog plan's current terms. Contracts and plan
// assignments freeze their own copy, so these only apply to new purchases,
// assignments and reporting. MonthlyCreditCents is set only when the schedule
// is one ongoing monthly grant, the shape subscription contracts represent.
// Available reports whether checkout may sell the plan. Retired families keep
// returning their last published terms with Retired set, so reporting can
// still value contracts against them; checkout and assignment refuse them.
type planTerms struct {
	OfferKey           string
	DisplayName        string
	FeeCents           int64
	IntervalMonths     int32
	MonthlyCreditCents int64
	VersionID          uuid.UUID
	Version            int32
	PricingVersion     string
	Family             string
	Kind               string
	Grants             []planGrant
	Matching           *planMatching
	Allowance          *planAllowance
	Limits             planLimits
	Available          bool
	Retired            bool
}

var errUnknownPlan = errors.New("unsupported offer")

func planOfferInterval(offerKey string) (string, int32, bool) {
	for suffix, months := range map[string]int32{"_monthly": 1, "_annual": 12} {
		if family, ok := strings.CutSuffix(offerKey, suffix); ok && planFamilyPattern(family) {
			return family, months, true
		}
	}
	return "", 0, false
}

const pricingSwitchCacheTTL = 5 * time.Second

type pricingSwitchCache struct {
	mu      sync.Mutex
	version string
	readAt  time.Time
}

var pricingSwitch pricingSwitchCache

// pricingVersion is the one reader of the pricing switch: "legacy" or "v2".
// The database row is authoritative; this process caches it for a few
// seconds so hot paths do not query it on every call.
func (h *Handlers) pricingVersion(ctx context.Context) (string, error) {
	if h.Pool == nil {
		return "legacy", nil
	}
	pricingSwitch.mu.Lock()
	cached, fresh := pricingSwitch.version, time.Since(pricingSwitch.readAt) < pricingSwitchCacheTTL
	pricingSwitch.mu.Unlock()
	if cached != "" && fresh {
		return cached, nil
	}
	readAt := time.Now()
	var version string
	if err := h.Pool.QueryRow(ctx, `SELECT billing_pricing_version()`).Scan(&version); err != nil {
		return "", err
	}
	pricingSwitch.mu.Lock()
	if readAt.After(pricingSwitch.readAt) {
		pricingSwitch.version, pricingSwitch.readAt = version, readAt
	}
	pricingSwitch.mu.Unlock()
	return version, nil
}

// pricingV2Enabled reports whether the v2 pricing model is live in this region.
func (h *Handlers) pricingV2Enabled(ctx context.Context) (bool, error) {
	version, err := h.pricingVersion(ctx)
	return version == "v2", err
}

func forgetPricingVersion() {
	pricingSwitch.mu.Lock()
	pricingSwitch.version, pricingSwitch.readAt = "", time.Now()
	pricingSwitch.mu.Unlock()
}

// planTerms is the one lookup for a plan's current terms. It reads the
// family's published version in the live pricing model; a family the live
// model does not offer answers with its most recently retired or other-model
// version, flagged Retired, except legacy pay as you go, which v2 keeps for
// the teams on it. Subscriptions are keyed "<family>_monthly" or
// "<family>_annual"; every other kind is keyed by its bare family and has
// FeeCents and IntervalMonths of zero.
//
// Keys are catalog families, not billing_signup_choice.offer_key values: the
// signup choice "free" means legacy pay as you go, while the v2 "free" family
// is the Free plan. v2 code reads a team's plan from its plan assignment only.
func (h *Handlers) planTerms(ctx context.Context, offerKey string) (planTerms, error) {
	model, err := h.pricingVersion(ctx)
	if err != nil {
		return planTerms{}, err
	}
	return h.planTermsForPricingVersion(ctx, offerKey, model)
}

func (h *Handlers) planTermsForPricingVersion(ctx context.Context, offerKey, model string, readers ...db.DBTX) (planTerms, error) {
	family, months, ok := planOfferInterval(offerKey)
	if !ok && planFamilyPattern(offerKey) {
		family, ok = offerKey, true
	}
	if !ok || h.Pool == nil {
		return planTerms{}, errUnknownPlan
	}
	var reader db.DBTX = h.Pool
	if len(readers) > 0 {
		reader = readers[0]
	}
	v, err := scanPlanVersion(reader.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version
 WHERE family=$1 AND state<>'draft' ORDER BY (pricing_version=$2 AND state='published') DESC, pricing_version=$2 DESC, state='published' DESC, retired_at DESC NULLS LAST, version DESC LIMIT 1`, family, model))
	if errors.Is(err, pgx.ErrNoRows) {
		return planTerms{}, errUnknownPlan
	}
	if err != nil {
		return planTerms{}, err
	}
	t, err := h.termsOfVersion(ctx, v, months, readers...)
	if v.PricingVersion != model {
		// Legacy pay as you go stays in force for the teams on it under v2:
		// not sold, but still assignable.
		t.Available, t.Retired = false, t.Retired || v.Kind != "legacy_payg"
	}
	return t, err
}

// planTermsVersion returns the terms of one exact version, for staff who
// assign a specific version. months is 1 or 12 for a subscription and 0 for
// every other kind.
func (h *Handlers) planTermsVersion(ctx context.Context, versionID uuid.UUID, months int32) (planTerms, error) {
	if h.Pool == nil {
		return planTerms{}, errUnknownPlan
	}
	v, err := scanPlanVersion(h.Pool.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1 AND state<>'draft'`, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return planTerms{}, errUnknownPlan
	}
	if err != nil {
		return planTerms{}, err
	}
	return h.termsOfVersion(ctx, v, months)
}

// listAssignableVersions lists the published versions of the live pricing
// model that staff can assign, including ones checkout does not sell.
func (h *Handlers) listAssignableVersions(ctx context.Context) ([]planVersion, error) {
	model, err := h.pricingVersion(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := h.Pool.Query(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE state='published' AND (pricing_version=$1 OR (family='payg' AND pricing_version='legacy' AND kind='legacy_payg')) AND NOT display_only ORDER BY sort_order,family`, model)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (planVersion, error) { return scanPlanVersion(row) })
}

func (h *Handlers) termsOfVersion(ctx context.Context, v planVersion, months int32, readers ...db.DBTX) (planTerms, error) {
	if v.DisplayOnly {
		return planTerms{}, errUnknownPlan
	}
	offerKey := v.Family
	var feeCents int64
	switch months {
	case 0:
		if v.hasFee() {
			return planTerms{}, errUnknownPlan
		}
	case 1, 12:
		fee := v.feeCents(months)
		if fee == nil {
			return planTerms{}, errUnknownPlan
		}
		feeCents = *fee
		offerKey += map[int32]string{1: "_monthly", 12: "_annual"}[months]
	default:
		return planTerms{}, errUnknownPlan
	}
	allowance, err := h.resolveAllowance(ctx, v.Allowance, readers...)
	if err != nil {
		return planTerms{}, err
	}
	retired := v.State == "retired"
	credit, _ := uniformMonthlyCredit(v.CreditSchedule)
	return planTerms{OfferKey: offerKey, DisplayName: v.DisplayName, FeeCents: feeCents, IntervalMonths: months, MonthlyCreditCents: credit,
		VersionID: v.ID, Version: v.Version, PricingVersion: v.PricingVersion, Family: v.Family, Kind: v.Kind, Grants: v.CreditSchedule,
		Matching: v.Matching, Allowance: allowance, Limits: v.Limits, Available: v.sellable() && !retired, Retired: retired}, nil
}

// resolveAllowance prices a compute allowance at the public rate card, the
// same rates public pricing shows, rounded half up to the cent.
func (h *Handlers) resolveAllowance(ctx context.Context, a *planAllowance, readers ...db.DBTX) (*planAllowance, error) {
	if a == nil {
		return nil, nil
	}
	if a.Compute == nil {
		resolved := *a
		resolved.AmountUSD = decimalString(big.NewRat(a.AmountCents, 100))
		return &resolved, nil
	}
	queries := h.DB
	if len(readers) > 0 {
		queries = db.New(readers[0])
	}
	rows, err := queries.ListActivePricingRates(ctx, publicPricingPlanKey)
	if err != nil {
		return nil, err
	}
	rates := map[string]*big.Rat{}
	for _, r := range rows {
		if r.Unit == "second" {
			rates[r.Resource] = numericRat(r.PriceUsd)
		}
	}
	vcpu, memory := rates["vcpu"], rates["memory_gib"]
	if vcpu == nil || memory == nil {
		return nil, errors.New("rate card has no per-second vcpu and memory rates")
	}
	perSecond := new(big.Rat).Add(new(big.Rat).Mul(big.NewRat(int64(a.Compute.VCPU), 1), vcpu), new(big.Rat).Mul(big.NewRat(int64(a.Compute.MemoryGiB), 1), memory))
	usd := new(big.Rat).Mul(perSecond, big.NewRat(int64(a.Compute.Seconds), 1))
	cents := new(big.Rat).Mul(usd, big.NewRat(100, 1))
	cents.Add(cents, big.NewRat(1, 2))
	resolved := *a
	resolved.AmountCents = new(big.Int).Quo(cents.Num(), cents.Denom()).Int64()
	resolved.AmountUSD = decimalString(usd)
	return &resolved, nil
}

// decimalString writes r, a USD amount from numeric rates, as a plain
// decimal without trailing zeros.
func decimalString(r *big.Rat) string {
	s := strings.TrimRight(r.FloatString(12), "0")
	return strings.TrimSuffix(s, ".")
}

func numericRat(n pgtype.Numeric) *big.Rat {
	if !n.Valid || n.Int == nil || n.NaN {
		return nil
	}
	r := new(big.Rat).SetInt(n.Int)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs32(n.Exp))), nil)
	if n.Exp >= 0 {
		return r.Mul(r, new(big.Rat).SetInt(scale))
	}
	return r.Quo(r, new(big.Rat).SetInt(scale))
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// ownsPrice reports whether t gets its own Stripe price. The seeded legacy
// versions reproduce what the configured Stripe prices charge, so they are
// sold only on those prices; later versions get their own prices on demand.
func (t planTerms) ownsPrice() bool {
	return t.PricingVersion == "v2" || t.Version > 1
}

// planPriced reports whether checkout may sell t in this environment.
func (h *Handlers) planPriced(t planTerms) bool {
	stripe, ok := h.Stripe.(*stripeHTTPClient)
	return ok && stripe != nil && (t.ownsPrice() || (h.Config != nil && h.Config.PlanPriceID(t.OfferKey) != ""))
}

// freezeContractLimits records the limits a contract was sold or assigned
// with, so later catalog versions do not change them.
func freezeContractLimits(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, contractID uuid.UUID, l planLimits) error {
	if l.MaxConcurrent == nil {
		return errors.New("frozen limits need max running sandboxes")
	}
	_, err := q.Exec(ctx, `INSERT INTO billing_contract_limits(contract_id,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (contract_id) DO NOTHING`, contractID, *l.MaxConcurrent, l.MaxVCPU, l.MaxMemoryMiB, l.MaxDiskMiB, l.MaxTemplates)
	return err
}

// teamLimits are the limits a team works within, with manual overrides and
// plan limits already resolved.
type teamLimits struct {
	MaxConcurrent int32
	MaxVCPU       int32
	MaxMemoryMiB  int32
	MaxDiskMiB    int32
	MaxTemplates  int32
}

// teamEffectiveLimits is the one reader of a team's limits.
func (h *Handlers) teamEffectiveLimits(ctx context.Context, team uuid.UUID) (teamLimits, error) {
	l, err := h.DB.GetTeamEffectiveLimits(ctx, team)
	return teamLimits{MaxConcurrent: l.MaxConcurrent, MaxVCPU: l.MaxVcpu, MaxMemoryMiB: l.MaxMemoryMib, MaxDiskMiB: l.MaxDiskMib, MaxTemplates: l.MaxTemplates}, err
}
