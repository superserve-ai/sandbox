package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	mrrPAYGKey            = "payg"
	mrrSponsoredAnnualKey = "sponsored_annual_pro"
	// Fee-waived deals are valued at what the same team would pay for Pro.
	mrrWaivedReferenceOffer = "pro_annual"
)

// mrrContractGroup counts active contracts sharing the same frozen fee terms.
type mrrContractGroup struct {
	OfferKey        string
	ChargeKind      string
	FeeCents        int64
	IntervalMonths  int32
	SponsoredAnnual bool
	Teams           int64
}

type mrrPlan struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Teams    int64  `json:"teams"`
	MRRCents int64  `json:"mrr_cents"`
}

type mrrOverview struct {
	AsOf     time.Time `json:"as_of"`
	Region   string    `json:"region"`
	Currency string    `json:"currency"`
	MRRCents int64     `json:"mrr_cents"`
	Teams    int64     `json:"teams"`
	// RevenueTeams counts teams contributing to MRR, including fee-waived
	// deals valued at list price.
	RevenueTeams int64     `json:"revenue_teams"`
	Plans        []mrrPlan `json:"plans"`
}

func monthlyCents(feeCents int64, intervalMonths int32) int64 {
	if feeCents <= 0 || intervalMonths <= 0 {
		return 0
	}
	months := int64(intervalMonths)
	return (feeCents + months/2) / months
}

func mrrPlanKey(g mrrContractGroup) string {
	if g.OfferKey == "sponsored_usage" && g.SponsoredAnnual {
		return mrrSponsoredAnnualKey
	}
	return g.OfferKey
}

func mrrValuesAtProList(g mrrContractGroup) bool {
	return g.OfferKey == "yc_2026" || mrrPlanKey(g) == mrrSponsoredAnnualKey
}

// mrrPerTeamCents normalises one contract's recurring fee to a month. Paid
// contracts use their frozen fee; YC and sponsored annual Pro use the Pro
// annual list price; credit-only sponsorship has no recurring fee. Usage is
// never recurring revenue.
func mrrPerTeamCents(g mrrContractGroup, proAnnual planTerms) int64 {
	switch {
	case mrrValuesAtProList(g):
		return monthlyCents(proAnnual.FeeCents, proAnnual.IntervalMonths)
	case g.ChargeKind == "sponsored_entitlement":
		return 0
	default:
		return monthlyCents(g.FeeCents, g.IntervalMonths)
	}
}

func buildMRROverview(groups []mrrContractGroup, totalTeams int64, proAnnual planTerms, names map[string]string) mrrOverview {
	plans := map[string]*mrrPlan{}
	var contracted int64
	out := mrrOverview{Currency: "usd", Teams: totalTeams}
	for _, g := range groups {
		key := mrrPlanKey(g)
		p := plans[key]
		if p == nil {
			p = &mrrPlan{Key: key, Name: names[key]}
			if p.Name == "" {
				p.Name = key
			}
			plans[key] = p
		}
		cents := mrrPerTeamCents(g, proAnnual) * g.Teams
		p.Teams += g.Teams
		p.MRRCents += cents
		out.MRRCents += cents
		contracted += g.Teams
		if cents > 0 {
			out.RevenueTeams += g.Teams
		}
	}
	for _, p := range plans {
		out.Plans = append(out.Plans, *p)
	}
	sort.Slice(out.Plans, func(i, j int) bool {
		if out.Plans[i].MRRCents != out.Plans[j].MRRCents {
			return out.Plans[i].MRRCents > out.Plans[j].MRRCents
		}
		return out.Plans[i].Key < out.Plans[j].Key
	})
	out.Plans = append(out.Plans, mrrPlan{Key: mrrPAYGKey, Name: "Pay as you go", Teams: max(totalTeams-contracted, 0)})
	return out
}

// Contracts are current when active and inside their term; pending and ended
// contracts, and active ones whose term has lapsed, are excluded. A team has
// at most one non-ended contract, so contract counts are team counts.
const mrrContractGroupsQuery = `SELECT c.offer_key,c.charge_kind,c.charge_amount_cents,c.charge_interval_months,
 c.charge_kind='sponsored_entitlement' AND EXISTS(SELECT 1 FROM billing_sponsored_annual_authority a
  WHERE a.contract_id=c.id AND a.team_id=c.team_id AND a.state<>'ended') AS sponsored_annual,
 count(*)
FROM billing_commercial_contract c JOIN team t ON t.id=c.team_id
WHERE c.status='active' AND c.starts_at<=$1 AND (c.ends_at IS NULL OR c.ends_at>$1) AND t.home_region=$2
 AND t.id IS DISTINCT FROM NULLIF($3,'')::uuid
GROUP BY 1,2,3,4,5`

func (h *Handlers) loadMRROverview(ctx context.Context, q db.DBTX, now time.Time, region, systemTeam string) (mrrOverview, error) {
	rows, err := q.Query(ctx, mrrContractGroupsQuery, now, region, systemTeam)
	if err != nil {
		return mrrOverview{}, err
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (mrrContractGroup, error) {
		var g mrrContractGroup
		err := row.Scan(&g.OfferKey, &g.ChargeKind, &g.FeeCents, &g.IntervalMonths, &g.SponsoredAnnual, &g.Teams)
		return g, err
	})
	if err != nil {
		return mrrOverview{}, err
	}
	var totalTeams int64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM team WHERE home_region=$1 AND id IS DISTINCT FROM NULLIF($2,'')::uuid`, region, systemTeam).Scan(&totalTeams); err != nil {
		return mrrOverview{}, err
	}
	names := map[string]string{
		"yc_2026":             "YC 2026",
		mrrSponsoredAnnualKey: "Sponsored annual Pro",
		"sponsored_usage":     "Sponsored credits",
	}
	var proAnnual planTerms
	for _, g := range groups {
		key := mrrPlanKey(g)
		if _, ok := names[key]; ok {
			if mrrValuesAtProList(g) && proAnnual.OfferKey == "" {
				if proAnnual, err = h.planTerms(ctx, mrrWaivedReferenceOffer); err != nil {
					return mrrOverview{}, err
				}
			}
			continue
		}
		terms, err := h.planTerms(ctx, key)
		if errors.Is(err, errUnknownPlan) {
			continue
		}
		if err != nil {
			return mrrOverview{}, err
		}
		names[key] = terms.DisplayName + map[int32]string{1: " monthly", 12: " annual"}[terms.IntervalMonths]
	}
	out := buildMRROverview(groups, totalTeams, proAnnual, names)
	out.AsOf, out.Region = now, region
	return out, nil
}

// GetPlatformBillingMRR reports this cell's monthly recurring revenue from
// contract terms. It never consults Stripe, whose dashboard omits upfront and
// fee-waived deals.
func (h *Handlers) GetPlatformBillingMRR(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	if h.Pool == nil || h.Config == nil || h.Config.TeamCreationRegion == "" {
		respondErrorMsg(c, "service_unavailable", "billing is not configured", http.StatusServiceUnavailable)
		return
	}
	out, err := h.loadMRROverview(c.Request.Context(), h.Pool, h.nowUTC(), h.Config.TeamCreationRegion, h.Config.SystemTeamID)
	if err != nil {
		log.Error().Err(err).Msg("platform billing MRR query failed")
		respondError(c, ErrInternal)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.JSON(http.StatusOK, out)
}
