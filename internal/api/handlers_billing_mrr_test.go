package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

var testProAnnual = planTerms{OfferKey: "pro_annual", FeeCents: 1200000, IntervalMonths: 12}

func TestMRRPerTeamCents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group mrrContractGroup
		want  int64
	}{
		{"pro monthly", mrrContractGroup{OfferKey: "pro_monthly", ChargeKind: "subscription", FeeCents: 120000, IntervalMonths: 1}, 120000},
		{"pro annual", mrrContractGroup{OfferKey: "pro_annual", ChargeKind: "subscription", FeeCents: 1200000, IntervalMonths: 12}, 100000},
		{"starter monthly uses its frozen fee", mrrContractGroup{OfferKey: "starter_monthly", ChargeKind: "subscription", FeeCents: 10000, IntervalMonths: 1}, 10000},
		{"starter annual rounds to the nearest cent", mrrContractGroup{OfferKey: "starter_annual", ChargeKind: "subscription", FeeCents: 100000, IntervalMonths: 12}, 8333},
		{"yc counts at the pro annual list price, not its upfront charge", mrrContractGroup{OfferKey: "yc_2026", ChargeKind: "upfront", FeeCents: 10000000, IntervalMonths: 3}, 100000},
		{"sponsored annual pro counts at the pro annual list price", mrrContractGroup{OfferKey: "sponsored_usage", ChargeKind: "sponsored_entitlement", SponsoredAnnual: true}, 100000},
		{"credit-only sponsorship is not recurring", mrrContractGroup{OfferKey: "sponsored_usage", ChargeKind: "sponsored_entitlement"}, 0},
		{"unknown upfront deal is spread over its term", mrrContractGroup{OfferKey: "enterprise_2027", ChargeKind: "upfront", FeeCents: 600000, IntervalMonths: 6}, 100000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mrrPerTeamCents(tc.group, testProAnnual); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMRRWaivedDealsFollowProAnnualListPrice(t *testing.T) {
	list := planTerms{OfferKey: "pro_annual", FeeCents: 1440000, IntervalMonths: 12}
	if got := mrrPerTeamCents(mrrContractGroup{OfferKey: "yc_2026", ChargeKind: "upfront", FeeCents: 1, IntervalMonths: 1}, list); got != 120000 {
		t.Fatalf("yc = %d", got)
	}
	// A paid contract keeps the fee it was sold at after a catalog edit.
	if got := mrrPerTeamCents(mrrContractGroup{OfferKey: "pro_annual", ChargeKind: "subscription", FeeCents: 1200000, IntervalMonths: 12}, list); got != 100000 {
		t.Fatalf("frozen pro annual = %d", got)
	}
}

func TestBuildMRROverview(t *testing.T) {
	groups := []mrrContractGroup{
		{OfferKey: "pro_monthly", ChargeKind: "subscription", FeeCents: 120000, IntervalMonths: 1, Teams: 2},
		{OfferKey: "pro_annual", ChargeKind: "subscription", FeeCents: 1200000, IntervalMonths: 12, Teams: 1},
		{OfferKey: "yc_2026", ChargeKind: "upfront", FeeCents: 10000000, IntervalMonths: 3, Teams: 3},
		{OfferKey: "sponsored_usage", ChargeKind: "sponsored_entitlement", SponsoredAnnual: true, Teams: 1},
		{OfferKey: "sponsored_usage", ChargeKind: "sponsored_entitlement", Teams: 4},
	}
	out := buildMRROverview(groups, 20, testProAnnual, map[string]string{"pro_monthly": "Pro monthly"})
	if out.MRRCents != 2*120000+100000+3*100000+100000 {
		t.Fatalf("mrr = %d", out.MRRCents)
	}
	if out.Teams != 20 || out.RevenueTeams != 7 {
		t.Fatalf("teams = %d revenue = %d", out.Teams, out.RevenueTeams)
	}
	want := []mrrPlan{
		{Key: "yc_2026", Name: "yc_2026", Teams: 3, MRRCents: 300000},
		{Key: "pro_monthly", Name: "Pro monthly", Teams: 2, MRRCents: 240000},
		{Key: "pro_annual", Name: "pro_annual", Teams: 1, MRRCents: 100000},
		{Key: "sponsored_annual_pro", Name: "sponsored_annual_pro", Teams: 1, MRRCents: 100000},
		{Key: "sponsored_usage", Name: "sponsored_usage", Teams: 4, MRRCents: 0},
		{Key: "payg", Name: "Pay as you go", Teams: 9, MRRCents: 0},
	}
	if len(out.Plans) != len(want) {
		t.Fatalf("plans = %+v", out.Plans)
	}
	for i := range want {
		if out.Plans[i] != want[i] {
			t.Fatalf("plan %d = %+v, want %+v", i, out.Plans[i], want[i])
		}
	}
}

func TestBuildMRROverviewMergesFrozenTermVariants(t *testing.T) {
	out := buildMRROverview([]mrrContractGroup{
		{OfferKey: "starter_monthly", ChargeKind: "subscription", FeeCents: 10000, IntervalMonths: 1, Teams: 2},
		{OfferKey: "starter_monthly", ChargeKind: "subscription", FeeCents: 9000, IntervalMonths: 1, Teams: 1},
	}, 3, testProAnnual, nil)
	if len(out.Plans) != 2 || out.Plans[0] != (mrrPlan{Key: "starter_monthly", Name: "starter_monthly", Teams: 3, MRRCents: 29000}) || out.Plans[1].Teams != 0 {
		t.Fatalf("plans = %+v", out.Plans)
	}
}

func TestGetPlatformBillingMRRRequiresActor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handlers{}
	r.GET("/internal/billing/mrr", h.GetPlatformBillingMRR)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/internal/billing/mrr", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
}
