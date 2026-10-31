package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestExistingEventGrantSettlesOnMatchingTermsOnly(t *testing.T) {
	team := uuid.New()
	grant := func(id string, cents int64, mutate func(*entitlementGrant)) entitlementGrant {
		g := entitlementGrant{ID: id, Customer: "cus_current", Category: "promotional", Priority: 50, Metadata: map[string]string{"event_label": "event-label", "team_id": team.String()}}
		g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", cents
		g.Applicability.Scope.PriceType = "metered"
		if mutate != nil {
			mutate(&g)
		}
		return g
	}
	other := grant("credgr_other", 8000, func(g *entitlementGrant) { g.Metadata["team_id"] = uuid.NewString() })
	if id, err := existingEventGrant([]entitlementGrant{other}, team, "cus_current", "event-label", 8000); id != "" || err != nil {
		t.Fatalf("another team's grant settled: %q %v", id, err)
	}
	if id, err := existingEventGrant([]entitlementGrant{other, grant("credgr_manual", 8000, nil)}, team, "cus_current", "event-label", 8000); id != "credgr_manual" || err != nil {
		t.Fatalf("manual grant not reused: %q %v", id, err)
	}
	for name, g := range map[string][]entitlementGrant{
		"voided":         {grant("a", 8000, func(g *entitlementGrant) { g.VoidedAt = 1 })},
		"amount":         {grant("a", 10000, nil)},
		"expiring":       {grant("a", 8000, func(g *entitlementGrant) { g.ExpiresAt = 1 })},
		"duplicate":      {grant("a", 8000, nil), grant("b", 8000, nil)},
		"other customer": {grant("a", 8000, func(g *entitlementGrant) { g.Customer = "cus_prior" })},
	} {
		if id, err := existingEventGrant(g, team, "cus_current", "event-label", 8000); id != "" || err == nil || !strings.Contains(err.Error(), "operator review") {
			t.Fatalf("%s grant settled: %q %v", name, id, err)
		}
	}
}
