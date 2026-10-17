package api

import (
	"encoding/json"
	"testing"
)

func TestYCCreditScopeRejectsInvalidIdentities(t *testing.T) {
	valid := []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "cpu", EventName: "cpu", MeterID: "m_cpu", UnitAmountDecimal: "1"}, {ResourceKey: "memory_gib", PriceID: "memory", EventName: "memory", MeterID: "m_memory", UnitAmountDecimal: "1"}}
	for _, bad := range []string{"", "missing", "duplicate resource", "duplicate price", "empty price", "duplicate meter", "rounding overlap", "unknown resource", "storage required"} {
		t.Run(bad, func(t *testing.T) {
			terms := append([]StripeCheckoutResourceTerms{}, valid...)
			switch bad {
			case "missing":
				terms = terms[:1]
			case "duplicate resource":
				terms[1].ResourceKey = "vcpu"
			case "duplicate price":
				terms[1].PriceID = "cpu"
			case "empty price":
				terms[1].PriceID = ""
			case "duplicate meter":
				terms[1].MeterID = "m_cpu"
			case "rounding overlap":
				terms[1].PriceID = "round"
			case "unknown resource":
				terms[1].ResourceKey = "base"
			}
			err := validateEntitlementResourceTerms(terms, "round", "round", "m_round", bad == "storage required")
			if (err != nil) != (bad != "") {
				t.Fatal(err)
			}
		})
	}
	storage := append(valid, StripeCheckoutResourceTerms{ResourceKey: "storage_gib", PriceID: "storage", EventName: "storage", MeterID: "m_storage", UnitAmountDecimal: "1"})
	if err := validateEntitlementResourceTerms(storage, "round", "round", "m_round", true); err != nil {
		t.Fatal(err)
	}
}

func TestYCThreePriceSavedRequestScope(t *testing.T) {
	expected := []map[string]string{{"id": "cpu"}, {"id": "memory"}, {"id": "round"}}
	for _, bad := range []string{"", "duplicate", "missing", "extra", "empty", "base", "blanket"} {
		t.Run(bad, func(t *testing.T) {
			g := testEntitlementGrant()
			g.Applicability.Scope.Prices = g.Applicability.Scope.Prices[:3]
			switch bad {
			case "duplicate":
				g.Applicability.Scope.Prices[1].ID = "cpu"
			case "missing":
				g.Applicability.Scope.Prices = g.Applicability.Scope.Prices[:2]
			case "extra":
				g.Applicability.Scope.Prices = append(g.Applicability.Scope.Prices, testEntitlementGrant().Applicability.Scope.Prices[3])
			case "empty":
				g.Applicability.Scope.Prices[1].ID = ""
			case "base":
				g.Applicability.Scope.Prices[1].ID = "price_base"
			case "blanket":
				g.Applicability.Scope.PriceType = "metered"
			}
			raw, _ := json.Marshal(g)
			form, err := entitlementGrantForm(raw, expected)
			if (err != nil) != (bad != "") {
				t.Fatal(err)
			}
			if bad == "" && (form.Get("applicability_config[scope][prices][2][id]") != "round" || form.Get("amount[monetary][value]") != "100000") {
				t.Fatal(form)
			}
		})
	}
}
