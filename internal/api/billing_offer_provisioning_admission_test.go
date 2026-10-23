package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/config"
)

func TestOfferProviderFreezeAcceptedHistoricalRates(t *testing.T) {
	for _, fault := range []string{"", "changed_rate", "missing_mode", "missing_rounding", "duplicate_resource"} {
		t.Run(fault, func(t *testing.T) {
			terms := YCAcceptanceTerms{ChargeAmountCents: 1200000, ChargeIntervalMonths: 12, InitialFeeWaived: true}
			cfg := &config.Config{StripeProAnnualPriceID: "price_fee"}
			for _, resource := range []string{"vcpu", "memory_gib", "storage_gib"} {
				terms.ResourceRates = append(terms.ResourceRates, YCAcceptanceRate{Resource: resource, Unit: "second", Currency: "USD", PriceUSD: "0.00001"})
				cfg.BillingResources = append(cfg.BillingResources, config.BillingResourceConfig{ResourceKey: resource, UsageUnit: "second", StripePriceID: "price_" + resource, StripeEventName: resource})
			}
			if fault == "duplicate_resource" {
				cfg.BillingResources = append(cfg.BillingResources, cfg.BillingResources[0])
			}
			posts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					posts++
					http.Error(w, "unexpected mutation", 405)
					return
				}
				var result any
				switch r.URL.Path {
				case "/v1/account":
					result = map[string]any{"id": "acct_example"}
				case "/v1/balance":
					result = map[string]any{"livemode": false}
				case "/v1/prices":
					ids := []any{map[string]any{"id": "price_rounding"}}
					if fault == "missing_rounding" {
						ids = nil
					}
					result = map[string]any{"data": ids, "has_more": false}
				case "/v1/billing/meters":
					var meters []any
					for _, event := range []string{"vcpu", "memory_gib", "storage_gib", invoiceRoundingEvent} {
						meters = append(meters, map[string]any{"id": "mtr_" + event, "event_name": event, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
					}
					result = map[string]any{"data": meters, "has_more": false}
				default:
					id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
					recurring := map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": "mtr_" + strings.TrimPrefix(id, "price_")}
					amount := "3.6"
					if fault == "changed_rate" {
						amount = "7.2"
					}
					if id == "price_rounding" {
						amount = "1"
						recurring["meter"] = "mtr_" + invoiceRoundingEvent
					}
					if id == "price_fee" {
						amount = "1200000"
						recurring = map[string]any{"usage_type": "licensed", "interval": "year", "interval_count": 1}
					}
					price := map[string]any{"id": id, "product": "prod_example", "active": true, "livemode": false, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": amount, "recurring": recurring}
					if fault == "missing_mode" {
						delete(price, "livemode")
					}
					result = price
				}
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer srv.Close()
			client := &stripeHTTPClient{secretKey: "synthetic-key", baseURL: srv.URL, apiVersion: "synthetic-version", httpClient: srv.Client()}
			a := &offerProvisioningAuthority{h: &Handlers{Config: cfg}, client: client}
			offer, err := a.freezeProviderTerms(t.Context(), YCAcceptanceRecord{Terms: terms})
			if (err != nil) != (fault != "") {
				t.Fatalf("fault %q: %v", fault, err)
			}
			if posts != 0 {
				t.Fatal("catalog admission mutated provider")
			}
			if fault == "" {
				var frozen ProviderPairTerms
				if json.Unmarshal(offer.ProviderTerms, &frozen) != nil || len(frozen.Resources) != 3 || frozen.Resources[0].UnitAmountDecimal != "3.6" || frozen.Rounding.MeterID != "mtr_"+invoiceRoundingEvent || offer.Merchant != "acct_example" {
					t.Fatal("historical accepted terms not frozen", string(offer.ProviderTerms))
				}
			}
		})
	}
}
