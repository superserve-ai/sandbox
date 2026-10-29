package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func fundingOwnedDraftFixture(p billing.ExportPeriod, customer, subscription string) (StripeInvoiceAmounts, billing.InvoiceClosePlan) {
	plan := billing.InvoiceClosePlan{Customer: customer, Subscription: subscription, ExpectedCents: 360, AdjustmentTimestamp: p.Start.Unix(), Resources: []billing.InvoiceCloseResource{{Resource: "cpu", PriceID: "price_cpu", UnitUSD: "3.6", ProviderCents: 360, ExpectedCents: 360}, {Resource: "memory", PriceID: "price_memory", UnitUSD: "0"}}}
	raw := fmt.Sprintf(`{"id":"in_owned","customer":%q,"currency":"usd","status":"draft","billing_reason":"subscription_cycle","period_start":%d,"period_end":%d,"parent":{"subscription_details":{"subscription":%q}},"total_pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":360,"credit_balance_transaction":"cbtxn_owned"}],"lines":{"data":[
 {"id":"il_cpu","amount":360,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"360","price_details":{"price":"price_cpu"}},"parent":{"subscription_item_details":{"subscription":%q}},"pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":360,"credit_balance_transaction":"cbtxn_owned"}]},
 {"id":"il_memory","amount":0,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"0","price_details":{"price":"price_memory"}},"parent":{"subscription_item_details":{"subscription":%q}}},
 {"id":"il_rounding","amount":0,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"1","price_details":{"price":"price_rounding"}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, customer, p.Start.Unix(), p.End.Unix(), subscription, p.Start.Unix(), p.End.Unix(), subscription, p.Start.Unix(), p.End.Unix(), subscription, p.Start.Unix(), p.End.Unix(), subscription)
	var inv StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(raw), &inv); err != nil {
		panic(err)
	}
	return inv, plan
}

func TestFundingCreditOwnedDraftRequiresCompleteMeasuredCoverage(t *testing.T) {
	p := billing.ExportPeriod{TeamID: uuid.New(), Start: time.Unix(3600, 0), End: time.Unix(7200, 0)}
	a := invoiceAccount{Customer: "cus_example", Subscription: "sub_example", Price: "price_rounding"}
	for _, mode := range []string{"owned", "manual line", "missing coverage", "oversized reservation", "unattributed reservation"} {
		t.Run(mode, func(t *testing.T) {
			inv, plan := fundingOwnedDraftFixture(p, a.Customer, a.Subscription)
			coverage := []fundingPeriodReserve{{Start: p.Start, End: p.End, USD: "3.60"}}
			switch mode {
			case "manual line":
				inv.Lines.Data[0].Parent.SubscriptionItemDetails = nil
			case "missing coverage":
				coverage = nil
			case "oversized reservation":
				inv.Lines.Data[0].Amount = 1000
			case "unattributed reservation":
				inv.PretaxCredits[0].Amount = 1000
			}
			err := validateFundingDraftCoverage(inv, p, a, &plan, coverage)
			if (err == nil) != (mode == "owned") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
		})
	}
}

func TestFundingCreditProviderLedgerExpiryAndConcurrentDebit(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "changed", "pagination", "wrong customer", "external draft", "unattributed reservation", "reservation changed"} {
		t.Run(mode, func(t *testing.T) {
			at := time.Unix(200, 0)
			grant := entitlementGrant{ID: "credgr_example", Customer: "cus_example", Created: 100, EffectiveAt: 100, ExpiresAt: 230}
			grant.Amount.Type, grant.Amount.Monetary.Currency, grant.Amount.Monetary.Value = "monetary", "usd", 1000
			grant.Applicability.Scope.PriceType = "metered"
			if mode == "expired" {
				grant.ExpiresAt = 200
			}
			if mode == "wrong customer" {
				grant.Customer = "cus_other"
			}
			reads := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/billing/credit_grants":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []entitlementGrant{grant}, "has_more": mode == "pagination"})
				case "/v1/billing/credit_grants/credgr_example":
					_ = json.NewEncoder(w).Encode(grant)
				case "/v1/billing/credit_balance_summary":
					reads++
					value := 1000
					if mode == "changed" && reads > 1 {
						value = 900
					}
					available := value
					if mode == "external draft" || mode == "unattributed reservation" || mode == "reservation changed" && reads > 1 {
						available = 0
					}
					fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}},"available_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, value, available)
				case "/v1/invoices":
					if mode == "external draft" && r.URL.Query().Get("status") == "draft" {
						fmt.Fprint(w, `{"data":[{"id":"in_external","customer":"cus_example","status":"draft","total":1000,"created":50}],"has_more":false}`)
						return
					}
					fmt.Fprint(w, `{"data":[],"has_more":false}`)
				default:
					t.Errorf("unexpected provider request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			h := &Handlers{}
			balance, _, expiry, _, verify, err := h.observeProviderFundingGrants(t.Context(), client, uuid.New(), "cus_example", at)
			if mode == "pagination" || mode == "wrong customer" || mode == "external draft" {
				if err == nil {
					t.Fatal("ambiguous provider inventory accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				if balance != 0 || reads != 0 {
					t.Fatal("expired grant authorized usage")
				}
				return
			}
			if balance != 1000 || expiry.Time.Unix() != 230 {
				t.Fatalf("balance/expiry %d %v", balance, expiry)
			}
			err = verify(nil)
			if (err != nil) != (mode == "changed" || mode == "unattributed reservation" || mode == "reservation changed") {
				t.Fatalf("concurrent debit verification: %v", err)
			}
		})
	}
}

func TestFundingCreditSubtractsUnfinalizedUsageExactly(t *testing.T) {
	for _, tc := range []struct{ balance, usage, want string }{
		{"10", "9.9999991", "0.000000"},
		{"10", "3.0000001", "6.999999"},
		{"10", "11", "0.000000"},
		{"999999999999.999999", "999999999998.999999", "1.000000"},
		{"10", "0", "10.000000"},
	} {
		got, err := fundingNetSpendableUSD(tc.balance, tc.usage)
		if err != nil || got != tc.want {
			t.Errorf("balance=%s usage=%s: %s, %v; want %s", tc.balance, tc.usage, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"unknown", "-1", "NaN", "Infinity"} {
		if _, err := fundingNetSpendableUSD("10", invalid); err == nil {
			t.Errorf("accepted unavailable/invalid consumption %q", invalid)
		}
	}
}

func TestFundingCreditDoesNotTreatNarrowScopeAsGeneralFunds(t *testing.T) {
	g := entitlementGrant{}
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 1000
	g.Applicability.Scope.PriceType = "metered"
	if !fundingGrantCoversResources(g, nil) {
		t.Fatal("valid all-metered grant rejected")
	}
	g.Applicability.Scope.PriceType = ""
	g.Applicability.Scope.Prices = append(g.Applicability.Scope.Prices, struct {
		ID string `json:"id"`
	}{"price_cpu"})
	prices := []string{"price_cpu", "price_memory", "price_storage"}
	if fundingGrantCoversResources(g, prices) {
		t.Fatal("CPU-only credit funded memory/storage")
	}
	for _, id := range []string{"price_memory", "price_storage"} {
		g.Applicability.Scope.Prices = append(g.Applicability.Scope.Prices, struct {
			ID string `json:"id"`
		}{id})
	}
	if !fundingGrantCoversResources(g, prices) {
		t.Fatal("full resource scope rejected")
	}
	g.Amount.Monetary.Currency = "eur"
	if fundingGrantCoversResources(g, prices) {
		t.Fatal("wrong-currency credit authorized USD usage")
	}
}

func TestFundingCreditFrozenPricesAndStorageActivation(t *testing.T) {
	terms := []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "price_old_cpu"}, {ResourceKey: "memory_gib", PriceID: "price_old_memory"}, {ResourceKey: "storage_gib", PriceID: "price_old_storage"}}
	prices, err := fundingRequiredCreditPrices(terms, false, "price_rounding")
	if err != nil {
		t.Fatal(err)
	}
	g := entitlementGrant{}
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 1000
	for _, id := range []string{"price_old_cpu", "price_old_memory", "price_rounding"} {
		g.Applicability.Scope.Prices = append(g.Applicability.Scope.Prices, struct {
			ID string `json:"id"`
		}{id})
	}
	if !fundingGrantCoversResources(g, prices) {
		t.Fatal("purchased compute scope rejected before storage activation")
	}
	prices, err = fundingRequiredCreditPrices(terms, true, "price_rounding")
	if err != nil {
		t.Fatal(err)
	}
	if fundingGrantCoversResources(g, prices) {
		t.Fatal("storage activated without scoped storage credit")
	}
	prices, err = fundingRequiredCreditPrices(terms[:2], false, "price_new_rounding")
	if err != nil {
		t.Fatal(err)
	}
	if fundingGrantCoversResources(g, prices) {
		t.Fatal("credit omitted enrolled rounding price")
	}
}
