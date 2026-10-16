package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func testEntitlementGrant() entitlementGrant {
	var g entitlementGrant
	_ = json.Unmarshal([]byte(`{"id":"credgr_period","customer":"cus_example","category":"promotional","priority":50,"created":110,"effective_at":110,"expires_at":201,"amount":{"type":"monetary","monetary":{"currency":"usd","value":100000}},"applicability_config":{"scope":{"prices":[{"id":"cpu"},{"id":"memory"},{"id":"round"},{"id":"storage"}]}},"metadata":{"entitlement_id":"entitlement_example"}}`), &g)
	return g
}
func TestEntitlementRequestRetainsImmediateActivation(t *testing.T) {
	g := testEntitlementGrant()
	raw, _ := json.Marshal(g)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "effective_at")
	raw, _ = json.Marshal(fields)
	first, err := entitlementGrantForm(raw)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	replay, err := entitlementGrantForm(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, replay) || first.Has("effective_at") || first.Get("priority") != "50" || first.Get("expires_at") != "201" {
		t.Fatalf("replay changed saved semantics: %v / %v", first, replay)
	}
}
func TestEntitlementDebtChecksEveryFinalizedUnpaidStatus(t *testing.T) {
	for _, tc := range []struct {
		name, status, body string
		want               string
		fail               bool
	}{
		{"clean", "", `{"data":[]}`, "", false},
		{"partial old invoice", "open", `{"data":[{"id":"in_old","customer":"cus_example","status":"open","amount_remaining":100}],"has_more":true}`, "in_old", false},
		{"uncollectible", "uncollectible", `{"data":[{"id":"in_old","customer":"cus_example","status":"uncollectible"}]}`, "in_old", false},
		{"foreign customer", "open", `{"data":[{"id":"in_other","customer":"cus_other","status":"open"}]}`, "", true},
		{"incomplete empty", "open", `{"data":[],"has_more":true}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Query().Get("customer") != "cus_example" || r.URL.Query().Get("limit") != "1" {
					t.Error("unbounded debt query")
				}
				if r.URL.Query().Get("status") == tc.status {
					fmt.Fprint(w, tc.body)
				} else {
					fmt.Fprint(w, `{"data":[]}`)
				}
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			got, err := client.entitlementDebt(t.Context(), "cus_example")
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatalf("got %q %v", got, err)
			}
			if tc.status == "" && calls != 2 {
				t.Fatal("skipped debt status")
			}
		})
	}
}
func TestInvoiceCreditTransactionsRejectFalseAttribution(t *testing.T) {
	for _, bad := range []string{"", "wrong invoice", "wrong grant", "wrong line", "wrong scope", "changed ledger", "earlier credit skipped"} {
		t.Run(bad, func(t *testing.T) {
			g := testEntitlementGrant()
			raw, _ := json.Marshal(g)
			plan := billing.InvoiceClosePlan{CreditVersion: 1, Customer: g.Customer, ExpectedCents: 135000, InvoiceEnd: 200, CreditBeforeCents: 100000, CreditPrices: []string{"cpu", "memory", "round", "storage"}, CreditGrants: []billing.InvoiceCreditGrant{{ID: g.ID, Before: 100000, ExpiresAt: 201, Evidence: raw}}}
			var inv StripeInvoiceAmounts
			_ = json.Unmarshal([]byte(`{"id":"in_example","customer":"cus_example","status":"open","total_pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":100000,"credit_balance_transaction":"cbtxn_one"}],"lines":{"data":[{"id":"il_cpu","pricing":{"price_details":{"price":"cpu"}},"pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":100000,"credit_balance_transaction":"cbtxn_one"}]}]}}`), &inv)
			if bad == "wrong scope" {
				inv.Lines.Data[0].Pricing.PriceDetails.Price = "base"
			}
			if bad == "earlier credit skipped" {
				old := g
				old.ID = "credgr_earlier"
				old.ExpiresAt = 201
				g.ExpiresAt = 202
				plan.CreditGrants[0].ExpiresAt = 202
				newRaw, _ := json.Marshal(g)
				plan.CreditGrants[0].Evidence = newRaw
				oldRaw, _ := json.Marshal(old)
				plan.CreditGrants = append([]billing.InvoiceCreditGrant{{ID: old.ID, Before: 500, ExpiresAt: 201, Evidence: oldRaw}}, plan.CreditGrants...)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/billing/credit_balance_transactions/cbtxn_one":
					invoice, grant, line := "in_example", g.ID, "il_cpu"
					if bad == "wrong invoice" {
						invoice = "in_other"
					}
					if bad == "wrong grant" {
						grant = "credgr_other"
					}
					if bad == "wrong line" {
						line = "il_other"
					}
					fmt.Fprintf(w, `{"id":"cbtxn_one","credit_grant":%q,"type":"debit","debit":{"type":"credits_applied","amount":{"type":"monetary","monetary":{"currency":"usd","value":100000}},"credits_applied":{"invoice":%q,"invoice_line_item":%q}}}`, grant, invoice, line)
				case "/v1/billing/credit_grants/credgr_period":
					json.NewEncoder(w).Encode(g)
				case "/v1/billing/credit_grants/credgr_earlier":
					old := testEntitlementGrant()
					old.ID = "credgr_earlier"
					json.NewEncoder(w).Encode(old)
				case "/v1/billing/credit_balance_summary":
					balance := 0
					if bad == "changed ledger" {
						balance = 1
					}
					if r.URL.Query().Get("filter[credit_grant]") == "credgr_earlier" {
						balance = 500
					}
					fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, balance)
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			remaining, err := client.verifyInvoiceCreditTransactions(t.Context(), inv, plan)
			if bad == "" {
				if err != nil || remaining != 0 {
					t.Fatalf("valid credit rejected: %d %v", remaining, err)
				}
			} else if err == nil {
				t.Fatal("accepted false credit settlement")
			}
		})
	}
}

func TestEntitlementForfeitureRequiresFullPeriodDebt(t *testing.T) {
	inv := StripeInvoiceAmounts{Created: 99, Status: "open"}
	inv.StatusTransitions.FinalizedAt = 99
	if !entitlementDebtSpansPeriod(inv, 100, 200) {
		t.Fatal("rejected continuously unpaid debt")
	}
	inv.Status = "paid"
	inv.StatusTransitions.PaidAt = 150
	if entitlementDebtSpansPeriod(inv, 100, 200) {
		t.Fatal("forfeited allowance paid before expiry")
	}
	inv.StatusTransitions.PaidAt = 201
	if !entitlementDebtSpansPeriod(inv, 100, 200) {
		t.Fatal("late payment resets expired allowance")
	}
	inv.StatusTransitions.FinalizedAt = 120
	if entitlementDebtSpansPeriod(inv, 100, 200) {
		t.Fatal("late debt excused earlier platform outage")
	}
}

func TestEmptyCreditPlanSurvivesPersistence(t *testing.T) {
	plan := billing.InvoiceClosePlan{CreditVersion: 1, CreditGrants: []billing.InvoiceCreditGrant{}}
	raw, _ := json.Marshal(plan)
	var loaded billing.InvoiceClosePlan
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	if !sameInvoiceCreditGrants(plan.CreditGrants, loaded.CreditGrants) {
		t.Fatal("persisted empty credits cannot resume")
	}
}
