package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestMatchingUsageExcludesFeeDiscountsAndCredits(t *testing.T) {
	var inv StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(`{"lines":{"data":[
 {"amount":120000,"currency":"usd","pricing":{"price_details":{"price":"price_base"}},"pretax_credit_amounts":[{"type":"discount","amount":20000}]},
 {"amount":50000,"currency":"usd","pricing":{"price_details":{"price":"price_cpu"}},"pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":25000,"credit_balance_transaction":"cbtxn_1"},{"type":"discount","amount":3}]},
 {"amount":7,"currency":"usd","pricing":{"price_details":{"price":"price_round"}}}]}}`), &inv); err != nil {
		t.Fatal(err)
	}
	prices := []string{"price_cpu", "price_round"}
	u, err := matchingInvoiceUsage(inv, matchingPayment{AmountPaid: 125004}, prices)
	if err != nil || u.SkipReason != "" || u.UsageCents != 50007 || u.CreditCents != 25000 || u.DiscountCents != 3 || u.UnpaidCents != 0 {
		t.Fatalf("unexpected matchable usage: %+v %v", u, err)
	}
	if u, err = matchingInvoiceUsage(inv, matchingPayment{AmountPaid: 110000}, prices); err != nil || u.UnpaidCents != 15004 {
		t.Fatalf("usage the customer did not pay was matchable: %+v %v", u, err)
	}
	if u, err = matchingInvoiceUsage(inv, matchingPayment{AmountPaid: 125004, PaidOutOfBand: true}, prices); err != nil || u.SkipReason == "" {
		t.Fatal("invoice marked paid out of band was matched automatically")
	}
	inv.Taxes = []json.RawMessage{json.RawMessage(`{"amount":1}`)}
	if u, err = matchingInvoiceUsage(inv, matchingPayment{AmountPaid: 125004}, prices); err != nil || u.SkipReason == "" {
		t.Fatal("taxed invoice was matched automatically")
	}
	if u, err = matchingInvoiceUsage(StripeInvoiceAmounts{}, matchingPayment{}, nil); err != nil || u.SkipReason == "" {
		t.Fatal("invoice without usage price identification was matched")
	}
}

func TestMatchingUsageCountsBalanceCarryAsPaidWhereUsageHappened(t *testing.T) {
	var carried, collecting StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(`{"starting_balance":0,"ending_balance":40,"lines":{"data":[{"amount":40,"currency":"usd","pricing":{"price_details":{"price":"price_cpu"}}}]}}`), &carried); err != nil {
		t.Fatal(err)
	}
	if u, err := matchingInvoiceUsage(carried, matchingPayment{}, []string{"price_cpu"}); err != nil || u.UnpaidCents != 0 || u.UsageCents != 40 {
		t.Fatalf("usage carried onto the balance was not matched where it happened: %+v %v", u, err)
	}
	if err := json.Unmarshal([]byte(`{"starting_balance":40,"ending_balance":0,"lines":{"data":[{"amount":30,"currency":"usd","pricing":{"price_details":{"price":"price_cpu"}}}]}}`), &collecting); err != nil {
		t.Fatal(err)
	}
	if u, err := matchingInvoiceUsage(collecting, matchingPayment{AmountPaid: 70}, []string{"price_cpu"}); err != nil || u.UsageCents-u.UnpaidCents != 30 {
		t.Fatalf("carried balance was matched again on the collecting invoice: %+v %v", u, err)
	}
	var credited StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(`{"starting_balance":-100,"ending_balance":-30,"lines":{"data":[{"amount":70,"currency":"usd","pricing":{"price_details":{"price":"price_cpu"}}}]}}`), &credited); err != nil {
		t.Fatal(err)
	}
	if u, err := matchingInvoiceUsage(credited, matchingPayment{}, []string{"price_cpu"}); err != nil || u.UnpaidCents != 70 {
		t.Fatalf("usage settled from a credit balance was matched as paid: %+v %v", u, err)
	}
}

func TestMatchingGrantFormRejectsExpiringOrScopedRequests(t *testing.T) {
	valid := `{"customer":"cus_example","category":"promotional","name":"Matching credit","priority":50,"amount":{"type":"monetary","monetary":{"currency":"usd","value":100}},"applicability_config":{"scope":{"price_type":"metered"}},"metadata":{"matching_credit_id":"m","invoice_id":"in_example"}}`
	form, err := matchingGrantForm([]byte(valid))
	if err != nil || form.Get("applicability_config[scope][price_type]") != "metered" || form.Has("expires_at") {
		t.Fatal(form, err)
	}
	for _, bad := range []string{
		`{"customer":"cus_example","category":"promotional","name":"Matching credit","priority":50,"expires_at":5,"amount":{"type":"monetary","monetary":{"currency":"usd","value":100}},"applicability_config":{"scope":{"price_type":"metered"}},"metadata":{"matching_credit_id":"m","invoice_id":"in_example"}}`,
		`{"customer":"cus_example","category":"promotional","name":"Matching credit","priority":50,"amount":{"type":"monetary","monetary":{"currency":"usd","value":100}},"applicability_config":{"scope":{"prices":[{"id":"price_cpu"}]}},"metadata":{"matching_credit_id":"m","invoice_id":"in_example"}}`,
		`{"customer":"cus_example","category":"promotional","name":"Matching credit","priority":50,"amount":{"type":"monetary","monetary":{"currency":"usd","value":100}},"applicability_config":{"scope":{"price_type":"metered"}},"metadata":{"entitlement_id":"e","matching_credit_id":"m","invoice_id":"in_example"}}`,
	} {
		if _, err = matchingGrantForm([]byte(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestMatchingWritesRequireOperatorCredential(t *testing.T) {
	router := machineAdminRouter(t, nil)
	team, credit := uuid.NewString(), uuid.NewString()
	for _, path := range []string{"/billing/matching", "/billing/matching/revoke", "/billing/matching/credits/" + credit + "/acknowledge"} {
		for _, token := range []string{"", "test-infrastructure-only"} {
			response := machineAdminRequest(router, http.MethodPost, "/internal/teams/"+team+path, `{"reason":"test"}`, token, false)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("%s with token %q got %d", path, token, response.Code)
			}
		}
	}
}
