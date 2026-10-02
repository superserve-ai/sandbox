package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBillingInvoicePreviewRefreshesAfterCorrection(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/invoices/create_preview" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("subscription") != "sub_example" || r.Header.Get("Idempotency-Key") != "" {
			t.Errorf("invalid preview request: %v, %v", r.Form, err)
		}
		requests++
		fmt.Fprintf(w, `{"id":"upcoming_in_example","currency":"usd","status":"draft","subtotal":%d,"lines":{"data":[{"quantity_decimal":"1.05499999999","amount":105}]}}`, 104+requests)
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
	first, err := client.PreviewBillingInvoice(context.Background(), "sub_example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.PreviewBillingInvoice(context.Background(), "sub_example")
	if err != nil {
		t.Fatal(err)
	}
	if first.Subtotal != 105 || second.Subtotal != 106 || second.Lines.Data[0].QuantityDecimal != "1.05499999999" {
		t.Fatalf("preview was stale or quantity lost precision: first=%+v second=%+v", first, second)
	}
}

func TestBillingInvoiceRetrieveIncludesEveryLine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/invoices/in_example":
			fmt.Fprint(w, `{"id":"in_example","subtotal":106,"lines":{"has_more":true,"data":[{"id":"il_resource","amount":105}]}}`)
		case "/v1/invoices/in_example/lines":
			if r.URL.Query().Get("starting_after") == "" {
				fmt.Fprint(w, `{"data":[{"id":"il_resource","amount":105}],"has_more":true}`)
			} else if r.URL.Query().Get("starting_after") == "il_resource" {
				fmt.Fprint(w, `{"data":[{"id":"il_correction","amount":1}],"has_more":false}`)
			} else {
				t.Errorf("unexpected pagination cursor %q", r.URL.Query().Get("starting_after"))
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
	invoice, err := client.RetrieveBillingInvoice(context.Background(), "in_example")
	if err != nil {
		t.Fatal(err)
	}
	if invoice.Lines.HasMore || len(invoice.Lines.Data) != 2 || invoice.Lines.Data[1].Amount != 1 {
		t.Fatalf("missing correction line: %+v", invoice.Lines)
	}
	if _, err = client.RetrieveBillingInvoice(context.Background(), "upcoming_in_example"); err == nil {
		t.Fatal("accepted preview ID as persisted invoice")
	}
}

func TestBillingInvoiceSettlementRejectsIncorrectCreditEvenWhenNothingDue(t *testing.T) {
	zero := int64(0)
	invoice := StripeInvoiceAmounts{ID: "in_example", Currency: "usd", Status: "paid", Subtotal: 106, EndingBalance: &zero,
		PretaxCredits: []StripeInvoicePretaxCredit{{Type: "credit_balance_transaction", Amount: 106, CreditBalanceTransaction: "cbtxn_example"}},
	}
	if err := VerifyBillingInvoiceSettlement(invoice, 106, 1000, 894); err != nil {
		t.Fatal(err)
	}
	invoice.PretaxCredits[0].Amount = 105
	if err := VerifyBillingInvoiceSettlement(invoice, 106, 1000, 895); err == nil {
		t.Fatal("accepted incorrect credit consumption hidden by zero amount due")
	}
	invoice.PretaxCredits[0].Amount = 106
	invoice.PretaxCredits[0].CreditBalanceTransaction = ""
	if err := VerifyBillingInvoiceSettlement(invoice, 106, 1000, 894); err == nil {
		t.Fatal("accepted provisional preview credits as actual consumption")
	}
}

func TestBillingInvoiceSettlementRejectsPreviewAndIncompleteEvidence(t *testing.T) {
	zero := int64(0)
	base := StripeInvoiceAmounts{ID: "in_example", Currency: "usd", Status: "open", Subtotal: 105, Total: 105, AmountDue: 105, EndingBalance: &zero}
	if err := VerifyBillingInvoiceSettlement(base, 105, 0, 0); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*StripeInvoiceAmounts){
		func(i *StripeInvoiceAmounts) { i.ID = "upcoming_in_example" },
		func(i *StripeInvoiceAmounts) { i.Status = "draft" },
		func(i *StripeInvoiceAmounts) { i.AutoAdvance = true },
		func(i *StripeInvoiceAmounts) { i.Lines.HasMore = true },
		func(i *StripeInvoiceAmounts) { i.EndingBalance = nil },
		func(i *StripeInvoiceAmounts) { i.Currency = "eur" },
		func(i *StripeInvoiceAmounts) { i.PrePaymentCreditNotes = 1 },
		func(i *StripeInvoiceAmounts) { i.AmountShipping = 1 },
	} {
		invoice := base
		change(&invoice)
		if err := VerifyBillingInvoiceSettlement(invoice, 105, 0, 0); err == nil {
			t.Fatalf("accepted unsupported evidence: %+v", invoice)
		}
	}
}

func TestHeldRenewalFinalizationRecomputesThenRecoversWithoutSecondWrite(t *testing.T) {
	finalized := false
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.URL.Path != "/v1/invoices/in_example/finalize" || r.Header.Get("Idempotency-Key") != "example-period-finalize" {
				t.Errorf("unexpected finalization request %s", r.URL)
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("auto_advance") != "false" {
				t.Error("finalization must retain collection hold")
			}
			writes++
			finalized = true
		}
		if finalized {
			fmt.Fprint(w, `{"id":"in_example","currency":"usd","billing_reason":"subscription_cycle","status":"paid","auto_advance":false,"subtotal":106,"ending_balance":0}`)
		} else {
			fmt.Fprint(w, `{"id":"in_example","currency":"usd","billing_reason":"subscription_cycle","status":"draft","auto_advance":false,"subtotal":105}`)
		}
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
	for i := 0; i < 2; i++ {
		invoice, err := client.FinalizeHeldBillingInvoice(context.Background(), "in_example", true, "example-period-finalize")
		if err != nil || invoice.Subtotal != 106 || invoice.AutoAdvance {
			t.Fatalf("invoice=%+v error=%v", invoice, err)
		}
	}
	if writes != 1 {
		t.Fatalf("finalized %d times", writes)
	}
}

func TestHeldRenewalRejectsUnsupportedInvoiceBeforeFinalization(t *testing.T) {
	for _, tc := range []struct {
		reason                       string
		pricesUnchanged, autoAdvance bool
	}{
		{"subscription_update", true, false},
		{"subscription_threshold", true, false},
		{"subscription_cycle", false, false},
		{"subscription_cycle", true, true},
	} {
		t.Run(fmt.Sprintf("%s/%v/%v", tc.reason, tc.pricesUnchanged, tc.autoAdvance), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("attempted mutation for unsupported invoice")
				}
				fmt.Fprintf(w, `{"id":"in_example","status":"draft","currency":"usd","billing_reason":%q,"auto_advance":%v}`, tc.reason, tc.autoAdvance)
			}))
			defer server.Close()
			client := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
			if _, err := client.FinalizeHeldBillingInvoice(context.Background(), "in_example", tc.pricesUnchanged, "example-finalize"); err == nil {
				t.Fatal("accepted unsupported renewal")
			}
		})
	}
}
