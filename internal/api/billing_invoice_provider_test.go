package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInvoiceDiscountRecoveryPreservesOtherDiscounts(t *testing.T) {
	for _, kind := range []string{"new", "lost response", "foreign discount", "wrong coupon amount"} {
		t.Run(kind, func(t *testing.T) {
			created, attached := kind == "lost response" || kind == "wrong coupon amount", kind == "lost response"
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writes++
				}
				switch r.URL.Path {
				case "/v1/invoices/in_example":
					if r.Method == http.MethodPost {
						attached = true
					}
					discounts := []any{}
					if attached || kind == "foreign discount" {
						coupon := "rounding_in_example"
						if kind == "foreign discount" {
							coupon = "coupon_other"
						}
						discounts = append(discounts, map[string]any{"id": "di_example", "source": map[string]any{"coupon": coupon}})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "in_example", "status": "draft", "auto_advance": false, "discounts": discounts})
				case "/v1/coupons/rounding_in_example":
					if !created {
						http.Error(w, `{"error":{"message":"missing"}}`, 404)
						return
					}
					amount := 1
					if kind == "wrong coupon amount" {
						amount = 2
					}
					fmt.Fprintf(w, `{"id":"rounding_in_example","amount_off":%d,"currency":"usd"}`, amount)
				case "/v1/coupons":
					created = true
					fmt.Fprint(w, `{"id":"rounding_in_example","amount_off":1,"currency":"usd"}`)
				default:
					t.Errorf("unexpected provider call %s", r.URL)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			c := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
			err := c.applyInvoiceDiscount(context.Background(), "in_example", 1, "invoice-cent:in_example")
			bad := kind == "foreign discount" || kind == "wrong coupon amount"
			if (err != nil) != bad {
				t.Fatalf("err=%v", err)
			}
			if bad {
				if writes != 0 {
					t.Fatal("changed an incompatible discount")
				}
				return
			}
			if err = c.applyInvoiceDiscount(context.Background(), "in_example", 1, "invoice-cent:in_example"); err != nil {
				t.Fatal(err)
			}
			want := 0
			if kind == "new" {
				want = 2
			}
			if writes != want {
				t.Fatalf("writes=%d want=%d", writes, want)
			}
		})
	}
}

func TestInvoiceEnrollmentBoundaryUsesProtectedInvoices(t *testing.T) {
	for _, kind := range []string{"finalized before hold", "inflight draft", "lost hold response", "held draft", "unconfigured draft", "held unconfigured draft", "would orphan held invoice"} {
		t.Run(kind, func(t *testing.T) {
			status, auto, rounding := "draft", true, true
			if kind == "finalized before hold" {
				status = "paid"
			}
			if kind == "held draft" || kind == "held unconfigured draft" || kind == "would orphan held invoice" {
				auto = false
			}
			if kind == "unconfigured draft" || kind == "held unconfigured draft" {
				rounding = false
			}
			writes := 0
			invoice := func(id string, end int64, st string, advance bool) map[string]any {
				lines := []any{}
				if rounding {
					lines = append(lines, map[string]any{"pricing": map[string]any{"price_details": map[string]any{"price": "price_round"}}})
				}
				return map[string]any{"id": id, "created": 9, "customer": "cus_example", "billing_reason": "subscription_cycle", "period_end": end, "status": st, "auto_advance": advance, "parent": map[string]any{"subscription_details": map[string]any{"subscription": "sub_example"}}, "lines": map[string]any{"data": lines, "has_more": false}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var out any
				switch r.URL.Path {
				case "/v1/invoices":
					if r.URL.Query().Get("subscription") != "sub_example" || r.URL.Query().Get("created[gte]") != "" || r.URL.Query().Get("limit") != "100" {
						t.Error("enrollment inventory must include earlier-created invoices")
					}
					data := []any{invoice("in_example", 20, status, auto)}
					if kind == "would orphan held invoice" {
						data = append(data, invoice("in_later", 30, "paid", false))
					}
					out = map[string]any{"data": data, "has_more": false}
				case "/v1/invoices/in_example":
					if r.Method == http.MethodPost {
						_ = r.ParseForm()
						if r.Form.Get("auto_advance") != "false" {
							t.Error("collection was not held")
						}
						auto = false
						writes++
						if kind == "lost hold response" && writes == 1 {
							http.Error(w, "response lost", 500)
							return
						}
					}
					out = invoice("in_example", 20, status, auto)
				case "/v1/invoices/in_later":
					out = invoice("in_later", 30, "paid", false)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL)
					http.Error(w, "unexpected", 500)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			c := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
			a := invoiceAccount{Customer: "cus_example", Subscription: "sub_example", Price: "price_round"}
			attempt := time.Unix(10, 0)
			boundary, err := c.invoiceEnrollmentBoundary(t.Context(), a, attempt)
			if kind == "lost hold response" {
				if err == nil {
					t.Fatal("response loss not exercised")
				}
				boundary, err = c.invoiceEnrollmentBoundary(t.Context(), a, attempt)
			}
			bad := kind == "held unconfigured draft" || kind == "would orphan held invoice"
			if (err != nil) != bad {
				t.Fatalf("boundary=%s err=%v", boundary, err)
			}
			if bad {
				return
			}
			want := int64(10)
			if kind == "finalized before hold" || kind == "unconfigured draft" {
				want = 20
			}
			if boundary.Unix() != want {
				t.Fatalf("boundary=%d want=%d", boundary.Unix(), want)
			}
			wantWrites := 0
			if kind == "inflight draft" || kind == "lost hold response" {
				wantWrites = 1
			}
			if writes != wantWrites {
				t.Fatalf("hold writes=%d want=%d", writes, wantWrites)
			}
		})
	}
}

func TestInvoiceCatalogRecoversLostCreationResponses(t *testing.T) {
	for _, lost := range []string{"meter", "product", "price"} {
		t.Run(lost, func(t *testing.T) {
			meter, product, price := false, false, false
			writes := map[string]int{}
			fail := true
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				kind := ""
				var out any
				switch r.URL.Path {
				case "/v1/prices":
					if r.Method == http.MethodPost {
						price = true
						kind = "price"
						if r.Form.Get("lookup_key") != invoiceRoundingLookup || r.Form.Get("unit_amount") != "1" || r.Form.Get("recurring[meter]") != "mtr_round" {
							t.Error("wrong price configuration")
						}
						out = map[string]any{"id": "price_round"}
					} else {
						data := []any{}
						if price {
							data = append(data, map[string]any{"id": "price_round"})
						}
						out = map[string]any{"data": data, "has_more": false}
					}
				case "/v1/billing/meters":
					if r.Method == http.MethodPost {
						meter = true
						kind = "meter"
						if r.Form.Get("event_name") != invoiceRoundingEvent || r.Form.Get("default_aggregation[formula]") != "sum" {
							t.Error("wrong meter configuration")
						}
						out = map[string]any{"id": "mtr_round"}
					} else {
						data := []any{}
						if meter {
							data = append(data, map[string]any{"id": "mtr_round", "event_name": invoiceRoundingEvent, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
						}
						out = map[string]any{"data": data, "has_more": false}
					}
				case "/v1/products/" + invoiceRoundingProduct:
					if !product {
						http.Error(w, `{"error":{"message":"missing"}}`, 404)
						return
					}
					out = map[string]any{"id": invoiceRoundingProduct, "active": true}
				case "/v1/products":
					product = true
					kind = "product"
					if r.Form.Get("id") != invoiceRoundingProduct {
						t.Error("product lacks stable identity")
					}
					out = map[string]any{"id": invoiceRoundingProduct, "active": true}
				default:
					t.Errorf("unexpected %s", r.URL)
					http.Error(w, "unexpected", 400)
					return
				}
				if kind != "" {
					writes[kind]++
					if r.Header.Get("Idempotency-Key") == "" {
						t.Error("missing idempotency")
					}
					if kind == lost && fail {
						fail = false
						http.Error(w, `{"error":{"message":"lost response"}}`, 500)
						return
					}
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			c := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
			if _, err := c.ensureInvoiceCatalog(context.Background()); err == nil {
				t.Fatal("fixture did not lose response")
			}
			for i := 0; i < 2; i++ {
				a, err := c.ensureInvoiceCatalog(context.Background())
				if err != nil || a.Price != "price_round" || a.Event != invoiceRoundingEvent {
					t.Fatalf("catalog %+v err=%v", a, err)
				}
			}
			for _, kind := range []string{"meter", "product", "price"} {
				if writes[kind] != 1 {
					t.Fatalf("duplicate %s: %d", kind, writes[kind])
				}
			}
		})
	}
}
