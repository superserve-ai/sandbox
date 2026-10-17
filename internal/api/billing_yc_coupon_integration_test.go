//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestYCCouponRestrictionEvidence(t *testing.T) {
	for _, created := range []bool{false, true} {
		for _, evidence := range []string{"valid", "missing", "null", "malformed", "unrestricted", "wrong-product", "multiple-products", "wrong-percent", "wrong-duration", "wrong-id"} {
			t.Run(fmt.Sprintf("created=%t/%s", created, evidence), func(t *testing.T) {
				runYCCouponCreation(t, created, evidence, "")
			})
		}
	}
}

func TestYCCouponCreationResponseLoss(t *testing.T) {
	for _, loss := range []string{"coupon-create", "coupon-read", "subscription-create"} {
		t.Run(loss, func(t *testing.T) { runYCCouponCreation(t, true, "valid", loss) })
	}
}

func runYCCouponCreation(t *testing.T, create bool, evidence, loss string) {
	t.Helper()
	fixture := newEntitlementFixture(t, true, true)
	h := fixture.h
	team, err := h.DB.CreateTeam(t.Context(), "yc-coupon-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	sub, params, approval := ycTestSubscription()
	sub.Customer = "cus_" + team.ID.String()
	sub.ID = "sub_" + team.ID.String()
	sub.LatestInvoice = "in_" + team.ID.String()
	sub.Discounts = []string{"di_coupon_fixture"}
	approval.Customer = sub.Customer
	approval.CompanyIdentity = "https://example.com/companies/fixture-" + team.ID.String()
	request, _ := json.Marshal(approval)
	terms, _ := json.Marshal(params)
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO billing_yc_operation(team_id,approved_by,evidence_reference,request,resource_terms,customer_id) VALUES($1,'operator','fixture',$2,$3,$4)`, team.ID, request, terms, sub.Customer); err != nil {
		t.Fatal(err)
	}
	o, err := h.ycOperation(t.Context(), team.ID)
	if err != nil {
		t.Fatal(err)
	}
	sub.Metadata = map[string]string{"yc_operation": o.ID.String()}
	couponID := "yc-first-year-" + o.ID.String()
	couponExists, subscriptionExists, lost := !create, false, false
	couponWrites, subscriptionWrites, couponReads := 0, 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Stripe-Version") != "2026-05-27.dahlia" {
			t.Error("lost deployed API version")
		}
		_ = r.ParseForm()
		output := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		lose := func(point string) bool {
			if loss != point || lost {
				return false
			}
			lost = true
			// Provider committed the object, but the client cannot read its response.
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte(`{"id":`))
			return true
		}
		coupon := func(expanded bool) map[string]any {
			v := map[string]any{"id": couponID, "duration": "once", "percent_off": 100}
			if expanded {
				v["applies_to"] = map[string]any{"products": []string{"prod_annual"}}
				switch evidence {
				case "missing":
					delete(v, "applies_to")
				case "null":
					v["applies_to"] = nil
				case "malformed":
					v["applies_to"] = map[string]any{"products": "prod_annual"}
				case "unrestricted":
					v["applies_to"] = map[string]any{"products": []string{}}
				case "wrong-product":
					v["applies_to"] = map[string]any{"products": []string{"prod_usage"}}
				case "multiple-products":
					v["applies_to"] = map[string]any{"products": []string{"prod_annual", "prod_usage"}}
				case "wrong-percent":
					v["percent_off"] = 99
				case "wrong-duration":
					v["duration"] = "forever"
				case "wrong-id":
					v["id"] = "coupon_other"
				}
			}
			return v
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions":
			if r.Form.Get("customer") != o.Customer || r.Form.Get("status") != "all" {
				t.Error("changed discovery scope")
			}
			data := []invoiceSubscription{}
			if subscriptionExists {
				data = append(data, sub)
			}
			output(map[string]any{"data": data})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/prices/"+params.BasePriceID:
			output(sub.Items.Data[0].Price)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/coupons/"+couponID:
			couponReads++
			if !couponExists {
				http.Error(w, `{"error":{"code":"resource_missing"}}`, http.StatusNotFound)
				return
			}
			if create && couponWrites > 0 && lose("coupon-read") {
				return
			}
			output(coupon(r.Form.Get("expand[]") == "applies_to"))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/coupons":
			couponWrites++
			if couponExists {
				t.Error("attempted to replace an existing coupon")
			}
			want := map[string][]string{"id": {couponID}, "duration": {"once"}, "percent_off": {"100"}, "applies_to[products][0]": {"prod_annual"}}
			if !reflect.DeepEqual(map[string][]string(r.PostForm), want) || r.Header.Get("Idempotency-Key") != couponID {
				t.Error("changed replayable coupon creation")
			}
			couponExists = true
			if lose("coupon-create") {
				return
			}
			output(coupon(r.Form.Get("expand[]") == "applies_to"))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/subscriptions":
			subscriptionWrites++
			want := map[string][]string{"customer": {o.Customer}, "items[0][price]": {params.BasePriceID}, "items[0][quantity]": {"1"}, "discounts[0][coupon]": {couponID}, "collection_method": {"charge_automatically"}, "billing_mode[type]": {"flexible"}, "metadata[yc_operation]": {o.ID.String()}}
			if !reflect.DeepEqual(map[string][]string(r.PostForm), want) || r.Header.Get("Idempotency-Key") != "yc-subscription:"+o.ID.String() {
				t.Error("changed subscription identity or included usage in the waived invoice")
			}
			subscriptionExists = true
			if lose("subscription-create") {
				return
			}
			output(sub)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/invoices/"+sub.LatestInvoice:
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":"paid","currency":"usd","subtotal":1200000,"total":0,"amount_due":0,"amount_paid":0,"amount_remaining":0,"starting_balance":0,"ending_balance":0,"total_discount_amounts":[{"amount":1200000}],"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"amount":1200000,"currency":"usd","quantity":1,"period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":%q}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, sub.LatestInvoice, sub.Customer, sub.ID, sub.StartDate, sub.Items.Data[0].End, params.BasePriceID, sub.ID)
		case r.URL.Path == "/v1/subscriptions/"+sub.ID:
			if r.Method == http.MethodPost {
				if r.PostForm.Get("discounts") != "" || !r.PostForm.Has("discounts") || r.PostForm.Get("proration_behavior") != "none" || r.Header.Get("Idempotency-Key") != "yc-discount-consumed:"+o.ID.String() {
					t.Error("waiver was not removed before usage attachment")
				}
				sub.Discounts = nil
				output(sub)
			} else if r.Form.Get("expand[]") == "discounts.source.coupon" {
				output(map[string]any{"discounts": []any{map[string]any{"id": "di_coupon_fixture", "source": map[string]any{"coupon": coupon(false)}}}})
			} else {
				output(sub)
			}
		default:
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	c := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-05-27.dahlia", httpClient: srv.Client()}
	got, err := h.createYCSubscription(t.Context(), o, c)
	if evidence != "valid" {
		if err == nil || (evidence != "malformed" && !strings.Contains(err.Error(), "YC coupon differs")) {
			t.Fatalf("accepted %s evidence: %v", evidence, err)
		}
		if subscriptionWrites != 0 {
			t.Fatal("created subscription without restriction evidence")
		}
	} else {
		if loss != "" {
			if err == nil || !lost {
				t.Fatal("did not observe response loss", err)
			}
			saved, readErr := h.ycOperation(t.Context(), o.Team)
			if readErr != nil {
				t.Fatal(readErr)
			}
			o.Attempt = saved.Attempt
			got, err = h.createYCSubscription(t.Context(), o, c)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != sub.ID || len(got.Discounts) != 0 {
			t.Fatal("failed to recover the same subscription without a future waiver")
		}
		beforeReads := couponReads
		got, err = h.createYCSubscription(t.Context(), o, c)
		if err != nil || got.ID != sub.ID || couponReads != beforeReads {
			t.Fatal("retry did not discover existing subscription", err)
		}
		saved, readErr := h.ycOperation(t.Context(), o.Team)
		if readErr != nil || saved.Subscription != sub.ID || saved.FirstInvoice != sub.LatestInvoice || saved.ID != o.ID {
			t.Fatal("lost durable operation identity", readErr)
		}
		if subscriptionWrites != 1 {
			t.Fatalf("created %d subscriptions", subscriptionWrites)
		}
	}
	wantWrites := 0
	if create {
		wantWrites = 1
	}
	if couponWrites != wantWrites {
		t.Fatalf("created %d coupons, want %d", couponWrites, wantWrites)
	}
}
