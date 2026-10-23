package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRenewalChoiceCreationRecoveryRequiresOriginalRequestEvent(t *testing.T) {
	for _, scenario := range []string{"confirmed", "after_boundary", "wrong_request", "wrong_version", "wrong_account", "wrong_mode", "missing_request_id", "truncated", "expired", "duplicate", "late_creation"} {
		t.Run(scenario, func(t *testing.T) {
			k, op, _, response, _ := renewalReceiptFixture(t, "monthly")
			op.Steps = nil
			request, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: op.Binding.Anchor, Boundary: k.Boundary})
			if err != nil {
				t.Fatal(err)
			}
			op.Steps = []renewalChoiceStep{{Request: request, State: "outcome_unknown"}}
			dispatched := k.Boundary.Add(-2 * time.Minute)
			op.DispatchedAt = &dispatched
			now := k.Boundary.Add(-time.Minute)
			response["phases"] = response["phases"].([]any)[:1]
			raw, _ := json.Marshal(response)
			event := renewalScheduleEvent{ID: "evt_fixture", Object: "event", Type: "subscription_schedule.created", Version: renewalStripeVersion, Created: dispatched.Unix() + 1, Live: op.Binding.Live}
			event.Request.ID, event.Request.Idempotency = "req_fixture", request.Idempotency
			event.Data.Object = raw
			switch scenario {
			case "after_boundary":
				now = k.Boundary.Add(time.Minute)
			case "wrong_request":
				event.Request.Idempotency = "another_request"
			case "wrong_version":
				event.Version = "old_version"
			case "wrong_account":
				event.Account = "acct_other"
			case "wrong_mode":
				event.Live = !op.Binding.Live
			case "missing_request_id":
				event.Request.ID = ""
			case "expired":
				now = dispatched.Add(30 * 24 * time.Hour)
			case "late_creation":
				now = k.Boundary.Add(time.Minute)
				event.Created = k.Boundary.Unix()
			}
			reads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reads++
				if r.Method != http.MethodGet {
					t.Error("recovery attempted a provider write")
				}
				if r.URL.Path == "/v1/account" {
					_ = json.NewEncoder(w).Encode(map[string]string{"id": op.Binding.Merchant})
					return
				}
				if r.URL.Path != "/v1/events" || r.URL.Query().Get("type") != "subscription_schedule.created" || r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("created[gte]") == "" {
					t.Error("unbounded or unexpected recovery read", r.URL)
				}
				events := []renewalScheduleEvent{event}
				if scenario == "duplicate" {
					events = append(events, event)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": events, "has_more": scenario == "truncated"})
			}))
			defer server.Close()
			v := &stripeRenewalScheduleVerifier{Client: &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: renewalStripeVersion}}
			proof, err := v.recoverEvent(t.Context(), k, op, request, now)
			if scenario == "confirmed" || scenario == "after_boundary" {
				if err != nil || proof.Outcome != "confirmed" || proof.Choice != nil || !proof.VerifiedAt.Equal(now) || reads != 2 {
					t.Fatal("original creation evidence not recovered independently of choice", proof, err, reads)
				}
			} else if err == nil || proof.Outcome == "no_effect" {
				t.Fatal("incomplete history released unknown fence", proof, err)
			}
			if scenario == "expired" && reads != 0 {
				t.Fatal("queried history outside provider retention")
			}
		})
	}
}

func TestRenewalChoiceUpdateRecoveryRequiresOriginalRequestEvent(t *testing.T) {
	for _, scenario := range []string{"confirmed", "inflight_noop", "foreign_request", "wrong_event_type", "changed_configuration"} {
		t.Run(scenario, func(t *testing.T) {
			k, op, request, response, now := renewalReceiptFixture(t, "annual")
			dispatched := now.Add(-time.Minute)
			op.DispatchedAt = &dispatched
			raw, _ := json.Marshal(response)
			// The current schedule already matches this Annual no-op before POST starts.
			if _, err := verifyRenewalScheduleReceipt(k, op, request, raw, now); err != nil {
				t.Fatal(err)
			}
			event := renewalScheduleEvent{ID: "evt_update", Object: "event", Type: "subscription_schedule.updated", Version: renewalStripeVersion, Created: dispatched.Unix() + 1, Live: op.Binding.Live}
			event.Request.ID, event.Request.Idempotency = "req_update", request.Idempotency
			event.Data.Object = raw
			switch scenario {
			case "foreign_request":
				event.Request.Idempotency = "other"
			case "wrong_event_type":
				event.Type = "subscription_schedule.created"
			case "changed_configuration":
				response["end_behavior"] = "cancel"
				event.Data.Object, _ = json.Marshal(response)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("recovery wrote to provider")
				}
				if r.URL.Path == "/v1/account" {
					_ = json.NewEncoder(w).Encode(map[string]string{"id": op.Binding.Merchant})
					return
				}
				if r.URL.Path != "/v1/events" || r.URL.Query().Get("type") != "subscription_schedule.updated" {
					t.Error("unexpected recovery read", r.URL)
				}
				events := []renewalScheduleEvent{event}
				if scenario == "inflight_noop" {
					events = nil
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": events, "has_more": false})
			}))
			defer server.Close()
			v := &stripeRenewalScheduleVerifier{Client: &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: renewalStripeVersion}}
			proof, err := v.recoverEvent(t.Context(), k, op, request, now)
			if scenario == "confirmed" {
				if err != nil || proof.Choice == nil || proof.Outcome != "confirmed" {
					t.Fatal(proof, err)
				}
			} else if err == nil || proof.Outcome == "no_effect" {
				t.Fatal("matching GET released unresolved original write", proof, err)
			}
		})
	}
}

func TestRenewalChoiceWaiverRequiresOriginalOnceDiscount(t *testing.T) {
	for _, scenario := range []string{"expired_original", "retained_original", "foreign_discount", "extra_discount", "recurring_coupon", "foreign_invoice", "missing_invoice", "missing_discount_identity"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPairFixture(t)
			b := ContractProviderBinding{Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, FeeSubscriptionID: f.p.FeeSubscriptionID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeItemID: f.p.FeeItemID, Anchor: f.p.Anchor}
			coupon := map[string]string{"ID": f.p.WaiverCouponID, "Duration": "once"}
			var discounts []string
			switch scenario {
			case "retained_original":
				discounts = []string{"di_waiver"}
			case "foreign_discount":
				discounts = []string{"di_recurring"}
			case "extra_discount":
				discounts = []string{"di_waiver", "di_extra"}
			case "recurring_coupon":
				coupon["Duration"] = "forever"
			case "foreign_invoice":
				f.invoice.Customer = "cus_foreign"
			case "missing_invoice":
				f.invoice = proPaidInvoice{}
			case "missing_discount_identity":
				f.invoice.Discounts[0].ID = ""
			}
			raw, _ := json.Marshal(map[string]any{"Coupon": coupon, "Invoice": f.invoice})
			waiver, err := renewalVerifiedWaiver(b, raw, discounts)
			if scenario == "expired_original" || scenario == "retained_original" {
				if err != nil || waiver.Coupon != f.p.WaiverCouponID || waiver.Discount != "di_waiver" {
					t.Fatal(waiver, err)
				}
			} else if err == nil {
				t.Fatal("unverified or foreign recurring discount accepted", waiver)
			}
		})
	}
}
