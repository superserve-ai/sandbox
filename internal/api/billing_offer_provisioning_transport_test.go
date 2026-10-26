package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

func savedOfferWireRequest(step provisioning.Step, path string) provisioning.SavedRequest {
	now := time.Now()
	id := uuid.New()
	return provisioning.SavedRequest{
		OperationID: id, Step: step, Key: fmt.Sprintf("offer-provisioning/%s/%s/v1", id, step),
		Offer:   provisioning.AcceptedOffer{AcceptanceID: uuid.New(), Merchant: "acct_example", APIVersion: "2026-05-27.dahlia"},
		Request: provisioning.NewRequest(path, "metadata%5Bexample%5D=exact+saved%2Bbody"), State: "dispatched", DispatchedAt: &now,
	}
}

func offerWireServer(t *testing.T, account, balance string, post http.HandlerFunc) *stripeHTTPClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Stripe-Version") != "2026-05-27.dahlia" {
			t.Error("lost pinned API version")
		}
		name, _, ok := r.BasicAuth()
		if !ok || name != "fixture-secret" {
			t.Error("missing configured authentication")
		}
		if r.Method == http.MethodPost {
			post(w, r)
			return
		}
		if r.Header.Get("Idempotency-Key") != "" {
			t.Error("read carries write idempotency key")
		}
		switch r.URL.Path {
		case "/v1/account":
			fmt.Fprint(w, account)
		case "/v1/balance":
			fmt.Fprint(w, balance)
		default:
			t.Errorf("unexpected read %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return &stripeHTTPClient{baseURL: server.URL, secretKey: "fixture-secret", apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
}

func TestOfferProviderTransportPreservesEverySavedWrite(t *testing.T) {
	for step, path := range map[provisioning.Step]string{provisioning.Customer: "/v1/customers", provisioning.Waiver: "/v1/coupons", provisioning.Fee: "/v1/subscriptions", provisioning.Usage: "/v1/subscriptions", provisioning.UsageHold: "/v1/subscriptions/sub_example"} {
		t.Run(string(step), func(t *testing.T) {
			saved := savedOfferWireRequest(step, path)
			var writes atomic.Int32
			client := offerWireServer(t, `{"id":"acct_example"}`, `{"livemode":false}`, func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.URL.RequestURI() != saved.Request.Path || string(body) != saved.Request.Payload || r.Header.Get("Idempotency-Key") != saved.Key || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("saved request changed")
				}
				fmt.Fprint(w, `{"id":"provider_example"}`)
			})
			preflight := saved
			preflight.State, preflight.DispatchedAt = "prepared", nil
			if err := client.preflightOfferProviderRequest(t.Context(), preflight); err != nil {
				t.Fatal(err)
			}
			if raw, err := client.sendOfferProviderRequest(t.Context(), saved); err != nil || string(raw) != `{"id":"provider_example"}` || writes.Load() != 1 {
				t.Fatal(string(raw), err, writes.Load())
			}
		})
	}
}

func TestOfferProviderTransportRejectsWrongIdentityBeforeWrite(t *testing.T) {
	for _, test := range []struct{ name, account, balance string }{
		{"merchant", `{"id":"acct_other"}`, `{"livemode":false}`},
		{"mode", `{"id":"acct_example"}`, `{"livemode":true}`},
		{"missing_mode", `{"id":"acct_example"}`, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := offerWireServer(t, test.account, test.balance, func(http.ResponseWriter, *http.Request) { t.Error("unexpected write") })
			saved := savedOfferWireRequest(provisioning.Customer, "/v1/customers")
			saved.State, saved.DispatchedAt = "prepared", nil
			if err := client.preflightOfferProviderRequest(t.Context(), saved); !errors.Is(err, provisioning.ErrConflict) {
				t.Fatal(err)
			}
		})
	}
}

func TestOfferProviderTransportRejectsAlteredOrUncommittedRequest(t *testing.T) {
	for _, mutate := range []func(*provisioning.SavedRequest){
		func(r *provisioning.SavedRequest) { r.Request.Payload += "&extra=1" },
		func(r *provisioning.SavedRequest) { r.Offer.APIVersion = "other" },
		func(r *provisioning.SavedRequest) { r.State = "prepared" },
		func(r *provisioning.SavedRequest) { r.DispatchedAt = nil },
		func(r *provisioning.SavedRequest) { r.Key = "other" },
		func(r *provisioning.SavedRequest) {
			r.Request = provisioning.NewRequest("/v1/subscriptions/sub_example/cancel", "reason=test")
		},
	} {
		client := &stripeHTTPClient{secretKey: "fixture-secret", apiVersion: "2026-05-27.dahlia", httpClient: http.DefaultClient}
		saved := savedOfferWireRequest(provisioning.Customer, "/v1/customers")
		mutate(&saved)
		if _, err := client.sendOfferProviderRequest(t.Context(), saved); !errors.Is(err, provisioning.ErrConflict) {
			t.Fatal(err)
		}
	}
}

func TestOfferProviderTransportNeverRepeatsUncertainWrite(t *testing.T) {
	for _, failure := range []string{"disconnect", "redirect", "provider_error", "oversized", "null"} {
		t.Run(failure, func(t *testing.T) {
			var writes atomic.Int32
			client := offerWireServer(t, `{"id":"acct_example"}`, `{"livemode":false}`, func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch failure {
				case "disconnect":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
				case "redirect":
					w.Header().Set("Location", "/v1/customers")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "provider_error":
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, `{"error":"sensitive provider error"}`)
				case "oversized":
					fmt.Fprint(w, `{"value":"`+strings.Repeat("x", 1024*1024)+`"}`)
				case "null":
					fmt.Fprint(w, "null")
				}
			})
			_, err := client.sendOfferProviderRequest(t.Context(), savedOfferWireRequest(provisioning.Customer, "/v1/customers"))
			if !errors.Is(err, provisioning.ErrUnknown) || writes.Load() != 1 || strings.Contains(err.Error(), "sensitive") {
				t.Fatal(err, writes.Load())
			}
		})
	}
}

func TestOfferProviderPreflightFailureCanRetryBeforeDispatch(t *testing.T) {
	var reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writes.Add(1)
			fmt.Fprint(w, `{"id":"cus_example"}`)
			return
		}
		if r.URL.Path == "/v1/account" {
			if reads.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, `{"id":"acct_example"}`)
			return
		}
		fmt.Fprint(w, `{"livemode":false}`)
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, secretKey: "fixture-secret", apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
	r := savedOfferWireRequest(provisioning.Customer, "/v1/customers")
	r.State, r.DispatchedAt = "prepared", nil
	if err := client.preflightOfferProviderRequest(t.Context(), r); err == nil {
		t.Fatal("expected transient failure")
	}
	if writes.Load() != 0 {
		t.Fatal("preflight wrote provider state")
	}
	if err := client.preflightOfferProviderRequest(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.State, r.DispatchedAt = "dispatched", &now
	if _, err := client.sendOfferProviderRequest(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal(writes.Load())
	}
}
