package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type stripeCheckoutReplayControl struct {
	base http.RoundTripper
	path string
}

func (c stripeCheckoutReplayControl) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == c.path {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return c.base.RoundTrip(req)
}

func TestStripeCheckoutTransportPreservesAmbiguousResponseFailure(t *testing.T) {
	testStripeTransportPreservesAmbiguousResponseFailure(t, "/v1/checkout/sessions")
}

func TestStripeCreditGrantTransportPreservesAmbiguousResponseFailure(t *testing.T) {
	testStripeTransportPreservesAmbiguousResponseFailure(t, "/v1/billing/credit_grants")
}

func testStripeTransportPreservesAmbiguousResponseFailure(t *testing.T, path string) {
	t.Helper()
	for _, allowReplay := range []bool{false, true} {
		name := "client_disables_hidden_replay"
		if allowReplay {
			name = "control_with_replay_enabled"
		}
		t.Run(name, func(t *testing.T) {
			var mutationCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				if r.URL.Path == "/v1/customers" {
					_, _ = io.WriteString(w, `{"id":"cus_transport"}`)
					return
				}
				if r.URL.Path != path || r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") == "" {
					t.Errorf("unexpected mutation request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				if mutationCalls.Add(1) == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack mutation connection: %v", err)
						return
					}
					_ = conn.Close()
					return
				}
				http.Error(w, "request in progress", http.StatusConflict)
			}))
			defer server.Close()
			transport := &http.Transport{MaxIdleConnsPerHost: 1}
			defer transport.CloseIdleConnections()
			var roundTripper http.RoundTripper = transport
			if allowReplay {
				// The control proves this fixture triggers net/http's replay when
				// the GetBody protection is absent.
				roundTripper = stripeCheckoutReplayControl{base: transport, path: path}
			}
			client := &stripeHTTPClient{
				baseURL: server.URL, secretKey: "sk_test_example", apiVersion: "2025-06-30",
				httpClient: &http.Client{Transport: roundTripper, Timeout: 5 * time.Second},
			}
			if _, err := client.CreateCustomer(t.Context(), StripeCreateCustomerParams{Name: "example-team"}); err != nil {
				t.Fatalf("warm keep-alive connection: %v", err)
			}
			var connections atomic.Int32
			var reusedWarmConnection atomic.Bool
			ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				if connections.Add(1) == 1 {
					reusedWarmConnection.Store(info.Reused)
				}
			}})
			var err error
			if path == "/v1/checkout/sessions" {
				_, err = client.CreateCheckoutSession(ctx, StripeCreateCheckoutSessionParams{
					CustomerID: "cus_transport", SuccessURL: "https://example.com/success", CancelURL: "https://example.com/cancel",
					PriceIDs: []string{"price_example"}, IdempotencyKey: "checkout:transport-example",
				})
			} else {
				_, err = client.CreateBillingCreditGrant(ctx, StripeCreateBillingCreditGrantParams{
					CustomerID: "cus_transport", AmountCents: 9500, IdempotencyKey: "credit:transport-example",
				})
			}
			if !reusedWarmConnection.Load() {
				t.Fatal("mutation did not reuse the warmed connection")
			}
			wantCalls := int32(1)
			var transportError *url.Error
			if allowReplay {
				wantCalls = 2
				if err == nil || errors.As(err, &transportError) || !strings.Contains(err.Error(), "returned 409") {
					t.Fatalf("replay control did not replace the transport failure with a 409: %v", err)
				}
			} else if !errors.As(err, &transportError) {
				t.Fatalf("mutation lost the ambiguous transport failure: %v", err)
			}
			if got := mutationCalls.Load(); got != wantCalls {
				t.Fatalf("mutation wire requests = %d, want %d", got, wantCalls)
			}
		})
	}
}
