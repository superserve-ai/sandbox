//go:build integration

package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// The transport fixture stands in for the authenticated Stripe response. All
// other requests continue through the existing provider fixture.
func configurePairRejectionProvider(t *testing.T, h *Handlers, status int, body string) *atomic.Int32 {
	t.Helper()
	client := *h.Stripe.(*stripeHTTPClient)
	origin, err := url.Parse(client.baseURL)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	posts := new(atomic.Int32)
	httpClient := *client.httpClient
	httpClient.Transport = stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && req.URL.Path == "/v1/billing/credit_grants" {
			posts.Add(1)
			r := httptest.NewRecorder()
			r.Header().Set("Request-Id", "req_validation_fixture")
			r.WriteHeader(status)
			_, _ = r.WriteString(body)
			resp := r.Result()
			resp.Request = req
			resp.TLS = &tls.ConnectionState{HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{{}}}}
			return resp, nil
		}
		forward := req.Clone(req.Context())
		forward.URL.Scheme = origin.Scheme
		forward.URL.Host = origin.Host
		forward.Host = ""
		return transport.RoundTrip(forward)
	})
	client.baseURL = "https://api.stripe.com"
	client.httpClient = &httpClient
	h.Stripe = &client
	return posts
}

func TestProviderPairDispatchProvenRejection(t *testing.T) {
	for _, mode := range []string{"validation", "idempotency", "server"} {
		t.Run(mode, func(t *testing.T) {
			f := newPairWorkerFixture(t)
			status := 400
			body := `{"error":{"type":"invalid_request_error","code":"parameter_unknown"}}`
			if mode == "idempotency" {
				body = `{"error":{"type":"idempotency_error","message":"different parameters"}}`
			}
			if mode == "server" {
				status = 503
			}
			posts := configurePairRejectionProvider(t, f.h, status, body)
			if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err == nil {
				t.Fatal("expected provider rejection")
			}
			f.revoke(t)
			err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b)
			if mode == "validation" {
				if err != nil {
					t.Fatal("proven rejection blocked revocation", err)
				}
				if _, err = f.h.Pool.Exec(t.Context(), `UPDATE billing_provider_pair_dispatch SET rejected_at=NULL,rejection_evidence=NULL WHERE contract_id=$1`, f.b.ContractID); err == nil {
					t.Fatal("terminal rejection was mutable")
				}
			} else if !errors.Is(err, errProviderPairDispatchPending) {
				t.Fatal("ambiguous response allowed ACK", err)
			}
			_, _ = f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID)
			if posts.Load() != 1 {
				t.Fatal("rejection transferred send permission", posts.Load())
			}
		})
	}
}
