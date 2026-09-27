package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type stripeCheckoutRecoveryRoundTripper func(*http.Request) (*http.Response, error)

func (f stripeCheckoutRecoveryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestStripeRetrieveCheckoutSessionReadsExistingSession(t *testing.T) {
	calls := 0
	client := &stripeHTTPClient{
		baseURL:    "https://stripe.example.test",
		secretKey:  "sk_test_example",
		apiVersion: "2025-06-30",
		httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Method != http.MethodGet || req.URL.String() != "https://stripe.example.test/v1/checkout/sessions/cs_test_existing" {
				t.Fatalf("unexpected provider request: %s %s", req.Method, req.URL)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer sk_test_example" {
				t.Fatalf("Authorization = %q", got)
			}
			if got := req.Header.Get("Stripe-Version"); got != "2025-06-30" {
				t.Fatalf("Stripe-Version = %q", got)
			}
			if got := req.Header.Get("Idempotency-Key"); got != "" {
				t.Fatalf("retrieve sent an idempotency key: %q", got)
			}
			if req.Body != nil || req.ContentLength != 0 {
				t.Fatal("retrieve sent a request body")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"id":"cs_test_existing",
					"url":"https://checkout.stripe.test/existing",
					"customer":"cus_example",
					"client_reference_id":"example-team",
					"status":"open",
					"mode":"subscription",
					"expires_at":1787331600,
					"metadata":{"team_id":"example-team","activation_user_id":"example-user","checkout_generation":"example-generation"}
				}`)),
				Header:  make(http.Header),
				Request: req,
			}, nil
		})},
	}
	var retriever stripeCheckoutSessionRetriever = client
	session, err := retriever.RetrieveCheckoutSession(t.Context(), "cs_test_existing")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
	if session.ID != "cs_test_existing" || session.URL != "https://checkout.stripe.test/existing" || session.CustomerID != "cus_example" || session.ClientReferenceID != "example-team" || session.Status != "open" || session.Mode != "subscription" || session.ExpiresAt != 1787331600 {
		t.Fatalf("unexpected retrieved session: %+v", session)
	}
	if session.Metadata["team_id"] != "example-team" || session.Metadata["activation_user_id"] != "example-user" || session.Metadata["checkout_generation"] != "example-generation" {
		t.Fatalf("unexpected session metadata: %v", session.Metadata)
	}
}

func TestStripeRetrieveCheckoutSessionErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		notFound bool
	}{
		{name: "not found", status: http.StatusNotFound, body: `{"error":{"code":"resource_missing"}}`, notFound: true},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"error":{"message":"No such checkout session"}}`},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"error":{"message":"retry later"}}`},
		{name: "provider failure", status: http.StatusInternalServerError, body: `{"error":{"message":"404 upstream failure"}}`},
		{name: "malformed JSON", status: http.StatusOK, body: `{"id":`},
		{name: "invalid customer type", status: http.StatusOK, body: `{"id":"cs_test_existing","customer":123}`},
		{name: "invalid expiry type", status: http.StatusOK, body: `{"id":"cs_test_existing","expires_at":"tomorrow"}`},
		{name: "missing ID", status: http.StatusOK, body: `{}`},
		{name: "null response", status: http.StatusOK, body: `null`},
		{name: "empty response", status: http.StatusNoContent},
		{name: "trailing JSON", status: http.StatusOK, body: `{"id":"cs_test_existing"}{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &stripeHTTPClient{
				baseURL:    "https://stripe.example.test",
				secretKey:  "sk_test_example",
				apiVersion: "2025-06-30",
				httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header), Request: req}, nil
				})},
			}
			_, err := client.RetrieveCheckoutSession(t.Context(), "cs_test_existing")
			if err == nil || errors.Is(err, ErrStripeCheckoutSessionNotFound) != tc.notFound {
				t.Fatalf("retrieve error = %v, want error with not-found=%t", err, tc.notFound)
			}
		})
	}
}

func TestStripeRetrieveCheckoutSessionAllowsCompletedSessionWithoutURL(t *testing.T) {
	client := &stripeHTTPClient{
		baseURL:    "https://stripe.example.test",
		secretKey:  "sk_test_example",
		apiVersion: "2025-06-30",
		httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id":"cs_test_existing","url":null,"status":"complete"}`)), Header: make(http.Header), Request: req}, nil
		})},
	}
	session, err := client.RetrieveCheckoutSession(t.Context(), "cs_test_existing")
	if err != nil || session.Status != "complete" || session.URL != "" {
		t.Fatalf("retrieve completed session = %+v, %v", session, err)
	}
}

func TestStripeRetrieveCheckoutSessionRejectsInvalidIDsBeforeProviderCall(t *testing.T) {
	client := &stripeHTTPClient{
		baseURL:    "https://stripe.example.test",
		secretKey:  "sk_test_example",
		apiVersion: "2025-06-30",
		httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("invalid session ID reached provider: %s", req.URL)
			return nil, errors.New("unexpected provider call")
		})},
	}
	for _, sessionID := range []string{"", "cs_", "cus_example", " cs_test_existing", "cs_test_existing ", "cs_test_a/b", "cs_test_a?expand[]=customer", "cs_test_a#fragment", "cs_test_../x", "cs_test_a%2Fb", "cs_test_é"} {
		if _, err := client.RetrieveCheckoutSession(t.Context(), sessionID); err == nil {
			t.Errorf("session ID %q was accepted", sessionID)
		}
	}
}

func TestStripeRetrieveCheckoutSessionRequiresConfiguredVersion(t *testing.T) {
	client := &stripeHTTPClient{
		baseURL:   "https://stripe.example.test",
		secretKey: "sk_test_example",
		httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Fatal("unversioned retrieve reached provider")
			return nil, errors.New("unexpected provider call")
		})},
	}
	if _, err := client.RetrieveCheckoutSession(t.Context(), "cs_test_existing"); err == nil {
		t.Fatal("unversioned retrieve was accepted")
	}
}

func TestStripeRetrieveCheckoutSessionPropagatesTransportFailure(t *testing.T) {
	for _, cause := range []error{errors.New("provider unavailable"), context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			client := &stripeHTTPClient{
				baseURL:    "https://stripe.example.test",
				secretKey:  "sk_test_example",
				apiVersion: "2025-06-30",
				httpClient: &http.Client{Transport: stripeCheckoutRecoveryRoundTripper(func(*http.Request) (*http.Response, error) {
					return nil, cause
				})},
			}
			if _, err := client.RetrieveCheckoutSession(t.Context(), "cs_test_existing"); !errors.Is(err, cause) || errors.Is(err, ErrStripeCheckoutSessionNotFound) {
				t.Fatalf("transport error = %v, want %v", err, cause)
			}
		})
	}
}
