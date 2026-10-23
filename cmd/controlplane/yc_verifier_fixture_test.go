//go:build yc_verifier_fixture

package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

type fixtureUpstream func(*http.Request) (*http.Response, error)

func (f fixtureUpstream) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestYCFixtureTransportBoundary(t *testing.T) {
	delegated := 0
	transport := newYCFixtureTransport(fixtureUpstream(func(r *http.Request) (*http.Response, error) {
		delegated++
		return &http.Response{StatusCode: http.StatusNoContent, Request: r}, nil
	}), "boundary-test")
	v := ycclaims.NewVerifier()
	v.Client.Transport = transport
	evidence, _, err := v.Verify(context.Background(), "https://www.ycombinator.com/verify/synthetic-boundary-test-a")
	if err != nil || evidence.Email != "synthetic-boundary-test-a@example.test" || evidence.AutomaticCompany() != "https://www.ycombinator.com/companies/synthetic-boundary-test-a" {
		t.Fatal("real parser rejected synthetic evidence", evidence, err)
	}
	for _, url := range []string{
		"https://www.ycombinator.com/verify/unbound.json",
		"http://www.ycombinator.com/verify/synthetic-boundary-test-a.json",
		"https://www.ycombinator.com:443/verify/synthetic-boundary-test-a.json",
		"https://www.ycombinator.com/verify/synthetic-boundary-test-a.json?extra=1",
		"https://ycombinator.com/verify/synthetic-boundary-test-a.json",
	} {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		if _, err := transport.RoundTrip(req); err == nil {
			t.Error("unbound request accepted", url)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "https://www.ycombinator.com/verify/synthetic-boundary-test-a.json", nil)
	if _, err = transport.RoundTrip(req); err == nil {
		t.Fatal("provider mutation accepted")
	}
	if delegated != 0 {
		t.Fatal("unbound verification escaped to live provider")
	}
	for _, url := range []string{"https://api.stripe.com/v1/account", "http://127.0.0.1:54321/auth/v1/health"} {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		response, err := transport.RoundTrip(req)
		if err != nil || response.StatusCode != http.StatusNoContent || response.Request != req {
			t.Fatal("non-verifier transport changed", response, err)
		}
	}
	if delegated != 2 {
		t.Fatal("non-verifier requests were not delegated exactly once", delegated)
	}
}
