package secretsproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/superserve-ai/sandbox/internal/egresspolicy"
)

func TestHTTPRulesClient404FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rules, err := NewHTTPRulesClient(srv.URL, "tok").FetchRules(context.Background(), "sb-gone")
	if err != nil {
		t.Fatalf("404 must resolve to a deny-all policy, not an error (which would serve last-known-good): %v", err)
	}
	if rules.UnmatchedHostPolicy != "deny" || len(rules.Allow) != 0 {
		t.Fatalf("404 must fail closed (deny-all); got %+v", rules)
	}
	// A destroyed sandbox must be denied egress to any host.
	if ok, _ := egresspolicy.EvalEgress("api.anthropic.com", nil, rules.Allow, rules.Deny, rules.UnmatchedHostPolicy); ok {
		t.Fatal("deny-all policy from a 404 still allowed egress")
	}
}

func TestHTTPRulesClient200ParsesRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allow":["api.anthropic.com"],"deny":[],"unmatched_host_policy":"passthrough"}`))
	}))
	defer srv.Close()

	rules, err := NewHTTPRulesClient(srv.URL, "tok").FetchRules(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("200 fetch: %v", err)
	}
	if len(rules.Allow) != 1 || rules.Allow[0] != "api.anthropic.com" {
		t.Fatalf("rules not parsed: %+v", rules)
	}
}
