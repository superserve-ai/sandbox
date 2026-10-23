//go:build yc_verifier_fixture

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// This separate test binary must never be deployed to a customer environment.
// A build-time run ID keeps synthetic identities distinct across disposable runs.
var ycFixtureRunID = "local-test"

func init() {
	if !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(ycFixtureRunID) {
		panic("invalid synthetic verifier run ID")
	}
	http.DefaultTransport = newYCFixtureTransport(http.DefaultTransport, ycFixtureRunID)
}

type ycFixtureTransport struct {
	upstream http.RoundTripper
	bodies   map[string]string
}

func newYCFixtureTransport(upstream http.RoundTripper, run string) *ycFixtureTransport {
	t := &ycFixtureTransport{upstream: upstream, bodies: map[string]string{}}
	for _, suffix := range []string{"a", "b"} {
		identity := "synthetic-" + run + "-" + suffix
		body, _ := json.Marshal(map[string]any{
			"verified": true, "name": "Synthetic Founder", "email": identity + "@example.test",
			"companies": []any{map[string]string{"name": "Synthetic Company", "batch": "W26", "directory_url": "https://www.ycombinator.com/companies/" + identity}},
		})
		t.bodies["https://www.ycombinator.com/verify/"+identity+".json"] = string(body)
	}
	return t
}

func (t *ycFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if host != "www.ycombinator.com" && host != "ycombinator.com" {
		return t.upstream.RoundTrip(req)
	}
	body, ok := t.bodies[req.URL.String()]
	if !ok || req.Method != http.MethodGet || req.URL.User != nil {
		return nil, errors.New("synthetic verifier refused unbound provider request")
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
}
