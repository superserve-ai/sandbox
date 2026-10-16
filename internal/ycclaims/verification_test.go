package ycclaims

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestVerificationTrustBoundary(t *testing.T) {
	for _, raw := range []string{"http://www.ycombinator.com/verify/a", "https://www.ycombinator.com.evil.test/verify/a", "https://user@www.ycombinator.com/verify/a", "https://www.ycombinator.com:443/verify/a", "https://www.ycombinator.com/verify/%61", "https://www.ycombinator.com/verify/a?next=evil", "https://www.ycombinator.com/verify/../a", "https://www.ycombinator.com/verify/a#token"} {
		if _, err := VerificationURL(raw); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	if got, _ := VerificationURL("https://ycombinator.com/verify/abc/"); got != "https://www.ycombinator.com/verify/abc" {
		t.Fatal(got)
	}
	if got, _ := Email(" Founder@Example.test "); got != "founder@example.test" {
		t.Fatal(got)
	}
	for _, raw := range []string{"Founder <founder@example.test>", "founder@example.test\r\nBcc:x@example.test"} {
		if _, err := Email(raw); err == nil {
			t.Fatal(raw)
		}
	}
}
func TestProviderEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body       string
		status           int
		valid, automatic bool
	}{
		{"match", `{"verified":true,"name":"Founder","email":"Founder@Example.test","companies":[{"name":"Example","batch":"W26","directory_url":"https://www.ycombinator.com/companies/example"}]}`, 200, true, true},
		{"missing optional evidence", `{"verified":true,"name":"Founder"}`, 200, true, false},
		{"ambiguous company", `{"verified":true,"name":"Founder","companies":[{"name":"A","batch":"W26","directory_url":"https://www.ycombinator.com/companies/a"},{"name":"B","batch":"W26","directory_url":"https://www.ycombinator.com/companies/b"}]}`, 200, true, false},
		{"false", `{"verified":false,"name":"Founder"}`, 200, false, false},
		{"string truth", `{"verified":"true","name":"Founder"}`, 200, false, false},
		{"redirect", `{}`, 302, false, false},
		{"provider outage", `{}`, 503, false, false},
		{"oversized", strings.Repeat(" ", 32769), 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewVerifier()
			v.Client.Transport = transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://www.ycombinator.com/verify/abc.json" {
					t.Fatal(r.URL)
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})
			e, ref, err := v.Verify(context.Background(), "https://ycombinator.com/verify/abc")
			if (err == nil) != tc.valid {
				t.Fatalf("err=%v", err)
			}
			if err == nil && (len(ref) != 64 || (e.AutomaticCompany() != "") != tc.automatic) {
				t.Fatalf("evidence=%+v ref=%s", e, ref)
			}
		})
	}
}
