//go:build yc_staging_validation

package ycclaims

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testStagingRun = "0123456789abcdef0123456789abcdef"

func TestStagingCaptureBinding(t *testing.T) {
	link := "https://www.ycombinator.com/verify/staging-" + testStagingRun
	expiry := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	before := http.DefaultTransport
	verify, err := NewStagingCaptureVerifier(testStagingRun, "customer@example.test", expiry)
	if err != nil {
		t.Fatal(err)
	}
	e, ref, err := verify(t.Context(), link, "customer@example.test")
	if err != nil || !e.Verified || e.Email != "staging-"+testStagingRun+"@example.test" ||
		e.AutomaticCompany() != "https://www.ycombinator.com/companies/staging-"+testStagingRun || ref != Hash(link) {
		t.Fatalf("invalid fixture result: %+v %q %v", e, ref, err)
	}
	if before != http.DefaultTransport {
		t.Fatal("changed global transport")
	}
	for _, tc := range []struct{ link, email string }{
		{link, "other@example.test"}, {link, "Customer@example.test"},
		{link + "/", "customer@example.test"},
		{strings.Replace(link, "www.ycombinator", "ycombinator", 1), "customer@example.test"},
		{link + "?verified=true", "customer@example.test"},
	} {
		if e, ref, err := verify(t.Context(), tc.link, tc.email); err == nil || e.Verified || ref != "" {
			t.Fatalf("mismatched request yielded evidence: %+v", tc)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := verify(ctx, link, "customer@example.test"); err == nil {
		t.Fatal("ignored canceled request")
	}
}

func TestStagingCaptureInvalidConfiguration(t *testing.T) {
	future := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	for _, tc := range []struct{ run, email, expiry string }{
		{"", "customer@example.test", future}, {"local-test", "customer@example.test", future},
		{strings.Repeat("0", 31), "customer@example.test", future},
		{testStagingRun, "Customer@example.test", future}, {testStagingRun, "bad", future},
		{testStagingRun, "staging-" + testStagingRun + "@example.test", future},
		{testStagingRun, "customer@example.test", ""},
		{testStagingRun, "customer@example.test", time.Now().Add(-time.Second).UTC().Format(time.RFC3339)},
		{testStagingRun, "customer@example.test", time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)},
	} {
		if got, err := NewStagingCaptureVerifier(tc.run, tc.email, tc.expiry); got != nil || err == nil {
			t.Fatalf("accepted invalid configuration: %+v", tc)
		}
	}
}

func TestStagingExpiryDoesNotReplaceRealVerification(t *testing.T) {
	now := time.Now()
	link := "https://www.ycombinator.com/verify/staging-" + testStagingRun
	calls := 0
	wantErr := errors.New("real provider unavailable")
	v := stagingCapture{link: link, email: "customer@example.test", expires: now, now: func() time.Time { return now },
		real: func(_ context.Context, gotLink, email string) (Evidence, string, error) {
			calls++
			if gotLink == link || email != "customer@example.test" {
				t.Fatal("unexpected delegation")
			}
			return Evidence{}, "", wantErr
		}}
	if e, _, err := v.verify(t.Context(), link, v.email); err != ErrInvalid || e.Verified || calls != 0 {
		t.Fatal("expired fixture was not rejected before verification")
	}
	for _, realLink := range []string{"https://www.ycombinator.com/verify/real-proof", "https://www.ycombinator.com/verify/staging-" + strings.Repeat("f", 32)} {
		if _, _, err := v.verify(t.Context(), realLink, v.email); err != wantErr {
			t.Fatal("unbound request lost normal verifier behavior", err)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
