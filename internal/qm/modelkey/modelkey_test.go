package modelkey

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// answer stands in for the provider. It records what it was asked so the
// test can check the key never travels anywhere but the auth header.
type answer struct {
	mu     sync.Mutex
	status int
	reqs   []*http.Request
}

func (a *answer) RoundTrip(req *http.Request) (*http.Response, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reqs = append(a.reqs, req)
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	for _, provider := range []string{"anthropic", "openai", "openrouter"} {
		if !Supported(provider) {
			t.Errorf("%s is not checkable", provider)
		}
		rejecting := &answer{status: http.StatusUnauthorized}
		if err := Verify(ctx, &http.Client{Transport: rejecting}, provider, "a-key"); !errors.Is(err, ErrRejected) {
			t.Errorf("%s rejection: err = %v", provider, err)
		}
		// The key rides in a header, never in the URL, where it would be
		// logged by every proxy in between.
		req := rejecting.reqs[0]
		if strings.Contains(req.URL.String(), "a-key") {
			t.Errorf("%s: the key is in the url %s", provider, req.URL)
		}

		accepting := &answer{status: http.StatusOK}
		if err := Verify(ctx, &http.Client{Transport: accepting}, provider, "a-key"); err != nil {
			t.Errorf("%s acceptance: %v", provider, err)
		}
	}
}

// Only an unambiguous rejection counts. A provider having a bad afternoon
// must not fail a create or a provision.
func TestVerifyToleratesEverythingElse(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{
		http.StatusOK, http.StatusNotFound, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
	} {
		if err := Verify(ctx, &http.Client{Transport: &answer{status: status}}, "anthropic", "a-key"); err != nil {
			t.Errorf("status %d: %v", status, err)
		}
	}
	// Not being able to reach the provider at all is not a rejection.
	if err := Verify(ctx, &http.Client{Transport: unreachable{}}, "anthropic", "a-key"); err != nil {
		t.Errorf("unreachable provider: %v", err)
	}
	// A provider nothing knows how to check passes without a request.
	if Supported("mistral") {
		t.Error("mistral reported as checkable")
	}
	if err := Verify(ctx, &http.Client{Transport: unreachable{}}, "mistral", "a-key"); err != nil {
		t.Errorf("unknown provider: %v", err)
	}
}

type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no route to the provider")
}
