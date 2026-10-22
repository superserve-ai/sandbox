//go:build yc_staging_validation

package ycclaims

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var stagingRunID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type stagingCapture struct {
	link, email string
	expires     time.Time
	now         func() time.Time
	real        CaptureVerifier
	fixture     *Verifier
}

// NewStagingCaptureVerifier is available only in the dedicated validation build.
// Runtime target authorization belongs to its caller, before installation.
func NewStagingCaptureVerifier(run, submittedEmail, expiry string) (CaptureVerifier, error) {
	email, err := Email(submittedEmail)
	expires, timeErr := time.Parse(time.RFC3339, expiry)
	now := time.Now()
	founder := "staging-" + run + "@example.test"
	if !stagingRunID.MatchString(run) || err != nil || email != submittedEmail || email == founder ||
		timeErr != nil || !expires.After(now) || expires.After(now.Add(time.Hour)) {
		return nil, errors.New("invalid staging capture binding")
	}
	link := "https://www.ycombinator.com/verify/staging-" + run
	body, err := json.Marshal(Evidence{Verified: true, Name: "Validation Founder", Email: founder,
		Companies: []Company{{Name: "Validation Company", Batch: "W26", DirectoryURL: "https://www.ycombinator.com/companies/staging-" + run}}})
	if err != nil {
		return nil, errors.New("invalid staging evidence")
	}
	fixture := NewVerifier()
	fixture.Client.Transport = stagingEvidenceTransport{url: link + ".json", body: string(body)}
	v := &stagingCapture{link: link, email: email, expires: expires, now: time.Now, real: VerifyCapture, fixture: fixture}
	return v.verify, nil
}

func (v *stagingCapture) verify(ctx context.Context, link, email string) (Evidence, string, error) {
	canonical, err := VerificationURL(link)
	if err != nil {
		return Evidence{}, "", err
	}
	if canonical != v.link {
		return v.real(ctx, link, email)
	}
	if link != v.link || email != v.email || !v.now().Before(v.expires) {
		return Evidence{}, "", ErrInvalid
	}
	return v.fixture.Verify(ctx, link)
}

type stagingEvidenceTransport struct{ url, body string }

func (t stagingEvidenceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.String() != t.url || r.URL.User != nil {
		return nil, ErrInvalid
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(t.body)), ContentLength: int64(len(t.body)), Request: r}, nil
}
