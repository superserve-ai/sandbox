// Package ycclaims validates provider evidence without trusting browser claims.
package ycclaims

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid YC founder verification")
var ErrUnavailable = errors.New("YC verification unavailable")
var codePath = regexp.MustCompile(`^/verify/([A-Za-z0-9_-]{1,256})/?$`)
var companyPath = regexp.MustCompile(`^/companies/([a-z0-9][a-z0-9-]{0,199})/?$`)

type Company struct {
	Name         string `json:"name"`
	Batch        string `json:"batch"`
	DirectoryURL string `json:"directory_url"`
}

type Evidence struct {
	Verified  bool      `json:"verified"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Companies []Company `json:"companies"`
	Batches   []struct {
		Name string `json:"name"`
	} `json:"batches"`
}

func Email(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || len(v) > 254 || strings.ContainsAny(v, "\r\n\x00") {
		return "", ErrInvalid
	}
	return v, nil
}

func VerificationURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || (u.Host != "www.ycombinator.com" && u.Host != "ycombinator.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalid
	}
	m := codePath.FindStringSubmatch(u.Path)
	if len(m) != 2 || u.RawPath != "" {
		return "", ErrInvalid
	}
	return "https://www.ycombinator.com/verify/" + m[1], nil
}

func CompanyIdentity(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || (u.Host != "www.ycombinator.com" && u.Host != "ycombinator.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return ""
	}
	m := companyPath.FindStringSubmatch(u.Path)
	if len(m) != 2 {
		return ""
	}
	return "https://www.ycombinator.com/companies/" + m[1]
}

// Only an unambiguous company with batch evidence takes the automatic path.
func (e Evidence) AutomaticCompany() string {
	if len(e.Companies) != 1 || strings.TrimSpace(e.Companies[0].Batch) == "" {
		return ""
	}
	return CompanyIdentity(e.Companies[0].DirectoryURL)
}

func Hash(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }

type Verifier struct{ Client *http.Client }

func NewVerifier() *Verifier {
	return &Verifier{Client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (v *Verifier) Verify(ctx context.Context, link string) (Evidence, string, error) {
	u, err := VerificationURL(link)
	if err != nil {
		return Evidence{}, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+".json", nil)
	if err != nil {
		return Evidence{}, "", ErrInvalid
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.Client.Do(req)
	if err != nil {
		return Evidence{}, "", ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return Evidence{}, "", ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return Evidence{}, "", ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(b) > 32768 {
		return Evidence{}, "", ErrInvalid
	}
	var e Evidence
	if json.Unmarshal(b, &e) != nil || !e.Verified || strings.TrimSpace(e.Name) == "" || len(e.Name) > 256 || len(e.Companies) > 20 || len(e.Batches) > 20 {
		return Evidence{}, "", ErrInvalid
	}
	for _, c := range e.Companies {
		if strings.TrimSpace(c.Name) == "" || len(c.Name) > 256 || len(c.Batch) > 64 || len(c.DirectoryURL) > 512 {
			return Evidence{}, "", ErrInvalid
		}
	}
	for _, b := range e.Batches {
		if strings.TrimSpace(b.Name) == "" || len(b.Name) > 64 {
			return Evidence{}, "", ErrInvalid
		}
	}
	// Missing optional provider fields are durable manual-review evidence.
	if e.Email != "" {
		e.Email, err = Email(e.Email)
		if err != nil {
			return Evidence{}, "", ErrInvalid
		}
	}
	return e, Hash(u), nil
}
