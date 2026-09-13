// Package adminlink mints and verifies QM portal admin sign-in links.
//
// This is a port of the upstream QM CLI's `admin-login` command and the
// portal's verifier (cli/src/commands/admin-login.ts and
// plugins/portal/src/admin-login.ts in github.com/yc-software/qm): an
// HMAC-SHA256 sealed claim set, keyed by a label-derived subkey of the
// tenant's PORTAL_SESSION_SECRET, carried in the URL fragment so it never
// reaches the portal's access logs. The byte layout has to match exactly or
// the tenant's portal rejects the link, so the payload field order and the
// base64url (unpadded) encoding below mirror Node's JSON.stringify and
// Buffer.toString("base64url").
package adminlink

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// TTL is the link lifetime; the portal rejects anything longer.
	TTL = 5 * time.Minute

	keyLabel      = "portal.admin-login.v1"
	kind          = "admin-login"
	minSecretLen  = 32
	maxEmailLen   = 254
	maxTokenLen   = 4096
	jtiBytes      = 18 // base64url of 18 bytes is exactly the 24 chars the portal requires
	clockSkewSecs = 5
)

var (
	ErrPublicURL = errors.New("admin-login requires an HTTPS public URL (HTTP is allowed only on localhost)")
	ErrSecret    = errors.New("admin-login requires the deployment's PORTAL_SESSION_SECRET (at least 32 characters)")
	ErrEmail     = errors.New("admin-login requires a valid admin email")

	emailRe = regexp.MustCompile(`^[^@\s,;<>"]+@[^@\s,;<>"]+\.[^@\s,;<>"]+$`)
	jtiRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{24}$`)
)

// Claims is the sealed payload. Field order is part of the wire format.
type Claims struct {
	K   string `json:"k"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// Link is a minted admin sign-in link.
type Link struct {
	URL       string
	ExpiresAt time.Time
}

// Mint builds a link for email against publicURL, valid from now for TTL.
// jti must be 24 base64url characters (see NewJTI); tests pass a fixed one.
func Mint(publicURL, secret, email string, now time.Time, jti string) (Link, error) {
	origin, err := Origin(publicURL)
	if err != nil {
		return Link{}, err
	}
	if len(strings.TrimSpace(secret)) < minSecretLen {
		return Link{}, ErrSecret
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) > maxEmailLen || !emailRe.MatchString(email) {
		return Link{}, ErrEmail
	}
	if !jtiRe.MatchString(jti) {
		return Link{}, fmt.Errorf("admin-login: jti must be 24 base64url characters")
	}
	iat := now.Unix()
	claims := Claims{K: kind, Sub: email, Aud: origin, Iat: iat, Exp: iat + int64(TTL/time.Second), Jti: jti}
	body, err := marshalClaims(claims)
	if err != nil {
		return Link{}, err
	}
	token := body + "." + sign(deriveKey(secret), body)
	return Link{
		URL:       origin + "/auth/admin-login#token=" + token,
		ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}, nil
}

// NewJTI returns a fresh single-use link id in the portal's expected shape.
func NewJTI() (string, error) {
	var b [jtiBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Verify is the portal-side check (openAdminLogin), ported so tests can
// prove a minted link is one the tenant's portal will accept. It returns the
// admin email and link id on success and nil otherwise, exactly like upstream.
func Verify(token, secret, publicURL string, now time.Time) *Claims {
	if len(strings.TrimSpace(secret)) < minSecretLen || len(token) > maxTokenLen {
		return nil
	}
	claims, ok := open(token, deriveKey(secret))
	if !ok {
		return nil
	}
	nowSecs := now.Unix()
	switch {
	case claims.K != kind,
		claims.Aud != publicURL,
		len(claims.Sub) > maxEmailLen,
		!emailRe.MatchString(claims.Sub),
		claims.Sub != strings.ToLower(strings.TrimSpace(claims.Sub)),
		claims.Iat > nowSecs+clockSkewSecs,
		claims.Exp <= nowSecs,
		claims.Exp <= claims.Iat,
		claims.Exp-claims.Iat > int64(TTL/time.Second),
		!jtiRe.MatchString(claims.Jti):
		return nil
	}
	return &claims
}

// TokenFromURL extracts the token carried in a minted link's fragment.
func TokenFromURL(link string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return "", err
	}
	token := q.Get("token")
	if token == "" {
		return "", errors.New("admin-login: link carries no token")
	}
	return token, nil
}

// Origin applies the upstream CLI's public-URL rules and returns the
// WHATWG-style origin (scheme://host, default ports dropped, lowercase host).
func Origin(publicURL string) (string, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", ErrPublicURL
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	local := host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
	switch {
	case u.Scheme == "https":
		if port == "443" {
			port = ""
		}
	case u.Scheme == "http" && local:
		if port == "80" {
			port = ""
		}
	default:
		return "", ErrPublicURL
	}
	path := u.Path
	if path == "" {
		path = "/" // Node's URL normalizes a bare origin to pathname "/"
	}
	if path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || host == "" || strings.HasSuffix(host, ".") {
		return "", ErrPublicURL
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	origin := u.Scheme + "://" + host
	if port != "" {
		origin += ":" + port
	}
	return origin, nil
}

func deriveKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(keyLabel))
	return mac.Sum(nil)
}

func sign(key []byte, body string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// marshalClaims matches JSON.stringify: no HTML escaping, no trailing newline.
func marshalClaims(c Claims) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

func open(token string, key []byte) (Claims, bool) {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot == len(token)-1 {
		return Claims{}, false
	}
	body, got := token[:dot], token[dot+1:]
	if !hmac.Equal([]byte(got), []byte(sign(key, body))) {
		return Claims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Claims{}, false
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, false
	}
	return claims, true
}

// ValidEmail applies the portal's address rule (lowercased, trimmed,
// ≤254 chars, one @ and a dotted domain) so the API rejects an admin
// address that could never sign in.
func ValidEmail(email string) bool {
	return email != "" && len(email) <= maxEmailLen && email == strings.ToLower(strings.TrimSpace(email)) && emailRe.MatchString(email)
}
