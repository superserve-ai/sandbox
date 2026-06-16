package secretsproxy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// backgroundRefreshTimeout caps an async JWKS fetch — long enough for a slow
// control plane, short enough that a stuck fetcher doesn't hold a goroutine.
const backgroundRefreshTimeout = 30 * time.Second

// secretsJWTIssuer is the iss claim the daemon requires; matches the control
// plane's `api.SecretsJWTIssuer`.
const secretsJWTIssuer = "superserve-controlplane"

// JWTBindingClaim mirrors `api.SecretsBindingClaim` over the JWT wire shape.
// When Rules is present, AuthType/AuthConfig are unused; the daemon dispatches
// by upstream host using the rule list.
type JWTBindingClaim struct {
	ProxyToken string         `json:"p"`
	SecretID   string         `json:"s"`
	EnvKey     string         `json:"e"`
	Hosts      []string       `json:"h"`
	AuthType   string         `json:"t,omitempty"`
	AuthConfig map[string]any `json:"c,omitempty"`
	Rules      []JWTRuleClaim `json:"rules,omitempty"`
}

// JWTRuleClaim is one (hosts → auth shape) entry inside JWTBindingClaim.Rules.
type JWTRuleClaim struct {
	Hosts    []string          `json:"h"`
	AuthType string            `json:"t"`
	Username string            `json:"u,omitempty"`
	Header   string            `json:"hd,omitempty"`
	Prefix   string            `json:"pf,omitempty"`
	Headers  map[string]string `json:"hs,omitempty"`
}

// JWTClaims is the parsed JWT payload. Egress rules are not carried here — the
// proxy fetches them live so a PATCH applies without re-minting.
type JWTClaims struct {
	TeamID   string            `json:"team_id"`
	SourceIP string            `json:"source_ip"`
	Bindings []JWTBindingClaim `json:"bindings,omitempty"`

	jwt.RegisteredClaims
}

// JWT verification errors. Discrete sentinel values so callers can branch on
// reason (typically all map to 407 on the wire).
var (
	ErrJWTMissing          = errors.New("secretsproxy: jwt missing")
	ErrJWTMalformed        = errors.New("secretsproxy: jwt malformed")
	ErrJWTBadSignature     = errors.New("secretsproxy: jwt signature failed")
	ErrJWTExpired          = errors.New("secretsproxy: jwt expired")
	ErrJWTWrongIssuer      = errors.New("secretsproxy: jwt wrong issuer")
	ErrJWTUnknownKid       = errors.New("secretsproxy: jwt unknown kid")
	ErrJWTSourceIPMismatch = errors.New("secretsproxy: jwt source_ip does not match remote address")
	ErrJWTMissingClaim     = errors.New("secretsproxy: jwt missing required claim")
)

// JWKSFetcher loads the set of trusted verification keys. The production
// implementation hits the control plane's /internal/jwks endpoint; tests
// inject a stub that returns canned keys.
type JWKSFetcher interface {
	Fetch(ctx context.Context) (map[string]ed25519.PublicKey, error)
}

// Verifier parses and verifies secrets JWTs against keys fetched from a
// JWKSFetcher. Concurrency-safe; the key map is replaced atomically on refresh.
type Verifier struct {
	fetcher JWKSFetcher

	mu            sync.RWMutex
	keys          map[string]ed25519.PublicKey
	lastFetch     time.Time
	missCooldown  time.Duration // bounds how often a kid miss can trigger a refresh
	lastMissFetch time.Time
	refreshing    bool // true while a background JWKS fetch is in flight
	clock         func() time.Time

	// backgroundRefreshes increments after each background refresh attempt
	// (success or failure). Tests observe completion via this counter.
	backgroundRefreshes atomic.Uint64
}

// NewVerifier builds a Verifier and performs the initial JWKS load. Returns
// an error if the initial load fails — the daemon should refuse to start in
// that state rather than accept any JWT silently.
func NewVerifier(ctx context.Context, fetcher JWKSFetcher) (*Verifier, error) {
	v := &Verifier{
		fetcher:      fetcher,
		missCooldown: 60 * time.Second,
		clock:        time.Now,
	}
	if err := v.refresh(ctx); err != nil {
		return nil, fmt.Errorf("initial JWKS load: %w", err)
	}
	return v, nil
}

// Refresh re-fetches the JWKS and atomically replaces the cached keys.
func (v *Verifier) Refresh(ctx context.Context) error { return v.refresh(ctx) }

func (v *Verifier) refresh(ctx context.Context) error {
	keys, err := v.fetcher.Fetch(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = keys
	v.lastFetch = v.clock()
	v.mu.Unlock()
	return nil
}

// Verify parses jwtString, verifies signature + standard claims, and checks
// that the source_ip claim matches expectedSourceIP. On unknown kid, the
// verifier attempts one cached refresh (debounced) before failing.
func (v *Verifier) Verify(ctx context.Context, jwtString, expectedSourceIP string) (*JWTClaims, error) {
	if jwtString == "" {
		return nil, ErrJWTMissing
	}

	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(jwtString, claims, v.keyfunc(ctx),
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(secretsJWTIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	if !token.Valid {
		return nil, ErrJWTBadSignature
	}

	if claims.TeamID == "" || claims.SourceIP == "" || claims.Subject == "" {
		return nil, ErrJWTMissingClaim
	}
	if claims.SourceIP != expectedSourceIP {
		return nil, ErrJWTSourceIPMismatch
	}
	return claims, nil
}

// keyfunc returns the per-Parse callback the JWT library uses to look up a
// public key by kid. On unknown kid, kicks off an async JWKS refresh and
// fails the current request — JWKS fetch latency never blocks the request
// path; the next request after refresh completes will succeed.
func (v *Verifier) keyfunc(_ context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, ErrJWTMalformed
		}
		if key, ok := v.lookup(kid); ok {
			return key, nil
		}
		v.maybeRefreshAsync()
		return nil, ErrJWTUnknownKid
	}
}

// maybeRefreshAsync kicks off a JWKS refresh in a background goroutine if
// (a) the miss cooldown has elapsed and (b) no refresh is already in flight.
// Detached from the request context so the refresh isn't cancelled when the
// request returns.
func (v *Verifier) maybeRefreshAsync() {
	v.mu.Lock()
	now := v.clock()
	if v.refreshing || now.Sub(v.lastMissFetch) < v.missCooldown {
		v.mu.Unlock()
		return
	}
	v.refreshing = true
	v.lastMissFetch = now
	v.mu.Unlock()

	go func() {
		defer func() {
			v.mu.Lock()
			v.refreshing = false
			v.mu.Unlock()
			v.backgroundRefreshes.Add(1)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), backgroundRefreshTimeout)
		defer cancel()
		_ = v.refresh(ctx)
	}()
}

func (v *Verifier) lookup(kid string) (ed25519.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	return key, ok
}

// mapJWTError converts library errors to our sentinels so callers can branch
// uniformly. Anything we don't recognize maps to ErrJWTBadSignature.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return ErrJWTExpired
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return ErrJWTWrongIssuer
	case errors.Is(err, ErrJWTUnknownKid):
		return ErrJWTUnknownKid
	case errors.Is(err, ErrJWTMalformed):
		return ErrJWTMalformed
	case errors.Is(err, jwt.ErrTokenMalformed):
		return ErrJWTMalformed
	default:
		return ErrJWTBadSignature
	}
}

// HTTPJWKSFetcher reads the JWKS from the control plane's /internal/jwks
// endpoint. Authenticates with the daemon's shared token (same as the vault
// decrypt path).
type HTTPJWKSFetcher struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewHTTPJWKSFetcher builds a fetcher targeting {baseURL}/internal/jwks.
func NewHTTPJWKSFetcher(baseURL, authToken string) *HTTPJWKSFetcher {
	return &HTTPJWKSFetcher{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authToken:  authToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// jwksResponse mirrors the wire shape of /internal/jwks. Only Ed25519 keys
// (kty=OKP, crv=Ed25519) are accepted; other entries are skipped.
type jwksResponse struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	} `json:"keys"`
}

// Fetch implements JWKSFetcher.
func (f *HTTPJWKSFetcher) Fetch(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.baseURL+"/internal/jwks", nil)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.authToken)
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("control plane rejected daemon auth on JWKS fetch (%d): check DAEMON_AUTH_TOKEN matches control plane INTERNAL_API_TOKEN", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("control plane returned %d on JWKS fetch: %s", resp.StatusCode, string(raw))
	}
	var body jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	out := make(map[string]ed25519.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			continue
		}
		out[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable Ed25519 keys in JWKS response")
	}
	return out, nil
}
