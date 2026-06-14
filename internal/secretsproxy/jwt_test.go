package secretsproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stubFetcher is a JWKSFetcher driven by a function so tests can swap behavior
// (initial load, refresh-on-miss, rotation) without coordinating channels.
type stubFetcher struct {
	mu    sync.Mutex
	fn    func() (map[string]ed25519.PublicKey, error)
	calls int
}

func (f *stubFetcher) Fetch(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.fn()
}

func (f *stubFetcher) setFn(fn func() (map[string]ed25519.PublicKey, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fn = fn
}

func (f *stubFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// signForTest builds a JWT with the supplied private key and kid. Mirrors what
// the control plane's SecretsSigner would emit; redeclared here so the daemon
// tests don't import the api package.
func signForTest(t *testing.T, priv ed25519.PrivateKey, kid string, claims JWTClaims, now time.Time) string {
	t.Helper()
	if claims.Issuer == "" {
		claims.Issuer = secretsJWTIssuer
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
	}
	if claims.Subject == "" {
		claims.Subject = "sandbox-1"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifier_HappyPath(t *testing.T) {
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		Bindings: []JWTBindingClaim{{
			ProxyToken: "sk-ant-api03-aaaa",
			SecretID:   "secret-1",
			EnvKey:     "ANTHROPIC_API_KEY",
			Hosts:      []string{"api.anthropic.com"},
			AuthType:   "api-key",
			AuthConfig: map[string]any{"header": "x-api-key"},
		}},
	}, time.Now())

	claims, err := v.Verify(context.Background(), tok, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if claims.TeamID != "team-1" {
		t.Errorf("TeamID: %q", claims.TeamID)
	}
	if claims.Subject != "sandbox-1" {
		t.Errorf("Subject: %q", claims.Subject)
	}
	if len(claims.Bindings) != 1 || claims.Bindings[0].SecretID != "secret-1" {
		t.Errorf("bindings drift: %+v", claims.Bindings)
	}
}

func TestVerifier_RejectsBadSignature(t *testing.T) {
	pub, _ := newKeypair(t)       // trusted public key
	_, otherPriv := newKeypair(t) // attacker's private key, never trusted
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)

	tok := signForTest(t, otherPriv, "v1", JWTClaims{
		TeamID: "team-1", SourceIP: "10.0.0.5",
	}, time.Now())

	_, err := v.Verify(context.Background(), tok, "10.0.0.5")
	if !errors.Is(err, ErrJWTBadSignature) {
		t.Errorf("want ErrJWTBadSignature, got %v", err)
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}, time.Now())

	_, err := v.Verify(context.Background(), tok, "10.0.0.5")
	if !errors.Is(err, ErrJWTExpired) {
		t.Errorf("want ErrJWTExpired, got %v", err)
	}
}

func TestVerifier_RejectsWrongIssuer(t *testing.T) {
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID: "team-1", SourceIP: "10.0.0.5",
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "imposter"},
	}, time.Now())

	_, err := v.Verify(context.Background(), tok, "10.0.0.5")
	if !errors.Is(err, ErrJWTWrongIssuer) {
		t.Errorf("want ErrJWTWrongIssuer, got %v", err)
	}
}

func TestVerifier_RejectsSourceIPMismatch(t *testing.T) {
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID: "team-1", SourceIP: "10.0.0.5",
	}, time.Now())

	_, err := v.Verify(context.Background(), tok, "10.0.0.99")
	if !errors.Is(err, ErrJWTSourceIPMismatch) {
		t.Errorf("want ErrJWTSourceIPMismatch, got %v", err)
	}
}

func TestVerifier_RejectsMissingRequiredClaims(t *testing.T) {
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)

	cases := []struct {
		name   string
		claims JWTClaims
	}{
		{"no team_id", JWTClaims{SourceIP: "10.0.0.5"}},
		{"no source_ip", JWTClaims{TeamID: "team-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signForTest(t, priv, "v1", tc.claims, time.Now())
			_, err := v.Verify(context.Background(), tok, "10.0.0.5")
			if !errors.Is(err, ErrJWTMissingClaim) && !errors.Is(err, ErrJWTSourceIPMismatch) {
				// Missing source_ip slips through claim parse with empty string
				// and trips the source-IP check; the test accepts either.
				t.Errorf("want claim or source-ip rejection, got %v", err)
			}
		})
	}
}

func TestVerifier_RejectsEmptyJWT(t *testing.T) {
	pub, _ := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)
	if _, err := v.Verify(context.Background(), "", "10.0.0.5"); !errors.Is(err, ErrJWTMissing) {
		t.Errorf("want ErrJWTMissing, got %v", err)
	}
}

func TestVerifier_RejectsMalformed(t *testing.T) {
	pub, _ := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, _ := NewVerifier(context.Background(), fetcher)
	if _, err := v.Verify(context.Background(), "not.a.jwt", "10.0.0.5"); !errors.Is(err, ErrJWTMalformed) {
		t.Errorf("want ErrJWTMalformed, got %v", err)
	}
}

func TestVerifier_UnknownKidTriggersAsyncRefresh(t *testing.T) {
	// Unknown kid kicks off a background refresh: the request that triggered
	// the miss fails with ErrJWTUnknownKid (JWKS fetch never blocks the
	// request path), but the next request after the refresh completes succeeds.
	pub1, priv1 := newKeypair(t)
	pub2, priv2 := newKeypair(t)

	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub1}, nil
	}}
	v, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv1

	// Simulate rotation.
	fetcher.setFn(func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub1, "v2": pub2}, nil
	})
	tokV2 := signForTest(t, priv2, "v2", JWTClaims{TeamID: "t", SourceIP: "1.1.1.1"}, time.Now())

	// First attempt fails — refresh kicks off in the background.
	prevRefreshes := v.backgroundRefreshes.Load()
	if _, err := v.Verify(context.Background(), tokV2, "1.1.1.1"); !errors.Is(err, ErrJWTUnknownKid) {
		t.Fatalf("first miss must fail fast with ErrJWTUnknownKid, got %v", err)
	}
	waitForBackgroundRefresh(t, v, prevRefreshes)

	// Second attempt — keys are now refreshed.
	claims, err := v.Verify(context.Background(), tokV2, "1.1.1.1")
	if err != nil {
		t.Fatalf("after background refresh, expected success, got %v", err)
	}
	if claims.TeamID != "t" {
		t.Errorf("claims TeamID drift: %q", claims.TeamID)
	}
	if fetcher.callCount() != 2 {
		t.Errorf("expected exactly 2 fetches (initial + one background refresh), got %d", fetcher.callCount())
	}
}

// waitForBackgroundRefresh polls until at least one background refresh has
// completed since prev. Avoids time.Sleep dependence in tests.
func waitForBackgroundRefresh(t *testing.T, v *Verifier, prev uint64) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if v.backgroundRefreshes.Load() > prev {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background refresh never completed")
}

func TestVerifier_UnknownKidRefreshDebounced(t *testing.T) {
	pub, _ := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}

	// Build a v2 token that will trigger the miss path. Use a fresh key so it
	// would also fail signature, but we're asserting on fetch-call count.
	_, otherPriv := newKeypair(t)
	tok := signForTest(t, otherPriv, "v2", JWTClaims{TeamID: "t", SourceIP: "1.1.1.1"}, time.Now())

	// First miss kicks off an async refresh; subsequent misses within
	// the cooldown must NOT trigger more fetches.
	prevRefreshes := v.backgroundRefreshes.Load()
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(context.Background(), tok, "1.1.1.1")
	}
	waitForBackgroundRefresh(t, v, prevRefreshes)
	// 1 initial + 1 miss-refresh = 2 total.
	if fetcher.callCount() != 2 {
		t.Errorf("expected 2 fetches with cooldown, got %d", fetcher.callCount())
	}
}

func TestVerifier_InitialFetchFailureRefusesToStart(t *testing.T) {
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return nil, errors.New("control plane unreachable")
	}}
	if _, err := NewVerifier(context.Background(), fetcher); err == nil {
		t.Fatal("expected error from initial JWKS load failure")
	}
}

func TestHTTPJWKSFetcher_ParsesValidResponse(t *testing.T) {
	pub, _ := newKeypair(t)
	body := `{"keys":[{"kid":"v1","kty":"OKP","crv":"Ed25519","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-tok" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/internal/jwks" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	f := NewHTTPJWKSFetcher(srv.URL, "test-tok")
	keys, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !pub.Equal(keys["v1"]) {
		t.Errorf("keys mismatch: %+v", keys)
	}
}

func TestHTTPJWKSFetcher_SurfacesAuthFailure(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", code)
			}))
			defer srv.Close()
			f := NewHTTPJWKSFetcher(srv.URL, "wrong")
			_, err := f.Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), "DAEMON_AUTH_TOKEN") {
				t.Errorf("want auth-failure error mentioning DAEMON_AUTH_TOKEN, got %v", err)
			}
		})
	}
}

func TestHTTPJWKSFetcher_RejectsEmptyKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	f := NewHTTPJWKSFetcher(srv.URL, "tok")
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error on empty JWKS")
	}
}

func TestHTTPJWKSFetcher_SkipsNonEd25519Keys(t *testing.T) {
	pub, _ := newKeypair(t)
	body := `{"keys":[
		{"kid":"rsa","kty":"RSA","x":"ignored"},
		{"kid":"v1","kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := NewHTTPJWKSFetcher(srv.URL, "tok")
	keys, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["rsa"]; ok {
		t.Error("RSA key should have been skipped")
	}
	if _, ok := keys["v1"]; !ok {
		t.Error("Ed25519 key should be present")
	}
}

func TestVerifier_PerHostRulesRoundTrip(t *testing.T) {
	// A JWT minted with multi-rule bindings must survive parse and produce
	// the matching Rule list on the verified claims.
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		Bindings: []JWTBindingClaim{{
			ProxyToken: "ghp_proxy_aaa",
			SecretID:   "sec-gh",
			EnvKey:     "GITHUB_TOKEN",
			Hosts:      []string{"api.github.com", "github.com"},
			Rules: []JWTRuleClaim{
				{Hosts: []string{"api.github.com"}, AuthType: "bearer"},
				{Hosts: []string{"github.com"}, AuthType: "basic", Username: "x-access-token"},
			},
		}},
	}, time.Now())

	claims, err := v.Verify(context.Background(), tok, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Bindings) != 1 {
		t.Fatalf("bindings count: %d", len(claims.Bindings))
	}
	b := claims.Bindings[0]
	if len(b.Rules) != 2 {
		t.Fatalf("rules count: %d", len(b.Rules))
	}
	if b.Rules[0].AuthType != "bearer" || b.Rules[0].Hosts[0] != "api.github.com" {
		t.Errorf("rule 0 drift: %+v", b.Rules[0])
	}
	if b.Rules[1].AuthType != "basic" || b.Rules[1].Username != "x-access-token" {
		t.Errorf("rule 1 drift: %+v", b.Rules[1])
	}
}

func TestJWTResolver_PerHostRulesPopulateBindingRules(t *testing.T) {
	// Resolver must translate JWTRuleClaim → BindingRule with the right
	// AuthConfig shape so the inject pipeline finds the username.
	pub, priv := newKeypair(t)
	fetcher := &stubFetcher{fn: func() (map[string]ed25519.PublicKey, error) {
		return map[string]ed25519.PublicKey{"v1": pub}, nil
	}}
	v, err := NewVerifier(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewJWTResolver(v)

	tok := signForTest(t, priv, "v1", JWTClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		Bindings: []JWTBindingClaim{{
			ProxyToken: "ghp_proxy_bbb",
			SecretID:   "sec-gh",
			EnvKey:     "GITHUB_TOKEN",
			Hosts:      []string{"api.github.com", "github.com"},
			Rules: []JWTRuleClaim{
				{Hosts: []string{"api.github.com"}, AuthType: "bearer"},
				{Hosts: []string{"github.com"}, AuthType: "basic", Username: "x-access-token"},
			},
		}},
	}, time.Now())

	scope, err := resolver.Authenticate(context.Background(), "10.0.0.5", tok)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := scope.Bindings["ghp_proxy_bbb"]
	if !ok {
		t.Fatal("binding not present in scope")
	}
	if len(b.Rules) != 2 {
		t.Fatalf("rules count: %d", len(b.Rules))
	}
	// Basic rule's username must round-trip into AuthConfig where the writer reads it.
	got, _ := stringFromAuthConfig(b.Rules[1].AuthConfig, "username")
	if got != "x-access-token" {
		t.Errorf("basic rule username lost: cfg=%v", b.Rules[1].AuthConfig)
	}
}
