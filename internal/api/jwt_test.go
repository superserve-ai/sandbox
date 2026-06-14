package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// newTestSigner builds a signer with a fresh random keypair and the given kid.
func newTestSigner(t *testing.T, kid string) *SecretsSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	s, err := NewSecretsSigner(base64.StdEncoding.EncodeToString(seed), kid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSecretsSigner_SignAndVerifyRoundTrip(t *testing.T) {
	signer := newTestSigner(t, "v1")

	claims := SecretsClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		Bindings: []SecretsBindingClaim{{
			ProxyToken: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789012345678901",
			SecretID:   "secret-uuid-1",
			EnvKey:     "ANTHROPIC_API_KEY",
			Hosts:      []string{"api.anthropic.com"},
			AuthType:   "api-key",
			AuthConfig: map[string]any{"header": "x-api-key"},
		}},
	}

	tok, err := signer.Sign("sandbox-1", claims)
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	// Round-trip parse using the same library and the signer's public key.
	parsed, err := jwt.ParseWithClaims(tok, &SecretsClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			t.Method = jwt.SigningMethodEdDSA
		}
		return signer.PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
	got := parsed.Claims.(*SecretsClaims)
	if got.TeamID != "team-1" {
		t.Errorf("TeamID drift: %q", got.TeamID)
	}
	if got.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP drift: %q", got.SourceIP)
	}
	if got.Issuer != SecretsJWTIssuer {
		t.Errorf("iss: got %q, want %q", got.Issuer, SecretsJWTIssuer)
	}
	if got.Subject != "sandbox-1" {
		t.Errorf("sub: got %q", got.Subject)
	}
	if len(got.Bindings) != 1 || got.Bindings[0].SecretID != "secret-uuid-1" {
		t.Errorf("bindings drift: %+v", got.Bindings)
	}
}

func TestSecretsSigner_RejectsTamperedToken(t *testing.T) {
	signer := newTestSigner(t, "v1")
	tok, err := signer.Sign("sandbox-1", SecretsClaims{
		TeamID: "team-1", SourceIP: "10.0.0.5",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the payload (middle segment).
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload[0] ^= 0xff
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]

	_, err = jwt.ParseWithClaims(tampered, &SecretsClaims{}, func(*jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	})
	if err == nil {
		t.Fatal("tampered token unexpectedly accepted")
	}
}

func TestSecretsSigner_SignSetsKidAndAlg(t *testing.T) {
	signer := newTestSigner(t, "v7")
	tok, err := signer.Sign("sandbox-1", SecretsClaims{TeamID: "t", SourceIP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	headerB64 := strings.SplitN(tok, ".", 2)[0]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "v7" {
		t.Errorf("kid: got %v, want v7", header["kid"])
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("alg: got %v, want EdDSA", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ: got %v, want JWT", header["typ"])
	}
}

func TestSecretsSigner_ExpiryHorizon(t *testing.T) {
	signer := newTestSigner(t, "v1")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tok, err := signer.sign("sandbox-1", SecretsClaims{
		TeamID: "team-1", SourceIP: "10.0.0.5",
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.ParseWithClaims(tok, &SecretsClaims{}, func(*jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.Claims.(*SecretsClaims)
	wantExp := now.Add(SecretsJWTLifetime)
	if !got.ExpiresAt.Time.Equal(wantExp) {
		t.Errorf("exp: got %v, want %v", got.ExpiresAt.Time, wantExp)
	}
	if !got.IssuedAt.Time.Equal(now) {
		t.Errorf("iat: got %v, want %v", got.IssuedAt.Time, now)
	}
}

func TestSecretsSigner_RejectsMissingRequiredFields(t *testing.T) {
	signer := newTestSigner(t, "v1")
	cases := []struct {
		name      string
		sandboxID string
		claims    SecretsClaims
	}{
		{"missing sandbox id", "", SecretsClaims{TeamID: "t", SourceIP: "1.1.1.1"}},
		{"missing team id", "sandbox-1", SecretsClaims{SourceIP: "1.1.1.1"}},
		{"missing source ip", "sandbox-1", SecretsClaims{TeamID: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := signer.Sign(tc.sandboxID, tc.claims); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestNewSecretsSigner_RejectsBadKey(t *testing.T) {
	cases := []struct {
		name string
		seed string
		kid  string
	}{
		{"empty kid", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)), ""},
		{"bad base64", "not-base64-!@#", "v1"},
		{"wrong seed size", base64.StdEncoding.EncodeToString(make([]byte, 16)), "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSecretsSigner(tc.seed, tc.kid); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestNewSecretsSigner_AcceptsBase64Variants(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	encs := map[string]string{
		"std":     base64.StdEncoding.EncodeToString(seed),
		"raw-std": base64.RawStdEncoding.EncodeToString(seed),
		"url":     base64.URLEncoding.EncodeToString(seed),
		"raw-url": base64.RawURLEncoding.EncodeToString(seed),
	}
	for name, encoded := range encs {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSecretsSigner(encoded, "v1"); err != nil {
				t.Errorf("variant %s: %v", name, err)
			}
		})
	}
}

func TestJWKSHandler_ReturnsKeysWithAuth(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-tok")
	signer := newTestSigner(t, "v1")
	h := &Handlers{Signer: signer}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/internal/jwks", InternalAuth(), h.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/internal/jwks", nil)
	req.Header.Set("Authorization", "Bearer test-internal-tok")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var body JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Keys) != 1 || body.Keys[0].Kid != "v1" || body.Keys[0].Crv != "Ed25519" {
		t.Errorf("jwks drift: %+v", body)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(body.Keys[0].X)
	if err != nil {
		t.Fatalf("x not base64url: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("public key bytes: got %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
}

func TestJWKSHandler_RejectsMissingAuth(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-tok")
	h := &Handlers{Signer: newTestSigner(t, "v1")}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/internal/jwks", InternalAuth(), h.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/internal/jwks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestJWKSHandler_503WhenSignerNotConfigured(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-tok")
	h := &Handlers{Signer: nil}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/internal/jwks", InternalAuth(), h.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/internal/jwks", nil)
	req.Header.Set("Authorization", "Bearer test-tok")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestSecretsSigner_JWKS(t *testing.T) {
	signer := newTestSigner(t, "v3")
	jwks := signer.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kid != "v3" {
		t.Errorf("kid: %q", k.Kid)
	}
	if k.Kty != "OKP" {
		t.Errorf("kty: %q", k.Kty)
	}
	if k.Crv != "Ed25519" {
		t.Errorf("crv: %q", k.Crv)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("x not base64url: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("public key bytes: got %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
}

func TestSecretsSigner_JWTSizeAtCap(t *testing.T) {
	signer := newTestSigner(t, "v1")

	// SecretsBindingsCap bindings — the documented worst case.
	bindings := make([]SecretsBindingClaim, SecretsBindingsCap)
	for i := range bindings {
		bindings[i] = SecretsBindingClaim{
			ProxyToken: "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SecretID:   "11111111-2222-3333-4444-555555555555",
			EnvKey:     "ANTHROPIC_API_KEY_XX",
			Hosts:      []string{"api.anthropic.com"},
			AuthType:   "api-key",
			AuthConfig: map[string]any{"header": "x-api-key"},
		}
	}
	tok, err := signer.Sign("sandbox-1", SecretsClaims{
		TeamID:   "11111111-2222-3333-4444-555555555555",
		SourceIP: "10.0.0.5",
		Bindings: bindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mainstream HTTP clients accept URLs up to 16 KB without issue;
	// fail the test if we approach 12 KB so a future claim-bloat regression
	// is caught early.
	if len(tok) > 12*1024 {
		t.Errorf("JWT at binding cap is %d bytes; alarm threshold is 12 KB", len(tok))
	}
	t.Logf("JWT size at %d bindings: %d bytes", SecretsBindingsCap, len(tok))
}

func TestSecretsSigner_RejectsTooManyBindings(t *testing.T) {
	signer := newTestSigner(t, "v1")
	bindings := make([]SecretsBindingClaim, SecretsBindingsCap+1)
	for i := range bindings {
		bindings[i] = SecretsBindingClaim{
			ProxyToken: "x", SecretID: "y", AuthType: "bearer",
		}
	}
	_, err := signer.Sign("sandbox-1", SecretsClaims{
		TeamID: "t", SourceIP: "1.1.1.1", Bindings: bindings,
	})
	if err == nil {
		t.Fatal("want error for exceeding bindings cap, got nil")
	}
}

func TestSecretsSigner_PerHostRulesSurviveSignAndParse(t *testing.T) {
	// Round-trip a multi-rule binding through sign + parse, confirming the
	// wire-format Rules field carries through and the legacy t+c fields are
	// omitted when omitempty applies.
	signer := newTestSigner(t, "v1")
	claims := SecretsClaims{
		TeamID:   "team-1",
		SourceIP: "10.0.0.5",
		Bindings: []SecretsBindingClaim{{
			ProxyToken: "ghp_proxy_aaaa",
			SecretID:   "secret-gh-1",
			EnvKey:     "GITHUB_TOKEN",
			Hosts:      []string{"api.github.com", "github.com"},
			Rules: []SecretsBindingRuleClaim{
				{Hosts: []string{"api.github.com"}, AuthType: "bearer"},
				{Hosts: []string{"github.com"}, AuthType: "basic", Username: "x-access-token"},
			},
		}},
	}
	tok, err := signer.Sign("sandbox-1", claims)
	if err != nil {
		t.Fatal(err)
	}
	// Parse back and check Rules survive.
	parsed, err := jwt.ParseWithClaims(tok, &SecretsClaims{}, func(*jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := parsed.Claims.(*SecretsClaims)
	if len(got.Bindings) != 1 {
		t.Fatalf("bindings count: %d", len(got.Bindings))
	}
	b := got.Bindings[0]
	if b.AuthType != "" {
		t.Errorf("legacy AuthType should be empty for per_host binding, got %q", b.AuthType)
	}
	if len(b.Rules) != 2 {
		t.Fatalf("rules count: %d", len(b.Rules))
	}
	if b.Rules[0].AuthType != "bearer" || b.Rules[0].Hosts[0] != "api.github.com" {
		t.Errorf("rule 0 drift: %+v", b.Rules[0])
	}
	if b.Rules[1].AuthType != "basic" || b.Rules[1].Username != "x-access-token" {
		t.Errorf("rule 1 drift: %+v", b.Rules[1])
	}
	// Decode the JWT body and assert that the legacy `t` field is absent for
	// the multi-rule binding (omitempty had to fire).
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("malformed jwt")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	rawBindings := raw["bindings"].([]any)
	rawBinding := rawBindings[0].(map[string]any)
	if _, hasT := rawBinding["t"]; hasT {
		t.Errorf("legacy t field should be omitted from per_host binding, body=%v", rawBinding)
	}
	if _, hasC := rawBinding["c"]; hasC {
		t.Errorf("legacy c field should be omitted from per_host binding, body=%v", rawBinding)
	}
	if _, hasRules := rawBinding["rules"]; !hasRules {
		t.Errorf("rules field missing from JWT body: %v", rawBinding)
	}
}
