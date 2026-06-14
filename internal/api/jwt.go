package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// SecretsJWTIssuer is the fixed `iss` claim on every secrets JWT.
const SecretsJWTIssuer = "superserve-controlplane"

// SecretsJWTLifetime is the safety-net upper bound on a leaked JWT's blast
// radius. Revocation on sandbox destroy is the primary kill switch.
const SecretsJWTLifetime = 90 * 24 * time.Hour

// SecretsBindingsCap bounds the number of bindings allowed per sandbox so the
// resulting JWT stays within practical HTTPS_PROXY userinfo lengths
// (~10 KB worst case at this cap, comfortably under mainstream HTTP-client
// URL limits).
const SecretsBindingsCap = 32

// SecretsBindingClaim is the per-binding entry in the JWT's `bindings` array.
// Field tags use short names to keep the JWT compact in HTTPS_PROXY userinfo.
// When Rules is non-empty it overrides AuthType/AuthConfig; the daemon dispatches
// by upstream host. Hosts remains the binding-wide allowlist.
type SecretsBindingClaim struct {
	ProxyToken string                    `json:"p"`
	SecretID   string                    `json:"s"`
	EnvKey     string                    `json:"e"`
	Hosts      []string                  `json:"h"`
	AuthType   string                    `json:"t,omitempty"`
	AuthConfig map[string]any            `json:"c,omitempty"`
	Rules      []SecretsBindingRuleClaim `json:"rules,omitempty"`
}

// SecretsBindingRuleClaim is one (hosts → auth shape) entry inside Rules.
// Flat fields keep the JWT compact; the daemon dispatches on Hosts.
type SecretsBindingRuleClaim struct {
	Hosts    []string          `json:"h"`
	AuthType string            `json:"t"`
	Username string            `json:"u,omitempty"`  // basic only
	Header   string            `json:"hd,omitempty"` // api-key only
	Prefix   string            `json:"pf,omitempty"` // api-key only
	Headers  map[string]string `json:"hs,omitempty"` // custom only
}

// SecretsClaims is the JWT payload.
type SecretsClaims struct {
	TeamID   string                `json:"team_id"`
	SourceIP string                `json:"source_ip"`
	Bindings []SecretsBindingClaim `json:"bindings,omitempty"`

	jwt.RegisteredClaims
}

// SecretsSigner mints signed JWTs for the secrets feature.
type SecretsSigner struct {
	priv ed25519.PrivateKey
	kid  string
}

// NewSecretsSigner builds a signer from a base64-encoded 32-byte Ed25519 seed.
// Accepts both standard and URL-safe base64, with or without padding.
func NewSecretsSigner(seedBase64, kid string) (*SecretsSigner, error) {
	if kid == "" {
		return nil, errors.New("secrets signing key id is required")
	}
	seedBase64 = stripWhitespace(seedBase64)
	seed, err := decodeBase64Permissive(seedBase64)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key seed has %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return &SecretsSigner{
		priv: ed25519.NewKeyFromSeed(seed),
		kid:  kid,
	}, nil
}

// Sign returns a serialized JWT with the supplied claims. iss, iat, exp are
// filled in automatically; the caller supplies sandbox-specific fields.
func (s *SecretsSigner) Sign(sandboxID string, claims SecretsClaims) (string, error) {
	return s.sign(sandboxID, claims, time.Now())
}

// sign is the testable form; production callers use Sign which passes time.Now.
func (s *SecretsSigner) sign(sandboxID string, claims SecretsClaims, now time.Time) (string, error) {
	if sandboxID == "" {
		return "", errors.New("sandbox id is required")
	}
	if claims.TeamID == "" {
		return "", errors.New("team id is required")
	}
	if claims.SourceIP == "" {
		return "", errors.New("source ip is required")
	}
	if len(claims.Bindings) > SecretsBindingsCap {
		return "", fmt.Errorf("bindings count %d exceeds cap of %d", len(claims.Bindings), SecretsBindingsCap)
	}
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    SecretsJWTIssuer,
		Subject:   sandboxID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(SecretsJWTLifetime)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.priv)
}

// PublicKey returns the Ed25519 verification public key.
func (s *SecretsSigner) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// KeyID returns the kid that this signer puts on minted JWTs.
func (s *SecretsSigner) KeyID() string { return s.kid }

// JWKS returns the JSON Web Key Set the daemon polls. Single-key today;
// multi-key during rotation windows is a config change (one more entry).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one entry in the JWKS. We only emit Ed25519 keys (kty=OKP, crv=Ed25519).
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// JWKS returns the single-key JWKS for the daemon to fetch.
func (s *SecretsSigner) JWKS() JWKS {
	return JWKS{Keys: []JWK{{
		Kid: s.kid,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(s.PublicKey()),
	}}}
}

func decodeBase64Permissive(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// JWKS handles GET /internal/jwks. Authenticated by InternalAuth middleware.
// Returns 503 if no Signer is configured so a misconfigured deploy fails loud.
func (h *Handlers) JWKS(c *gin.Context) {
	if h.Signer == nil {
		log.Error().Msg("/internal/jwks called but no Signer configured")
		respondErrorMsg(c, "service_unavailable", "secrets signer not configured", http.StatusServiceUnavailable)
		return
	}
	c.JSON(http.StatusOK, h.Signer.JWKS())
}

func stripWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
