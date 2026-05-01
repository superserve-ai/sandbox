package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the proxy JWT payload. Standard registered claims (RFC 7519)
// plus two custom claims:
//
//	sid — secret_id this token authorizes a swap for
//	tid — team_id for cost attribution and team-scoped policy
//
// The subject (sub) is the sandbox_id; the proxy enforces that the
// connecting source IP maps to the same sandbox.
type Claims struct {
	SecretID string `json:"sid"`
	TeamID   string `json:"tid"`
	jwt.RegisteredClaims
}

// Signer mints and verifies proxy JWTs. One instance per process.
// Production wires the key from Secret Manager at boot; tests pass bytes
// directly.
type Signer struct {
	key      []byte
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
}

// NewSigner constructs a Signer. Returns an error if the key is shorter
// than 32 bytes — HS256 accepts any length but a sub-32-byte HMAC key has
// less than the equivalent 256 bits of strength.
func NewSigner(key []byte, kid, issuer, audience string, ttl time.Duration) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("signing key must be >=32 bytes, got %d", len(key))
	}
	if kid == "" {
		return nil, errors.New("kid must be non-empty")
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("issuer and audience must be set")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	return &Signer{
		key:      key,
		kid:      kid,
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
	}, nil
}

// Mint issues a token bound to a sandbox+secret. The caller passes the
// current time so tests can pin the clock; production code calls
// Mint(time.Now(), ...).
func (s *Signer) Mint(now time.Time, sandboxID, secretID, teamID uuid.UUID) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	claims := Claims{
		SecretID: secretID.String(),
		TeamID:   teamID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			Subject:   sandboxID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        base64.RawURLEncoding.EncodeToString(nonce),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.key)
}

// Verify parses and validates a token. The algorithm is pinned to HS256,
// rejecting alg=none and the classic alg-confusion attack with RS256.
// Issuer, audience, and expiry are validated; a successful return means
// the caller can trust the claims.
func (s *Signer) Verify(now time.Time, token string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience),
		jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithExpirationRequired(),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		// WithValidMethods already enforces this, but a double-check
		// defends against future library changes that might widen the
		// algorithm list.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.key, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}
