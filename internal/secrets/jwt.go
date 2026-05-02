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

// Claims is the JWT payload. RegisteredClaims uses sub for the bound
// sandbox id; sid and tid carry the secret and team ids.
type Claims struct {
	SecretID string `json:"sid"`
	TeamID   string `json:"tid"`
	jwt.RegisteredClaims
}

// Signer mints and verifies tokens. Construct once per process.
type Signer struct {
	key      []byte
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
}

// NewSigner requires a >=32-byte HMAC key.
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

// Mint issues a token. Caller supplies now so tests can pin the clock.
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

// Verify parses and validates a token. Algorithm is pinned to HS256;
// issuer, audience, and expiry are required.
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
		// Belt-and-braces: WithValidMethods already pins HS256.
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
