package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	s, err := NewSigner(key, "v1", "test-issuer", "test-audience", time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestNewSigner_Validation(t *testing.T) {
	good := make([]byte, 32)
	cases := []struct {
		name string
		key  []byte
		kid  string
		iss  string
		aud  string
		ttl  time.Duration
	}{
		{"short key", make([]byte, 16), "v1", "i", "a", time.Hour},
		{"empty kid", good, "", "i", "a", time.Hour},
		{"empty issuer", good, "v1", "", "a", time.Hour},
		{"empty audience", good, "v1", "i", "", time.Hour},
		{"zero ttl", good, "v1", "i", "a", 0},
		{"negative ttl", good, "v1", "i", "a", -time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.key, tc.kid, tc.iss, tc.aud, tc.ttl); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSigner_MintVerify_RoundTrip(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	sandboxID := uuid.New()
	secretID := uuid.New()
	teamID := uuid.New()

	tok, err := s.Mint(now, sandboxID, secretID, teamID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok == "" {
		t.Fatal("Mint returned empty token")
	}

	claims, err := s.Verify(now.Add(time.Minute), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != sandboxID.String() {
		t.Errorf("sub: got %q, want %q", claims.Subject, sandboxID.String())
	}
	if claims.SecretID != secretID.String() {
		t.Errorf("sid: got %q, want %q", claims.SecretID, secretID.String())
	}
	if claims.TeamID != teamID.String() {
		t.Errorf("tid: got %q, want %q", claims.TeamID, teamID.String())
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("iss: got %q", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "test-audience" {
		t.Errorf("aud: got %v", claims.Audience)
	}
	if claims.ID == "" {
		t.Error("jti (nonce) is empty")
	}
}

func TestSigner_DistinctNoncesAcrossMints(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	id := uuid.New()

	a, err := s.Mint(now, id, id, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Mint(now, id, id, id)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two mints returned identical tokens — nonce is not random")
	}
}

func TestVerify_Expired(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	tok, err := s.Mint(now, uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(now.Add(2*time.Hour), tok); err == nil {
		t.Fatal("Verify accepted expired token")
	} else if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_WrongSignature(t *testing.T) {
	a := newTestSigner(t)
	b := newTestSigner(t) // different key
	tok, err := a.Mint(time.Now(), uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(time.Now(), tok); err == nil {
		t.Fatal("Verify accepted token signed by a different key")
	}
}

func TestVerify_AlgNoneRejected(t *testing.T) {
	// Classic alg confusion: craft a token with alg=none and try to
	// verify it. Must be rejected because we pin HS256.
	s := newTestSigner(t)
	claims := Claims{
		SecretID: uuid.New().String(),
		TeamID:   uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign with none: %v", err)
	}
	if _, err := s.Verify(time.Now(), signed); err == nil {
		t.Fatal("Verify accepted alg=none token")
	}
}

func TestVerify_AlgRS256Rejected(t *testing.T) {
	// Generate an RSA key and sign a token with RS256. A naive verifier
	// that doesn't pin the algorithm could be tricked into using the
	// HS256 secret as a public key. We must reject anything not HS256.
	s := newTestSigner(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(rsaKey)
	if err != nil {
		t.Fatalf("sign with RS256: %v", err)
	}
	if _, err := s.Verify(time.Now(), signed); err == nil {
		t.Fatal("Verify accepted RS256 token")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	a, _ := NewSigner(make([]byte, 32), "v1", "issuer-a", "test-audience", time.Hour)
	b, _ := NewSigner(make([]byte, 32), "v1", "issuer-b", "test-audience", time.Hour)
	// Same key bytes so signature would verify; only the iss claim differs.
	tok, err := a.Mint(time.Now(), uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(time.Now(), tok); err == nil {
		t.Fatal("Verify accepted token from different issuer")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	a, _ := NewSigner(make([]byte, 32), "v1", "test-issuer", "audience-a", time.Hour)
	b, _ := NewSigner(make([]byte, 32), "v1", "test-issuer", "audience-b", time.Hour)
	tok, err := a.Mint(time.Now(), uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(time.Now(), tok); err == nil {
		t.Fatal("Verify accepted token for different audience")
	}
}

func TestVerify_GarbageTokenRejected(t *testing.T) {
	s := newTestSigner(t)
	cases := []string{
		"",
		"not.a.jwt",
		"a.b.c.d.e",
		"...",
	}
	for _, tok := range cases {
		t.Run(tok, func(t *testing.T) {
			if _, err := s.Verify(time.Now(), tok); err == nil {
				t.Fatalf("Verify accepted %q", tok)
			}
		})
	}
}

func TestMint_KIDInHeader(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.Mint(time.Now(), uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(tok, "."); len(parts) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(parts))
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, &Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if parsed.Header["kid"] != "v1" {
		t.Errorf("kid: got %v, want v1", parsed.Header["kid"])
	}
	if parsed.Header["alg"] != "HS256" {
		t.Errorf("alg: got %v, want HS256", parsed.Header["alg"])
	}
}
