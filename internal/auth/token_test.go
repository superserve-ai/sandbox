package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// helper: generate a fresh keypair for each test so tests are independent
// and a leaked key in one test cannot affect another.
func newKeypair(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return NewSigner(priv), NewVerifier(pub)
}

func TestMintAndVerify_HappyPath(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, err := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	p, err := verifier.Verify(tok, now, ScopeTerminal)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.SandboxID != "sbx-1" || p.TeamID != "team-1" || p.Scope != ScopeTerminal {
		t.Errorf("payload mismatch: %+v", p)
	}
	if p.Nonce == "" {
		t.Error("nonce should be populated")
	}
}

func TestVerify_Expired(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, err := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Verify well past expiry + skew window.
	later := now.Add(DefaultTTL + MaxClockSkew + time.Second)
	if _, err := verifier.Verify(tok, later, ScopeTerminal); !errors.Is(err, ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_WithinSkewAfterExpiry(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	// Slightly past expiry but within skew tolerance — should still verify.
	justOver := now.Add(DefaultTTL + 1*time.Second)
	if _, err := verifier.Verify(tok, justOver, ScopeTerminal); err != nil {
		t.Errorf("expected verify to succeed within skew window, got %v", err)
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	// Verify well before issuance — should fail with NotYetValid.
	earlier := now.Add(-time.Hour)
	if _, err := verifier.Verify(tok, earlier, ScopeTerminal); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("expected ErrNotYetValid, got %v", err)
	}
}

func TestVerify_ScopeMismatch(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	if _, err := verifier.Verify(tok, now, Scope("files")); !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("expected ErrScopeMismatch, got %v", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	// Flip a single character in the signature segment. Token format is
	// v1.<payload>.<sig>, so the third part is the signature. We swap a
	// known-different character to guarantee the signature changes.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", tok)
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	tampered := strings.Join(parts, ".")

	if _, err := verifier.Verify(tampered, now, ScopeTerminal); !errors.Is(err, ErrBadSignature) {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	// Tamper the payload segment so the signature no longer matches.
	parts := strings.Split(tok, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	tampered := strings.Join(parts, ".")

	// Could fail as either ErrBadSignature (sig doesn't match new
	// payload) or ErrMalformed (base64 still decodes but JSON now
	// invalid). Either is fine — both reject the token.
	_, err := verifier.Verify(tampered, now, ScopeTerminal)
	if err == nil {
		t.Fatal("expected verify to fail on tampered payload, got nil")
	}
}

func TestVerify_DifferentKey(t *testing.T) {
	signer1, _ := newKeypair(t)
	_, verifier2 := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	tok, _ := signer1.Mint(now, "sbx-1", "team-1", ScopeTerminal)

	// Verifying with a different keypair must fail. This is the test
	// that asserts asymmetric key isolation works as expected.
	if _, err := verifier2.Verify(tok, now, ScopeTerminal); !errors.Is(err, ErrBadSignature) {
		t.Errorf("expected ErrBadSignature when verifying with foreign key, got %v", err)
	}
}

func TestVerify_MalformedShape(t *testing.T) {
	_, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "abcdef"},
		{"one dot", "v1.abc"},
		{"too many dots", "v1.a.b.c"},
		{"wrong version", "v2.aGVsbG8.dGVzdA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(tc.token, now, ScopeTerminal)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc.token)
			}
		})
	}
}

func TestMint_RejectsEmptyFields(t *testing.T) {
	signer, _ := newKeypair(t)
	now := time.Now()

	cases := []struct{ sid, tid string }{
		{"", "team-1"},
		{"sbx-1", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if _, err := signer.Mint(now, tc.sid, tc.tid, ScopeTerminal); err == nil {
			t.Errorf("expected error for sid=%q tid=%q, got nil", tc.sid, tc.tid)
		}
	}
}

func TestSameSandbox(t *testing.T) {
	p := &Payload{SandboxID: "sbx-1"}
	if err := SameSandbox(p, "sbx-1"); err != nil {
		t.Errorf("expected match, got %v", err)
	}
	if err := SameSandbox(p, "sbx-2"); !errors.Is(err, ErrSandboxMismatch) {
		t.Errorf("expected ErrSandboxMismatch, got %v", err)
	}
}

func TestNonce_UniquePerMint(t *testing.T) {
	signer, verifier := newKeypair(t)
	now := time.Unix(1_700_000_000, 0)

	// Mint a bunch of tokens for the same sandbox and confirm every
	// nonce is unique. This guards against a future change accidentally
	// reusing a nonce (e.g. if someone replaces rand.Read with a
	// deterministic seed).
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := signer.Mint(now, "sbx-1", "team-1", ScopeTerminal)
		if err != nil {
			t.Fatalf("mint #%d: %v", i, err)
		}
		p, err := verifier.Verify(tok, now, ScopeTerminal)
		if err != nil {
			t.Fatalf("verify #%d: %v", i, err)
		}
		if seen[p.Nonce] {
			t.Fatalf("nonce collision at #%d: %s", i, p.Nonce)
		}
		seen[p.Nonce] = true
	}
}
