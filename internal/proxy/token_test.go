package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/auth"
)

func TestLoadTerminalVerifier_HappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := base64.StdEncoding.EncodeToString(pub)

	v, err := LoadTerminalVerifier(enc)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Round-trip a token: sign with priv, verify with the loaded
	// verifier. This proves the loader actually wraps the right key.
	signer := auth.NewSigner(priv)
	tok, err := signer.Mint(time.Now(), "sbx-1", "team-1", auth.ScopeTerminal)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := v.Verify(tok, time.Now(), auth.ScopeTerminal); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestLoadTerminalVerifier_Missing(t *testing.T) {
	if _, err := LoadTerminalVerifier(""); err == nil {
		t.Error("expected error for empty env value")
	}
}

func TestLoadTerminalVerifier_BadBase64(t *testing.T) {
	_, err := LoadTerminalVerifier("not-base64!!!")
	if err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("expected base64 error, got %v", err)
	}
}

func TestLoadTerminalVerifier_WrongLength(t *testing.T) {
	// 16 bytes is valid base64 but the wrong length for an Ed25519 key.
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := LoadTerminalVerifier(short)
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Errorf("expected length error, got %v", err)
	}
}
