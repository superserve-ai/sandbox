package proxy

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// LoadTerminalVerifier reads the Ed25519 public key from the
// TERMINAL_TOKEN_PUBLIC_KEY env var (standard base64) and returns a Verifier
// the proxy can use to validate terminal tokens minted by the control plane.
//
// Why a separate loader (not config.Load): the edge proxy is a separate
// binary with a much smaller footprint than the control plane and we don't
// want to drag the entire config package into it. The proxy reads its own
// env vars directly in cmd/proxy/main.go and passes the verifier into the
// handler.
//
// The proxy MUST have a public key — there is no auto-generate fallback
// because a freshly generated key would not match anything the control
// plane signed with. If the env var is missing we return an error and let
// main fail loudly.
func LoadTerminalVerifier(envValue string) (*auth.Verifier, error) {
	if envValue == "" {
		return nil, errors.New("TERMINAL_TOKEN_PUBLIC_KEY is required")
	}
	raw, err := base64.StdEncoding.DecodeString(envValue)
	if err != nil {
		return nil, fmt.Errorf("TERMINAL_TOKEN_PUBLIC_KEY: not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("TERMINAL_TOKEN_PUBLIC_KEY: decoded length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return auth.NewVerifier(ed25519.PublicKey(raw)), nil
}

// LoadTerminalVerifierFromEnv is a convenience wrapper used by main.
func LoadTerminalVerifierFromEnv() (*auth.Verifier, error) {
	return LoadTerminalVerifier(os.Getenv("TERMINAL_TOKEN_PUBLIC_KEY"))
}
