// Package config loads application configuration from environment variables.
package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

// Config holds all configuration for the Superserve Sandbox control plane.
type Config struct {
	Port        string // API_PORT, default "8080"
	VMDAddress  string // VMD_GRPC_ADDRESS, default "localhost:50051"
	DatabaseURL string // DATABASE_URL, required

	// TerminalTokenPrivateKey is the Ed25519 private key used to mint
	// short-lived tokens that grant browsers WebSocket access to the
	// terminal endpoint on the edge proxy. Loaded from
	// TERMINAL_TOKEN_PRIVATE_KEY (standard base64 of the 64-byte private
	// key). If unset, an ephemeral keypair is generated at startup with a
	// loud warning — fine for local dev, broken across multi-instance
	// deployments since the edge proxy needs the matching public key.
	TerminalTokenPrivateKey ed25519.PrivateKey

	// EdgeProxyDomain is the public hostname suffix served by the edge
	// proxy, used by the control plane to construct WebSocket URLs in
	// terminal-token responses. From EDGE_PROXY_DOMAIN (must match the
	// PROXY_DOMAIN env var on the edge proxy itself).
	EdgeProxyDomain string
}

// Load reads configuration from environment variables, applying defaults where
// appropriate.
func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	priv, err := loadTerminalKey(os.Getenv("TERMINAL_TOKEN_PRIVATE_KEY"), os.Getenv("ALLOW_EPHEMERAL_TERMINAL_KEY") == "1")
	if err != nil {
		return nil, fmt.Errorf("TERMINAL_TOKEN_PRIVATE_KEY: %w", err)
	}

	cfg := &Config{
		Port:                    envOrDefault("API_PORT", "8080"),
		VMDAddress:              envOrDefault("VMD_GRPC_ADDRESS", "localhost:50051"),
		DatabaseURL:             dbURL,
		TerminalTokenPrivateKey: priv,
		EdgeProxyDomain:         envOrDefault("EDGE_PROXY_DOMAIN", "sandbox.superserve.ai"),
	}
	return cfg, nil
}

// loadTerminalKey decodes the env-supplied Ed25519 private key. Returns an
// error if the env var is empty UNLESS the caller explicitly opted in to
// an ephemeral key via ALLOW_EPHEMERAL_TERMINAL_KEY=1.
//
// The opt-in exists so `go test`, local `go run`, and CI jobs can work
// without managing real secrets, but production startups that forget to
// set TERMINAL_TOKEN_PRIVATE_KEY hard-fail at boot instead of silently
// generating a per-replica key that will never verify against anything.
//
// Multi-replica control planes would generate a DIFFERENT ephemeral key
// per replica, so every token would fail verification at the edge proxy
// (which has a single stable public key). That failure mode is the one
// this guard is designed to prevent from shipping to prod.
func loadTerminalKey(envValue string, allowEphemeral bool) (ed25519.PrivateKey, error) {
	if envValue == "" {
		if !allowEphemeral {
			return nil, fmt.Errorf("required in production; set ALLOW_EPHEMERAL_TERMINAL_KEY=1 to auto-generate for local dev")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		log.Warn().
			Str("public_key", base64.StdEncoding.EncodeToString(pub)).
			Msg("TERMINAL_TOKEN_PRIVATE_KEY unset, ALLOW_EPHEMERAL_TERMINAL_KEY=1 — generated ephemeral keypair (DO NOT USE IN PRODUCTION)")
		return priv, nil
	}

	raw, err := base64.StdEncoding.DecodeString(envValue)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded length %d, want %d (Ed25519 private key)", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
