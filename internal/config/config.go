package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// Config holds all configuration for the Superserve Sandbox control plane.
type Config struct {
	Port        string // API_PORT, default "8080"
	VMDAddress  string // VMD_GRPC_ADDRESS, default "localhost:50051"
	DatabaseURL string // DATABASE_URL, required

	// SandboxAccessTokenSeed is the HMAC seed shared with the edge
	// proxy. Both sides derive per-sandbox access tokens as
	// HMAC-SHA256(seed, sandboxID). Loaded from SANDBOX_ACCESS_TOKEN_SEED
	// (hex-encoded, >= 32 bytes).
	SandboxAccessTokenSeed []byte

	// EdgeProxyDomain is the public hostname suffix served by the edge
	// proxy, used to construct URLs in sandbox responses.
	EdgeProxyDomain string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	seed, err := loadSeed(
		os.Getenv("SANDBOX_ACCESS_TOKEN_SEED"),
		os.Getenv("ALLOW_EPHEMERAL_SEED") == "1",
	)
	if err != nil {
		return nil, fmt.Errorf("SANDBOX_ACCESS_TOKEN_SEED: %w", err)
	}

	cfg := &Config{
		Port:                   envOrDefault("API_PORT", "8080"),
		VMDAddress:             envOrDefault("VMD_GRPC_ADDRESS", "localhost:50051"),
		DatabaseURL:            dbURL,
		SandboxAccessTokenSeed: seed,
		EdgeProxyDomain:        envOrDefault("EDGE_PROXY_DOMAIN", "sandbox.superserve.ai"),
	}
	return cfg, nil
}

func loadSeed(envValue string, allowEphemeral bool) ([]byte, error) {
	if envValue == "" {
		if !allowEphemeral {
			return nil, fmt.Errorf("required in production; set ALLOW_EPHEMERAL_SEED=1 for local dev")
		}
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generate ephemeral seed: %w", err)
		}
		log.Warn().Msg("SANDBOX_ACCESS_TOKEN_SEED unset — generated ephemeral seed (DO NOT USE IN PRODUCTION)")
		return seed, nil
	}

	seed, err := hex.DecodeString(envValue)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if err := auth.ValidateSeed(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
