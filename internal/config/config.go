// Package config loads application configuration from environment variables.
package config

import (
	"os"
)

// Config holds all configuration for the AgentBox control plane.
type Config struct {
	Port       string // API_PORT, default "8080"
	VMDAddress string // VMD_GRPC_ADDRESS, default "localhost:50051"
}

// Load reads configuration from environment variables, applying defaults where
// appropriate.
func Load() (*Config, error) {
	cfg := &Config{
		Port:       envOrDefault("API_PORT", "8080"),
		VMDAddress: envOrDefault("VMD_GRPC_ADDRESS", "localhost:50051"),
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
