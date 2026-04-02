// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"os"
)

// Config holds all configuration for the Superserve Sandbox control plane.
type Config struct {
	Port        string // API_PORT, default "8080"
	VMDAddress  string // VMD_GRPC_ADDRESS, default "localhost:50051"
	DatabaseURL string // DATABASE_URL, required
}

// Load reads configuration from environment variables, applying defaults where
// appropriate.
func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	cfg := &Config{
		Port:        envOrDefault("API_PORT", "8080"),
		VMDAddress:  envOrDefault("VMD_GRPC_ADDRESS", "localhost:50051"),
		DatabaseURL: dbURL,
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
