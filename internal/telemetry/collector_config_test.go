package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectorConfigsDropBannedLabels(t *testing.T) {
	t.Parallel()

	configs := []string{
		filepath.Join("..", "..", "deploy", "otel", "collector-local.yaml"),
		filepath.Join("..", "..", "deploy", "otel", "collector-gmp.yaml"),
	}
	bannedKeys := []string{
		"sandbox_id",
		"user_id",
		"api_key_id",
		"request_id",
		"url",
		"error",
	}

	for _, cfg := range configs {
		content, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatalf("read %s: %v", cfg, err)
		}
		text := string(content)
		for _, key := range bannedKeys {
			want := "key: " + key
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q drop rule", cfg, want)
			}
		}
	}
}
