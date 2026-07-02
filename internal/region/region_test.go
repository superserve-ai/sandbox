package region

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseAPIKeyRegion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		known     bool
		unknown   bool
		absent    bool
		malformed bool
		region    string
	}{
		{name: "use", key: "ss_live_use_abc123", known: true, region: USE},
		{name: "usw", key: "ss_live_usw_abc123", known: true, region: USW},
		{name: "legacy", key: "ss_live_legacykeymaterial", absent: true},
		{name: "unknown token", key: "ss_live_euw_abc123", unknown: true, region: "euw"},
		{name: "malformed empty segment", key: "ss_live__abc123", malformed: true},
		{name: "malformed bad chars", key: "ss_live_us-west_abc123", malformed: true},
		{name: "no prefix", key: "not_a_live_key", absent: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseAPIKeyRegion(tt.key)
			if got.Known != tt.known || got.Unknown != tt.unknown || got.Absent != tt.absent || got.Malformed != tt.malformed || got.Region != tt.region {
				t.Fatalf("ParseAPIKeyRegion(%q) = %+v", tt.key, got)
			}
		})
	}
}

func TestParseSandboxID(t *testing.T) {
	t.Parallel()

	id := uuid.New()

	t.Run("public sandbox id", func(t *testing.T) {
		got, err := ParseSandboxID(SandboxID(USW, id))
		if err != nil {
			t.Fatalf("ParseSandboxID: %v", err)
		}
		if got.UUID != id || got.Region != USW || !got.Known || got.Legacy {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("legacy uuid", func(t *testing.T) {
		got, err := ParseSandboxID(id.String())
		if err != nil {
			t.Fatalf("ParseSandboxID legacy: %v", err)
		}
		if got.UUID != id || !got.Legacy || got.Known {
			t.Fatalf("unexpected legacy parse result: %+v", got)
		}
	})

	t.Run("invalid region", func(t *testing.T) {
		if _, err := ParseSandboxID("sb-euw-" + id.String()); err == nil {
			t.Fatal("expected invalid region error")
		}
	})
}
