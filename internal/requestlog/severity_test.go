package requestlog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
)

func TestStructuredSeverityPreservesLevel(t *testing.T) {
	for _, tc := range []struct {
		level    zerolog.Level
		severity string
	}{{zerolog.InfoLevel, "INFO"}, {zerolog.WarnLevel, "WARNING"}, {zerolog.ErrorLevel, "ERROR"}} {
		var buf bytes.Buffer
		logger := zerolog.New(&buf).Hook(CloudSeverityHook{})
		logger.WithLevel(tc.level).Str("event_type", "request").Msg("request")
		var event map[string]any
		if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event["severity"] != tc.severity || event["level"] != tc.level.String() || event["event_type"] != "request" {
			t.Fatalf("lost severity or structured metadata: %s", buf.Bytes())
		}
	}
}
