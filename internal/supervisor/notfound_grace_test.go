package supervisor

import (
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func TestClassifyNotFound(t *testing.T) {
	grace := 60 * time.Second
	now := time.Unix(1_000_000, 0)
	dispatched := func(ago time.Duration) time.Time { return now.Add(-ago) }

	tests := []struct {
		name string
		res  vmdclient.BuildStatusResult
		at   time.Time
		want notFoundDecision
	}{
		{"vmd has the build -> proceed", vmdclient.BuildStatusResult{Status: "running"}, dispatched(5 * time.Second), nfProceed},
		{"ready -> proceed", vmdclient.BuildStatusResult{Status: "ready"}, dispatched(5 * time.Second), nfProceed},
		{"not found within grace -> wait", vmdclient.BuildStatusResult{NotFound: true}, dispatched(5 * time.Second), nfWait},
		{"not found past grace -> fail", vmdclient.BuildStatusResult{NotFound: true}, dispatched(90 * time.Second), nfFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNotFound(tc.res, tc.at, true, now, grace); got != tc.want {
				t.Errorf("classifyNotFound = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNotFoundIsTerminal(t *testing.T) {
	grace := 60 * time.Second
	now := time.Unix(1_000_000, 0)

	tests := []struct {
		name         string
		startedAt    time.Time
		startedValid bool
		want         bool
	}{
		{
			name:         "within grace -> not terminal",
			startedAt:    now.Add(-5 * time.Second),
			startedValid: true,
			want:         false,
		},
		{
			name:         "just dispatched -> not terminal",
			startedAt:    now,
			startedValid: true,
			want:         false,
		},
		{
			name:         "past grace -> terminal",
			startedAt:    now.Add(-90 * time.Second),
			startedValid: true,
			want:         true,
		},
		{
			name:         "exactly at grace -> terminal",
			startedAt:    now.Add(-grace),
			startedValid: true,
			want:         true,
		},
		{
			name:         "no valid dispatch time -> never terminal here",
			startedAt:    now.Add(-time.Hour),
			startedValid: false,
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := notFoundIsTerminal(tc.startedAt, tc.startedValid, now, grace)
			if got != tc.want {
				t.Errorf("notFoundIsTerminal = %v, want %v", got, tc.want)
			}
		})
	}
}
