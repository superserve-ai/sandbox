package proxy

import (
	"testing"
)

const testDomain = "sandbox.superserve.ai"

func TestParseHost(t *testing.T) {
	tests := []struct {
		host           string
		wantPort       int
		wantInstanceID string
		wantErr        bool
	}{
		// Happy path
		{
			host:           "49983-abc123.sandbox.superserve.ai",
			wantPort:       49983,
			wantInstanceID: "abc123",
		},
		{
			host:           "3000-mybox.sandbox.superserve.ai",
			wantPort:       3000,
			wantInstanceID: "mybox",
		},
		{
			host:           "49983-abc123.sandbox.superserve.ai:443",
			wantPort:       49983,
			wantInstanceID: "abc123",
		},
		// UUID-style instance IDs (our actual format)
		{
			host:           "49983-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       49983,
			wantInstanceID: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},

		// Domain suffix validation
		{
			host:    "49983-abc.attacker.com",
			wantErr: true,
		},
		{
			host:    "49983-abc.evil.sandbox.superserve.ai.attacker.com",
			wantErr: true,
		},
		{
			host:    "49983-abc", // no domain at all
			wantErr: true,
		},

		// Missing separator
		{
			host:    "noseparator.sandbox.superserve.ai",
			wantErr: true,
		},

		// Bad port
		{
			host:    "badport-abc.sandbox.superserve.ai",
			wantErr: true,
		},
		{
			host:    "99999-abc.sandbox.superserve.ai",
			wantErr: true,
		},
		{
			host:    "0-abc.sandbox.superserve.ai",
			wantErr: true,
		},
		{
			host:    "-abc.sandbox.superserve.ai", // empty port
			wantErr: true,
		},

		// Empty instance ID
		{
			host:    "49983-.sandbox.superserve.ai",
			wantErr: true,
		},

		// Path traversal in instance ID
		{
			host:    "3000-..%2fshutdown.sandbox.superserve.ai",
			wantErr: true,
		},
		{
			host:    "3000-../etc.sandbox.superserve.ai",
			wantErr: true,
		},

		// Charset violations
		{
			host:    "3000-abc_def.sandbox.superserve.ai", // underscore not allowed
			wantErr: true,
		},
		{
			host:    "3000-abc def.sandbox.superserve.ai", // space not allowed
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			port, instanceID, err := ParseHost(tt.host, testDomain)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got port=%d instanceID=%q", port, instanceID)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if port != tt.wantPort {
				t.Errorf("port: got %d, want %d", port, tt.wantPort)
			}
			if instanceID != tt.wantInstanceID {
				t.Errorf("instanceID: got %q, want %q", instanceID, tt.wantInstanceID)
			}
		})
	}
}
