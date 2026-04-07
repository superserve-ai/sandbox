package proxy

import (
	"testing"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		host           string
		wantPort       int
		wantInstanceID string
		wantErr        bool
	}{
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
		{
			host:    "noseparator.sandbox.superserve.ai",
			wantErr: true,
		},
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
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			port, instanceID, err := ParseHost(tt.host)
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
