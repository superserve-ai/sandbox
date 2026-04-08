package proxy

import "testing"

func TestParseTerminalHost(t *testing.T) {
	tests := []struct {
		host    string
		want    string
		wantErr bool
	}{
		// Happy path — bare instance ID as the leftmost label.
		{
			host: "b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			want: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},
		// With explicit port (TLS terminator passes Host:443).
		{
			host: "abc123.sandbox.superserve.ai:443",
			want: "abc123",
		},
		// Domain mismatch must be rejected — same suffix-validation
		// guarantee as the user-app proxy.
		{
			host:    "abc.attacker.com",
			wantErr: true,
		},
		{
			host:    "abc.evil.sandbox.superserve.ai.attacker.com",
			wantErr: true,
		},
		// Empty subdomain.
		{
			host:    ".sandbox.superserve.ai",
			wantErr: true,
		},
		// Charset violations — underscore, space, etc.
		{
			host:    "abc_def.sandbox.superserve.ai",
			wantErr: true,
		},
		// Path-traversal attempt encoded into the host.
		{
			host:    "..%2fshutdown.sandbox.superserve.ai",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, err := ParseTerminalHost(tt.host, testDomain)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
