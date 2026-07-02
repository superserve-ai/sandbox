package proxy

import (
	"net/http"
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
		// Happy path — boxd label maps to boxdPort
		{
			host:           "boxd-abc123.sandbox.superserve.ai",
			wantPort:       boxdPort,
			wantInstanceID: "abc123",
		},
		{
			host:           "boxd-abc123.sandbox.superserve.ai:443",
			wantPort:       boxdPort,
			wantInstanceID: "abc123",
		},
		// UUID-style instance IDs (our actual format)
		{
			host:           "boxd-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       boxdPort,
			wantInstanceID: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},
		// Region-tagged public IDs (sb-<region>-<uuid>) normalize to the
		// bare UUID that VMD and the token HMACs are keyed on.
		{
			host:           "boxd-sb-use-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       boxdPort,
			wantInstanceID: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},
		{
			host:           "8080-sb-usw-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       8080,
			wantInstanceID: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},
		// "sb-" that isn't the public shape passes through untouched.
		{
			host:           "3000-sb-shortid.sandbox.superserve.ai",
			wantPort:       3000,
			wantInstanceID: "sb-shortid",
		},
		// Right length but not a UUID tail: no alias to an internal-looking ID.
		{
			host:           "3000-sb-use-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sandbox.superserve.ai",
			wantPort:       3000,
			wantInstanceID: "sb-use-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		// Hyphenated region segment: the API would never mint it, so the
		// proxy passes it through rather than guessing a split.
		{
			host:           "3000-sb-us-east-1-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       3000,
			wantInstanceID: "sb-us-east-1-b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},
		// User application ports — numeric label
		{
			host:           "3000-mybox.sandbox.superserve.ai",
			wantPort:       3000,
			wantInstanceID: "mybox",
		},
		{
			host:           "8080-b150ee22-4956-4f5b-926a-f921ed8c37d6.sandbox.superserve.ai",
			wantPort:       8080,
			wantInstanceID: "b150ee22-4956-4f5b-926a-f921ed8c37d6",
		},

		// Boxd's numeric port is intentionally refused — the only way
		// to reach boxd is via the "boxd" label.
		{
			host:    "49983-abc.sandbox.superserve.ai",
			wantErr: true,
		},

		// Domain suffix validation
		{
			host:    "boxd-abc.attacker.com",
			wantErr: true,
		},
		{
			host:    "boxd-abc.evil.sandbox.superserve.ai.attacker.com",
			wantErr: true,
		},
		{
			host:    "boxd-abc", // no domain at all
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
			host:    "boxd-.sandbox.superserve.ai",
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

func TestParseRequest(t *testing.T) {
	const sandboxID = "b150ee22-4956-4f5b-926a-f921ed8c37d6"

	tests := []struct {
		name           string
		host           string
		headerID       string
		wantPort       int
		wantInstanceID string
		wantErr        bool
	}{
		// Shared-host routes via header.
		{
			name:           "shared-host with header",
			host:           testDomain,
			headerID:       sandboxID,
			wantPort:       boxdPort,
			wantInstanceID: sandboxID,
		},
		{
			name:           "shared-host with :443 suffix",
			host:           testDomain + ":443",
			headerID:       sandboxID,
			wantPort:       boxdPort,
			wantInstanceID: sandboxID,
		},
		{
			name:    "shared-host missing header",
			host:    testDomain,
			wantErr: true,
		},
		{
			name:     "shared-host with path traversal in header",
			host:     testDomain,
			headerID: "../etc",
			wantErr:  true,
		},
		{
			name:     "shared-host with underscore in header",
			host:     testDomain,
			headerID: "abc_def",
			wantErr:  true,
		},

		// Subdomain path unchanged.
		{
			name:           "subdomain still routes",
			host:           "boxd-" + sandboxID + "." + testDomain,
			wantPort:       boxdPort,
			wantInstanceID: sandboxID,
		},
		{
			name:           "subdomain on user app port",
			host:           "3000-mybox." + testDomain,
			wantPort:       3000,
			wantInstanceID: "mybox",
		},
		{
			name:           "subdomain header ignored when not on shared host",
			host:           "boxd-" + sandboxID + "." + testDomain,
			headerID:       "different-sandbox",
			wantPort:       boxdPort,
			wantInstanceID: sandboxID,
		},
		{
			name:    "off-domain host with header",
			host:    "sandbox.attacker.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerID != "" {
				headers.Set(headerSandboxID, tt.headerID)
			}
			port, instanceID, err := ParseRequest(tt.host, headers, testDomain)
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

// On a subdomain Host, the routing header is ignored — the subdomain wins.
func TestParseRequest_HeaderRoutingRequiresSharedHost(t *testing.T) {
	const targetID = "b150ee22-4956-4f5b-926a-f921ed8c37d6"
	const attackerID = "deadbeef"

	headers := http.Header{}
	headers.Set(headerSandboxID, attackerID)

	_, gotID, err := ParseRequest("boxd-"+targetID+"."+testDomain, headers, testDomain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != targetID {
		t.Errorf("header overrode subdomain routing: got id %q, want %q", gotID, targetID)
	}
}
