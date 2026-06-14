package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildUpstreamTransport(t *testing.T) {
	// DialContext is always set so the internal-IP guard applies, whether or
	// not a policy resolver is configured.
	if got := buildUpstreamTransport(nil); got.DialContext == nil {
		t.Error("DialContext should be set for the internal-IP guard without a resolver")
	}
	if got := buildUpstreamTransport(buildPolicyResolver("127.0.0.1:19053")); got.DialContext == nil {
		t.Error("DialContext should be set with a resolver")
	}
}

func TestDenyInternalDial(t *testing.T) {
	cases := []struct {
		addr      string
		wantBlock bool
	}{
		{"10.0.0.1:443", true},
		{"169.254.169.254:443", true},
		{"192.168.0.5:8080", true},
		{"8.8.8.8:443", false},
		{"1.1.1.1:80", false},
	}
	for _, c := range cases {
		err := denyInternalDial("tcp", c.addr, nil)
		if (err != nil) != c.wantBlock {
			t.Errorf("denyInternalDial(%q) err=%v, wantBlock=%v", c.addr, err, c.wantBlock)
		}
	}
}

func TestLoadBlockedPorts(t *testing.T) {
	// No path configured: no ports, no error.
	if ports, err := loadBlockedPorts(""); err != nil || ports != nil {
		t.Errorf("empty path: ports=%v err=%v", ports, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.yaml")
	if err := os.WriteFile(path, []byte("blocked_egress_ports:\n  - 3333\n  - 4444\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ports, err := loadBlockedPorts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 3333 || ports[1] != 4444 {
		t.Errorf("got %v, want [3333 4444]", ports)
	}
}
