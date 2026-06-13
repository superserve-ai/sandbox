package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildUpstreamTransport(t *testing.T) {
	// No resolver configured: keep the default DialContext (host resolver).
	if got := buildUpstreamTransport(""); got.DialContext != nil {
		t.Error("empty resolver address should leave DialContext unset")
	}
	// Resolver configured: install a custom DialContext that routes name
	// resolution through the policy resolver.
	if got := buildUpstreamTransport("127.0.0.1:19053"); got.DialContext == nil {
		t.Error("resolver address should install a custom DialContext")
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
