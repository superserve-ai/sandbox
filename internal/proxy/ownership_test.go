package proxy

import "testing"

func TestValidateSandboxRouteNormalizesAndRejectsUnusableEndpoints(t *testing.T) {
	valid := SandboxRoute{HostID: " host-a ", ProxyAddr: " 127.0.0.1:443 "}
	if err := ValidateSandboxRoute(valid); err != nil {
		t.Fatalf("trimmed usable endpoint rejected: %v", err)
	}
	for _, route := range []SandboxRoute{
		{HostID: "host-a", ProxyAddr: "   "},
		{HostID: "host-a", ProxyAddr: "127.0.0.1"},
		{HostID: "host-a", ProxyAddr: "127.0.0.1:abc"},
		{HostID: "host-a", ProxyAddr: "127.0.0.1:0"},
	} {
		if err := ValidateSandboxRoute(route); err == nil {
			t.Errorf("ValidateSandboxRoute(%q) accepted unusable endpoint", route.ProxyAddr)
		}
	}
}

func TestNormalizeSandboxRouteTrimsValues(t *testing.T) {
	route, err := NormalizeSandboxRoute(SandboxRoute{HostID: " host-a ", ProxyAddr: " 127.0.0.1:443 "})
	if err != nil {
		t.Fatal(err)
	}
	if route.HostID != "host-a" || route.ProxyAddr != "127.0.0.1:443" {
		t.Fatalf("route was not normalized: %#v", route)
	}
}
