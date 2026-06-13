package main

import "testing"

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
