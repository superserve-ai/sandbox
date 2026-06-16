package egresspolicy

import (
	"net"
	"testing"
)

func TestMatchHost(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "*.openai.com", true},
		{"a.b.openai.com", "*.openai.com", true}, // egress wildcard matches any depth
		{"openai.com", "*.openai.com", false},    // bare apex not matched by wildcard
		{"evil.com", "api.openai.com", false},
		{"API.OpenAI.com", "api.openai.com", true}, // case-insensitive
		{"x", "", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.host, c.pattern); got != c.want {
			t.Errorf("MatchHost(%q,%q)=%v want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestMatchHostStrict(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "*.openai.com", true},
		{"a.b.openai.com", "*.openai.com", false}, // strict: single label only
		{"openai.com", "*.openai.com", false},
	}
	for _, c := range cases {
		if got := MatchHostStrict(c.host, c.pattern); got != c.want {
			t.Errorf("MatchHostStrict(%q,%q)=%v want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestHasCIDR(t *testing.T) {
	if !HasCIDR([]string{"api.openai.com", "10.0.0.0/8"}) {
		t.Error("should detect a CIDR entry")
	}
	if !HasCIDR([]string{"1.2.3.4"}) {
		t.Error("should detect a bare IP entry")
	}
	if HasCIDR([]string{"api.openai.com", "*.example.com"}) {
		t.Error("domain-only should not report a CIDR")
	}
}

func TestEvalEgress(t *testing.T) {
	priv := net.ParseIP("10.1.2.3")
	pub := net.ParseIP("8.8.8.8")

	// CIDR allow: in-range allowed, out-of-range denied (allowlist mode).
	if ok, _ := EvalEgress("api.internal", priv, []string{"10.0.0.0/8"}, nil, "passthrough"); !ok {
		t.Error("CIDR allow should permit in-range IP")
	}
	if ok, reason := EvalEgress("api.public", pub, []string{"10.0.0.0/8"}, nil, "passthrough"); ok || reason != "host_not_allowed" {
		t.Errorf("CIDR allow should deny out-of-range; ok=%v reason=%q", ok, reason)
	}

	// CIDR deny: in-range blocked; out-of-range unaffected.
	if ok, reason := EvalEgress("api.internal", priv, nil, []string{"10.0.0.0/8"}, "passthrough"); ok || reason != "host_denied" {
		t.Errorf("CIDR deny should block in-range; ok=%v reason=%q", ok, reason)
	}
	if ok, _ := EvalEgress("api.public", pub, nil, []string{"10.0.0.0/8"}, "passthrough"); !ok {
		t.Error("CIDR deny should not affect out-of-range")
	}

	// Domain allow still works; a nil IP never matches a CIDR.
	if ok, _ := EvalEgress("api.openai.com", nil, []string{"*.openai.com"}, nil, "passthrough"); !ok {
		t.Error("domain allow should permit a matching host")
	}
	if ok, reason := EvalEgress("api.public", nil, []string{"10.0.0.0/8"}, nil, "passthrough"); ok || reason != "host_not_allowed" {
		t.Errorf("CIDR-only allow with nil IP should deny; ok=%v reason=%q", ok, reason)
	}

	// No rules: passthrough allows, deny policy blocks.
	if ok, _ := EvalEgress("anything.com", nil, nil, nil, "passthrough"); !ok {
		t.Error("no rules + passthrough should allow")
	}
	if ok, reason := EvalEgress("anything.com", nil, nil, nil, "deny"); ok || reason != "unmatched_host_denied" {
		t.Errorf("no rules + deny should block; ok=%v reason=%q", ok, reason)
	}
}
