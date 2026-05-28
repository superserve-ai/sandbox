package network

import (
	"net"
	"testing"

	"github.com/rs/zerolog"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name        string
		rules       *EgressRules
		hostname    string
		dstIP       string
		wantAllowed bool
		wantMatch   string
	}{
		{
			name:        "nil rules → allow",
			rules:       nil,
			hostname:    "api.openai.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "default",
		},
		{
			name:        "empty rules → allow",
			rules:       &EgressRules{},
			hostname:    "anything.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "default",
		},
		{
			name: "allow domain only, hostname matches → allow",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
			},
			hostname:    "api.openai.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "domain",
		},
		{
			name: "allow domain only, hostname mismatch → implicit deny",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
			},
			hostname:    "evil.com",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "implicit-deny",
		},
		{
			name: "allow CIDR only, IP matches → allow",
			rules: &EgressRules{
				AllowedCIDRs: []string{"8.8.8.0/24"},
			},
			hostname:    "",
			dstIP:       "8.8.8.8",
			wantAllowed: true,
			wantMatch:   "cidr",
		},
		{
			name: "allow CIDR only, IP outside → implicit deny",
			rules: &EgressRules{
				AllowedCIDRs: []string{"8.8.8.0/24"},
			},
			hostname:    "",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "implicit-deny",
		},
		{
			name: "deny CIDR only, IP matches → deny",
			rules: &EgressRules{
				DeniedCIDRs: []string{"1.2.3.0/24"},
			},
			hostname:    "",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
		{
			name: "deny CIDR only, IP outside → default allow",
			rules: &EgressRules{
				DeniedCIDRs: []string{"1.2.3.0/24"},
			},
			hostname:    "",
			dstIP:       "8.8.8.8",
			wantAllowed: true,
			wantMatch:   "default",
		},
		{
			// Regression: previously returned (false, "cidr") because the
			// 0.0.0.0/0 deny was evaluated before the domain allow.
			name: "deny all + allow domain, hostname matches → allow",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "api.openai.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "domain",
		},
		{
			name: "deny all + allow domain, hostname mismatch → deny",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "evil.com",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
		{
			name: "deny all + allow CIDR, IP matches → allow",
			rules: &EgressRules{
				AllowedCIDRs: []string{"8.8.8.0/24"},
				DeniedCIDRs:  []string{"0.0.0.0/0"},
			},
			hostname:    "",
			dstIP:       "8.8.8.8",
			wantAllowed: true,
			wantMatch:   "cidr",
		},
		{
			name: "deny all + allow CIDR, IP outside → deny",
			rules: &EgressRules{
				AllowedCIDRs: []string{"8.8.8.0/24"},
				DeniedCIDRs:  []string{"0.0.0.0/0"},
			},
			hostname:    "",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
		{
			name: "wildcard allow domain matches subdomain",
			rules: &EgressRules{
				AllowedDomains: []string{"*.openai.com"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "api.openai.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "domain",
		},
		{
			name: "wildcard allow domain does not match unrelated host",
			rules: &EgressRules{
				AllowedDomains: []string{"*.openai.com"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "evil.com",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
		{
			name: "bare wildcard '*' is rejected (no domain match)",
			rules: &EgressRules{
				AllowedDomains: []string{"*"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "anything.com",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
		{
			name: "broad allow CIDR shadows specific deny CIDR",
			rules: &EgressRules{
				AllowedCIDRs: []string{"10.0.0.0/8"},
				DeniedCIDRs:  []string{"10.1.1.1/32"},
			},
			hostname:    "",
			dstIP:       "10.1.1.1",
			wantAllowed: true,
			wantMatch:   "cidr",
		},
		{
			name: "domain allow shadows deny CIDR that would otherwise match",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
				DeniedCIDRs:    []string{"1.2.3.0/24"},
			},
			hostname:    "api.openai.com",
			dstIP:       "1.2.3.4",
			wantAllowed: true,
			wantMatch:   "domain",
		},
		{
			name: "no hostname, allow domain present, allow CIDR matches → allow",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
				AllowedCIDRs:   []string{"8.8.8.0/24"},
				DeniedCIDRs:    []string{"0.0.0.0/0"},
			},
			hostname:    "",
			dstIP:       "8.8.8.8",
			wantAllowed: true,
			wantMatch:   "cidr",
		},
		{
			name: "no hostname, only allow domain configured, IP not in any allow → implicit deny",
			rules: &EgressRules{
				AllowedDomains: []string{"api.openai.com"},
			},
			hostname:    "",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "implicit-deny",
		},
		{
			name: "malformed allow CIDR is skipped, valid one still matches",
			rules: &EgressRules{
				AllowedCIDRs: []string{"not-a-cidr", "8.8.8.0/24"},
				DeniedCIDRs:  []string{"0.0.0.0/0"},
			},
			hostname:    "",
			dstIP:       "8.8.8.8",
			wantAllowed: true,
			wantMatch:   "cidr",
		},
		{
			name: "malformed deny CIDR is skipped, evaluation continues",
			rules: &EgressRules{
				DeniedCIDRs: []string{"not-a-cidr", "1.2.3.0/24"},
			},
			hostname:    "",
			dstIP:       "1.2.3.4",
			wantAllowed: false,
			wantMatch:   "cidr",
		},
	}

	p := NewEgressProxy(0, 0, 0, 0, zerolog.Nop())

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.dstIP)
			if ip == nil {
				t.Fatalf("invalid test IP %q", tc.dstIP)
			}
			gotAllowed, gotMatch := p.isAllowed(tc.rules, tc.hostname, ip)
			if gotAllowed != tc.wantAllowed || gotMatch != tc.wantMatch {
				t.Errorf("isAllowed(hostname=%q, ip=%s) = (%v, %q), want (%v, %q)",
					tc.hostname, tc.dstIP, gotAllowed, gotMatch, tc.wantAllowed, tc.wantMatch)
			}
		})
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		hostname string
		pattern  string
		want     bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"API.OPENAI.COM", "api.openai.com", true},
		{"api.openai.com", "API.OPENAI.COM", true},
		{"api.openai.com", "*.openai.com", true},
		{"deep.api.openai.com", "*.openai.com", true},
		{"openai.com", "*.openai.com", false},
		{"api.openai.com", "*.example.com", false},
		{"anything.com", "*", false},
		{"anything.com", "", false},
	}
	for _, tc := range tests {
		got := matchDomain(tc.hostname, tc.pattern)
		if got != tc.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", tc.hostname, tc.pattern, got, tc.want)
		}
	}
}
