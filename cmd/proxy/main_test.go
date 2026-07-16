package main

import (
	"reflect"
	"testing"
)

func TestProxyDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains string // PROXY_DOMAINS
		domain  string // PROXY_DOMAIN
		want    []string
	}{
		{
			name: "default when nothing configured",
			want: []string{"sandbox.superserve.ai"},
		},
		{
			name:   "single PROXY_DOMAIN fallback",
			domain: "usw-sandbox.superserve.ai",
			want:   []string{"usw-sandbox.superserve.ai"},
		},
		{
			name:    "comma-separated list",
			domains: "sandbox.superserve.ai,usw-sandbox.superserve.ai",
			want:    []string{"sandbox.superserve.ai", "usw-sandbox.superserve.ai"},
		},
		{
			name:    "whitespace and empty entries tolerated",
			domains: " sandbox.superserve.ai , ,usw-sandbox.superserve.ai ",
			want:    []string{"sandbox.superserve.ai", "usw-sandbox.superserve.ai"},
		},
		{
			name:    "PROXY_DOMAINS wins over PROXY_DOMAIN",
			domains: "usw-sandbox.superserve.ai",
			domain:  "sandbox.superserve.ai",
			want:    []string{"usw-sandbox.superserve.ai"},
		},
		{
			name:    "blank PROXY_DOMAINS falls back",
			domains: " , ",
			domain:  "usw-sandbox.superserve.ai",
			want:    []string{"usw-sandbox.superserve.ai"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PROXY_DOMAINS", tt.domains)
			t.Setenv("PROXY_DOMAIN", tt.domain)
			if got := proxyDomains(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("proxyDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
