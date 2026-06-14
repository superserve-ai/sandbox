package egresspolicy

import (
	"net"
	"testing"
)

func TestIsIPDenied(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"169.254.169.254", true}, // link-local / cloud metadata
		{"172.16.5.5", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.32.0.1", false}, // just outside 172.16/12
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := IsIPDenied(ip); got != c.want {
			t.Errorf("IsIPDenied(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
