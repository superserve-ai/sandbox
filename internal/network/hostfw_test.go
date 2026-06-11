package network

import (
	"reflect"
	"testing"
)

func TestDNSRedirectRules(t *testing.T) {
	if got := dnsRedirectRules(0); got != nil {
		t.Fatalf("port 0 must disable the redirect, got %v", got)
	}

	want := [][]string{
		{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "19053"},
		{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "19053"},
	}
	if got := dnsRedirectRules(19053); !reflect.DeepEqual(got, want) {
		t.Fatalf("dnsRedirectRules(19053) = %v, want %v", got, want)
	}
}
