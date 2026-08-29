package api

import (
	"net/http/httptest"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	for _, tc := range []struct{ name, remote, xff, want string }{
		{"no xff", "10.0.0.2:443", "", "10.0.0.2"},
		{"valid", "10.0.0.2:443", "192.0.2.1, 198.51.100.7", "192.0.2.1"},
		{"attacker prefixed", "10.0.0.2:443", "203.0.113.9, 192.0.2.1, 198.51.100.7", "192.0.2.1"},
		{"wrong lb", "10.0.0.2:443", "192.0.2.1, 198.51.100.8", "10.0.0.2"},
		{"malformed", "10.0.0.2:443", "not-an-ip, 198.51.100.7", "10.0.0.2"},
		{"ipv6", "[fd00::2]:443", "2001:db8::1, 2001:db8::7", "2001:db8::1"},
		{"public peer spoof", "203.0.113.10:443", "192.0.2.1, 198.51.100.7", "203.0.113.10"},
		{"direct run app", "10.0.0.2:443", "192.0.2.1, 198.51.100.7, 198.51.100.8", "10.0.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://service.run.app/", nil)
			r.RemoteAddr, r.Header = tc.remote, make(map[string][]string)
			if tc.name != "direct run app" {
				r.Host = "api.example.test"
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := resolveClientIP(r, map[string]string{"valid": "198.51.100.7", "attacker prefixed": "198.51.100.7", "ipv6": "2001:db8::7", "public peer spoof": "198.51.100.7", "direct run app": "198.51.100.7", "no xff": "198.51.100.7", "wrong lb": "198.51.100.7", "malformed": "198.51.100.7"}[tc.name]); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
