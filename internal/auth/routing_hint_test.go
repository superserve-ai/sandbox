package auth

import (
	"strings"
	"testing"
	"time"
)

func TestRoutingHintBindings(t *testing.T) {
	seed := []byte(strings.Repeat("k", 32))
	now := time.Now().Truncate(time.Second)
	token := SignRoutingHint(seed, "sandbox", "host-a", "sandbox.example.com", now, 1)
	if h, ok := VerifyRoutingHint(seed, token, "sandbox", []string{"sandbox.example.com"}, now); !ok || h.HostID != "host-a" {
		t.Fatal(h, ok)
	}
	cases := []struct {
		name, token, id, audience string
		seed                      []byte
		at                        time.Time
	}{
		{"tampered", token + "x", "sandbox", "sandbox.example.com", seed, now},
		{"wrong sandbox", token, "other", "sandbox.example.com", seed, now},
		{"wrong cell", token, "sandbox", "other.example.com", seed, now},
		{"rotated key", token, "sandbox", "sandbox.example.com", []byte(strings.Repeat("z", 32)), now},
		{"expired", token, "sandbox", "sandbox.example.com", seed, now.Add(RoutingHintTTL)},
		{"oversized", strings.Repeat("x", MaxRoutingHintBytes+1), "sandbox", "sandbox.example.com", seed, now},
		{"access token", ComputeAccessToken(seed, "sandbox"), "sandbox", "sandbox.example.com", seed, now},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := VerifyRoutingHint(c.seed, c.token, c.id, []string{c.audience}, c.at); ok {
				t.Fatal("accepted invalid hint")
			}
		})
	}
	if VerifyAccessToken(seed, "sandbox", token) {
		t.Fatal("routing hint authorized sandbox access")
	}
}

func BenchmarkSignRoutingHint(b *testing.B) {
	seed := []byte(strings.Repeat("k", 32))
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		SignRoutingHint(seed, "00000000-0000-4000-8000-000000000001", "host-a", "sandbox.example.com", now, 1)
	}
}
func BenchmarkVerifyRoutingHint(b *testing.B) {
	seed := []byte(strings.Repeat("k", 32))
	now := time.Now()
	token := SignRoutingHint(seed, "sandbox", "host-a", "sandbox.example.com", now, 1)
	b.ReportAllocs()
	for b.Loop() {
		VerifyRoutingHint(seed, token, "sandbox", []string{"sandbox.example.com"}, now)
	}
}

func TestRoutingHintClockFaultDoesNotMintFutureCredential(t *testing.T) {
	seed := []byte(strings.Repeat("k", 32))
	for _, observed := range []time.Time{time.Now().Add(3 * time.Hour), time.Now().Add(-2 * time.Hour), {}} {
		if token := SignRoutingHint(seed, "sandbox", "owner", "sandbox.example.com", observed, 1); token != "" {
			t.Fatal("issued hint from unsafe database time")
		}
	}
	// Clock correction only permits a newly observed route; no credential from
	// the fault can later become valid after its tombstone has been reclaimed.
	if token := SignRoutingHint(seed, "sandbox", "owner", "sandbox.example.com", time.Now(), 1); token == "" {
		t.Fatal("clock recovery did not restore issuance")
	}
}
