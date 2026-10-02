package network

import (
	"net/netip"
	"testing"
)

func TestCoalescePrefixes(t *testing.T) {
	parse := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s).Masked())
		}
		return out
	}
	key := func(ps []netip.Prefix) map[string]bool {
		m := map[string]bool{}
		for _, p := range ps {
			m[p.String()] = true
		}
		return m
	}

	tests := []struct {
		name string
		in   []netip.Prefix
		want []string
	}{
		{
			name: "drops prefix covered by a broader one",
			in:   parse("203.0.113.0/24", "203.0.113.7/32"),
			want: []string{"203.0.113.0/24"},
		},
		{
			name: "drops exact duplicates",
			in:   parse("198.51.100.0/24", "198.51.100.0/24"),
			want: []string{"198.51.100.0/24"},
		},
		{
			name: "keeps disjoint prefixes",
			in:   parse("10.0.0.0/8", "192.168.0.0/16"),
			want: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name: "collapses several nested under one",
			in:   parse("172.16.0.0/12", "172.16.1.0/24", "172.16.1.5/32", "8.8.8.8/32"),
			want: []string{"172.16.0.0/12", "8.8.8.8/32"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := key(coalescePrefixes(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %s in %v", w, got)
				}
			}
		})
	}
}

func TestCidrsToElementsCoalesces(t *testing.T) {
	// Overlapping input must not produce overlapping interval elements
	// (which nftables would reject). /24 + contained /32 → just the /24 pair.
	elems, err := cidrsToElements([]string{"203.0.113.0/24", "203.0.113.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 2 {
		t.Errorf("got %d set elements, want 2 (one start/end pair)", len(elems))
	}
}

func TestCidrsToElementsAcceptsBareIP(t *testing.T) {
	// A bare address must produce the same interval as its /32. Rows written
	// before the API normalized entries still carry the bare form, and one
	// unparseable entry would otherwise fail the whole rule set.
	bare, err := cidrsToElements([]string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("bare IP rejected: %v", err)
	}
	cidr, err := cidrsToElements([]string{"1.1.1.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != 2 || len(cidr) != 2 {
		t.Fatalf("got %d and %d elements, want 2 and 2", len(bare), len(cidr))
	}
	for i := range bare {
		if string(bare[i].Key) != string(cidr[i].Key) || bare[i].IntervalEnd != cidr[i].IntervalEnd {
			t.Errorf("element %d differs: bare=%v cidr=%v", i, bare[i], cidr[i])
		}
	}
	if _, err := cidrsToElements([]string{"not-an-ip"}); err == nil {
		t.Error("garbage entry should still be rejected")
	}
}

func TestCidrsToElementsUnmapsIPv4Mapped(t *testing.T) {
	// ::ffff:a.b.c.d is an IPv4 rule; it must apply, not be skipped as v6.
	mapped, err := cidrsToElements([]string{"::ffff:203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cidrsToElements([]string{"203.0.113.9/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mapped) != 2 {
		t.Fatalf("mapped address produced %d elements, want 2", len(mapped))
	}
	for i := range mapped {
		if string(mapped[i].Key) != string(plain[i].Key) {
			t.Errorf("element %d differs: mapped=%v plain=%v", i, mapped[i], plain[i])
		}
	}
	mappedPrefix, err := cidrsToElements([]string{"::ffff:203.0.113.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	plainPrefix, _ := cidrsToElements([]string{"203.0.113.0/24"})
	if len(mappedPrefix) != 2 || string(mappedPrefix[1].Key) != string(plainPrefix[1].Key) {
		t.Errorf("mapped prefix not applied as its IPv4 equivalent: %v vs %v", mappedPrefix, plainPrefix)
	}
}
