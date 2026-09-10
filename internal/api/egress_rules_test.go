package api

import (
	"reflect"
	"testing"
)

func TestNormalizeCIDR(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":             "1.1.1.1/32",
		"8.8.8.8/32":          "8.8.8.8/32",
		"0.0.0.0/0":           "0.0.0.0/0",
		"203.0.113.0/24":      "203.0.113.0/24",
		"api.example.com":     "api.example.com",
		"*.example.com":       "*.example.com",
		"not an address":      "not an address",
		"2001:db8::1":         "2001:db8::1/128", // rejected upstream by validateEgressRules; still canonical
		"2001:db8::/32":       "2001:db8::/32",
		"::ffff:10.0.0.1":     "10.0.0.1/32",
		"::ffff:10.0.0.0/120": "10.0.0.0/24",
		"":                    "",
	}
	for in, want := range cases {
		if got := normalizeCIDR(in); got != want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitEgressEntriesNormalizesBothLists(t *testing.T) {
	allowedCIDRs, deniedCIDRs, allowedDomains := splitEgressEntries(
		[]string{"1.1.1.1", "8.8.8.8/32", "api.example.com", "*.example.com"},
		[]string{"0.0.0.0/0", "9.9.9.9"},
	)
	if want := []string{"1.1.1.1/32", "8.8.8.8/32"}; !reflect.DeepEqual(allowedCIDRs, want) {
		t.Errorf("allowedCIDRs = %v, want %v", allowedCIDRs, want)
	}
	if want := []string{"0.0.0.0/0", "9.9.9.9/32"}; !reflect.DeepEqual(deniedCIDRs, want) {
		t.Errorf("deniedCIDRs = %v, want %v", deniedCIDRs, want)
	}
	if want := []string{"api.example.com", "*.example.com"}; !reflect.DeepEqual(allowedDomains, want) {
		t.Errorf("allowedDomains = %v, want %v", allowedDomains, want)
	}
}

func TestSplitEgressEntriesEmpty(t *testing.T) {
	a, d, dom := splitEgressEntries(nil, nil)
	if a != nil || d != nil || dom != nil {
		t.Errorf("expected nil slices, got %v %v %v", a, d, dom)
	}
}

// The persisted network_config must carry the normalized entries: it is what
// reapplyNetworkConfig pushes to VMD after every resume.
func TestEgressConfigJSONPersistsNormalizedEntries(t *testing.T) {
	_, _, _, raw := egressConfigJSON(&networkConfigRequest{
		AllowOut: []string{"1.1.1.1", "api.example.com"},
		DenyOut:  []string{"0.0.0.0/0"},
	})
	got := string(raw)
	for _, want := range []string{`"1.1.1.1/32"`, `"api.example.com"`, `"0.0.0.0/0"`} {
		if !contains(got, want) {
			t.Errorf("persisted config %s missing %s", got, want)
		}
	}
	if contains(got, `"1.1.1.1"`) {
		t.Errorf("persisted config %s still carries the bare IP", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
