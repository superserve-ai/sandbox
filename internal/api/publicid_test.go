package api

import (
	"testing"

	"github.com/google/uuid"
)

func TestFormatSandboxID(t *testing.T) {
	id := uuid.MustParse("1b4e28ba-2fa1-11d2-883f-0016d3cca427")

	t.Setenv("SANDBOX_ID_REGION", "")
	if got := formatSandboxID(id); got != id.String() {
		t.Errorf("flag off: want bare uuid, got %q", got)
	}

	t.Setenv("SANDBOX_ID_REGION", "use")
	if got := formatSandboxID(id); got != "sb-use-"+id.String() {
		t.Errorf("flag on: got %q", got)
	}
}

func TestParsePublicSandboxID(t *testing.T) {
	id := uuid.MustParse("1b4e28ba-2fa1-11d2-883f-0016d3cca427")

	for _, tc := range []struct {
		in   string
		want uuid.UUID
		ok   bool
	}{
		{id.String(), id, true},              // legacy bare uuid
		{"sb-use-" + id.String(), id, true},  // current region codes
		{"sb-usw-" + id.String(), id, true},
		{"sb-euw1-" + id.String(), id, true}, // future longer code
		{"sb--" + id.String(), uuid.Nil, false},        // empty region
		{"sb-USE-" + id.String(), uuid.Nil, false},     // uppercase region
		{"sb-use-not-a-uuid-padded-to-36-chars!!", uuid.Nil, false},
		{"sb-use-", uuid.Nil, false},
		{"sb-" + id.String(), uuid.Nil, false}, // prefix but no region segment
		{"", uuid.Nil, false},
		{"garbage", uuid.Nil, false},
	} {
		got, err := parsePublicSandboxID(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parse(%q): got (%v, %v), want %v", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parse(%q): expected error, got %v", tc.in, got)
		}
	}
}

func TestValidateSandboxIDRegion(t *testing.T) {
	for _, tc := range []struct {
		env string
		ok  bool
	}{
		{"", true},    // unset: legacy bare UUIDs
		{"use", true},
		{"usw", true},
		{"euw1", true},
		{"  use  ", true},      // whitespace is trimmed before minting too
		{"us-east-1", false},   // hyphens break the region/uuid split
		{"USE", false},         // uppercase is not DNS-label-safe here
		{"ss_live", false},     // underscores are not DNS-safe
		{"abcdefghijklmnopqr", false}, // 18 chars: over the DNS-label budget
	} {
		t.Setenv("SANDBOX_ID_REGION", tc.env)
		err := ValidateSandboxIDRegion()
		if tc.ok && err != nil {
			t.Errorf("ValidateSandboxIDRegion(%q): unexpected error %v", tc.env, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("ValidateSandboxIDRegion(%q): expected error, got nil", tc.env)
		}
	}
}

func TestPublicSandboxIDRoundTrip(t *testing.T) {
	t.Setenv("SANDBOX_ID_REGION", "usw")
	id := uuid.New()
	got, err := parsePublicSandboxID(formatSandboxID(id))
	if err != nil || got != id {
		t.Fatalf("round trip: got (%v, %v), want %v", got, err, id)
	}
}
