package api

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

// Public sandbox IDs optionally carry the cell's region as a prefix:
//
//	sb-<region>-<uuid>   e.g. sb-use-1b4e28ba-2fa1-11d2-883f-0016d3cca427
//
// The prefix lets the edge route a sandbox-scoped request to its home cell
// from the ID string alone — the same scheme as ss_live_<region>_ API keys.
// Unlike keys, sandbox IDs are embedded as hostname labels by the proxy
// ({port}-{id}.{domain}), so the separator is a hyphen: underscores are not
// DNS-safe. The DB primary key stays a bare uuid; the prefix exists only at
// the API boundary.
//
// Rollout is two-phase to keep it non-breaking: parsing accepts both forms
// unconditionally, while minting is gated on SANDBOX_ID_REGION (unset =
// legacy bare UUIDs, byte-for-byte today's behavior).
const sandboxIDPrefix = "sb-"

// uuidStrLen is the canonical textual UUID length (8-4-4-4-12).
const uuidStrLen = 36

// sandboxIDRegionFromEnv returns the region code minted into new public
// sandbox IDs, or "" to mint legacy bare UUIDs. Read per call: minting is
// off the hot path and this keeps tests to t.Setenv.
func sandboxIDRegionFromEnv() string {
	return strings.TrimSpace(os.Getenv("SANDBOX_ID_REGION"))
}

// formatSandboxID renders a sandbox's public ID.
func formatSandboxID(id uuid.UUID) string {
	region := sandboxIDRegionFromEnv()
	if region == "" {
		return id.String()
	}
	return sandboxIDPrefix + region + "-" + id.String()
}

// parsePublicSandboxID accepts a legacy bare UUID or a region-tagged public
// ID and returns the inner UUID. The region segment is validated for shape
// but not against a region list — this cell serves whatever the edge routed
// to it, and rejecting unknown codes here would couple every cell deploy to
// the region vocabulary.
func parsePublicSandboxID(raw string) (uuid.UUID, error) {
	if !strings.HasPrefix(raw, sandboxIDPrefix) {
		return uuid.Parse(raw)
	}
	rest := raw[len(sandboxIDPrefix):]
	// The UUID is always the fixed-length tail; the region is whatever sits
	// between the prefix and the "-<uuid>" suffix (region length may vary
	// as cells launch).
	if len(rest) < uuidStrLen+2 { // shortest region is 1 char + "-"
		return uuid.Nil, fmt.Errorf("public sandbox ID %q too short", raw)
	}
	region, idPart := rest[:len(rest)-uuidStrLen-1], rest[len(rest)-uuidStrLen:]
	if rest[len(rest)-uuidStrLen-1] != '-' || !validRegionCode(region) {
		return uuid.Nil, fmt.Errorf("public sandbox ID %q has a malformed region segment", raw)
	}
	return uuid.Parse(idPart)
}

// validRegionCode: non-empty lowercase alphanumeric. Hyphens are excluded so
// the region/uuid split stays unambiguous.
func validRegionCode(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
