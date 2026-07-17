package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// API keys optionally carry the issuing cell's region between the live prefix
// and the random component:
//
//	ss_live_<region>_<random>   e.g. ss_live_usw_k3TQxV...
//
// Each cell's database holds only its own teams' keys, so a key presented to
// the wrong cell fails the hash lookup exactly like an invalid key. When the
// key names a different cell's region, the 401 says so — otherwise a valid
// key pointed at the wrong endpoint reads as "invalid key" with no hint that
// the fix is the URL, not the key.
const apiKeyLivePrefix = "ss_live_"

// knownRegions maps region tokens with a launched cell to that cell's
// canonical API endpoint, grown by hand per cell launch. Endpoints are
// stored rather than derived because regional hostnames aren't uniform:
// the primary cell predates the region scheme and lives at the bare api
// hostname, not api-use. The allowlist half also kills false positives:
// legacy key randoms are base64url and may contain underscores, so a legacy
// "ss_live_abc_..." key parses as region "abc" by coincidence — without the
// allowlist we would point that user at a nonexistent api-abc endpoint. The
// tradeoff is that a key from a cell launched after this deploy gets the
// generic 401 instead of the redirect hint until the map catches up; cells
// launch rarely, so that window is accepted.
var knownRegions = map[string]string{
	"use": "https://api.superserve.ai",
	"usw": "https://api-usw.superserve.ai",
}

// cellRegion is this cell's own region token. Empty SANDBOX_ID_REGION means
// the pre-multi-region primary cell, which is region "use".
func cellRegion() string {
	if r := sandboxIDRegionFromEnv(); r != "" {
		return r
	}
	return "use"
}

// apiKeyRegion extracts the region token from a region-tagged API key. It
// returns "" for legacy keys (ss_live_<random>, no region segment) and for
// anything that does not parse — a non-conforming segment is treated as "no
// region", never an error. Shape rules match sandbox IDs: 1-17 lowercase
// alphanumeric characters.
func apiKeyRegion(key string) string {
	rest, ok := strings.CutPrefix(key, apiKeyLivePrefix)
	if !ok {
		return ""
	}
	region, random, ok := strings.Cut(rest, "_")
	if !ok || random == "" {
		return "" // legacy: random only, no region segment
	}
	if len(region) > maxRegionCodeLen || !validRegionCode(region) {
		return ""
	}
	return region
}

// respondWrongRegion writes the redirect 401 when the key is tagged with a
// known region other than this cell's, and reports whether it responded. The
// hint comes from the key's own region tag, so it applies regardless of how
// the lookup failed — a wrong-cell key can never authenticate here. The
// region token is client-visible plaintext, so echoing it back leaks nothing.
func respondWrongRegion(c *gin.Context, apiKey string) bool {
	if region := apiKeyRegion(apiKey); region != "" && region != cellRegion() {
		if endpoint, known := knownRegions[region]; known {
			respondErrorMsg(c, "wrong_region",
				"this API key belongs to region '"+region+"'; use that region's endpoint ("+endpoint+") or upgrade your SDK, which routes automatically",
				http.StatusUnauthorized)
			return true
		}
	}
	return false
}

// respondAuthFailed writes the 401 for a key the lookup rejected. Every
// failure other than the wrong-region redirect — invalid, legacy, same-region
// key not found, unparseable — returns the identical generic 401, so the
// response reveals nothing about whether a key exists.
func respondAuthFailed(c *gin.Context, apiKey string) {
	if respondWrongRegion(c, apiKey) {
		return
	}
	respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
}
