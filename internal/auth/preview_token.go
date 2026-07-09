package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Preview access policy values, as stored in the sandbox row, carried on the
// vmd instance record, and returned by VMD's /instances endpoint. A missing
// or empty value means public — sandboxes that predate the feature keep
// today's behavior.
const (
	PreviewAccessPublic  = "public"
	PreviewAccessPrivate = "private"
)

// Preview token carrier names. Defined here — next to the token itself — so
// the edge proxy (which consumes them) and the control plane (which returns
// them from the mint endpoints) can never drift apart.
const (
	// PreviewTokenHeader carries the token for machine clients.
	PreviewTokenHeader = "X-Superserve-Preview-Token"
	// PreviewTokenQueryParam bootstraps browser access; the proxy exchanges
	// it for the cookie and strips it from the URL.
	PreviewTokenQueryParam = "superserve_preview_token"
	// PreviewTokenCookie is the host-scoped browser cookie set by the proxy.
	PreviewTokenCookie = "__Host-superserve_preview_token"
)

const (
	// previewTokenPrefix versions the token format. Verification is strict on
	// the prefix: claims that would RESTRICT access further must ship under a
	// new prefix, because an older verifier ignores unknown claim fields.
	previewTokenPrefix = "spv1"

	// previewMACDomain domain-separates the preview MAC from the boxd access
	// token (HMAC over "<sandboxID>|<window>"). Sandbox IDs cannot contain
	// "." (host label charset), so the two input spaces never collide.
	previewMACDomain = "superserve-preview.v1|"

	// maxPreviewTokenLen caps the presented token before any parsing. Real
	// tokens are ~200 bytes; anything larger is hostile input.
	maxPreviewTokenLen = 512
)

// PreviewClaims is the authenticated payload of a preview token.
type PreviewClaims struct {
	// SandboxID is the bare sandbox UUID (region prefix stripped), matching
	// what the edge proxy derives from the request host.
	SandboxID string `json:"sid"`
	// Version must equal the sandbox's current preview_token_version.
	// Rotating the version invalidates every previously minted token.
	Version int64 `json:"v"`
	// Port restricts the token to one preview port; 0 means any port.
	Port int `json:"p,omitempty"`
	// ExpiresAt is a Unix-seconds expiry; 0 means no expiry (the token lives
	// until the version rotates or the sandbox goes public/away).
	ExpiresAt int64 `json:"exp,omitempty"`
}

var previewB64 = base64.RawURLEncoding

// ComputePreviewToken mints a preview token: "spv1.<payload>.<mac>" with
// base64url(JSON claims) and HMAC-SHA256(seed, domain|payload).
func ComputePreviewToken(seed []byte, claims PreviewClaims) (string, error) {
	if err := ValidateSeed(seed); err != nil {
		return "", err
	}
	if claims.SandboxID == "" {
		return "", fmt.Errorf("auth: preview token requires a sandbox ID")
	}
	if claims.Version <= 0 {
		return "", fmt.Errorf("auth: preview token requires a positive version")
	}
	if claims.Port < 0 || claims.Port > 65535 {
		return "", fmt.Errorf("auth: preview token port out of range: %d", claims.Port)
	}
	if claims.ExpiresAt < 0 {
		return "", fmt.Errorf("auth: preview token expiry must not be negative")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshal preview claims: %w", err)
	}
	payload := previewB64.EncodeToString(raw)
	return previewTokenPrefix + "." + payload + "." + previewB64.EncodeToString(previewMAC(seed, payload)), nil
}

// VerifyPreviewToken checks a presented token against the sandbox identity
// derived from the request host, the record's current token version, and the
// requested port. It fails closed: any parse error, signature mismatch, claim
// mismatch, or a non-positive record version rejects the token. The MAC is
// verified before the payload is decoded, so unauthenticated bytes never
// reach the JSON parser.
func VerifyPreviewToken(seed []byte, sandboxID string, recordVersion int64, port int, presented string) bool {
	if len(seed) == 0 || sandboxID == "" || recordVersion <= 0 {
		return false
	}
	if presented == "" || len(presented) > maxPreviewTokenLen {
		return false
	}
	parts := strings.Split(presented, ".")
	if len(parts) != 3 || parts[0] != previewTokenPrefix {
		return false
	}
	payload, sig := parts[1], parts[2]
	sigBytes, err := previewB64.DecodeString(sig)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(previewMAC(seed, payload), sigBytes) != 1 {
		return false
	}

	raw, err := previewB64.DecodeString(payload)
	if err != nil {
		return false
	}
	var claims PreviewClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return false
	}
	if claims.SandboxID != sandboxID {
		return false
	}
	if claims.Version != recordVersion {
		return false
	}
	if claims.Port != 0 && claims.Port != port {
		return false
	}
	if claims.ExpiresAt != 0 && time.Now().Unix() >= claims.ExpiresAt {
		return false
	}
	return true
}

func previewMAC(seed []byte, payload string) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(previewMACDomain))
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}
