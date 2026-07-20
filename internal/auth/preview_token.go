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
// vmd instance record, and returned by VMD's /instances endpoint. Empty and
// legacy_public preserve the pre-publication behavior for sandboxes and
// clients that predate the feature. New public/private policies both require
// an explicitly published port; private additionally requires its token.
const (
	PreviewAccessLegacyPublic = "legacy_public"
	PreviewAccessPublic       = "public"
	PreviewAccessPrivate      = "private"
)

// Host data-plane capabilities, advertised by vmd on every heartbeat and
// checked by the control plane before it enables a preview policy on a
// sandbox. Defined here — next to the policy values they authorize — so the
// advertiser (vmd) and the checker (API) can never drift apart. A host that
// advertises nothing cannot hold strict-preview sandboxes: on a partially
// deployed fleet the API call fails instead of recording a policy that the
// host's proxy would not enforce.
const (
	// HostCapabilityPreviewPorts: the host enforces the published-port
	// allowlist (unpublished ports 404 for strict sandboxes).
	HostCapabilityPreviewPorts = "preview_ports_v1"
	// HostCapabilityPreviewPortTokens: the host verifies per-port preview
	// tokens (header, signed-link query param, and cookie carriers).
	HostCapabilityPreviewPortTokens = "preview_port_tokens_v1"
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

// PreviewClaims is the authenticated payload of a preview token. Every token
// is scoped to exactly one published port: there is no sandbox-wide token, so
// a leaked or shared credential can never reach a port other than the one it
// was minted for.
type PreviewClaims struct {
	// SandboxID is the bare sandbox UUID (region prefix stripped), matching
	// what the edge proxy derives from the request host.
	SandboxID string `json:"sid"`
	// Port is the single published port this token authorizes. Required.
	Port int `json:"p"`
	// Version must equal that port's current token_version. Rotating one
	// port's version invalidates only that port's outstanding tokens.
	Version int64 `json:"v"`
	// ExpiresAt is a Unix-seconds expiry; 0 means no expiry (the token lives
	// until the port's version rotates or the port is unpublished).
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
	if claims.Port < 1 || claims.Port > 65535 {
		return "", fmt.Errorf("auth: preview token requires a port in [1, 65535], got %d", claims.Port)
	}
	if claims.Version <= 0 {
		return "", fmt.Errorf("auth: preview token requires a positive version")
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
// derived from the request host, the requested port, and that published
// port's current token version. It fails closed: any parse error, signature
// mismatch, claim mismatch, or a non-positive published version rejects the
// token. The MAC is verified before the payload is decoded, so unauthenticated
// bytes never reach the JSON parser. The caller is responsible for having
// already confirmed the port is published (deny-by-default 404) — this only
// authenticates the token for an established port.
func VerifyPreviewToken(seed []byte, sandboxID string, port int, publishedVersion int64, presented string) bool {
	if len(seed) == 0 || sandboxID == "" || port <= 0 || publishedVersion <= 0 {
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
	// Port is mandatory and exact — no sandbox-wide tokens.
	if claims.Port != port {
		return false
	}
	if claims.Version != publishedVersion {
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
