package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Preview token carrier names are shared by the control plane and edge proxy
// so credential responses cannot drift from enforcement.
const (
	// PreviewTokenHeader carries a token for clients that can attach request
	// headers.
	PreviewTokenHeader = "X-Superserve-Preview-Token"
	// PreviewTokenQueryParam bootstraps browser access. The edge exchanges a
	// valid value for a host-only cookie and redirects to a clean URL.
	PreviewTokenQueryParam = "superserve_preview_token"
	// PreviewTokenCookie is the exact host-scoped browser cookie consumed by
	// the edge. The __Host- prefix requires Secure, Path=/, and no Domain.
	PreviewTokenCookie = "__Host-superserve_preview_token"
)

const (
	previewTokenPrefix = "spv1"

	// previewMACDomain separates these MACs from the boxd access tokens, which
	// use the same seed but sign "<sandbox-id>|<hour-window>" directly.
	previewMACDomain = "superserve.preview-port-token.v1\x00"

	// A canonical payload is currently under 100 bytes. These bounds leave
	// ample room for format evolution while limiting work on hostile input.
	maxPreviewTokenLen           = 512
	maxPreviewTokenPayloadLen    = 256
	maxPreviewTokenPayloadB64Len = 342 // RawURLEncoding.EncodedLen(256).
)

var (
	previewB64 = base64.RawURLEncoding.Strict()

	errPreviewTokenFormat         = errors.New("auth: invalid preview token format")
	errPreviewTokenAuthentication = errors.New("auth: invalid preview token authentication")
	errPreviewTokenClaims         = errors.New("auth: invalid preview token claims")
)

// PreviewClaims is the authenticated payload of a preview token. Every token
// is scoped to exactly one sandbox, published port, and token generation.
type PreviewClaims struct {
	// SandboxID is the canonical, lowercase, hyphenated UUID string.
	SandboxID string `json:"sid"`
	// Port is the single port this token authorizes.
	Port int `json:"p"`
	// Version is the port's positive token generation.
	Version int64 `json:"v"`
	// ExpiresAt is an optional Unix timestamp in whole seconds. Zero omits the
	// claim, leaving rotation or unpublication as the token's expiry mechanism.
	ExpiresAt int64 `json:"exp,omitempty"`
}

// ComputePreviewToken deterministically mints
// "spv1.<base64url-json>.<base64url-hmac>". The JSON is emitted in a single
// canonical representation and the HMAC uses the existing sandbox seed in a
// domain separate from boxd access tokens.
func ComputePreviewToken(seed []byte, claims PreviewClaims) (string, error) {
	if err := ValidateSeed(seed); err != nil {
		return "", err
	}
	if err := validatePreviewClaims(claims); err != nil {
		return "", err
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshal preview token claims: %w", err)
	}
	if len(raw) > maxPreviewTokenPayloadLen {
		return "", fmt.Errorf("%w: payload is too large", errPreviewTokenFormat)
	}

	payload := previewB64.EncodeToString(raw)
	signingInput := previewTokenPrefix + "." + payload
	signature := previewB64.EncodeToString(previewTokenMAC(seed, signingInput))
	token := signingInput + "." + signature
	if len(token) > maxPreviewTokenLen {
		return "", fmt.Errorf("%w: token is too large", errPreviewTokenFormat)
	}
	return token, nil
}

// VerifyPreviewToken checks a token against the sandbox identity derived from
// the request host, the requested port, and that port's current generation.
// It verifies the MAC before base64-decoding or parsing the claims.
func VerifyPreviewToken(seed []byte, sandboxID string, port int, version int64, presented string) bool {
	return verifyPreviewTokenAt(seed, sandboxID, port, version, presented, time.Now()) == nil
}

func verifyPreviewTokenAt(seed []byte, sandboxID string, port int, version int64, presented string, now time.Time) error {
	if err := ValidateSeed(seed); err != nil {
		return err
	}
	if err := validatePreviewClaims(PreviewClaims{
		SandboxID: sandboxID,
		Port:      port,
		Version:   version,
	}); err != nil {
		return err
	}
	if presented == "" || len(presented) > maxPreviewTokenLen {
		return errPreviewTokenFormat
	}

	prefix, remainder, ok := strings.Cut(presented, ".")
	if !ok || prefix != previewTokenPrefix {
		return errPreviewTokenFormat
	}
	payload, signature, ok := strings.Cut(remainder, ".")
	if !ok || payload == "" || signature == "" || strings.Contains(signature, ".") {
		return errPreviewTokenFormat
	}
	if len(payload) > maxPreviewTokenPayloadB64Len {
		return errPreviewTokenFormat
	}
	if len(signature) != previewB64.EncodedLen(sha256.Size) {
		return errPreviewTokenFormat
	}

	providedMAC, err := previewB64.DecodeString(signature)
	if err != nil || len(providedMAC) != sha256.Size {
		return errPreviewTokenFormat
	}
	signingInput := prefix + "." + payload
	if !hmac.Equal(previewTokenMAC(seed, signingInput), providedMAC) {
		return errPreviewTokenAuthentication
	}

	// The payload remains opaque until after authentication. This both avoids
	// parser work on attacker-controlled bytes and keeps failures fail-closed.
	if previewB64.DecodedLen(len(payload)) > maxPreviewTokenPayloadLen {
		return errPreviewTokenFormat
	}
	raw, err := previewB64.DecodeString(payload)
	if err != nil || len(raw) > maxPreviewTokenPayloadLen {
		return errPreviewTokenFormat
	}
	// Encoding.Strict still permits CR and LF. Re-encoding closes that
	// malleability and requires one exact raw-base64url representation.
	if previewB64.EncodeToString(raw) != payload {
		return errPreviewTokenFormat
	}

	claims, err := decodePreviewClaims(raw)
	if err != nil {
		return err
	}
	if claims.SandboxID != sandboxID || claims.Port != port || claims.Version != version {
		return fmt.Errorf("%w: scope mismatch", errPreviewTokenClaims)
	}
	if claims.ExpiresAt != 0 && now.Unix() >= claims.ExpiresAt {
		return fmt.Errorf("%w: token has expired", errPreviewTokenClaims)
	}
	return nil
}

func decodePreviewClaims(raw []byte) (PreviewClaims, error) {
	var claims PreviewClaims
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return PreviewClaims{}, fmt.Errorf("%w: %v", errPreviewTokenClaims, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PreviewClaims{}, fmt.Errorf("%w: trailing JSON", errPreviewTokenClaims)
	}
	if err := validatePreviewClaims(claims); err != nil {
		return PreviewClaims{}, err
	}

	// Requiring the exact representation emitted by ComputePreviewToken also
	// rejects duplicate keys, reordered keys, explicit zero optional claims,
	// trailing whitespace, and alternate JSON spellings.
	canonical, err := json.Marshal(claims)
	if err != nil {
		return PreviewClaims{}, fmt.Errorf("%w: cannot canonicalize", errPreviewTokenClaims)
	}
	if !bytes.Equal(raw, canonical) {
		return PreviewClaims{}, fmt.Errorf("%w: non-canonical JSON", errPreviewTokenClaims)
	}
	return claims, nil
}

func validatePreviewClaims(claims PreviewClaims) error {
	sandboxID, err := uuid.Parse(claims.SandboxID)
	if err != nil || sandboxID == uuid.Nil || sandboxID.String() != claims.SandboxID {
		return fmt.Errorf("%w: sandbox ID must be a canonical UUID", errPreviewTokenClaims)
	}
	if claims.Port < 1 || claims.Port > 65535 {
		return fmt.Errorf("%w: port must be in [1, 65535]", errPreviewTokenClaims)
	}
	if claims.Version <= 0 {
		return fmt.Errorf("%w: version must be positive", errPreviewTokenClaims)
	}
	if claims.ExpiresAt < 0 {
		return fmt.Errorf("%w: expiry must be a positive Unix timestamp", errPreviewTokenClaims)
	}
	return nil
}

func previewTokenMAC(seed []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte(previewMACDomain))
	_, _ = mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
