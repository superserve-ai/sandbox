package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// ComputeAccessToken derives a per-sandbox access token from the
// shared seed and the sandbox ID. The result is a stable hex-encoded
// HMAC-SHA256 digest — same inputs always produce the same output.
func ComputeAccessToken(seed []byte, sandboxID string) string {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(sandboxID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAccessToken checks whether a presented token matches the
// expected HMAC for the given sandbox ID. Uses constant-time
// comparison to prevent timing side-channels.
func VerifyAccessToken(seed []byte, sandboxID, presentedToken string) bool {
	expected := ComputeAccessToken(seed, sandboxID)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presentedToken)) == 1
}

// ValidateSeed checks that a seed key is present and of reasonable length.
func ValidateSeed(seed []byte) error {
	if len(seed) == 0 {
		return fmt.Errorf("auth: sandbox access token seed is empty")
	}
	if len(seed) < 32 {
		return fmt.Errorf("auth: sandbox access token seed is too short (%d bytes, want >= 32)", len(seed))
	}
	return nil
}
