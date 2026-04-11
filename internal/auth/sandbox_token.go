package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// tokenWindow is the granularity of token expiry. Tokens are valid for
// the current window and the previous one, giving a lifespan of 1-2h.
const tokenWindow = time.Hour

// computeTokenForWindow derives a token for a specific time window.
func computeTokenForWindow(seed []byte, sandboxID string, window int64) string {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(sandboxID))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(window, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// currentWindow returns the hour-granular window number for the given time.
func currentWindow(t time.Time) int64 {
	return t.Unix() / int64(tokenWindow.Seconds())
}

// ComputeAccessToken derives a per-sandbox access token from the shared
// seed, sandbox ID, and the current hour window. The token expires when
// the current window and the next window both pass (~1-2 hours).
func ComputeAccessToken(seed []byte, sandboxID string) string {
	return computeTokenForWindow(seed, sandboxID, currentWindow(time.Now()))
}

// VerifyAccessToken checks whether a presented token matches the expected
// HMAC for the current or previous hour window. Uses constant-time
// comparison to prevent timing side-channels.
func VerifyAccessToken(seed []byte, sandboxID, presentedToken string) bool {
	now := currentWindow(time.Now())

	// Accept current window or previous window.
	for _, w := range []int64{now, now - 1} {
		expected := computeTokenForWindow(seed, sandboxID, w)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(presentedToken)) == 1 {
			return true
		}
	}
	return false
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
