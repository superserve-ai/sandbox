package secretsproxy

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrMissingProxyAuth   = errors.New("missing Proxy-Authorization header")
	ErrMalformedProxyAuth = errors.New("Proxy-Authorization malformed (want 'Basic <base64(user:jwt)>')")
)

// ParseProxyAuthJWT extracts the JWT from r's Proxy-Authorization header.
// The header carries `Basic base64(<user>:<jwt>)`; user is informational
// (typically "sb") and ignored — the JWT in the password position is what
// the daemon verifies.
func ParseProxyAuthJWT(r *http.Request) (string, error) {
	raw := r.Header.Get("Proxy-Authorization")
	if raw == "" {
		return "", ErrMissingProxyAuth
	}

	const scheme = "Basic "
	if !strings.HasPrefix(raw, scheme) {
		return "", ErrMalformedProxyAuth
	}
	encoded := strings.TrimSpace(raw[len(scheme):])
	if encoded == "" {
		return "", ErrMalformedProxyAuth
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", ErrMalformedProxyAuth
		}
	}

	creds := string(decoded)
	colon := strings.IndexByte(creds, ':')
	if colon < 0 || colon == len(creds)-1 {
		return "", ErrMalformedProxyAuth
	}
	return creds[colon+1:], nil
}
