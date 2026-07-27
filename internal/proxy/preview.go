package proxy

import (
	"net/http"
	"strings"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/preview"
)

// enforcePreviewPublication runs before status handling. Legacy records retain
// all-port routing. Recognized strict policies require publication first, then
// exact per-port access: public routes, raw private stays closed, and only the
// token wire sentinel can authenticate. Unknown sandbox modes return 404.
func enforcePreviewPublication(w http.ResponseWriter, r *http.Request, instanceID string, port int, info InstanceInfo, seed []byte) bool {
	switch info.PreviewAccess {
	case "", preview.AccessLegacyPublic:
		// Preserve legacy all-port routing unless an additive Phase 2 record
		// explicitly marks this exact port non-public. That defensive exception
		// keeps an inconsistent rollback snapshot fail closed even if it bypasses
		// VMD's restrictive top-level normalization.
		if mode, recorded := info.PreviewPortAccess[port]; recorded && mode != "" && mode != preview.AccessPublic {
			http.Error(w, "private preview authentication is not available", http.StatusUnauthorized)
			return false
		}
		return true
	case preview.AccessPublic, preview.AccessPrivate:
	default:
		// A newer control plane may introduce policy values this proxy cannot
		// enforce. Never interpret them as public publication.
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}
	if _, published := info.PreviewPorts[port]; !published {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}
	mode := info.PreviewPortAccess[port]
	if mode == "" {
		mode = info.PreviewAccess
	}
	if mode == preview.AccessPublic {
		return true
	}
	if mode == preview.AccessPrivateTokenV1 {
		version := info.PreviewPortTokenVersions[port]
		if version <= 0 || auth.ValidateSeed(seed) != nil {
			http.Error(w, "private preview authentication is not available", http.StatusUnauthorized)
			return false
		}
		// Browsers must be able to perform a standards-compliant CORS preflight
		// before sending the credential header. OPTIONS by itself is an ordinary
		// application request and remains authenticated.
		if isCORSPreflight(r) {
			return true
		}
		values := headerValues(r.Header, auth.PreviewTokenHeader)
		if len(values) == 1 &&
			auth.VerifyPreviewToken(seed, instanceID, port, version, values[0]) {
			return true
		}
	}
	http.Error(w, "private preview authentication is not available", http.StatusUnauthorized)
	return false
}

func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

func headerValues(header http.Header, name string) []string {
	var values []string
	for key, current := range header {
		if strings.EqualFold(key, name) {
			values = append(values, current...)
		}
	}
	return values
}

// scrubHeader removes every differently-cased map entry and every repeated
// value of a reserved credential header before the request reaches user code.
func scrubHeader(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}
