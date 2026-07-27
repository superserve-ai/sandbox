package proxy

import (
	"net/http"

	"github.com/superserve-ai/sandbox/internal/preview"
)

// enforcePreviewPublication runs before status handling. Legacy records retain
// all-port routing. Recognized strict policies require publication first, then
// exact per-port access: public routes and private/unknown returns 401 until the
// token-authentication phase lands. Unknown sandbox modes always return 404.
func enforcePreviewPublication(w http.ResponseWriter, port int, info InstanceInfo) bool {
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
	http.Error(w, "private preview authentication is not available", http.StatusUnauthorized)
	return false
}
