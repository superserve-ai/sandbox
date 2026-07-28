package proxy

import (
	"net/http"

	"github.com/superserve-ai/sandbox/internal/preview"
)

// enforcePreviewPublication runs before status handling. Legacy records retain
// all-port routing; every other policy requires explicit publication and uses
// the same 404 whether the sandbox is running, paused, or absent from the set.
func enforcePreviewPublication(w http.ResponseWriter, port int, info InstanceInfo) bool {
	switch info.PreviewAccess {
	case "", preview.AccessLegacyPublic:
		return true
	case preview.AccessPublic:
		if _, published := info.PreviewPorts[port]; !published {
			http.Error(w, "sandbox not found", http.StatusNotFound)
			return false
		}
		return true
	default:
		// A newer control plane may introduce policy values this proxy cannot
		// enforce. Never interpret them as public publication.
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}
}
