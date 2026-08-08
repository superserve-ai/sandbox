package proxy

import (
	"net/http"
	"time"

	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

const (
	desktopScreenshotPath  = boxdpbconnect.DesktopServiceScreenshotProcedure
	desktopStreamPath      = boxdpbconnect.DesktopServiceStreamProcedure
	desktopSendPointerPath = boxdpbconnect.DesktopServiceSendPointerProcedure
	desktopSendKeyPath     = boxdpbconnect.DesktopServiceSendKeyProcedure
	desktopScrollPath      = boxdpbconnect.DesktopServiceScrollProcedure
	desktopResizePath      = boxdpbconnect.DesktopServiceResizeProcedure
	desktopSendActionsPath = boxdpbconnect.DesktopServiceSendActionsProcedure

	// Sized above the largest request boxd itself accepts — a SendActions
	// batch of 64 actions × 64KiB text (~4MiB) plus envelope/JSON-encoding
	// headroom — so the proxy never rejects a request boxd would take,
	// while still bounding abuse.
	maxDesktopRequestBytes = 8 << 20 // 8 MiB

	// desktopUsageWindow debounces desktop usage events per (sandbox,
	// event). Screenshots and input arrive per agent-loop iteration —
	// orders of magnitude denser than any other usage event — and would
	// otherwise crowd out the low-frequency events the usage pipeline
	// reports on (the analytics buffer drops on overflow).
	desktopUsageWindow = time.Minute
)

// WithDesktop exposes only the DesktopService RPC paths through the reserved
// boxd host. Every request still requires the sandbox-scoped access token.
func (h *Handler) WithDesktop() *Handler {
	if h.seedKey == nil {
		panic("proxy: WithDesktop requires WithAuth to be called first")
	}
	h.desktopEnabled = true
	h.desktopUsageLast = make(map[string]time.Time)
	return h
}

// captureDesktopUsage emits a usage event at most once per
// desktopUsageWindow per (sandbox, event).
func (h *Handler) captureDesktopUsage(instanceID, event string, info InstanceInfo) {
	now := time.Now()
	key := instanceID + "\x00" + event

	h.desktopUsageMu.Lock()
	// ponytail: linear sweep keyed off map size; an LRU if fleets of
	// concurrently-active desktop sandboxes ever exceed ~4k.
	if len(h.desktopUsageLast) > 4096 {
		for k, t := range h.desktopUsageLast {
			if now.Sub(t) > desktopUsageWindow {
				delete(h.desktopUsageLast, k)
			}
		}
	}
	last, seen := h.desktopUsageLast[key]
	if seen && now.Sub(last) < desktopUsageWindow {
		h.desktopUsageMu.Unlock()
		return
	}
	h.desktopUsageLast[key] = now
	h.desktopUsageMu.Unlock()

	h.captureUsage(instanceID, event, info)
}

func (h *Handler) serveDesktop(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.desktopEnabled {
		http.NotFound(w, r)
		return
	}

	// Browser clients are expected to use the Connect protocol; gRPC-web
	// is not supported (its required headers are deliberately absent here).
	if origin := r.Header.Get("Origin"); origin != "" {
		if h.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "X-Access-Token, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject declared-oversize bodies before proxying; MaxBytesReader
	// backstops clients that lie or stream chunked, surfacing as 413 via
	// the proxy's ErrorHandler.
	if r.ContentLength > maxDesktopRequestBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDesktopRequestBytes)

	info, ok := h.authorizeBoxdRequest(w, r, instanceID, "desktop")
	if !ok {
		return
	}

	event := "desktop_input"
	switch r.URL.Path {
	case desktopStreamPath:
		event = "desktop_stream"
	case desktopScreenshotPath:
		event = "desktop_screenshot"
	}
	h.captureDesktopUsage(instanceID, event, info)

	h.newBoxdReverseProxy(r, instanceID, info, "desktop").ServeHTTP(w, r)
}
