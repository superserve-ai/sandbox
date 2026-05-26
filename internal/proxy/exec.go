package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const (
	// execPath is the synchronous data-plane exec endpoint on the boxd
	// host label: POST → run command to completion → JSON response.
	// Shape matches the controlplane's /sandboxes/{id}/exec.
	execPath = "/exec"

	// execStreamPath is the SSE data-plane exec endpoint on the boxd
	// host label: POST → stream stdout/stderr/end events as SSE.
	// Shape matches the controlplane's /sandboxes/{id}/exec/stream.
	execStreamPath = "/exec/stream"
)

// WithExec enables the /exec and /exec/stream HTTP reverse proxy on
// boxdPort. Requires WithAuth to have been called first. Off by default
// — the SDK keeps using the controlplane /sandboxes/{id}/exec path
// until both proxy and SDK have been upgraded.
func (h *Handler) WithExec() *Handler {
	if h.seedKey == nil {
		panic("proxy: WithExec requires WithAuth to be called first")
	}
	h.execEnabled = true
	return h
}

// serveExec handles POST /exec on the boxd host label. Auth + scrub +
// reverse-proxy to boxd's HTTP /exec handler. Mirror of serveFiles
// without the path-traversal check (no path query param here) and
// without CORS (data-plane exec is not browser-facing today).
func (h *Handler) serveExec(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.execEnabled {
		// Started without WithExec — don't leak that the feature exists.
		http.NotFound(w, r)
		return
	}
	h.serveExecCommon(w, r, instanceID, false)
}

// serveExecStream handles POST /exec/stream on the boxd host label. Same
// shape as serveExec but configures the reverse proxy for SSE: forces
// flushing on every write so events aren't buffered en route, and never
// retries on error mid-stream (headers have committed once the upstream
// starts writing).
func (h *Handler) serveExecStream(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.execEnabled {
		http.NotFound(w, r)
		return
	}
	h.serveExecCommon(w, r, instanceID, true)
}

func (h *Handler) serveExecCommon(w http.ResponseWriter, r *http.Request, instanceID string, streaming bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get(accessTokenHeader)
	if token == "" {
		http.Error(w, "missing X-Access-Token header", http.StatusUnauthorized)
		return
	}
	r.Header.Del(accessTokenHeader)
	w.Header().Set("Referrer-Policy", "no-referrer")

	info, fail := h.authorizeSandboxRequest(r.Context(), token, instanceID)
	if fail != nil {
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg("exec: auth failed")
		fail.write(w)
		return
	}

	transport := h.transports.get(instanceID, info)
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, boxdPort),
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = r.Host
			// Same header scrub as serveFiles: drop forwarded-* + caller-
			// supplied real-IP headers so boxd or any future middleware
			// can't be fooled about who initiated the request.
			req.Header["X-Forwarded-For"] = nil
			for _, hdr := range []string{
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
				"X-Real-Ip",
				"Forwarded",
			} {
				req.Header.Del(hdr)
			}
		},
		Transport: transport,
		// FlushInterval -1 streams every chunk as it arrives. Required for
		// /exec/stream so SSE events reach the client without buffering;
		// harmless for synchronous /exec where the body is small.
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("target", target.Host).
				Bool("streaming", streaming).
				Msg("exec: upstream error")
			h.resolver.Invalidate(instanceID)
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}
