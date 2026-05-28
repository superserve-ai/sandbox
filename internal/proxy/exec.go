package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const (
	execPath       = "/exec"
	execStreamPath = "/exec/stream"
)

// WithExec enables /exec and /exec/stream on the boxd host label.
// Requires WithAuth.
func (h *Handler) WithExec() *Handler {
	if h.seedKey == nil {
		panic("proxy: WithExec requires WithAuth to be called first")
	}
	h.execEnabled = true
	return h
}

func (h *Handler) serveExec(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.execEnabled {
		http.NotFound(w, r)
		return
	}
	h.serveExecCommon(w, r, instanceID, false)
}

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
	r.Header.Del(headerSandboxID)
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
		// -1: stream each chunk as it arrives — required for SSE.
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
