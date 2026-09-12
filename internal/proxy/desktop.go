package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

const (
	desktopStreamPath      = boxdpbconnect.DesktopServiceStreamProcedure
	desktopSendPointerPath = boxdpbconnect.DesktopServiceSendPointerProcedure
	desktopSendKeyPath     = boxdpbconnect.DesktopServiceSendKeyProcedure
	desktopScrollPath      = boxdpbconnect.DesktopServiceScrollProcedure
	desktopResizePath      = boxdpbconnect.DesktopServiceResizeProcedure

	maxDesktopRequestBytes = 64 * 1024
)

// WithDesktop exposes only the DesktopService RPC paths through the reserved
// boxd host. Every request still requires the sandbox-scoped access token.
func (h *Handler) WithDesktop() *Handler {
	if h.seedKey == nil {
		panic("proxy: WithDesktop requires WithAuth to be called first")
	}
	h.desktopEnabled = true
	return h
}

func (h *Handler) serveDesktop(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.desktopEnabled {
		http.NotFound(w, r)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		if h.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "X-Access-Token, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, Grpc-Timeout")
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
	r.Body = http.MaxBytesReader(w, r.Body, maxDesktopRequestBytes)

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
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg("desktop: auth failed")
		fail.write(w)
		return
	}

	event := "desktop_input"
	if r.URL.Path == desktopStreamPath {
		event = "desktop_stream"
	}
	h.captureUsage(instanceID, event, info)

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
			for _, header := range []string{
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
				"X-Real-Ip",
				"Forwarded",
			} {
				req.Header.Del(header)
			}
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("method", r.URL.Path).
				Str("target", target.Host).
				Msg("desktop: upstream error")
			h.resolver.Invalidate(instanceID)
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}
