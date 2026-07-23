package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
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
	tStart := time.Now()

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
	tAuthDone := time.Now()
	h.captureUsage(instanceID, "command_run", info)

	transport := h.transports.get(instanceID, info)
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, boxdPort),
	}

	// Per-request phase fields, mirroring the create path's phase log:
	// aggregate across requests or read one line for a single create→exec
	// flow. upstream_ttfb spans dial + request + boxd's whole run for the
	// sync path (boxd buffers to completion), so the guest-side headers
	// are what split it further.
	var (
		upstreamStatus int
		ttfbMs         int64 = -1
		boxdSpawnMs    int64 = -1
		boxdRunMs      int64 = -1
		tProxy         time.Time
	)

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
		ModifyResponse: func(resp *http.Response) error {
			ttfbMs = time.Since(tProxy).Milliseconds()
			upstreamStatus = resp.StatusCode
			boxdSpawnMs = headerMs(resp, "X-Boxd-Spawn-Ms")
			boxdRunMs = headerMs(resp, "X-Boxd-Run-Ms")
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("target", target.Host).
				Bool("streaming", streaming).
				Msg("exec: upstream error")
			h.resolver.Invalidate(instanceID)
			// ModifyResponse never ran; record what the client actually got
			// so unreachable-sandbox 502s show up in status-based queries.
			upstreamStatus = http.StatusBadGateway
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}
	tProxy = time.Now()
	rp.ServeHTTP(w, r)

	h.log.Info().
		Str("sandbox_id", instanceID).
		Bool("streaming", streaming).
		Int("status", upstreamStatus).
		Int64("auth_ms", tAuthDone.Sub(tStart).Milliseconds()).
		Int64("upstream_ttfb_ms", ttfbMs).
		Int64("total_ms", time.Since(tStart).Milliseconds()).
		Int64("boxd_spawn_ms", boxdSpawnMs).
		Int64("boxd_run_ms", boxdRunMs).
		Msg("exec phases")
}

// headerMs parses a millisecond timing header; -1 means absent or unparseable
// (an old boxd, or a non-exec error response), keeping the field numeric so
// it aggregates with the other *_ms fields.
func headerMs(resp *http.Response, name string) int64 {
	v := resp.Header.Get(name)
	if v == "" {
		return -1
	}
	ms, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return ms
}
