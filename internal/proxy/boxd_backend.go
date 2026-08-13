package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Shared plumbing for every endpoint that reverse-proxies to boxd's
// in-VM listener (files, exec, desktop). The auth sequence and the
// forwarded-header scrub are security-relevant; keep them here so a
// change lands in every boxd-fronted endpoint at once.

// authorizeBoxdRequest runs the common auth sequence: require the access
// token, scrub caller-controlled headers, verify the token against the
// sandbox. On failure it writes the response and returns ok=false.
func (h *Handler) authorizeBoxdRequest(w http.ResponseWriter, r *http.Request, instanceID, logPrefix string) (InstanceInfo, bool) {
	token := r.Header.Get(accessTokenHeader)
	if token == "" {
		http.Error(w, "missing X-Access-Token header", http.StatusUnauthorized)
		return InstanceInfo{}, false
	}
	r.Header.Del(accessTokenHeader)
	r.Header.Del(headerSandboxID)
	w.Header().Set("Referrer-Policy", "no-referrer")

	info, fail := h.authorizeSandboxRequest(r.Context(), token, instanceID)
	if fail != nil {
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg(logPrefix + ": auth failed")
		fail.write(w)
		return InstanceInfo{}, false
	}
	return info, true
}

// boxdTarget is boxd's in-VM listener for the given sandbox.
func boxdTarget(info InstanceInfo) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, boxdPort),
	}
}

// boxdDirector rewrites the request to the boxd target and strips all
// forwarding / origin headers — a caller could otherwise inject these to
// spoof identity in any boxd log or future handler that trusts them. The
// original Host is preserved so boxd logs the public name, not the VM
// private IP. Note the explicit `= nil` for X-Forwarded-For:
// httputil.ReverseProxy re-appends that header after the Director runs
// unless its value is the nil slice; a plain Del leaves it missing, which
// httputil then "helpfully" refills.
func boxdDirector(originalHost string, target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = originalHost
		req.Header["X-Forwarded-For"] = nil
		for _, hdr := range []string{
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Real-Ip",
			"Forwarded",
		} {
			req.Header.Del(hdr)
		}
	}
}

// newBoxdReverseProxy builds the standard streaming reverse proxy to boxd
// for one request. Upstream failures invalidate the resolver entry (the VM
// may have been replaced mid-stream) and return 502 — except a tripped
// MaxBytesReader cap on the request body, which is the caller's fault and
// maps to 413 without touching the resolver.
func (h *Handler) newBoxdReverseProxy(r *http.Request, instanceID string, info InstanceInfo, logPrefix string) *httputil.ReverseProxy {
	target := boxdTarget(info)
	return &httputil.ReverseProxy{
		Director:      boxdDirector(r.Host, target),
		Transport:     h.transports.get(instanceID, info),
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			var mbe *http.MaxBytesError
			if errors.As(proxyErr, &mbe) {
				http.Error(rw, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("path", req.URL.Path).
				Str("target", target.Host).
				Msg(logPrefix + ": upstream error")
			h.resolver.Invalidate(instanceID)
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}
}
