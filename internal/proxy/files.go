package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// File bridge constants. The /files path lives on the same boxd port that
// the terminal bridge talks to (boxdPort, defined in terminal.go), because
// boxd serves both its connect-rpc services and the raw /files HTTP
// endpoint on a single HTTP listener. The proxy treats all traffic to
// boxdPort as sensitive regardless of path — only /files is allowlisted
// through, everything else is 404'd so the in-VM connect-rpc services
// stay strictly internal.
const (
	// filesPath is the single path we forward to boxd on boxdPort.
	// Anything else lands on an explicit 404.
	filesPath = "/files"

	// bearerPrefix matches the standard Authorization header format.
	bearerPrefix = "Bearer "

	// tokenQueryParam is the query-string fallback for contexts that
	// cannot set headers — notably <a href> downloads, <img src>
	// embeds, and any `window.open()` style flows. The mint endpoint
	// returns the token separately so callers can choose whichever
	// carrier fits their environment.
	tokenQueryParam = "token"
)

// serveBoxdPort is the entry point for any request addressed at
// `{boxdPort}-{instanceID}.{domain}`. It is reachable from ServeHTTP
// after ParseHost has validated the host label.
//
// The boxd port is a special case: it exposes both the raw file HTTP
// endpoint and internal connect-rpc services. We only ever expose /files
// through the edge, and only with a valid signed ScopeFiles token. Every
// other path and every other method returns an opaque 404 so a caller
// probing the in-VM surface learns nothing about what exists behind the
// proxy.
func (h *Handler) serveBoxdPort(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.filesEnabled {
		// The proxy was started without WithFiles — either this is a
		// legacy deployment that doesn't have the feature on yet or a
		// misconfigured one. Don't leak which: return the same 404 a
		// caller would see probing any other internal path.
		http.NotFound(w, r)
		return
	}

	if r.URL.Path != filesPath {
		// Block connect-rpc endpoints (e.g. /superserve.boxd.v1.ProcessService/Start)
		// and any future unlisted paths. NotFound rather than Forbidden
		// so scanners cannot enumerate which services exist.
		http.NotFound(w, r)
		return
	}

	// boxd's /files handler only implements GET (download) and POST
	// (upload). Anything else is a client bug and should surface loudly.
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, fromQuery := extractFileToken(r)
	if token == "" {
		http.Error(w,
			"missing token (pass Authorization: Bearer <token> or ?token=<token>)",
			http.StatusUnauthorized)
		return
	}

	// Scrub the token before we touch the upstream request. Two reasons:
	//
	//  1. boxd has no business seeing our bearer token — it trusts the
	//     edge proxy implicitly because it's bound to the VM's private
	//     IP and is not reachable from outside the host.
	//  2. If a caller used ?token= we want to strip it from the forwarded
	//     URL so it cannot land in any intermediate access log between
	//     here and the disk, however unlikely that is (there is none
	//     today, but keeping the token's blast radius minimal is cheap).
	r.Header.Del("Authorization")
	if fromQuery {
		q := r.URL.Query()
		q.Del(tokenQueryParam)
		r.URL.RawQuery = q.Encode()
	}

	// Don't emit a Referrer on anything this proxy might spawn. The
	// token-carrier is the sensitive piece; this matches the "token as a
	// secret" posture from the terminal bridge.
	w.Header().Set("Referrer-Policy", "no-referrer")

	_, info, fail := h.authorizeSandboxRequest(
		r.Context(), token, auth.ScopeFiles, instanceID, time.Now(),
	)
	if fail != nil {
		if fail.LogMsg != "" {
			evt := h.log.Warn().Str("sandbox_id", instanceID)
			if fail.LogKV[0] != "" {
				evt = evt.Str(fail.LogKV[0], fail.LogKV[1])
			}
			evt.Msg("files: " + fail.LogMsg)
		}
		fail.write(w)
		return
	}

	// From here on it's just a transparent reverse proxy to boxd.
	// Reuse the lifecycle-keyed transport cache for the same reasons
	// as the generic forwarder: one pooled set of TCP connections per
	// sandbox incarnation, reset on pause/resume.
	transport := h.transports.get(instanceID, info)
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, boxdPort),
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Preserve the original Host so boxd logs the public name,
			// not the VM private IP. Also avoids Host-header confusion
			// on any downstream middleware that trusts it.
			req.Host = r.Host
			// Strip all forwarding / origin headers — a caller could
			// otherwise inject these to spoof identity in any boxd
			// log or future handler that trusts them. Note the
			// explicit `= nil` for X-Forwarded-For: httputil.ReverseProxy
			// re-appends that header after the Director runs unless
			// its value is the nil slice. A plain Del leaves it
			// missing, which httputil then "helpfully" refills.
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
		// FlushInterval -1 streams the response as it arrives, which is
		// what we want for large downloads: the client sees bytes as
		// boxd produces them, not after the whole file is buffered.
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("target", target.Host).
				Msg("files: upstream error")
			// Invalidate so the next request re-resolves from VMD,
			// in case the VM was replaced mid-stream.
			h.resolver.Invalidate(instanceID)
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// extractFileToken pulls the signed token out of either the Authorization
// header or the ?token= query parameter, in that order. The second return
// value reports whether the token came from the query string so the
// caller can strip it before forwarding upstream.
//
// We accept both carriers because file transfers have contexts the
// terminal bridge doesn't: plain HTML downloads via <a href> cannot set
// custom headers, but they can embed the token in the URL; programmatic
// uploads from an SDK can (and should) use the header carrier to keep
// the token out of server access logs. Supporting both mirrors the E2B
// precedent and avoids pushing SDK authors into a worse default.
func extractFileToken(r *http.Request) (token string, fromQuery bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(h, bearerPrefix) {
			return strings.TrimSpace(h[len(bearerPrefix):]), false
		}
	}
	if q := r.URL.Query().Get(tokenQueryParam); q != "" {
		return q, true
	}
	return "", false
}
