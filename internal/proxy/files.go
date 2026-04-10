package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// File bridge constants. The /files path lives on the same boxd port that
// the terminal bridge talks to (boxdPort, defined in terminal.go), because
// boxd serves both its connect-rpc services and the raw /files HTTP
// endpoint on a single HTTP listener. The proxy treats all traffic to
// boxdPort as sensitive regardless of path — only /files is allowlisted
// through, everything else is 404'd so the in-VM connect-rpc services
// stay strictly internal.
const (
	// filesPath is the HTTP path the edge proxy forwards to boxd's
	// raw /files handler after verifying the access token.
	filesPath = "/files"

	// terminalPath is the HTTP path the edge proxy upgrades to a
	// WebSocket and bridges to boxd's connect-rpc ProcessService.
	// The bridge itself is implemented in terminal.go; this constant
	// just names the route serveBoxdPort dispatches to it on.
	terminalPath = "/terminal"

	// accessTokenHeader is the carrier for the per-sandbox HMAC access token.
	accessTokenHeader = "X-Access-Token"
)

// serveBoxdPort is the entry point for any request addressed at the
// reserved `boxd-{instanceID}.{domain}` host label. It dispatches by
// path to the concrete handler for each boxd-fronted feature.
//
// boxd is a special case: inside the VM a single HTTP listener serves
// both the raw /files endpoint and the full connect-rpc service
// surface (ProcessService, FilesystemService). We only ever expose the
// narrow set of paths we explicitly handle below; any other path
// returns an opaque 404 so a caller probing the in-VM surface cannot
// enumerate what exists behind the proxy. That includes `/health`,
// connect-rpc routes, and anything future boxd grows internally
// without our knowledge.
func (h *Handler) serveBoxdPort(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.sandboxConns.acquire(instanceID) {
		http.Error(w, "too many connections to sandbox", http.StatusTooManyRequests)
		return
	}
	defer h.sandboxConns.release(instanceID)

	clientIP := clientAddr(r)
	if !h.ipConns.acquire(clientIP) {
		http.Error(w, "too many connections from this IP", http.StatusTooManyRequests)
		return
	}
	defer h.ipConns.release(clientIP)

	switch r.URL.Path {
	case filesPath:
		h.serveFiles(w, r, instanceID)
	case terminalPath:
		if h.terminal == nil {
			// Proxy started without WithTerminal — don't leak that
			// the feature exists but is off.
			http.NotFound(w, r)
			return
		}
		h.serveTerminal(w, r, instanceID)
	default:
		http.NotFound(w, r)
	}
}

// serveFiles handles POST/GET /files on the boxd host label. It
// verifies the sandbox access token, scrubs the token and caller-
// controlled headers, and reverse-proxies the request to boxd's
// internal /files handler.
func (h *Handler) serveFiles(w http.ResponseWriter, r *http.Request, instanceID string) {
	if !h.filesEnabled {
		// The proxy was started without WithFiles — either this is a
		// legacy deployment that doesn't have the feature on yet or a
		// misconfigured one. Don't leak which: return the same 404 a
		// caller would see probing any other internal path.
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

	// Path traversal rejection. boxd's own safePath runs filepath.Clean,
	// which silently resolves `..` segments instead of refusing them —
	// `/home/user/../../../etc/x` quietly becomes `/etc/x` and gets
	// written as root. That's technically no worse than what a caller
	// could do via the exec endpoint, but it contradicts the documented
	// "path traversal rejected" contract and turns a typo in a relative
	// path into a silent write to an unintended location. Reject any
	// request whose ?path= contains a literal `..` segment, before we
	// hit the auth check.
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "missing path query parameter", http.StatusBadRequest)
		return
	}
	for _, seg := range strings.Split(requestedPath, "/") {
		if seg == ".." {
			http.Error(w, "path traversal not allowed", http.StatusBadRequest)
			return
		}
	}

	token := r.Header.Get(accessTokenHeader)
	if token == "" {
		http.Error(w, "missing X-Access-Token header", http.StatusUnauthorized)
		return
	}

	// Scrub the token before forwarding to boxd.
	r.Header.Del(accessTokenHeader)

	w.Header().Set("Referrer-Policy", "no-referrer")

	info, fail := h.authorizeSandboxRequest(r.Context(), token, instanceID)
	if fail != nil {
		h.log.Warn().Str("sandbox_id", instanceID).Int("status", fail.Status).Msg("files: auth failed")
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

