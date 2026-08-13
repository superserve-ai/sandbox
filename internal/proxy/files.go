package proxy

import (
	"net/http"
	"strings"
)

// File bridge constants. The /files path lives on the same boxd port that
// the terminal bridge talks to (boxdPort, defined in terminal.go), because
// boxd serves both its connect-rpc services and the raw /files HTTP
// endpoint on a single HTTP listener. The proxy treats all traffic to
// boxdPort as sensitive regardless of path — serveBoxdPort forwards only
// the explicit per-path allowlist in its switch (/files, the exec
// endpoints, and the DesktopService connect-rpc procedures); everything
// else is 404'd. Any new boxd route or RPC stays unreachable from outside
// until it is deliberately added to that allowlist.
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

	// maxUploadBytes caps a single file upload at the proxy layer.
	// The real per-sandbox storage limit is ENOSPC (VM disk size), but
	// this prevents a caller from streaming an absurdly large payload
	// that ties up proxy resources before the VM disk fills.
	maxUploadBytes = 4 << 30 // 4 GB
)

// serveBoxdPort is the entry point for any request addressed at the
// reserved `boxd-{instanceID}.{domain}` host label. It dispatches by
// path to the concrete handler for each boxd-fronted feature.
//
// boxd is a special case: inside the VM a single HTTP listener serves
// both the raw /files endpoint and the full connect-rpc service
// surface (ProcessService, FilesystemService, DesktopService). We only
// ever expose the narrow set of paths we explicitly handle below; any
// other path returns an opaque 404 so a caller probing the in-VM
// surface cannot enumerate what exists behind the proxy. That includes
// `/health`, the ProcessService/FilesystemService connect-rpc routes,
// and anything future boxd grows internally without our knowledge.
// DesktopService procedures are the one connect-rpc surface deliberately
// exposed (see desktop.go) — a new DesktopService RPC must also be added
// to the switch below or it will 404 here while working in direct-to-boxd
// testing.
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
	case execPath:
		h.serveExec(w, r, instanceID)
	case execStreamPath:
		h.serveExecStream(w, r, instanceID)
	case execConnectPath:
		h.serveExecWS(w, r, instanceID)
	case desktopScreenshotPath,
		desktopStreamPath,
		desktopSendPointerPath,
		desktopSendKeyPath,
		desktopScrollPath,
		desktopResizePath,
		desktopSendActionsPath:
		h.serveDesktop(w, r, instanceID)
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

	// CORS: allow browser-based file uploads and downloads from permitted
	// origins. Expose Content-Disposition so the console can read the archive
	// filename (e.g. "<dir>.zip") off a cross-origin download response — it is
	// not a CORS-safelisted response header, so without this it stays invisible
	// to JS even though boxd sends it.
	if origin := r.Header.Get("Origin"); origin != "" {
		if h.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "X-Access-Token, Content-Type")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// boxd's /files handler only implements GET (download) and POST
	// (upload). Anything else is a client bug and should surface loudly.
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
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
	if strings.ContainsRune(requestedPath, 0) {
		http.Error(w, "path contains null byte", http.StatusBadRequest)
		return
	}
	for _, seg := range strings.Split(requestedPath, "/") {
		if seg == ".." {
			http.Error(w, "path traversal not allowed", http.StatusBadRequest)
			return
		}
	}

	info, ok := h.authorizeBoxdRequest(w, r, instanceID, "files")
	if !ok {
		return
	}
	fileEvent := "file_read" // only GET/POST reach here; POST is a write
	if r.Method == http.MethodPost {
		fileEvent = "file_write"
	}
	h.captureUsage(instanceID, fileEvent, info)

	// From here on it's a transparent reverse proxy to boxd, on the
	// lifecycle-keyed transport cache: one pooled set of TCP connections
	// per sandbox incarnation, reset on pause/resume.
	h.newBoxdReverseProxy(r, instanceID, info, "files").ServeHTTP(w, r)
}
