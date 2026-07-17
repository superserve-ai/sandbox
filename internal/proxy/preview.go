package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/superserve-ai/sandbox/internal/auth"
)

// Preview auth carriers. All three names are reserved: the proxy consumes
// them for authentication and strips them before forwarding, so they never
// reach the user's app — on public and private sandboxes alike. The
// canonical names live in internal/auth beside the token format; the control
// plane returns them from the mint endpoints.
const (
	// previewTokenHeader carries the token for machine clients (a customer's
	// own proxy injecting auth upstream, curl, SDKs).
	previewTokenHeader = auth.PreviewTokenHeader

	// previewCookieName carries the token for browsers after the query-param
	// bootstrap. The __Host- prefix pins it to this exact preview origin:
	// no Domain attribute, Path=/, Secure — a sandbox cannot plant it for a
	// sibling preview host.
	previewCookieName = auth.PreviewTokenCookie

	// previewQueryParam bootstraps browser access: a signed link carries the
	// token once, the proxy answers with a redirect that moves it into the
	// cookie and strips it from the URL.
	previewQueryParam = auth.PreviewTokenQueryParam
)

// enforcePreviewAccess gates a numeric-port request against the sandbox's
// preview policy. It returns true when the request may proceed to the
// reverse proxy; false when it has already written a response (404 for an
// unpublished port, 401 for a missing/invalid token, or the cookie-bootstrap
// redirect).
//
// The order is publication → auth → status, all before the reverse proxy:
//   - public and private sandboxes route ONLY explicitly published ports. Any
//     other port returns 404, even with a valid token for a different port —
//     publishing 3001 never makes 3000 reachable.
//   - A published public port routes without a token. A published private port
//     requires a token scoped to that exact port and its current version.
//   - Empty and legacy_public retain the pre-publication behavior for existing
//     sandboxes and callers that omit the new policy field.
//   - Auth runs before the status check, so an unauthenticated caller can't
//     even learn whether the sandbox is running or paused.
func (h *Handler) enforcePreviewAccess(w http.ResponseWriter, r *http.Request, instanceID string, port int, info InstanceInfo) bool {
	switch info.PreviewAccess {
	case "", auth.PreviewAccessLegacyPublic:
		// Empty = the record predates the feature. Both legacy values keep
		// every listening port open so rollout cannot break existing URLs.
		return true
	}
	// public, private, and any unknown future policy all require publication.
	// An older proxy must interpret an unknown value as the most restrictive
	// policy it knows how to enforce, never as legacy-public.

	// Deny-by-default allowlist. A port is reachable only if it has been
	// explicitly published; everything else is 404 before any auth or status
	// is revealed. A nil/empty set (private sandbox with nothing published,
	// or an older vmd record) therefore denies every port — fail closed.
	version, published := info.PreviewPorts[port]
	if !published {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}

	if info.PreviewAccess == auth.PreviewAccessPublic {
		return true
	}

	// CORS preflights carry no credentials or custom headers by spec —
	// blocking them would break every authenticated cross-origin fetch.
	// Only reached for a published port; the app answers it.
	if r.Method == http.MethodOptions {
		return true
	}

	// A proxy running without the data-plane seed cannot verify anything.
	// Fail closed with the same 401 as a bad token.
	deny := func() bool {
		http.Error(w, "missing or invalid preview token", http.StatusUnauthorized)
		return false
	}
	if h.seedKey == nil {
		return deny()
	}

	verify := func(tok string) bool {
		return auth.VerifyPreviewToken(h.seedKey, instanceID, port, version, tok)
	}

	// Carriers are tried independently — a stale cookie must not lock out a
	// request that also presents a fresh header or signed link.
	if verify(r.Header.Get(previewTokenHeader)) {
		return true
	}
	if c, err := r.Cookie(previewCookieName); err == nil && verify(c.Value) {
		return true
	}
	if tok := r.URL.Query().Get(previewQueryParam); tok != "" && verify(tok) {
		// Non-GET requests and WebSocket handshakes cannot round-trip a
		// redirect; accept directly — the scrub strips the param upstream.
		if r.Method != http.MethodGet || r.Header.Get("Upgrade") != "" {
			return true
		}
		h.redirectWithPreviewCookie(w, r, tok)
		return false
	}

	return deny()
}

// redirectWithPreviewCookie answers a valid signed-link request: set the
// host-scoped cookie and bounce to the same URL with the token removed, so
// the credential never lingers in the address bar, browser history,
// Referer headers, or the app's own logs.
func (h *Handler) redirectWithPreviewCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     previewCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		// The console (and customer dashboards) embed previews in iframes;
		// that is a third-party context, so the cookie needs SameSite=None
		// and, under Chrome's cookie partitioning, the Partitioned attribute.
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")

	target := r.URL.Path
	if target == "" {
		target = "/"
	}
	if q := queryWithoutPreviewToken(r.URL); q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// scrubPreviewCredentials removes every preview credential carrier from a
// request before it is forwarded into the VM. The app behind the port never
// sees the token: the credential authenticates to the proxy, not to the
// sandbox, and anything forwarded ends up in attacker-visible territory
// (the sandbox runs untrusted code that can log every header it receives).
func scrubPreviewCredentials(r *http.Request) {
	r.Header.Del(previewTokenHeader)

	if _, err := r.Cookie(previewCookieName); err == nil {
		remaining := make([]string, 0, 4)
		for _, c := range r.Cookies() {
			if c.Name == previewCookieName {
				continue
			}
			remaining = append(remaining, c.Name+"="+c.Value)
		}
		if len(remaining) == 0 {
			r.Header.Del("Cookie")
		} else {
			r.Header.Set("Cookie", strings.Join(remaining, "; "))
		}
	}

	if r.URL.Query().Has(previewQueryParam) {
		r.URL.RawQuery = queryWithoutPreviewToken(r.URL)
	}
}

// queryWithoutPreviewToken returns the encoded query string with every
// instance of the preview token param removed.
func queryWithoutPreviewToken(u *url.URL) string {
	q := u.Query()
	q.Del(previewQueryParam)
	return q.Encode()
}
