package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/preview"
)

// enforcePreviewPublication runs before status handling. Legacy records retain
// all-port routing. Recognized strict policies require publication first, then
// exact per-port access. Phase 3 token policy remains header-only; the Phase 4
// browser sentinel additively permits query bootstrap and the resulting
// host-only cookie. Unknown modes always fail closed.
func enforcePreviewPublication(w http.ResponseWriter, r *http.Request, instanceID string, port int, info InstanceInfo, seed []byte, preflightOriginAllowed bool) bool {
	switch info.PreviewAccess {
	case "", preview.AccessLegacyPublic:
		// Preserve legacy all-port routing unless an additive Phase 2 record
		// explicitly marks this exact port non-public. That defensive exception
		// keeps an inconsistent rollback snapshot fail closed even if it bypasses
		// VMD's restrictive top-level normalization.
		if mode, recorded := info.PreviewPortAccess[port]; recorded && mode != "" && mode != preview.AccessPublic {
			return denyPrivatePreview(w)
		}
		return true
	case preview.AccessPublic, preview.AccessPrivate:
	default:
		// A newer control plane may introduce policy values this proxy cannot
		// enforce. Never interpret them as public publication.
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}

	if _, published := info.PreviewPorts[port]; !published {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return false
	}
	mode := info.PreviewPortAccess[port]
	if mode == "" {
		mode = info.PreviewAccess
	}
	if mode == preview.AccessPublic {
		return true
	}
	if !preview.IsTokenizedAccess(mode) {
		return denyPrivatePreview(w)
	}

	version := info.PreviewPortTokenVersions[port]
	if version <= 0 || auth.ValidateSeed(seed) != nil {
		return denyPrivatePreview(w)
	}
	// Browsers must be able to perform a standards-compliant CORS preflight
	// before sending a credential. Preflight headers are attacker-controlled,
	// so answer the request at the edge and never forward an unauthenticated
	// OPTIONS request to the private application. OPTIONS by itself remains an
	// ordinary authenticated application request.
	if isCORSPreflight(r) {
		if !preflightOriginAllowed {
			return denyPrivatePreview(w)
		}
		respondPrivatePreviewPreflight(w, r)
		return false
	}
	verify := func(token string) bool {
		return auth.VerifyPreviewToken(seed, instanceID, port, version, token)
	}

	if mode == preview.AccessPrivateTokenV1 {
		// Preserve Phase 3's deliberately narrow and unambiguous carrier
		// contract. Browser support becomes active only after the distinct Phase
		// 4 sentinel has reached a browser-capable host.
		values := headerValues(r.Header, auth.PreviewTokenHeader)
		if len(values) == 1 && verify(values[0]) {
			return true
		}
		return denyPrivatePreview(w)
	}

	queryTokens := previewQueryTokens(r.URL.RawQuery)
	if r.Method == http.MethodGet && !isWebSocketUpgrade(r) {
		// A valid signed-link token wins over an already-valid header or cookie:
		// redirecting removes the live credential from the address bar and gives
		// subsequent subresources and WebSockets the host-only cookie.
		if token, ok := firstValidPreviewToken(queryTokens, verify); ok {
			redirectWithPreviewCookie(w, r, token)
			return false
		}
	}

	// Carrier values are independent. A stale cookie/header/query occurrence
	// must not mask a fresh value supplied alongside it.
	if _, ok := firstValidPreviewToken(previewHeaderTokens(r.Header), verify); ok {
		return true
	}
	if _, ok := firstValidPreviewToken(previewCookieTokens(r.Header), verify); ok {
		return true
	}
	if _, ok := firstValidPreviewToken(queryTokens, verify); ok {
		// Non-GET requests and real WebSocket handshakes cannot round-trip the
		// bootstrap redirect. The reverse-proxy Director still strips the query.
		return true
	}
	return denyPrivatePreview(w)
}

func denyPrivatePreview(w http.ResponseWriter) bool {
	http.Error(w, "private preview authentication is not available", http.StatusUnauthorized)
	return false
}

func firstValidPreviewToken(tokens []string, verify func(string) bool) (string, bool) {
	for _, token := range tokens {
		if verify(token) {
			return token, true
		}
	}
	return "", false
}

func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// respondPrivatePreviewPreflight grants the browser permission to send the
// subsequent credentialed request without consulting the sandbox application.
// The caller must first validate the requesting origin against the proxy's
// configured allowlist. The actual request still passes through preview
// authentication, and this response exposes no sandbox data.
func respondPrivatePreviewPreflight(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	header.Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
	if requestedHeaders := r.Header.Get("Access-Control-Request-Headers"); requestedHeaders != "" {
		header.Set("Access-Control-Allow-Headers", requestedHeaders)
	}
	header.Set("Access-Control-Allow-Credentials", "true")
	header.Set("Access-Control-Max-Age", "600")
	header.Add("Vary", "Origin")
	header.Add("Vary", "Access-Control-Request-Method")
	header.Add("Vary", "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
}

// isWebSocketUpgrade requires the complete HTTP/1.1 handshake markers. A
// random non-empty Upgrade header must not suppress a browser bootstrap.
func isWebSocketUpgrade(r *http.Request) bool {
	return headerContainsToken(r.Header, "Upgrade", "websocket") &&
		headerContainsToken(r.Header, "Connection", "upgrade")
}

func headerContainsToken(header http.Header, name, token string) bool {
	for _, value := range headerValues(header, name) {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), token) {
				return true
			}
		}
	}
	return false
}

func headerValues(header http.Header, name string) []string {
	var values []string
	for key, current := range header {
		if strings.EqualFold(key, name) {
			values = append(values, current...)
		}
	}
	return values
}

// previewHeaderTokens treats comma-coalesced browser-carrier values as
// independent candidates. Preview tokens cannot contain commas, and an
// intermediary is allowed to combine repeated HTTP field lines. Phase 3 does
// not use this helper because its exact single-field-value contract remains
// intentionally unchanged.
func previewHeaderTokens(header http.Header) []string {
	var tokens []string
	for _, value := range headerValues(header, auth.PreviewTokenHeader) {
		for _, token := range strings.Split(value, ",") {
			tokens = append(tokens, strings.TrimSpace(token))
		}
	}
	return tokens
}

// previewCookieTokens reads every exact-name cookie from every differently
// cased Cookie header entry. Parsing one semicolon-delimited segment at a time
// prevents an unrelated malformed cookie from hiding a later valid carrier.
func previewCookieTokens(header http.Header) []string {
	var values []string
	for key, lines := range header {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, line := range lines {
			for _, segment := range strings.Split(line, ";") {
				segment = strings.TrimSpace(segment)
				name, _, found := strings.Cut(segment, "=")
				if !found || strings.TrimSpace(name) != auth.PreviewTokenCookie {
					continue
				}
				cookies, err := http.ParseCookie(segment)
				if err == nil && len(cookies) == 1 && cookies[0].Name == auth.PreviewTokenCookie {
					values = append(values, cookies[0].Value)
				}
			}
		}
	}
	return values
}

// previewQueryTokens decodes every exact reserved key independently while
// leaving malformed or unrelated entries out of authentication. Scrubbing is
// performed by a separate raw-preserving helper below.
func previewQueryTokens(rawQuery string) []string {
	var values []string
	for _, part := range strings.Split(rawQuery, "&") {
		key, rawValue, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil || decodedKey != auth.PreviewTokenQueryParam {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err == nil {
			values = append(values, value)
		}
	}
	return values
}

// redirectWithPreviewCookie moves a valid signed-link credential into a
// secure host-only cookie and redirects to an absolute URL on the already
// validated preview origin. An absolute target keeps a path such as
// "//attacker.example/x" from becoming a network-path redirect.
func redirectWithPreviewCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:        auth.PreviewTokenCookie,
		Value:       token,
		Path:        "/",
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	target := *r.URL
	target.Scheme = "https"
	target.Host = r.Host
	target.User = nil
	target.Opaque = ""
	target.Fragment = ""
	target.RawFragment = ""
	cleanQuery, _, hasQueryComponent := queryWithoutPreviewToken(target.RawQuery)
	target.RawQuery = cleanQuery
	if target.RawQuery == "" {
		target.ForceQuery = hasQueryComponent
	}
	if target.Path == "" {
		target.Path = "/"
		target.RawPath = ""
	}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// scrubPreviewCredentials removes every reserved carrier before a request is
// forwarded into user-controlled code. It runs for public, legacy, and private
// ports alike so a stray credential can never become application input.
func scrubPreviewCredentials(r *http.Request) {
	scrubHeader(r.Header, auth.PreviewTokenHeader)
	scrubPreviewCookie(r.Header)
	if r.URL != nil {
		cleanQuery, removed, hasQueryComponent := queryWithoutPreviewToken(r.URL.RawQuery)
		if removed {
			r.URL.RawQuery = cleanQuery
			if r.URL.RawQuery == "" {
				r.URL.ForceQuery = hasQueryComponent
			}
		}
	}
}

// scrubHeader removes every differently-cased map entry and every repeated
// value of a reserved credential header before the request reaches user code.
func scrubHeader(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}

// scrubPreviewCookie surgically removes exact reserved cookie segments while
// preserving unrelated segments verbatim, including ones net/http considers
// malformed. Re-parsing and serializing the whole header would silently drop
// those values and alter quoted application cookies.
func scrubPreviewCookie(header http.Header) {
	var cleaned []string
	for key, lines := range header {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		delete(header, key)
		for _, line := range lines {
			if value, keep := cookieLineWithoutPreviewToken(line); keep {
				cleaned = append(cleaned, value)
			}
		}
	}
	for _, line := range cleaned {
		header.Add("Cookie", line)
	}
}

func cookieLineWithoutPreviewToken(line string) (string, bool) {
	parts := strings.Split(line, ";")
	kept := make([]string, 0, len(parts))
	removed := false
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		name, _, _ := strings.Cut(trimmed, "=")
		if strings.TrimSpace(name) == auth.PreviewTokenCookie {
			removed = true
			continue
		}
		kept = append(kept, part)
	}
	if !removed {
		return line, true
	}
	for _, part := range kept {
		if strings.TrimSpace(part) != "" {
			return strings.Join(kept, ";"), true
		}
	}
	return "", false
}

// queryWithoutPreviewToken removes every decoded exact-name reserved query
// parameter while preserving all unrelated raw bytes, ordering, escapes,
// malformed segments, and empty components. The final result reports whether
// a credential was removed and whether any query component remains; the latter
// lets callers preserve a meaningful bare "?" when the remaining component is
// empty. url.Values.Encode would normalize or discard these details.
func queryWithoutPreviewToken(rawQuery string) (clean string, removed, hasRemainingComponent bool) {
	parts := strings.Split(rawQuery, "&")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err == nil && decodedKey == auth.PreviewTokenQueryParam {
			removed = true
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&"), removed, len(kept) != 0
}
