package secretsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

// Server is the HTTP listener sandboxes hit. Source IP identifies the
// sandbox; path prefix identifies the provider; the auth header carries
// a signed token authorizing a specific (sandbox, secret) swap.
type Server struct {
	state    *State
	verifier *secrets.Signer
	provs    *Registry
	audit    *AuditWriter
	upstream *http.Client
	dns      *dnsCache
}

// NewServer constructs the request handler.
func NewServer(state *State, verifier *secrets.Signer, provs *Registry, audit *AuditWriter) *Server {
	return &Server{
		state:    state,
		verifier: verifier,
		provs:    provs,
		audit:    audit,
		dns:      &dnsCache{ttl: 30 * time.Second, entries: map[string]dnsCacheEntry{}},
		upstream: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
			// No client timeout — SSE streams from upstream may be long-lived.
		},
	}
}

// dnsCache memoizes A-record lookups for the egress check.
type dnsCache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

func (c *dnsCache) Lookup(ctx context.Context, host string) []netip.Addr {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.ips
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	c.entries[host] = dnsCacheEntry{ips: addrs, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return addrs
}

// Handler returns the forward-path http.Handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	srcIP := remoteHost(r.RemoteAddr)

	sb, ok := s.state.LookupBySourceIP(srcIP)
	if !ok {
		writeProxyError(w, http.StatusForbidden, "unknown_sandbox", "source IP not registered")
		return
	}

	cfg, upstreamPath, ok := s.provs.MatchPath(r.URL.Path)
	if !ok {
		writeProxyError(w, http.StatusNotFound, "unknown_provider", "no provider for path "+r.URL.Path)
		return
	}

	claims, err := s.verifier.Verify(time.Now(), extractToken(r, cfg))
	if err != nil {
		writeProxyError(w, http.StatusUnauthorized, "invalid_token", "token verification failed")
		s.recordAudit(sb, uuid.Nil, cfg, r, http.StatusUnauthorized, nil, time.Since(start), "invalid_token")
		return
	}
	if claims.Subject != sb.SandboxID {
		writeProxyError(w, http.StatusForbidden, "token_sandbox_mismatch",
			"token does not match this sandbox")
		log.Warn().Str("source_ip", srcIP).Str("token_sub", claims.Subject).
			Str("sandbox_id", sb.SandboxID).Msg("JWT/source mismatch")
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusForbidden, nil, time.Since(start), "token_sandbox_mismatch")
		return
	}

	binding, ok := sb.Bindings[claims.SecretID]
	if !ok {
		writeProxyError(w, http.StatusServiceUnavailable, "secret_revoked",
			"secret no longer bound to this sandbox")
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusServiceUnavailable, nil, time.Since(start), "secret_revoked")
		return
	}
	if binding.Provider != cfg.Name {
		// Reject cross-provider use so a token issued for one provider's
		// secret can't authenticate against another's path.
		writeProxyError(w, http.StatusForbidden, "provider_mismatch",
			"secret provider does not match request path")
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusForbidden, nil, time.Since(start), "provider_mismatch")
		return
	}

	upstreamURL, err := url.Parse(cfg.Upstream + upstreamPath)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "bad_upstream", err.Error())
		return
	}
	if r.URL.RawQuery != "" {
		upstreamURL.RawQuery = r.URL.RawQuery
	}
	if !egressAllowed(r.Context(), sb.Egress, upstreamURL, s.dns.Lookup) {
		writeProxyError(w, http.StatusForbidden, "egress_blocked",
			fmt.Sprintf("%s is not allowed by this sandbox's egress policy", upstreamURL.Host))
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusForbidden, nil, time.Since(start), "egress_blocked")
		return
	}

	bodyReader := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bodyReader)
	if err != nil {
		writeProxyError(w, http.StatusInternalServerError, "build_request", err.Error())
		return
	}
	copyForwardableHeaders(r.Header, outReq.Header, cfg.KeyHeader)
	cfg.SetKey(outReq, binding.RealValue)

	resp, err := s.upstream.Do(outReq)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusBadGateway, nil, time.Since(start), "upstream_unreachable")
		return
	}
	defer resp.Body.Close()

	// Flush after each chunk so SSE reaches the caller promptly.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	sawStreamErr := streamBody(w, resp.Body, flusher)

	upstreamStatus := int32(resp.StatusCode)
	errCode := ""
	if sawStreamErr {
		// HTTP 200 but body carried `event: error`.
		errCode = "upstream_stream_error"
	}
	s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, resp.StatusCode, &upstreamStatus, time.Since(start), errCode)
}

// extractToken returns the JWT from the provider's auth header,
// stripping the format prefix and WrapPrefix.
func extractToken(r *http.Request, cfg ServiceConfig) string {
	raw := r.Header.Get(cfg.KeyHeader)
	if raw == "" {
		return ""
	}
	if hp := strings.TrimSuffix(cfg.KeyFormat, "%s"); hp != "" && strings.HasPrefix(raw, hp) {
		raw = strings.TrimPrefix(raw, hp)
	}
	if cfg.WrapPrefix != "" && strings.HasPrefix(raw, cfg.WrapPrefix) {
		raw = strings.TrimPrefix(raw, cfg.WrapPrefix)
	}
	return raw
}

// copyForwardableHeaders copies inbound headers to the outbound request,
// dropping the existing auth header (replaced) and hop-by-hop headers.
func copyForwardableHeaders(in, out http.Header, keyHeader string) {
	stripped := map[string]struct{}{
		strings.ToLower(keyHeader): {},
		"authorization":            {},
		"x-forwarded-for":          {},
		"x-forwarded-host":         {},
		"x-forwarded-proto":        {},
		"x-real-ip":                {},
		"forwarded":                {},
		"connection":               {},
		"keep-alive":               {},
		"proxy-authenticate":       {},
		"proxy-authorization":      {},
		"te":                       {},
		"trailer":                  {},
		"transfer-encoding":        {},
		"upgrade":                  {},
	}
	for k, vs := range in {
		if _, drop := stripped[strings.ToLower(k)]; drop {
			continue
		}
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	out.Set("User-Agent", "superserve-secretsproxy/1.0")
}

// Hard cap on inbound bodies. Provider limits are typically lower (e.g.
// 20–32 MiB); this is the abuse ceiling, not the per-provider quota.
const maxRequestBodyBytes = 50 * 1024 * 1024

// SSE event line indicating a mid-stream failure after a 200.
var sseStreamErrorMarker = []byte("event: error")

// streamBody copies body to w, flushing per read. Returns true if
// sseStreamErrorMarker was seen anywhere in the stream.
func streamBody(w io.Writer, body io.Reader, flusher http.Flusher) bool {
	buf := make([]byte, 4096)
	matched := 0
	sawError := false
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			// Forward first; the scan must not delay the byte stream.
			if _, werr := w.Write(buf[:n]); werr != nil {
				return sawError
			}
			if flusher != nil {
				flusher.Flush()
			}
			if !sawError {
				matched, sawError = scanForMarker(buf[:n], sseStreamErrorMarker, matched)
			}
		}
		if errors.Is(rerr, io.EOF) {
			return sawError
		}
		if rerr != nil {
			return sawError
		}
	}
}

// scanForMarker continues a partial match across chunk boundaries.
// `matched` is bytes matched so far; returns updated progress + done.
func scanForMarker(chunk, marker []byte, matched int) (int, bool) {
	for _, b := range chunk {
		if b == marker[matched] {
			matched++
			if matched == len(marker) {
				return 0, true
			}
			continue
		}
		if b == marker[0] {
			matched = 1
		} else {
			matched = 0
		}
	}
	return matched, false
}


// egressAllowed applies the rules to a target URL. Hostname / *.suffix
// entries match the URL's host; IP / CIDR entries match its resolved
// A records. Deny first, then allow; implicit deny when AllowOut is set.
func egressAllowed(ctx context.Context, rules api.EgressRules, target *url.URL, resolve func(context.Context, string) []netip.Addr) bool {
	if len(rules.AllowOut) == 0 && len(rules.DenyOut) == 0 {
		return true
	}
	host := target.Hostname()

	var ips []netip.Addr
	if anyIPOrCIDR(rules.DenyOut) || anyIPOrCIDR(rules.AllowOut) {
		ips = resolve(ctx, host)
	}

	for _, entry := range rules.DenyOut {
		if matchEgressEntry(entry, host, ips) {
			return false
		}
	}
	if len(rules.AllowOut) == 0 {
		return true
	}
	for _, entry := range rules.AllowOut {
		if matchEgressEntry(entry, host, ips) {
			return true
		}
	}
	return false
}

// matchEgressEntry: exact host, *.suffix wildcard, IP, or CIDR.
func matchEgressEntry(entry, host string, ips []netip.Addr) bool {
	if entry == host {
		return true
	}
	if strings.HasPrefix(entry, "*.") {
		suffix := entry[1:]
		if strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix)) {
			return true
		}
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		for _, ip := range ips {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		for _, ip := range ips {
			if addr == ip {
				return true
			}
		}
	}
	return false
}

// anyIPOrCIDR is the predicate that decides whether to resolve.
func anyIPOrCIDR(entries []string) bool {
	for _, e := range entries {
		if _, err := netip.ParsePrefix(e); err == nil {
			return true
		}
		if _, err := netip.ParseAddr(e); err == nil {
			return true
		}
	}
	return false
}

func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func parseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func writeProxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, message)
}

func (s *Server) recordAudit(sb Sandbox, secretID uuid.UUID, cfg ServiceConfig, r *http.Request, status int, upstreamStatus *int32, latency time.Duration, errCode string) {
	if s.audit == nil {
		return
	}
	team, err := uuid.Parse(sb.TeamID)
	if err != nil {
		return
	}
	sandboxID, err := uuid.Parse(sb.SandboxID)
	if err != nil {
		return
	}
	ms := int32(latency.Milliseconds())
	ev := auditEvent{
		TeamID:         team,
		SandboxID:      sandboxID,
		SecretID:       secretID,
		Provider:       cfg.Name,
		Method:         r.Method,
		Path:           r.URL.Path,
		Status:         int32(status),
		UpstreamStatus: upstreamStatus,
		LatencyMs:      &ms,
	}
	if errCode != "" {
		ev.ErrorCode = &errCode
	}
	s.audit.Enqueue(ev)
}

