package secretsproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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
}

// NewServer constructs the request handler.
func NewServer(state *State, verifier *secrets.Signer, provs *Registry, audit *AuditWriter) *Server {
	return &Server{
		state:    state,
		verifier: verifier,
		provs:    provs,
		audit:    audit,
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
	if !egressAllowed(sb.Egress, upstreamURL) {
		writeProxyError(w, http.StatusForbidden, "egress_blocked",
			fmt.Sprintf("%s is not allowed by this sandbox's egress policy", upstreamURL.Host))
		s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, http.StatusForbidden, nil, time.Since(start), "egress_blocked")
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
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
	streamBody(w, resp.Body, flusher)

	upstreamStatus := int32(resp.StatusCode)
	s.recordAudit(sb, parseUUID(claims.SecretID), cfg, r, resp.StatusCode, &upstreamStatus, time.Since(start), "")
}

// extractToken returns the token from the provider's auth header,
// stripping any literal prefix the format requires (e.g. "Bearer ").
func extractToken(r *http.Request, cfg ServiceConfig) string {
	raw := r.Header.Get(cfg.KeyHeader)
	if raw == "" {
		return ""
	}
	prefix := strings.TrimSuffix(cfg.KeyFormat, "%s")
	if prefix != "" && strings.HasPrefix(raw, prefix) {
		return strings.TrimPrefix(raw, prefix)
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

// streamBody copies body to w, flushing after each read.
func streamBody(w io.Writer, body io.Reader, flusher http.Flusher) {
	buf := make([]byte, 4096)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if errors.Is(rerr, io.EOF) {
			return
		}
		if rerr != nil {
			return
		}
	}
}

// egressAllowed applies the rules to a target URL. Deny first, then
// allow; implicit deny when AllowOut is set and nothing matches.
func egressAllowed(rules api.EgressRules, target *url.URL) bool {
	if len(rules.AllowOut) == 0 && len(rules.DenyOut) == 0 {
		return true
	}
	host := target.Hostname()
	for _, entry := range rules.DenyOut {
		if matchEgressEntry(entry, host) {
			return false
		}
	}
	if len(rules.AllowOut) == 0 {
		return true
	}
	for _, entry := range rules.AllowOut {
		if matchEgressEntry(entry, host) {
			return true
		}
	}
	return false
}

// matchEgressEntry: exact match or *.suffix wildcard.
func matchEgressEntry(entry, host string) bool {
	if entry == host {
		return true
	}
	if strings.HasPrefix(entry, "*.") {
		suffix := entry[1:]
		if strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix)) {
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

