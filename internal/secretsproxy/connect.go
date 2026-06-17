package secretsproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/egresspolicy"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// hop-by-hop headers per RFC 7230 plus proxy-auth headers; none of these
// are forwarded to the upstream.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// handleConnect terminates a CONNECT tunnel, runs the MITM TLS handshake
// on the client side, and forwards each inner request to the captured upstream.
// A panic in any per-tunnel stage is reported to Sentry and contained so the
// daemon keeps serving other sandboxes.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	defer sentrylog.Recover("secretsproxy.handleConnect")
	target := r.Host
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}

	jwtString, err := ParseProxyAuthJWT(r)
	if err != nil {
		writeProxyAuthChallenge(w)
		return
	}

	scope, err := p.resolver.Authenticate(r.Context(), remoteHost(r.RemoteAddr), jwtString)
	if err != nil {
		p.logger.Warn("proxy auth rejected",
			"remote", r.RemoteAddr, "host", host, "err", err.Error())
		writeProxyAuthChallenge(w)
		return
	}

	if p.revoker != nil && p.revoker.IsSandboxRevoked(scope.SandboxID) {
		p.logger.Warn("sandbox revoked", "sandbox", scope.SandboxID, "host", host)
		http.Error(w, "sandbox revoked", http.StatusForbidden)
		return
	}

	if p.isBlockedPort(port) {
		p.logger.Warn("blocked egress port", "sandbox", scope.SandboxID, "host", host, "port", port)
		http.Error(w, "destination port blocked by policy", http.StatusForbidden)
		return
	}

	// IP-literal targets in an internal range are rejected here; hostnames that
	// resolve to an internal IP are caught by the upstream dialer.
	if p.blockInternalAddrs {
		if ip := net.ParseIP(host); ip != nil && egresspolicy.IsIPDenied(ip) {
			p.logger.Warn("blocked internal address", "sandbox", scope.SandboxID, "host", host)
			http.Error(w, "destination address blocked by policy", http.StatusForbidden)
			return
		}
	}

	// Operator egress blocklist by hostname and IP-literal target. A hostname
	// that resolves to a blocklisted CIDR is caught by the upstream dialer.
	if p.blocklist != nil {
		if blocked, dim := p.blocklist.Blocked(host, net.ParseIP(host)); blocked {
			p.logger.Warn("blocked by egress blocklist", "sandbox", scope.SandboxID, "host", host, "match", dim)
			http.Error(w, "destination blocked by policy", http.StatusForbidden)
			return
		}
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "internal proxy error", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		p.logger.Warn("hijack failed", "err", err.Error())
		http.Error(w, "internal proxy error", http.StatusInternalServerError)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}

	// Leaf cert SAN binds to the CONNECT target, not the inner-handshake SNI.
	innerTLSConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = host
			}
			return p.ca.MintLeaf(sni)
		},
	}
	tlsConn := tls.Server(clientConn, innerTLSConf)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Warn("mitm TLS handshake failed",
			"host", host,
			"sandbox", scope.SandboxID,
			"err", err.Error())
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler:           p.forwardHandler(target, host, scope),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

// writeProxyAuthChallenge writes a 407 with a Proxy-Authenticate header.
func writeProxyAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="superserve-proxy"`)
	http.Error(w, "Proxy-Authorization required", http.StatusProxyAuthRequired)
}

// oneShotListener wraps a single net.Conn so http.Server.Serve can drive it.
type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

var errOneShotListenerClosed = errors.New("secretsproxy: one-shot listener closed")

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errOneShotListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// forwardHandler returns the per-tunnel http.Handler: pipeline + forward + audit.
func (p *Proxy) forwardHandler(target, host string, scope *Scope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture before outReq mutation / body consumption.
		method := r.Method
		path := r.URL.Path
		start := time.Now()

		baseEvent := AuditEvent{
			SandboxID: scope.SandboxID,
			TeamID:    scope.TeamID,
			Method:    method,
			Host:      host,
			Path:      path,
		}
		// finalize emits one audit row per swapped secret. With no swap,
		// a single row is emitted with secret_id="" so the request is recorded.
		finalize := func(status int, upstreamStatus *int32, secretIDs []string, reason string) {
			latency := int32(time.Since(start).Milliseconds())
			if len(secretIDs) == 0 {
				ev := baseEvent
				ev.Status = int32(status)
				ev.UpstreamStatus = upstreamStatus
				ev.ErrorCode = reason
				ev.LatencyMs = latency
				p.audit.Emit(ev)
				return
			}
			for _, sid := range secretIDs {
				ev := baseEvent
				ev.Status = int32(status)
				ev.UpstreamStatus = upstreamStatus
				ev.SecretID = sid
				ev.ErrorCode = reason
				ev.LatencyMs = latency
				p.audit.Emit(ev)
			}
		}

		// Re-check revocation per request, not only at CONNECT: an open
		// keep-alive tunnel must stop injecting as soon as the sandbox is
		// revoked, without waiting for the tunnel to idle out.
		if p.revoker != nil && scope != nil && p.revoker.IsSandboxRevoked(scope.SandboxID) {
			writeBrokerError(w, http.StatusForbidden, "sandbox_revoked", "sandbox access revoked")
			finalize(http.StatusForbidden, nil, nil, "sandbox_revoked")
			return
		}

		// Re-check the operator blocklist on every request, not only at CONNECT,
		// so blocklist updates apply within an already-open tunnel.
		if p.blocklist != nil {
			if blocked, dim := p.blocklist.Blocked(host, net.ParseIP(host)); blocked {
				p.logger.Warn("blocked by egress blocklist", "sandbox", scope.SandboxID, "host", host, "match", dim)
				writeBrokerError(w, http.StatusForbidden, "egress_blocked", "destination blocked by policy")
				finalize(http.StatusForbidden, nil, nil, "egress_blocked")
				return
			}
		}

		// Rebuild against the captured host so a Host-header rewrite cannot redirect mid-stream.
		upstreamURL := *r.URL
		upstreamURL.Scheme = "https"
		upstreamURL.Host = target

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		bodyReader := http.MaxBytesReader(w, r.Body, p.maxRequestBodyBytes)
		outReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), bodyReader)
		if err != nil {
			p.logger.Warn("build upstream request failed",
				"host", host, "sandbox", scope.SandboxID, "err", err.Error())
			writeBrokerError(w, http.StatusBadGateway, "build_request", "could not build upstream request")
			finalize(http.StatusBadGateway, nil, nil, "build_request")
			return
		}
		copyForwardableHeaders(r.Header, outReq.Header)
		outReq.Host = forwardedHostHeader(target, host)

		// Pipeline runs when both Vault and a non-empty Scope are wired; otherwise pass through.
		transport := p.upstream
		var matchedSecretIDs []string
		if scope != nil && p.vault != nil {
			rules, ok := p.fetchEgressRules(ctx, scope.SandboxID)
			if !ok {
				// Cold cache + control plane unreachable: fail the request
				// closed and loud rather than enforce no policy.
				writeBrokerError(w, http.StatusServiceUnavailable, "policy_unavailable", "egress policy temporarily unavailable")
				finalize(http.StatusServiceUnavailable, nil, nil, "policy_unavailable")
				return
			}
			// Resolve the upstream only when CIDR rules need an IP to match.
			var upstreamIP net.IP
			if egresspolicy.HasCIDR(rules.Allow) || egresspolicy.HasCIDR(rules.Deny) {
				upstreamIP = p.resolveUpstreamIP(ctx, host)
				// Dial the IP the policy was evaluated against, not a re-resolved one.
				if upstreamIP != nil {
					outReq = outReq.WithContext(WithPinnedDialIP(outReq.Context(), upstreamIP))
					// Use the no-reuse transport so a CIDR-pinned request dials the
					// policy-evaluated IP through the guard.
					transport = p.upstreamPinned
				}
			}
			out, ierr := injectRequest(ctx, scope, p.vault, outReq, host, upstreamIP, rules)
			if ierr != nil {
				p.logger.Warn("inject pipeline failed",
					"host", host, "sandbox", scope.SandboxID, "err", ierr.Error())
				writeBrokerError(w, http.StatusBadGateway, "inject_error", "request rejected by sandbox proxy")
				finalize(http.StatusBadGateway, nil, out.MatchedSecretIDs, "inject_error")
				return
			}
			matchedSecretIDs = out.MatchedSecretIDs
			switch out.Action {
			case denyAction:
				writeBrokerError(w, http.StatusForbidden, out.Reason, "host or credential blocked by sandbox policy")
				finalize(http.StatusForbidden, nil, matchedSecretIDs, out.Reason)
				return
			case revokedAction:
				writeBrokerError(w, http.StatusServiceUnavailable, out.Reason, "credential revoked")
				finalize(http.StatusServiceUnavailable, nil, matchedSecretIDs, out.Reason)
				return
			}
		}

		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			// Body-size overflow surfaces here as RoundTrip returning a
			// MaxBytesError wrapped by the transport; distinguish it from
			// genuine unreachable upstream so the agent sees the right code.
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				msg := fmt.Sprintf("request body exceeds %d bytes", p.maxRequestBodyBytes)
				writeBrokerError(w, http.StatusRequestEntityTooLarge, "body_too_large", msg)
				finalize(http.StatusRequestEntityTooLarge, nil, matchedSecretIDs, "body_too_large")
				return
			}
			p.logger.Warn("upstream RoundTrip failed",
				"host", host, "sandbox", scope.SandboxID, "err", err.Error())
			writeBrokerError(w, http.StatusBadGateway, "upstream_unreachable", "upstream unreachable")
			finalize(http.StatusBadGateway, nil, matchedSecretIDs, "upstream_unreachable")
			return
		}
		defer resp.Body.Close()

		copyForwardableHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		// Flush per chunk so SSE / streaming responses reach the client promptly.
		flusher, _ := w.(http.Flusher)
		streamWithFlush(w, resp.Body, flusher)

		upstreamStatus := int32(resp.StatusCode)
		finalize(resp.StatusCode, &upstreamStatus, matchedSecretIDs, "")
	})
}

// writeBrokerError emits a structured proxy-layer rejection with X-Superserve-Proxy-Error.
func writeBrokerError(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("X-Superserve-Proxy-Error", "true")
	w.Header().Set("X-Superserve-Proxy-Reason", reason)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// copyForwardableHeaders copies headers, skipping both the fixed hop-by-hop set
// and any header names the message lists in its own Connection header (RFC 7230
// §6.1), which are scoped to this hop and must not be forwarded.
func copyForwardableHeaders(src, dst http.Header) {
	perMsg := connectionHopByHop(src)
	for k, vv := range src {
		ck := http.CanonicalHeaderKey(k)
		if hopByHop[ck] || perMsg[ck] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// forwardedHostHeader returns the Host header value for the upstream request:
// the CONNECT authority, with the port kept when it is not the default 443 so
// custom-port virtual hosts route correctly.
func forwardedHostHeader(target, host string) string {
	if _, port, err := net.SplitHostPort(target); err == nil && port != "443" {
		return target
	}
	return host
}

// pinnedDialIPKey carries the upstream IP the dial must use; see WithPinnedDialIP.
type pinnedDialIPKey struct{}

// WithPinnedDialIP pins the upstream dial to ip, so the address used for CIDR
// policy evaluation is the address actually connected to — closing the gap where
// a second DNS lookup at dial time could resolve to a different IP.
func WithPinnedDialIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, pinnedDialIPKey{}, ip)
}

// PinnedDialIP returns the pinned upstream IP, or nil when none was set.
func PinnedDialIP(ctx context.Context) net.IP {
	ip, _ := ctx.Value(pinnedDialIPKey{}).(net.IP)
	return ip
}

// connectionHopByHop returns the header names listed in the Connection header.
func connectionHopByHop(h http.Header) map[string]bool {
	var set map[string]bool
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				if set == nil {
					set = make(map[string]bool)
				}
				set[name] = true
			}
		}
	}
	return set
}

// streamWithFlush copies src → dst, flushing after each read for SSE / chunked transfers.
func streamWithFlush(dst io.Writer, src io.Reader, flusher http.Flusher) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
