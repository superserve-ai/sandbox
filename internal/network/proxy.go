package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"

	"github.com/superserve-ai/sandbox/internal/blocklist"
	"github.com/superserve-ai/sandbox/internal/egresspolicy"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// upstreamDialTimeout is the maximum time to wait for upstream connections.
const upstreamDialTimeout = 30 * time.Second

// EgressProxy is a per-sandbox TCP proxy that intercepts egress traffic
// for domain-based filtering. It listens on three ports:
//   - HTTP port:  inspects Host header
//   - TLS port:   inspects SNI (Server Name Indication)
//   - Other port: CIDR-only (no protocol inspection)
//
// Traffic is redirected to these ports by nftables REDIRECT rules in each
// sandbox's network namespace.
type EgressProxy struct {
	httpPort  uint16
	tlsPort   uint16
	otherPort uint16

	log     zerolog.Logger
	limiter *ConnectionLimiter

	// maxConnsPerSandbox is the per-sandbox connection limit. -1 = unlimited.
	maxConnsPerSandbox int

	// flowSink records one event per connection. Never nil — defaults to a nop
	// sink so the data path is unaffected when logging is not configured.
	// Guarded by sinkMu so it can be installed after Start.
	sinkMu   sync.RWMutex
	flowSink FlowSink

	// blocklist is the global egress denylist (nil = disabled). Checked
	// before per-sandbox rules; a blocklist hit cannot be overridden by a
	// sandbox's own allow rules.
	blocklist *blocklist.Blocklist

	// sandboxRules maps sandbox host IPs to their egress config.
	mu    sync.RWMutex
	rules map[string]*EgressRules // key = sandbox host IP
}

// EgressRules holds the allow/deny configuration for a sandbox's egress traffic.
type EgressRules struct {
	AllowedCIDRs   []string
	DeniedCIDRs    []string
	AllowedDomains []string
	// SandboxID attributes flow-log rows. Empty disables logging for the sandbox.
	SandboxID string
}

func NewEgressProxy(httpPort, tlsPort, otherPort uint16, maxConns int, log zerolog.Logger) *EgressProxy {
	return &EgressProxy{
		httpPort:           httpPort,
		tlsPort:            tlsPort,
		otherPort:          otherPort,
		log:                log.With().Str("component", "egress-proxy").Logger(),
		limiter:            NewConnectionLimiter(),
		maxConnsPerSandbox: maxConns,
		flowSink:           NewNopFlowSink(),
		rules:              make(map[string]*EgressRules),
	}
}

// SetFlowSink installs the connection-flow logging sink. Safe to call after Start.
func (p *EgressProxy) SetFlowSink(sink FlowSink) {
	if sink == nil {
		return
	}
	p.sinkMu.Lock()
	p.flowSink = sink
	p.sinkMu.Unlock()
}

func (p *EgressProxy) getFlowSink() FlowSink {
	p.sinkMu.RLock()
	defer p.sinkMu.RUnlock()
	return p.flowSink
}

// RegisterSandbox associates a sandbox ID with a host IP for flow attribution,
// preserving any allow/deny rules already set for that IP. Idempotent.
func (p *EgressProxy) RegisterSandbox(hostIP, sandboxID string) {
	if hostIP == "" || sandboxID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.rules[hostIP]; ok {
		r.SandboxID = sandboxID
	} else {
		p.rules[hostIP] = &EgressRules{SandboxID: sandboxID}
	}
}

// SetBlocklist attaches the global egress denylist. Must be called before
// Start; the blocklist's own snapshot swapping handles later updates.
func (p *EgressProxy) SetBlocklist(b *blocklist.Blocklist) {
	p.blocklist = b
}

// SetRules updates the egress rules for a sandbox identified by its host IP.
func (p *EgressProxy) SetRules(hostIP string, rules *EgressRules) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rules == nil {
		delete(p.rules, hostIP)
	} else {
		p.rules[hostIP] = rules
	}
}

// RemoveRules removes egress rules for a sandbox.
func (p *EgressProxy) RemoveRules(hostIP string) {
	p.mu.Lock()
	delete(p.rules, hostIP)
	p.mu.Unlock()
	p.limiter.Remove(hostIP)
}

func (p *EgressProxy) getRules(hostIP string) *EgressRules {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rules[hostIP]
}

// Start begins listening on the three proxy ports. Blocks until ctx is cancelled.
// If any listener fails to bind, all listeners are shut down and the error is returned.
func (p *EgressProxy) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 3)

	go func() { errCh <- p.listen(ctx, p.httpPort, p.handleHTTP) }()
	go func() { errCh <- p.listen(ctx, p.tlsPort, p.handleTLS) }()
	go func() { errCh <- p.listen(ctx, p.otherPort, p.handleOther) }()

	p.log.Info().
		Uint16("http_port", p.httpPort).
		Uint16("tls_port", p.tlsPort).
		Uint16("other_port", p.otherPort).
		Msg("egress proxy started")

	// Wait for first error or context cancellation. The deferred cancel()
	// ensures all listeners are shut down if one fails.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (p *EgressProxy) listen(ctx context.Context, port uint16, handler func(context.Context, net.Conn)) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", port, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			p.log.Warn().Err(err).Uint16("port", port).Msg("accept error")
			continue
		}
		go func() { defer sentrylog.Recover("net-conn"); handler(ctx, conn) }()
	}
}

// handleHTTP handles port 80 traffic — reads the HTTP Host header for domain filtering.
func (p *EgressProxy) handleHTTP(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, "http", func(peeked []byte) string {
		return extractHTTPHost(peeked)
	})
}

// handleTLS handles port 443 traffic — reads the TLS ClientHello SNI for domain filtering.
func (p *EgressProxy) handleTLS(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, "tls", func(peeked []byte) string {
		return extractSNI(peeked)
	})
}

// handleOther handles all other TCP traffic — CIDR-only, no protocol inspection.
func (p *EgressProxy) handleOther(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, "other", nil)
}

func (p *EgressProxy) handleConn(ctx context.Context, conn net.Conn, protocol string, extractHostname func([]byte) string) {
	defer conn.Close()

	// Get original destination before REDIRECT.
	dstIP, dstPort, err := getOriginalDst(conn)
	if err != nil {
		p.log.Debug().Err(err).Msg("failed to get original dst")
		return
	}

	// Identify sandbox by source IP.
	srcAddr := conn.RemoteAddr().String()
	srcHost, _, _ := net.SplitHostPort(srcAddr)

	// Connection limit check.
	_, acquired := p.limiter.TryAcquire(srcHost, p.maxConnsPerSandbox)
	if !acquired {
		p.log.Warn().Str("src", srcHost).Msg("connection limit exceeded")
		return
	}
	defer p.limiter.Release(srcHost)

	// Extract hostname if we have a protocol inspector.
	// Read enough data to inspect the protocol header. HTTP Host and TLS
	// ClientHello are both in the first flight, so we read until we have
	// enough or the deadline expires. We accumulate reads to handle cases
	// where the kernel delivers the data in multiple segments.
	var hostname string
	var peekedData []byte
	if extractHostname != nil {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			// Try to extract after each read — stop as soon as we get a result
			// or have enough data (TLS ClientHello is at most ~2KB).
			if hostname = extractHostname(buf); hostname != "" {
				break
			}
			if len(buf) >= 4096 {
				break
			}
			if err != nil {
				break
			}
		}
		conn.SetReadDeadline(time.Time{})
		if len(buf) == 0 {
			return
		}
		peekedData = buf
	}

	// Identify the sandbox up front so every block path (global blocklist,
	// per-sandbox rule, dial-time) can attribute a flow-log row.
	rules := p.getRules(srcHost)
	var sandboxID string
	if rules != nil {
		sandboxID = rules.SandboxID
	}
	flow := FlowEvent{
		SandboxID: sandboxID,
		Protocol:  protocol,
		Host:      hostname,
		DstIP:     dstIP.String(),
		DstPort:   int32(dstPort),
	}

	// Global blocklist first — a hit here cannot be overridden by the
	// sandbox's own allow rules.
	if p.blocklist != nil {
		if blocked, dim := p.blocklist.Blocked(hostname, dstIP); blocked {
			p.log.Warn().
				Str("src", srcHost).
				Str("dst", dstIP.String()).
				Str("hostname", hostname).
				Str("match", dim).
				Msg("egress blocked by global blocklist")
			if sandboxID != "" {
				flow.Verdict = "blocked"
				flow.MatchRule = "blocklist"
				p.getFlowSink().Emit(flow)
			}
			return
		}
	}

	// Check egress rules.
	allowed, matchType := p.isAllowed(rules, hostname, dstIP)
	flow.MatchRule = matchType

	if !allowed {
		p.log.Info().
			Str("src", srcHost).
			Str("dst", dstIP.String()).
			Str("hostname", hostname).
			Str("match", matchType).
			Msg("egress blocked")
		if sandboxID != "" {
			flow.Verdict = "blocked"
			p.getFlowSink().Emit(flow)
		}
		return
	}

	// Determine upstream address.
	var upstreamAddr string
	if matchType == "domain" && hostname != "" {
		// Dial by hostname to prevent DNS spoofing — re-resolve from host.
		upstreamAddr = net.JoinHostPort(hostname, fmt.Sprintf("%d", dstPort))
	} else {
		upstreamAddr = net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))
	}

	// Dial upstream with DNS rebinding protection. The flags distinguish a
	// policy block (internal-IP guard or blocklist, caught once the hostname
	// resolves) from a plain dial failure, for logging. Atomic because Control
	// may run on parallel dial goroutines for dual-stack hosts.
	var ipDenied, dialBlocklisted atomic.Bool
	dialer := &net.Dialer{
		Timeout: upstreamDialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			resolved := net.ParseIP(host)
			if resolved != nil && IsIPDenied(resolved) {
				ipDenied.Store(true)
				return fmt.Errorf("blocked: hostname resolved to internal IP %s", resolved)
			}
			if resolved != nil && p.blocklist != nil {
				if blocked, _ := p.blocklist.Blocked("", resolved); blocked {
					dialBlocklisted.Store(true)
					return fmt.Errorf("blocked: hostname resolved to blocklisted IP %s", resolved)
				}
			}
			return nil
		},
	}

	upstream, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		p.log.Debug().Err(err).Str("upstream", upstreamAddr).Msg("dial failed")
		if sandboxID != "" {
			// A resolved-IP rejection is a policy block; anything else failed
			// to connect.
			switch {
			case dialBlocklisted.Load():
				flow.Verdict = "blocked"
				flow.MatchRule = "blocklist"
			case ipDenied.Load():
				flow.Verdict = "blocked"
				flow.MatchRule = "internal-ip"
			default:
				flow.Verdict = "failed"
			}
			p.getFlowSink().Emit(flow)
		}
		return
	}
	defer upstream.Close()

	// If we peeked data, write it to upstream first.
	sent := int64(len(peekedData))
	if len(peekedData) > 0 {
		if _, err := upstream.Write(peekedData); err != nil {
			if sandboxID != "" {
				flow.Verdict = "failed"
				p.getFlowSink().Emit(flow)
			}
			return
		}
	}

	// Bidirectional proxy.
	start := time.Now()
	up, down := relay(conn, upstream)
	if sandboxID != "" {
		flow.Verdict = "allowed"
		flow.BytesSent = sent + up
		flow.BytesRecv = down
		flow.DurationMs = int32(time.Since(start).Milliseconds())
		p.getFlowSink().Emit(flow)
	}
}

// isAllowed uses an "allow wins" model: a match in allow_out short-circuits
// before deny_out, so {"allow_out": ["api.openai.com"], "deny_out": ["0.0.0.0/0"]}
// allows the named host and blocks everything else. A broad allow therefore
// shadows a more specific deny — narrow the allow list rather than relying on
// overlapping denies.
func (p *EgressProxy) isAllowed(rules *EgressRules, hostname string, dstIP net.IP) (bool, string) {
	if rules == nil {
		return true, "default"
	}

	if hostname != "" {
		for _, domain := range rules.AllowedDomains {
			if matchDomain(hostname, domain) {
				return true, "domain"
			}
		}
	}

	for _, cidr := range rules.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(dstIP) {
			return true, "cidr"
		}
	}

	for _, cidr := range rules.DeniedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(dstIP) {
			return false, "cidr"
		}
	}

	if len(rules.AllowedDomains) > 0 || len(rules.AllowedCIDRs) > 0 {
		return false, "implicit-deny"
	}

	return true, "default"
}

// matchDomain checks if a hostname matches a domain pattern.
// Supports exact match and suffix wildcard (*.example.com).
// A bare "*" is NOT supported — it's too easy to misuse and would silently
// bypass all deny rules. Use explicit CIDR allow rules for "match all".
func matchDomain(hostname, pattern string) bool {
	return egresspolicy.MatchHost(hostname, pattern)
}

// relay proxies bytes in both directions and returns the totals: aToB is bytes
// sent from the sandbox (a) to the upstream (b), bToA the reverse.
func relay(a, b net.Conn) (aToB, bToA int64) {
	done := make(chan struct{})
	go func() {
		aToB, _ = io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	bToA, _ = io.Copy(a, b)
	if tc, ok := a.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	<-done
	return aToB, bToA
}

// ---------------------------------------------------------------------------
// Protocol inspection helpers
// ---------------------------------------------------------------------------

// extractHTTPHost extracts the Host header from an HTTP request.
func extractHTTPHost(data []byte) string {
	s := string(data)
	lines := strings.Split(s, "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			// Strip port if present.
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return host
		}
	}
	return ""
}

// extractSNI extracts the Server Name Indication from a TLS ClientHello.
func extractSNI(data []byte) string {
	// Minimal TLS ClientHello parsing to extract SNI.
	// Use crypto/tls.Server with a config that captures the SNI.
	var sni string
	srv := tls.Server(&sniReader{data: data}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, fmt.Errorf("sni captured")
		},
	})
	srv.Handshake() //nolint:errcheck // intentionally fails after capturing SNI
	return sni
}

// sniReader wraps a byte slice as a net.Conn for SNI extraction.
type sniReader struct {
	data []byte
	pos  int
}

func (r *sniReader) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *sniReader) Write(b []byte) (int, error)        { return len(b), nil }
func (r *sniReader) Close() error                       { return nil }
func (r *sniReader) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (r *sniReader) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (r *sniReader) SetDeadline(t time.Time) error      { return nil }
func (r *sniReader) SetReadDeadline(t time.Time) error  { return nil }
func (r *sniReader) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// SO_ORIGINAL_DST — retrieve original destination before REDIRECT
// ---------------------------------------------------------------------------

// getOriginalDst retrieves the original destination IP and port before
// nftables/iptables REDIRECT was applied. Uses the SO_ORIGINAL_DST socket option.
func getOriginalDst(conn net.Conn) (net.IP, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}

	var ip net.IP
	var port int
	var sockErr error

	err = rawConn.Control(func(fd uintptr) {
		var addr [16]byte
		addrLen := uint32(len(addr))

		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT, fd,
			syscall.SOL_IP, unix.SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&addrLen)), 0,
		)
		if errno != 0 {
			sockErr = errno
			return
		}

		// sockaddr_in layout: family(2) + port(2 big-endian) + addr(4) + zero(8)
		port = int(addr[2])<<8 | int(addr[3])
		ip = net.IPv4(addr[4], addr[5], addr[6], addr[7])
	})
	if err != nil {
		return nil, 0, err
	}

	return ip, port, sockErr
}
