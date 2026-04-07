package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
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

	// sandboxRules maps sandbox host IPs to their egress config.
	mu    sync.RWMutex
	rules map[string]*EgressRules // key = sandbox host IP
}

// EgressRules holds the allow/deny configuration for a sandbox's egress traffic.
type EgressRules struct {
	AllowedCIDRs   []string
	DeniedCIDRs    []string
	AllowedDomains []string
}

func NewEgressProxy(httpPort, tlsPort, otherPort uint16, maxConns int, log zerolog.Logger) *EgressProxy {
	return &EgressProxy{
		httpPort:           httpPort,
		tlsPort:            tlsPort,
		otherPort:          otherPort,
		log:                log.With().Str("component", "egress-proxy").Logger(),
		limiter:            NewConnectionLimiter(),
		maxConnsPerSandbox: maxConns,
		rules:              make(map[string]*EgressRules),
	}
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
		go handler(ctx, conn)
	}
}

// handleHTTP handles port 80 traffic — reads the HTTP Host header for domain filtering.
func (p *EgressProxy) handleHTTP(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, func(peeked []byte) string {
		return extractHTTPHost(peeked)
	})
}

// handleTLS handles port 443 traffic — reads the TLS ClientHello SNI for domain filtering.
func (p *EgressProxy) handleTLS(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, func(peeked []byte) string {
		return extractSNI(peeked)
	})
}

// handleOther handles all other TCP traffic — CIDR-only, no protocol inspection.
func (p *EgressProxy) handleOther(ctx context.Context, conn net.Conn) {
	p.handleConn(ctx, conn, nil)
}

func (p *EgressProxy) handleConn(ctx context.Context, conn net.Conn, extractHostname func([]byte) string) {
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

	// Check egress rules.
	rules := p.getRules(srcHost)
	allowed, matchType := p.isAllowed(rules, hostname, dstIP)
	if !allowed {
		p.log.Info().
			Str("src", srcHost).
			Str("dst", dstIP.String()).
			Str("hostname", hostname).
			Str("match", matchType).
			Msg("egress blocked")
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

	// Dial upstream with DNS rebinding protection.
	dialer := &net.Dialer{
		Timeout: upstreamDialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			resolved := net.ParseIP(host)
			if resolved != nil && IsIPDenied(resolved) {
				return fmt.Errorf("blocked: hostname resolved to internal IP %s", resolved)
			}
			return nil
		},
	}

	upstream, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		p.log.Debug().Err(err).Str("upstream", upstreamAddr).Msg("dial failed")
		return
	}
	defer upstream.Close()

	// If we peeked data, write it to upstream first.
	if len(peekedData) > 0 {
		if _, err := upstream.Write(peekedData); err != nil {
			return
		}
	}

	// Bidirectional proxy.
	relay(conn, upstream)
}

// isAllowed checks if egress is allowed based on domain and CIDR rules.
// Returns (allowed, matchType).
//
// Priority order is fail-safe: deny is always checked BEFORE allow, so a
// user who writes {"allow_out": ["*.example.com"], "deny_out": ["0.0.0.0/0"]}
// cannot accidentally bypass the deny rule via a matching allowlist entry.
//
//  1. No rules configured → allow (default)
//  2. Destination matches any deny CIDR → deny
//  3. Destination matches any allow domain → allow
//  4. Destination matches any allow CIDR → allow
//  5. Allow list is non-empty but nothing matched → deny (implicit deny)
//  6. Allow list is empty → allow (deny list only)
func (p *EgressProxy) isAllowed(rules *EgressRules, hostname string, dstIP net.IP) (bool, string) {
	if rules == nil {
		return true, "default"
	}

	// Priority 1: deny CIDRs — evaluated first so they cannot be bypassed
	// by a matching allow entry.
	for _, cidr := range rules.DeniedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(dstIP) {
			return false, "cidr"
		}
	}

	// Priority 2: allow domains.
	if hostname != "" {
		for _, domain := range rules.AllowedDomains {
			if matchDomain(hostname, domain) {
				return true, "domain"
			}
		}
	}

	// Priority 2: allow CIDRs.
	for _, cidr := range rules.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(dstIP) {
			return true, "cidr"
		}
	}

	// Allow list was non-empty but nothing matched → implicit deny.
	// This makes {"allow_out": ["api.openai.com"]} work as users expect
	// (only the listed domain is allowed, everything else blocked).
	if len(rules.AllowedDomains) > 0 || len(rules.AllowedCIDRs) > 0 {
		return false, "implicit-deny"
	}

	// Only a deny list was configured and nothing matched → allow.
	return true, "default"
}

// matchDomain checks if a hostname matches a domain pattern.
// Supports exact match and suffix wildcard (*.example.com).
// A bare "*" is NOT supported — it's too easy to misuse and would silently
// bypass all deny rules. Use explicit CIDR allow rules for "match all".
func matchDomain(hostname, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return false // bare wildcard is intentionally rejected
	}
	if strings.EqualFold(pattern, hostname) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(strings.ToLower(hostname), strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

// relay copies data bidirectionally between two connections.
func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(a, b)
	if tc, ok := a.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	<-done
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
func (r *sniReader) Close() error                        { return nil }
func (r *sniReader) LocalAddr() net.Addr                 { return &net.TCPAddr{} }
func (r *sniReader) RemoteAddr() net.Addr                { return &net.TCPAddr{} }
func (r *sniReader) SetDeadline(t time.Time) error       { return nil }
func (r *sniReader) SetReadDeadline(t time.Time) error   { return nil }
func (r *sniReader) SetWriteDeadline(t time.Time) error  { return nil }

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
