package secretsproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Resolver authenticates a proxy connection from its source IP and bearer JWT.
type Resolver interface {
	Authenticate(ctx context.Context, sourceIP, jwt string) (*Scope, error)
}

// Scope is the per-connection authorization context built from a verified JWT.
// Egress rules are not carried here — they are fetched live per request so a
// PATCH takes effect without re-minting the JWT.
type Scope struct {
	SandboxID string
	TeamID    string
	SourceIP  string
	// Bindings is the proxy_token → Binding map the inject pipeline uses to
	// match outbound requests against the sandbox's configured credentials.
	Bindings map[string]Binding
}

// Binding is one (proxy_token → credential) pair carried in the JWT. When
// Rules is non-empty, AuthType/AuthConfig are unused at egress; the inject
// pipeline picks a rule by upstream host. Hosts stays as the binding-wide
// allowlist regardless.
type Binding struct {
	SecretID   string
	EnvKey     string
	AuthType   string         // bearer | basic | api-key | custom
	AuthConfig map[string]any // type-specific config
	Hosts      []string       // upstream hosts this credential applies to
	Rules      []BindingRule  // per-host rules, dispatched at egress
}

// BindingRule is one (hosts → auth shape) entry inside Binding.Rules.
type BindingRule struct {
	Hosts      []string
	AuthType   string
	AuthConfig map[string]any
}

// ErrUnknownSandbox is returned for any rejection of the proxy CONNECT (bad
// signature, expired JWT, source-IP mismatch, etc.). The dispatcher maps all
// of these to a 407.
var ErrUnknownSandbox = errors.New("secretsproxy: connection rejected")

// Proxy is the MITM HTTPS ingress.
type Proxy struct {
	addr     string
	ca       *CA
	resolver Resolver
	logger   *slog.Logger

	vault               VaultClient
	rules               RulesClient
	audit               AuditSink
	revoker             *Revoker
	httpServer          *http.Server
	tlsConfig           *tls.Config
	upstream            *http.Transport
	upstreamPinned      *http.Transport
	isListening         atomic.Bool
	sandboxFacingHost   string
	maxRequestBodyBytes int64
	blockedPorts        map[int]bool
	blockInternalAddrs  bool
	dnsResolver         *net.Resolver
	blocklist           EgressBlocklist
}

// EgressBlocklist reports whether a destination is on the operator egress
// blocklist, by hostname (domain feeds / pinned domains) and/or resolved IP
// (pinned CIDRs). A blocklist hit is refused regardless of a sandbox's own
// allow rules, mirroring the host firewall on the direct path.
type EgressBlocklist interface {
	Blocked(host string, ip net.IP) (bool, string)
}

// Options carries Proxy dependencies. Nil Logger, Vault, Audit, and UpstreamTransport
// fall back to safe defaults (discard logger, passthrough, no-op sink, strict TLS transport).
type Options struct {
	CA                *CA
	Resolver          Resolver
	Vault             VaultClient
	Rules             RulesClient
	Audit             AuditSink
	Revoker           *Revoker
	Logger            *slog.Logger
	UpstreamTransport *http.Transport

	// IP sandboxes connect to. SNI fallback for clients that omit it (e.g. curl to an IP).
	SandboxFacingHost string

	// MaxRequestBodyBytes caps each forwarded request body. Zero falls back
	// to defaultMaxRequestBodyBytes.
	MaxRequestBodyBytes int64

	// BlockedPorts lists egress ports the proxy refuses to tunnel to,
	// matching the operator's host-firewall port policy.
	BlockedPorts []int

	// BlockInternalAddrs rejects CONNECTs to internal-range IP literals.
	BlockInternalAddrs bool

	// DNSResolver resolves upstream hosts for CIDR egress rules. Nil uses the
	// default resolver.
	DNSResolver *net.Resolver

	// Blocklist enforces the operator egress blocklist on the proxied path.
	// Nil disables blocklist enforcement (the host firewall still covers
	// direct traffic).
	Blocklist EgressBlocklist
}

const defaultMaxRequestBodyBytes int64 = 256 * 1024 * 1024

// NewProxy constructs the proxy bound to addr.
func NewProxy(addr string, opts Options) *Proxy {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	upstream := opts.UpstreamTransport
	if upstream == nil {
		upstream = &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     false,
		}
	}
	// Reuse-disabled transport for CIDR-pinned requests, so each dials the
	// policy-evaluated IP through the guard.
	upstreamPinned := upstream.Clone()
	upstreamPinned.DisableKeepAlives = true
	audit := opts.Audit
	if audit == nil {
		audit = NewNopAuditSink()
	}
	maxBody := opts.MaxRequestBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxRequestBodyBytes
	}
	var blockedPorts map[int]bool
	if len(opts.BlockedPorts) > 0 {
		blockedPorts = make(map[int]bool, len(opts.BlockedPorts))
		for _, port := range opts.BlockedPorts {
			blockedPorts[port] = true
		}
	}
	p := &Proxy{
		addr:                addr,
		ca:                  opts.CA,
		resolver:            opts.Resolver,
		vault:               opts.Vault,
		rules:               opts.Rules,
		audit:               audit,
		revoker:             opts.Revoker,
		logger:              logger,
		upstream:            upstream,
		upstreamPinned:      upstreamPinned,
		sandboxFacingHost:   opts.SandboxFacingHost,
		maxRequestBodyBytes: maxBody,
		blockedPorts:        blockedPorts,
		blockInternalAddrs:  opts.BlockInternalAddrs,
		dnsResolver:         opts.DNSResolver,
		blocklist:           opts.Blocklist,
	}

	p.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = p.sandboxFacingHost
			}
			if sni == "" {
				host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String())
				if err != nil || host == "" {
					host = "127.0.0.1"
				}
				sni = host
			}
			return p.ca.MintLeaf(sni)
		},
	}

	p.httpServer = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(p.dispatch),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return p
}

// Addr returns the configured listener address.
func (p *Proxy) Addr() string { return p.addr }

// RootPEM returns the CA cert in PEM form for installation into client trust stores.
func (p *Proxy) RootPEM() []byte { return p.ca.RootPEM() }

// IsListening reports whether the listener is bound and accepting connections.
func (p *Proxy) IsListening() bool { return p.isListening.Load() }

// ListenAndServe binds and serves. Blocks until Shutdown is called.
func (p *Proxy) ListenAndServe() error {
	l, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

// Serve accepts on the provided listener, wrapping it in TLS so the
// Proxy-Authorization header is encrypted on the wire.
func (p *Proxy) Serve(l net.Listener) error {
	p.isListening.Store(true)
	defer p.isListening.Store(false)
	return p.httpServer.Serve(tls.NewListener(l, p.tlsConfig))
}

// Shutdown stops the listener gracefully.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.upstream.CloseIdleConnections()
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	http.Error(w,
		"this endpoint is an HTTPS forward proxy; only CONNECT is supported",
		http.StatusBadRequest)
}

// isBlockedPort reports whether portStr is an operator-blocked egress port.
// An unparseable port is treated as not blocked; the dial fails downstream.
func (p *Proxy) isBlockedPort(portStr string) bool {
	if len(p.blockedPorts) == 0 {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return p.blockedPorts[port]
}

// fetchEgressRules returns the sandbox's current egress rules. ok is false only
// when there is no policy source at all (cold cache + control plane unreachable),
// so the caller can fail the request closed instead of enforcing nothing. A nil
// rules client (passthrough/test mode) yields empty rules and ok=true.
func (p *Proxy) fetchEgressRules(ctx context.Context, sandboxID string) (EgressRules, bool) {
	if p.rules == nil {
		return EgressRules{}, true
	}
	r, err := p.rules.FetchRules(ctx, sandboxID)
	if err != nil {
		p.logger.Warn("fetch egress rules failed", "sandbox", sandboxID, "err", err.Error())
		return EgressRules{}, false
	}
	return r, true
}

// resolveUpstreamIP resolves host to a single IP for CIDR rule evaluation. An
// IP-literal host is returned as-is; a resolution failure returns nil, which
// never matches a CIDR rule.
func (p *Proxy) resolveUpstreamIP(ctx context.Context, host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	r := p.dnsResolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return ips[0]
}

// remoteHost extracts the host portion (no port) from r.RemoteAddr.
func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
