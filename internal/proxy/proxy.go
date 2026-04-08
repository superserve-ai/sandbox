package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// Timeout constants.
//
// The client-facing idle timeout must be longer than the upstream idle timeout
// so we don't race the upstream close. GCP LB has a 600s upstream idle timeout,
// so the VM-facing transport idle is 610s and the server idle is 620s.
const (
	serverIdleTimeout    = 620 * time.Second
	transportIdleTimeout = 610 * time.Second
	dialTimeout          = 5 * time.Second

	// maxDialAttempts handles the window where boxd is starting up inside the VM.
	// We retry with linear backoff: 100ms, 200ms, 300ms before giving up.
	maxDialAttempts = 3

	// minProxiedPort blocks privileged ports (< 1024) which could expose system
	// services (SSH, etc.) running inside the VM. User app ports and boxd (49983)
	// are all above this threshold.
	minProxiedPort = 1024

	// maxConnsPerSandbox limits concurrent connections to a single sandbox.
	// Prevents one sandbox from exhausting host file descriptors.
	maxConnsPerSandbox = 200

	// maxConnsPerIP limits concurrent connections from a single client IP.
	// Mitigates abuse from a single source.
	maxConnsPerIP = 100

	// transportSweepInterval controls how often the transport cache is swept
	// to close transports for sandboxes that are no longer alive.
	transportSweepInterval = 5 * time.Minute
	transportMaxAge        = 10 * time.Minute
)

// Handler is the core reverse proxy handler.
type Handler struct {
	domain       string // expected hostname suffix, e.g. "sandbox.superserve.ai"
	resolver     Resolver
	transports   *transportCache
	sandboxConns *connLimiter
	ipConns      *connLimiter
	log          zerolog.Logger

	// terminal holds the dependencies for the /terminal WebSocket bridge.
	// Set via WithTerminal — nil means the /terminal path falls through to
	// the generic reverse proxy and likely 404s (there's no boxd endpoint
	// at /terminal today), which is the safe default if a proxy is
	// deployed without terminal config.
	terminal *terminalBridgeDeps
}

// NewHandler creates a proxy Handler that only accepts requests whose Host
// header ends in ".{domain}".
func NewHandler(domain string, resolver Resolver, log zerolog.Logger) *Handler {
	h := &Handler{
		domain:       domain,
		resolver:     resolver,
		transports:   newTransportCache(),
		sandboxConns: newConnLimiter(maxConnsPerSandbox),
		ipConns:      newConnLimiter(maxConnsPerIP),
		log:          log,
	}
	return h
}

// StartSweeper launches a background goroutine that periodically closes
// transports for sandboxes that haven't been seen in transportMaxAge.
// It stops when ctx is cancelled.
func (h *Handler) StartSweeper(ctx context.Context) {
	go func() {
		t := time.NewTicker(transportSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				h.transports.sweep()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The /terminal path uses a different host format ({id}.{domain},
	// no port label) and is handled by a dedicated WS→connect-rpc
	// bridge instead of the generic reverse proxy. We check the path
	// before calling ParseHost because the bare-id host won't parse as
	// {port}-{id}.
	if r.URL.Path == "/terminal" && h.terminal != nil {
		h.serveTerminal(w, r)
		return
	}

	port, instanceID, err := ParseHost(r.Host, h.domain)
	if err != nil {
		h.log.Warn().Err(err).Str("host", r.Host).Msg("bad host")
		http.Error(w, "invalid sandbox URL", http.StatusBadRequest)
		return
	}

	// Block privileged ports — prevents accessing SSH or other system services
	// that may be bound on the VM's network interface.
	if port < minProxiedPort {
		http.Error(w, "port not allowed", http.StatusForbidden)
		return
	}

	info, err := h.resolver.Lookup(r.Context(), instanceID)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			http.Error(w, "sandbox not found", http.StatusNotFound)
			return
		}
		h.log.Error().Err(err).Str("instance", instanceID).Msg("resolver error")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "sandbox unavailable", http.StatusServiceUnavailable)
		return
	}

	if info.Status != "running" {
		w.Header().Set("Retry-After", "5")
		http.Error(w, fmt.Sprintf("sandbox is %s", info.Status), http.StatusServiceUnavailable)
		return
	}

	// Enforce per-sandbox connection limit.
	if !h.sandboxConns.acquire(instanceID) {
		http.Error(w, "too many connections to sandbox", http.StatusTooManyRequests)
		return
	}
	defer h.sandboxConns.release(instanceID)

	// Enforce per-IP connection limit.
	clientIP := clientAddr(r)
	if !h.ipConns.acquire(clientIP) {
		http.Error(w, "too many connections from this IP", http.StatusTooManyRequests)
		return
	}
	defer h.ipConns.release(clientIP)

	transport := h.transports.get(instanceID, info)

	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, port),
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Preserve the original Host so boxd sees the sandbox URL, not the VM IP.
			// This prevents the VM IP from leaking in redirects or cookies that echo Host.
			req.Host = r.Host
			// Strip all forwarding headers — a client could inject these to
			// spoof origin info that boxd or user apps might trust.
			for _, h := range []string{
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
				"X-Real-Ip",
				"Forwarded",
			} {
				req.Header.Del(h)
			}
		},
		Transport: transport,
		// FlushInterval: -1 enables immediate flushing for streaming responses
		// (PTY output, SSE). Without this Go buffers until the copy buffer fills.
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			h.log.Error().Err(proxyErr).
				Str("instance", instanceID).
				Str("target", target.Host).
				Msg("upstream error")
			// Invalidate so the next request re-resolves from VMD,
			// in case the VM was replaced.
			h.resolver.Invalidate(instanceID)
			rw.Header().Set("Retry-After", "2")
			http.Error(rw, "sandbox unreachable", http.StatusBadGateway)
		},
	}

	rp.ServeHTTP(w, r)
}

// CloseTransport closes and removes the transport for an instance.
// Call this when VMD destroys a sandbox to terminate idle connections immediately.
func (h *Handler) CloseTransport(instanceID string) {
	h.transports.close(instanceID)
}

// ---------------------------------------------------------------------------
// Transport cache
// ---------------------------------------------------------------------------

// transportCache maintains one *http.Transport per sandbox lifecycle.
// When a sandbox restarts, its lifecycleKey changes (new StartedAt), so the old
// transport is closed and a fresh one is created, preventing stale TCP connections.
type transportCache struct {
	mu    sync.Mutex
	items map[string]*transportEntry
}

type transportEntry struct {
	lifecycleKey string
	transport    *http.Transport
	lastUsed     time.Time
}

func newTransportCache() *transportCache {
	return &transportCache{items: make(map[string]*transportEntry)}
}

// get returns a transport for the given instance, creating or replacing it if
// the lifecycle key has changed since the last call.
func (c *transportCache) get(instanceID string, info InstanceInfo) *http.Transport {
	key := info.lifecycleKey()

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.items[instanceID]; ok {
		if e.lifecycleKey == key {
			e.lastUsed = time.Now()
			return e.transport
		}
		// Sandbox was replaced — close idle connections on old transport.
		e.transport.CloseIdleConnections()
	}

	t := newTransport()
	c.items[instanceID] = &transportEntry{
		lifecycleKey: key,
		transport:    t,
		lastUsed:     time.Now(),
	}
	return t
}

// close tears down the transport for an instance and removes it from the cache.
func (c *transportCache) close(instanceID string) {
	c.mu.Lock()
	e, ok := c.items[instanceID]
	if ok {
		delete(c.items, instanceID)
	}
	c.mu.Unlock()

	if ok {
		e.transport.CloseIdleConnections()
	}
}

// sweep closes and removes transports that haven't been used recently.
// This handles the case where a sandbox was destroyed without an explicit
// CloseTransport call (e.g. VMD restart).
//
// The lock is held only while collecting stale keys and deleting them from the
// map. Transport teardown (CloseIdleConnections) happens outside the lock so
// concurrent requests are not blocked during cleanup.
func (c *transportCache) sweep() {
	cutoff := time.Now().Add(-transportMaxAge)

	c.mu.Lock()
	stale := make([]*http.Transport, 0)
	for id, e := range c.items {
		if e.lastUsed.Before(cutoff) {
			stale = append(stale, e.transport)
			delete(c.items, id)
		}
	}
	c.mu.Unlock()

	for _, t := range stale {
		t.CloseIdleConnections()
	}
}

// ---------------------------------------------------------------------------
// Transport factory
// ---------------------------------------------------------------------------

// newTransport builds an http.Transport for VM-facing connections.
//
// Key decisions:
//   - Keep-alives enabled: the lifecycle-keyed transport cache already handles stale
//     connections on VM restart (StartedAt changes → new transport, old one swept).
//     Reusing TCP connections avoids a handshake per request for high-frequency HTTP.
//   - DisableCompression: we're a transparent proxy — client and server negotiate it.
//   - Retry dial on ECONNREFUSED only: boxd may not be ready immediately after the
//     sandbox reaches "running". We retry up to maxDialAttempts with linear backoff.
//     Other errors (DNS failure, host unreachable, cancelled ctx) are not retried.
//   - No ResponseHeaderTimeout: PTY and streaming responses can take arbitrarily long.
func newTransport() *http.Transport {
	return &http.Transport{
		DisableCompression:  true,
		IdleConnTimeout:     transportIdleTimeout,
		TLSHandshakeTimeout: 0,
		ForceAttemptHTTP2:   false,
		DialContext:         retryDial(maxDialAttempts, dialTimeout),
	}
}

// retryDial returns a DialContext func that retries on ECONNREFUSED with linear
// backoff. Only ECONNREFUSED is retried — this is the specific error that occurs
// when boxd hasn't finished binding its port yet after VM start.
// Other errors (host unreachable, context cancelled, DNS failure) fail immediately.
func retryDial(maxAttempts int, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: timeout}
		var (
			conn net.Conn
			err  error
		)
		for attempt := range maxAttempts {
			conn, err = d.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
			// Only retry connection refused — boxd startup window.
			// All other errors (unreachable, cancelled, etc.) are non-retriable.
			if !errors.Is(err, syscall.ECONNREFUSED) {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Don't sleep after the last attempt.
			if attempt < maxAttempts-1 {
				backoff := time.Duration(100*(attempt+1)) * time.Millisecond
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
		return nil, err
	}
}

// clientAddr extracts the client IP from the request.
// Behind GCP HTTPS LB, RemoteAddr is the LB's egress IP, not the client's.
// GCP sets X-Forwarded-For to: "<client>, <lb>" — we take the first entry.
// We read XFF before the director strips it (director runs later in ServeHTTP).
// Falls back to RemoteAddr if XFF is missing (direct access, tests).
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF may contain: "client, proxy1, proxy2" — first is the client.
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

// NewServer builds an http.Server for the proxy.
// No ReadTimeout/WriteTimeout — PTY and streaming need long-lived connections.
// ReadHeaderTimeout guards against slow-loris without breaking streams.
// MaxHeaderBytes limits header size to 1 MiB.
func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
}

// ListenAndServe starts the proxy and blocks until ctx is cancelled.
func ListenAndServe(ctx context.Context, addr string, handler http.Handler, log zerolog.Logger) error {
	srv := NewServer(addr, handler)

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", addr).Msg("proxy listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		log.Info().Msg("proxy shutting down")
		err := srv.Shutdown(shutdownCtx)
		// Drain in case Shutdown races with a serve error.
		<-errCh
		return err
	}
}
