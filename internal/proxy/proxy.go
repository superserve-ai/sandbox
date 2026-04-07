package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Timeout constants.
//
// The client-facing idle timeout must be longer than the upstream idle timeout
// so we don't race the upstream close. GCP LB has a 600s upstream idle timeout,
// so the VM-facing transport idle is set to 610s and the server idle to 620s.
const (
	serverIdleTimeout    = 620 * time.Second
	transportIdleTimeout = 610 * time.Second
	dialTimeout          = 5 * time.Second

	// maxDialAttempts handles the window where boxd is starting up inside the VM.
	// We retry with linear backoff: 100ms, 200ms, 300ms before giving up.
	maxDialAttempts = 3
)

// Handler is the core reverse proxy handler.
type Handler struct {
	resolver  *Resolver
	transports *transportCache
	log       zerolog.Logger
}

// NewHandler creates a proxy Handler.
func NewHandler(resolver *Resolver, log zerolog.Logger) *Handler {
	return &Handler{
		resolver:  resolver,
		transports: newTransportCache(),
		log:       log,
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	port, instanceID, err := ParseHost(r.Host)
	if err != nil {
		h.log.Warn().Err(err).Str("host", r.Host).Msg("bad host")
		http.Error(w, "invalid sandbox URL", http.StatusBadRequest)
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

	transport := h.transports.get(instanceID, info)

	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", info.VMIP, port),
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header.Del("X-Forwarded-For")
		},
		Transport: transport,
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

// CloseTransport closes the transport for an instance (e.g. when VMD destroys it).
// This terminates any idle connections to that VM immediately.
func (h *Handler) CloseTransport(instanceID string) {
	h.transports.close(instanceID)
}

// ---------------------------------------------------------------------------
// Transport cache
// ---------------------------------------------------------------------------

// transportCache maintains one *http.Transport per sandbox lifecycle.
// When a sandbox restarts, its lifecycleKey changes (new CreatedAt), so the old
// transport is closed and a fresh one is created, preventing stale TCP connections.
type transportCache struct {
	mu    sync.Mutex
	items map[string]*transportEntry
}

type transportEntry struct {
	lifecycleKey string
	transport    *http.Transport
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
			return e.transport
		}
		// Sandbox was replaced — close idle conns on old transport before discarding.
		e.transport.CloseIdleConnections()
	}

	t := newTransport()
	c.items[instanceID] = &transportEntry{lifecycleKey: key, transport: t}
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

// ---------------------------------------------------------------------------
// Transport factory
// ---------------------------------------------------------------------------

// newTransport builds an http.Transport for VM-facing connections.
//
// Key decisions:
//   - DisableKeepAlives: sandboxes are ephemeral and can restart; never reuse TCP.
//   - DisableCompression: we're a transparent proxy — the client and server negotiate compression.
//   - Retry dial: boxd may not be ready the instant the sandbox reaches "running".
//     We retry up to maxDialAttempts times with linear backoff so the SDK doesn't
//     need to handle this transient window.
//   - No ResponseHeaderTimeout: PTY and streaming responses can take arbitrarily long.
func newTransport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives:   true,
		DisableCompression:  true,
		IdleConnTimeout:     transportIdleTimeout,
		TLSHandshakeTimeout: 0, // no TLS to VMs
		ForceAttemptHTTP2:   false,
		DialContext:         retryDial(maxDialAttempts, dialTimeout),
	}
}

// retryDial returns a DialContext func that retries on connection refused with
// linear backoff. This handles the window between a sandbox reaching "running"
// status and boxd finishing its startup inside the VM.
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

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

// NewServer builds an http.Server for the proxy.
// No ReadTimeout/WriteTimeout — PTY and streaming need long-lived connections.
// ReadHeaderTimeout guards against slow-loris without breaking streams.
func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
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
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		log.Info().Msg("proxy shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
