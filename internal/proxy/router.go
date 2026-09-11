package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// RoutingHandler selects an owner once, then delegates locally or bridges one
// opaque stream to the owner's private peer ingress.
type RoutingHandler struct {
	domains     []string
	localHostID string
	ownership   OwnershipResolver
	peers       PeerTransport
	local       http.Handler
	log         zerolog.Logger
	recorder    telemetry.RoutingOutcomeRecorder
}

func NewRoutingHandler(domains []string, localHostID string, ownership OwnershipResolver, peers PeerTransport, local http.Handler, log zerolog.Logger, recorders ...telemetry.RoutingOutcomeRecorder) *RoutingHandler {
	var recorder telemetry.RoutingOutcomeRecorder
	if len(recorders) > 0 {
		recorder = recorders[0]
	}
	return &RoutingHandler{domains: domains, localHostID: localHostID, ownership: ownership, peers: peers, local: local, log: log, recorder: recorder}
}

func (h *RoutingHandler) record(ctx context.Context, outcome, hostID string) {
	if h.recorder != nil {
		h.recorder.RecordRoutingOutcome(ctx, telemetry.RoutingOutcome{Outcome: outcome, HostID: hostID})
	}
}

func (h *RoutingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, id, err := ParseRequest(r.Host, r.Header, h.domains)
	if err != nil {
		h.record(r.Context(), "ownership_error", "")
		http.Error(w, "invalid sandbox URL", http.StatusBadRequest)
		return
	}
	started := time.Now()
	route, err := h.ownership.ResolveSandbox(r.Context(), id)
	if recorder, ok := h.recorder.(telemetry.OwnershipLookupRecorder); ok {
		result := "success"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			result = "timeout"
		case errors.Is(err, context.Canceled):
			result = "canceled"
		case err != nil:
			result = "error"
		}
		recorder.RecordOwnershipLookup(r.Context(), telemetry.OwnershipLookup{Duration: time.Since(started), Result: result})
	}
	if err != nil {
		h.record(r.Context(), "ownership_error", "")
		h.log.Warn().Str("route_outcome", "ownership_lookup_error").Err(err).Msg("sandbox ownership lookup failed")
		http.Error(w, "sandbox routing unavailable", http.StatusBadGateway)
		return
	}
	route, err = NormalizeSandboxRoute(route)
	if err != nil {
		h.record(r.Context(), "ownership_error", route.HostID)
		h.log.Warn().Str("route_outcome", "ownership_invalid").Err(err).Msg("sandbox ownership route invalid")
		http.Error(w, "sandbox routing unavailable", http.StatusBadGateway)
		return
	}
	if route.HostID == h.localHostID {
		h.record(r.Context(), "local", route.HostID)
		h.log.Debug().Str("route", "local").Str("route_outcome", "local").Str("host_id", route.HostID).Msg("sandbox routed locally")
		h.local.ServeHTTP(w, r)
		return
	}
	if h.peers == nil {
		h.record(r.Context(), "peer_error", route.HostID)
		h.log.Warn().Str("route_outcome", "peer_unavailable").Msg("peer forwarding unavailable")
		http.Error(w, "peer forwarding unavailable", http.StatusBadGateway)
		return
	}
	stream, err := h.peers.OpenStream(r.Context(), route.HostID, route.ProxyAddr)
	if err != nil {
		h.record(r.Context(), "peer_error", route.HostID)
		h.log.Warn().Str("route_outcome", "peer_forward_error").Err(err).Msg("peer forwarding failed")
		http.Error(w, "sandbox forwarding unavailable", http.StatusBadGateway)
		return
	}
	h.log.Debug().Str("route", "remote").Str("route_outcome", "remote").Str("host_id", route.HostID).Msg("sandbox routed to peer")
	defer stream.Close()
	if err := bridgeRequest(w, r, stream); err != nil {
		h.record(r.Context(), "peer_error", route.HostID)
		h.log.Warn().Str("route_outcome", "peer_stream_error").Err(err).Msg("peer stream failed")
		return
	}
	h.record(r.Context(), "remote", route.HostID)
}

// Serialize the fallback response with the response pump. A partial response
// must never be followed by a second HTTP status line.
type bridgeResponseWriter struct {
	conn              net.Conn
	mu                sync.Mutex
	started, finished bool
}

func (w *bridgeResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return 0, net.ErrClosed
	}
	n, err := w.conn.Write(p)
	w.started = w.started || n > 0
	return n, err
}

func (w *bridgeResponseWriter) hasStarted() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started
}

func (w *bridgeResponseWriter) finish(err error) {
	if err == nil {
		_ = w.conn.Close()
		return
	}
	// Bound both an in-flight downstream write and the gateway response.
	_ = w.conn.SetWriteDeadline(time.Now().Add(time.Second))
	w.mu.Lock()
	w.finished = true
	if !w.started {
		_, _ = io.WriteString(w.conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 31\r\nConnection: close\r\n\r\nsandbox forwarding unavailable\n")
	}
	w.mu.Unlock()
	_ = w.conn.Close()
}

func bridgeRequest(w http.ResponseWriter, r *http.Request, stream PeerStream) error {
	// A peer stream is a raw connection. Hijacking preserves websocket, upgrade,
	// streaming, and upload semantics without parsing application payloads.
	hj, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("response writer does not support hijacking")
	}
	conn, buffered, err := hj.Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	output := &bridgeResponseWriter{conn: conn}
	defer stream.Close()
	// Request.Write owns both headers and transfer framing, including chunked
	// bodies and trailers. Run it alongside the response pump for early replies.
	request := new(http.Request)
	*request = *r
	request.Header = r.Header.Clone()
	upgrade := r.Header.Get("Upgrade") != ""
	if !upgrade {
		request.Close = true
	}
	// A half-close on the upload side must not tear down the download side.
	// Conversely, once the peer finishes (or the request is cancelled), close
	// both descriptors so the other copy cannot remain blocked forever.
	done := make(chan struct{})
	var once sync.Once
	var bridgeErr error
	closeBoth := func(err error) {
		once.Do(func() {
			if r.Context().Err() == nil {
				bridgeErr = err
			}
			close(done)
			_ = stream.Close()
			output.finish(bridgeErr)
		})
	}
	go func() {
		select {
		case <-r.Context().Done():
			closeBoth(nil)
		case <-done:
		}
	}()
	upgraded := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := request.Write(stream); err != nil {
			closeBoth(err)
			return
		}
		if upgrade {
			select {
			case <-upgraded:
			case <-done:
				return
			}
			// Hijack may have already buffered bytes after the HTTP request.
			if _, err := io.Copy(stream, buffered.Reader); err != nil {
				closeBoth(err)
				return
			}
			if err := stream.CloseSend(); err != nil {
				closeBoth(err)
			}
		} else {
			// Hijacking disables net/http's disconnect watcher. Once the body
			// is consumed, drain without forwarding pipelined requests so EOF
			// cancels a quiet upstream as well.
			_, _ = io.Copy(io.Discard, conn)
			closeBoth(nil)
		}
		// HTTP framing ends the body. A TCP half-close at the destination would
		// cancel net/http's request context before its reverse proxy responds.
	}()
	go func() {
		defer wg.Done()
		var source io.Reader = stream
		if upgrade {
			reader := bufio.NewReader(stream)
			source = reader
			for {
				response, err := http.ReadResponse(reader, request)
				if err != nil {
					closeBoth(err)
					return
				}
				if response.StatusCode == http.StatusSwitchingProtocols {
					if _, err = fmt.Fprintf(output, "%s %s\r\n", response.Proto, response.Status); err == nil {
						err = response.Header.Write(output)
					}
					if err == nil {
						_, err = io.WriteString(output, "\r\n")
					}
					if err != nil {
						closeBoth(err)
						return
					}
					close(upgraded)
					break
				}
				final := response.StatusCode >= 200
				if final {
					response.Close = true
				}
				err = response.Write(output)
				_ = response.Body.Close()
				if err != nil || final {
					closeBoth(err)
					return
				}
			}
		}
		_, err := io.Copy(output, source)
		if err == nil && !output.hasStarted() {
			err = io.ErrUnexpectedEOF
		}
		// The first terminal event owns the result; closing either descriptor
		// can make the other pump fail as a consequence.
		closeBoth(err)
	}()
	wg.Wait()
	closeBoth(nil)
	return bridgeErr
}
