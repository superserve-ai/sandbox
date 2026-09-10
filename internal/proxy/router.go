package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	h.record(r.Context(), "remote", route.HostID)
	if err := bridgeRequest(w, r, stream); err != nil {
		h.record(r.Context(), "peer_error", route.HostID)
		h.log.Warn().Str("route_outcome", "peer_stream_error").Err(err).Msg("peer stream failed")
	}
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
	closeBoth := func() { once.Do(func() { close(done); _ = conn.Close(); _ = stream.Close() }) }
	go func() {
		select {
		case <-r.Context().Done():
			closeBoth()
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := request.Write(stream); err != nil {
			closeBoth()
			return
		}
		if upgrade {
			// Hijack may have already buffered bytes after the HTTP request.
			_, _ = io.Copy(stream, buffered.Reader)
		}
		_ = stream.CloseSend()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, stream)
		closeBoth()
	}()
	wg.Wait()
	closeBoth()
	return nil
}
