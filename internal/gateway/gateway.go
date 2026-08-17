package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Gateway owns the public ports and routes them to the active upstream
// generation. Construct with New, point it at a generation via Router, then
// serve the gRPC and resolver listeners.
type Gateway struct {
	router *Router

	// resolverHold bounds how long a resolver (:9090) request waits for a
	// cutover to finish before failing. Data-plane requests query the resolver
	// live and its results are uncacheable (they carry current access policy),
	// so a cutover holds the request rather than returning 503.
	resolverHoldMax time.Duration

	connMu sync.Mutex
	conns  map[string]*grpc.ClientConn // upstream gRPC conns, keyed by socket

	rtMu       sync.Mutex
	transports map[string]*http.Transport // resolver HTTP transports, per socket
}

// Stream and message limits must mirror vmd's own gRPC server so the gateway
// never becomes the tighter bottleneck: without an explicit stream limit gRPC
// clients self-cap at 100 streams/conn, and the default 4 MiB message size
// would reject requests vmd accepts.
const (
	maxConcurrentStreams = 2000
	maxMessageBytes      = 64 << 20 // 64 MiB
)

// New returns a Gateway with an empty routing table.
func New() *Gateway {
	return &Gateway{
		router: NewRouter(),
		// Longer than any normal cutover's quiesce window (now just the new
		// generation's activation, since draining happens before the hold). The
		// caller's own request context still bounds an individual wait, so a
		// generous cap never pins a request past when its client gave up.
		resolverHoldMax: 30 * time.Second,
		conns:           map[string]*grpc.ClientConn{},
		transports:      map[string]*http.Transport{},
	}
}

// Router exposes the routing/quiesce control surface.
func (g *Gateway) Router() *Router { return g.router }

// SetActive points the gateway at a generation and evicts cached upstream
// connections/transports for sockets that are no longer routed to, so drained
// generations do not leak a ClientConn/Transport for the host's lifetime.
func (g *Gateway) SetActive(up Upstream) {
	g.router.SetActive(up)
	g.evictExcept(up.GRPCSocket, up.ResolverSocket)
}

func (g *Gateway) evictExcept(grpcSocket, resolverSocket string) {
	g.connMu.Lock()
	for s, c := range g.conns {
		if s != grpcSocket {
			_ = c.Close()
			delete(g.conns, s)
		}
	}
	g.connMu.Unlock()
	g.rtMu.Lock()
	for s, t := range g.transports {
		if s != resolverSocket {
			t.CloseIdleConnections()
			delete(g.transports, s)
		}
	}
	g.rtMu.Unlock()
}

// GRPCServer builds the transparent-proxy gRPC server that serves the public
// control-plane port. Serve it on the public listener.
func (g *Gateway) GRPCServer() *grpc.Server {
	return grpc.NewServer(
		grpc.ForceServerCodecV2(rawCodec{}),
		grpc.UnknownServiceHandler(g.direct),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
	)
}

// upstreamConn returns a cached gRPC client conn to an upstream generation's
// unix socket, dialing lazily. The conn uses the raw passthrough codec so the
// gateway forwards opaque bytes.
func (g *Gateway) upstreamConn(socket string) (*grpc.ClientConn, error) {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if c, ok := g.conns[socket]; ok {
		return c, nil
	}
	c, err := grpc.NewClient(
		"unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodecV2(rawCodec{}),
			grpc.MaxCallRecvMsgSize(maxMessageBytes),
			grpc.MaxCallSendMsgSize(maxMessageBytes),
		),
	)
	if err != nil {
		return nil, err
	}
	g.conns[socket] = c
	return c, nil
}

// ResolverHandler is the HTTP handler for the loopback resolver port. During a
// cutover it holds the request up to resolverHold waiting for resume, then
// proxies to the active upstream — it does not return 503 mid-cutover, because
// the edge proxy queries this live per data-plane request.
func (g *Gateway) ResolverHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up, held, resumed := g.router.resolverState()
		if held {
			select {
			case <-resumed:
				up, _, _ = g.router.resolverState()
			case <-time.After(g.resolverHoldMax):
				http.Error(w, "gateway draining", http.StatusServiceUnavailable)
				return
			case <-r.Context().Done():
				return
			}
		}
		if up.ResolverSocket == "" {
			http.Error(w, "no upstream", http.StatusServiceUnavailable)
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = "vmd" // ignored by the unix transport
			},
			Transport: g.resolverTransport(up.ResolverSocket),
		}
		proxy.ServeHTTP(w, r)
	})
}

func (g *Gateway) resolverTransport(socket string) *http.Transport {
	g.rtMu.Lock()
	defer g.rtMu.Unlock()
	if t, ok := g.transports[socket]; ok {
		return t
	}
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	g.transports[socket] = t
	return t
}

// Close releases cached upstream connections.
func (g *Gateway) Close() {
	g.connMu.Lock()
	for _, c := range g.conns {
		_ = c.Close()
	}
	g.conns = map[string]*grpc.ClientConn{}
	g.connMu.Unlock()
}
