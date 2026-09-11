package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/superserve-ai/sandbox/proto/peerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/stats"
)

// PeerStream is the opaque bidirectional stream exposed to forwarding callers.
// Implementations preserve the generated peer-proxy stream semantics.
type PeerStream interface {
	io.ReadWriteCloser
	CloseSend() error
}

// PeerClient is the small portion of the generated peer-proxy client used by the pool.
type PeerClient interface {
	OpenPeerStream(context.Context) (PeerStream, error)
}

// PeerDialer establishes one authenticated persistent client connection.
type PeerDialer func(context.Context, string, string) (PeerClient, io.Closer, error)

const peerDialTimeout = 5 * time.Second

var errPeerUnavailable = errors.New("peer connection unavailable")

// GRPCPeerDialer returns a dialer backed by the generated peer-proxy client.
// Successful credentials are cached and refreshed in the background on new
// connections. Peer identity is checked before a client is published to the pool.
func GRPCPeerDialer(tlsConfig func() (*tls.Config, error)) PeerDialer {
	return grpcPeerDialer(tlsConfig, peerDialTimeout)
}

func grpcPeerDialer(tlsConfig func() (*tls.Config, error), timeout time.Duration) PeerDialer {
	// A stalled refresh must neither block cached credentials nor accumulate
	// background I/O. Initial callers share one deadline-bound load.
	type credentialLoad struct {
		done   chan struct{}
		config *tls.Config
		err    error
	}
	var mu sync.Mutex
	var cached *tls.Config
	var loading *credentialLoad
	return func(ctx context.Context, _ string, addr string) (PeerClient, io.Closer, error) {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		attemptError := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return errPeerUnavailable
		}
		if attemptCtx.Err() != nil {
			return nil, nil, attemptError()
		}
		mu.Lock()
		cfg := cached
		if loading == nil {
			loading = &credentialLoad{done: make(chan struct{})}
			load := loading
			go func() {
				load.config, load.err = tlsConfig()
				if load.err == nil && load.config == nil {
					load.err = errors.New("peer credentials are required")
				}
				mu.Lock()
				if load.err == nil {
					cached = load.config
				}
				loading = nil
				close(load.done)
				mu.Unlock()
			}()
		}
		load := loading
		mu.Unlock()
		if cfg == nil {
			select {
			case <-attemptCtx.Done():
				return nil, nil, attemptError()
			case <-load.done:
			}
			if attemptCtx.Err() != nil {
				return nil, nil, attemptError()
			}
			if load.err != nil {
				return nil, nil, load.err
			}
			cfg = load.config
		}
		client, closer, err := dialGRPCPeer(attemptCtx, addr, cfg, timeout)
		if err != nil && attemptCtx.Err() != nil {
			err = attemptError()
		}
		return client, closer, err
	}
}

func dialGRPCPeer(ctx context.Context, addr string, cfg *tls.Config, timeout time.Duration) (PeerClient, io.Closer, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := &generatedPeerClient{done: make(chan struct{})}
	var attempted atomic.Bool
	conn, err := grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithIdleTimeout(0), grpc.WithDisableRetry(), grpc.WithStatsHandler(c),
		grpc.WithContextDialer(func(dialCtx context.Context, target string) (net.Conn, error) {
			// Reconnects must return to the pool for backoff and fresh credentials.
			if !attempted.CompareAndSwap(false, true) {
				c.fail()
				return nil, errPeerUnavailable
			}
			return (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	c.conn = conn
	c.client = peerpb.NewPeerProxyClient(conn)
	conn.Connect()
	for {
		if err := attemptCtx.Err(); err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			// The attempt deadline is a peer failure, not the caller's cancellation.
			return nil, nil, errPeerUnavailable
		}
		state := conn.GetState()
		if state == connectivity.Ready {
			return c, conn, nil
		}
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, errPeerUnavailable
		}
		conn.WaitForStateChange(attemptCtx, state)
	}
}

type generatedPeerClient struct {
	client   peerpb.PeerProxyClient
	conn     *grpc.ClientConn
	done     chan struct{}
	failOnce sync.Once
}

func (c *generatedPeerClient) Done() <-chan struct{} { return c.done }
func (c *generatedPeerClient) fail()                 { c.failOnce.Do(func() { close(c.done) }) }
func (*generatedPeerClient) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (*generatedPeerClient) HandleRPC(context.Context, stats.RPCStats) {}
func (*generatedPeerClient) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (c *generatedPeerClient) HandleConn(_ context.Context, event stats.ConnStats) {
	// Connectivity can become IDLE on disconnect; ConnEnd records the actual
	// transport loss without interpreting application-level RPC statuses.
	if _, ok := event.(*stats.ConnEnd); ok {
		c.fail()
	}
}

func (c *generatedPeerClient) OpenPeerStream(ctx context.Context) (PeerStream, error) {
	select {
	case <-c.done:
		return nil, errPeerUnavailable
	default:
	}
	ctx, cancel := context.WithCancel(ctx)
	s, err := c.client.Forward(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	return &generatedPeerStream{BidiStreamingClient: s, cancel: cancel}, nil
}

type generatedPeerStream struct {
	grpc.BidiStreamingClient[peerpb.PeerProxyFrame, peerpb.PeerProxyFrame]
	mu      sync.Mutex
	pending []byte
	cancel  context.CancelFunc
}

func (s *generatedPeerStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	f, e := s.Recv()
	if e != nil {
		return 0, e
	}
	data := f.GetData()
	n := copy(p, data)
	if n < len(data) {
		s.pending = append(s.pending, data[n:]...)
	}
	return n, nil
}

// Reserve room for the protobuf tag and length below the ingress message limit.
const peerFrameDataLimit = maxPeerFrameBytes - 16

func (s *generatedPeerStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), peerFrameDataLimit)
		if err := s.Send(&peerpb.PeerProxyFrame{Data: append([]byte(nil), p[:n]...)}); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
func (s *generatedPeerStream) Close() error { s.cancel(); return nil }

// PeerTransport opens streams through a bounded per-host pool.
type PeerTransport interface {
	OpenStream(context.Context, string, string) (PeerStream, error)
	Close() error
}
