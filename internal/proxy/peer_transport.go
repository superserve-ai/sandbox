package proxy

import (
	"context"
	"crypto/tls"
	"github.com/superserve-ai/sandbox/proto/peerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"io"
	"sync"
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

// GRPCPeerDialer returns a dialer backed by the generated peer-proxy client.
// Credentials are loaded for each new connection and peer identity is checked
// by the TLS config before the client is published to the pool.
func GRPCPeerDialer(tlsConfig func() (*tls.Config, error)) PeerDialer {
	return func(ctx context.Context, _ string, addr string) (PeerClient, io.Closer, error) {
		cfg, err := tlsConfig()
		if err != nil {
			return nil, nil, err
		}
		conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)), grpc.WithBlock())
		if err != nil {
			return nil, nil, err
		}
		c := &generatedPeerClient{client: peerpb.NewPeerProxyClient(conn), conn: conn, done: make(chan struct{})}
		go c.watchTransport()
		return c, conn, nil
	}
}

type generatedPeerClient struct {
	client peerpb.PeerProxyClient
	conn   *grpc.ClientConn
	done   chan struct{}
}

func (c *generatedPeerClient) Done() <-chan struct{} { return c.done }

func (c *generatedPeerClient) watchTransport() {
	for {
		state := c.conn.GetState()
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			close(c.done)
			return
		}
		if !c.conn.WaitForStateChange(context.Background(), state) {
			close(c.done)
			return
		}
	}
}

func (c *generatedPeerClient) OpenPeerStream(ctx context.Context) (PeerStream, error) {
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

// Leave ample room for protobuf framing below gRPC's receive-message limit.
const peerFrameDataLimit = 64 * 1024

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
