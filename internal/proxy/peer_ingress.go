package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/proto/peerpb"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// diagnosticTransportCredentials observes the handshake result itself. TLS
// failures are reported only during authentication, never on later socket I/O.
type diagnosticTransportCredentials struct {
	credentials.TransportCredentials
	log zerolog.Logger
}

func (c diagnosticTransportCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	wrapped, info, err := c.TransportCredentials.ServerHandshake(conn)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		c.log.Warn().Err(err).Msg("peer TLS handshake failed")
	}
	return wrapped, info, err
}

func (c diagnosticTransportCredentials) Clone() credentials.TransportCredentials {
	return diagnosticTransportCredentials{TransportCredentials: c.TransportCredentials.Clone(), log: c.log}
}

// peerShutdownGrace bounds how long a peer stream may delay process shutdown.
// Forward streams are allowed to finish normally, but a peer that never
// closes must not retain the listener indefinitely.
const peerShutdownGrace = 5 * time.Second

// Bound local connections across all peer transports, not just one HTTP/2 connection.
const maxPeerStreams = 128

// Include idle and handshaking transports, which never reach stream admission.
const maxPeerConnections = 128

// Leave protobuf overhead above the 32 KiB forwarding chunks.
const maxPeerFrameBytes = 64 * 1024

type PeerIngress struct {
	peerpb.UnimplementedPeerProxyServer
	Target     string
	Log        zerolog.Logger
	Recorder   telemetry.Recorder
	MaxStreams int64

	activeStreams atomic.Int64
}

// halfCloseWrite propagates the peer's receive-side half-close to the fixed
// local proxy without tearing down the connection's response direction.
// Keep this capability interface-based so wrapped TCP connections retain the
// same semantics when the dialer implementation changes.
func halfCloseWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (p *PeerIngress) Forward(s peerpb.PeerProxy_ForwardServer) error {
	active := p.activeStreams.Add(1)
	defer p.activeStreams.Add(-1)
	limit := p.MaxStreams
	if limit <= 0 {
		limit = maxPeerStreams
	}
	if active > limit {
		if p.Recorder != nil {
			p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "stream_rejected", Result: telemetry.ResultError})
		}
		return status.Error(codes.ResourceExhausted, "peer stream limit reached")
	}
	started := time.Now()
	if p.Recorder != nil {
		p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "tls_auth", Result: telemetry.ResultSuccess})
	}
	// Reaching the RPC means the TLS stack has completed client
	// authentication and the configured SPIFFE identity check. Keep this
	// low-cardinality diagnostic useful when handshake failures are otherwise
	// only visible to the transport.
	p.Log.Debug().Msg("peer TLS authentication succeeded")
	// Tie the local connection attempt to the peer stream so cancellation does
	// not leave a stalled dial running after the caller has gone away.
	conn, err := (&net.Dialer{}).DialContext(s.Context(), "tcp", p.Target)
	if err != nil {
		if p.Recorder != nil {
			p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "stream", Result: telemetry.ResultError, Duration: time.Since(started)})
		}
		p.Log.Error().Err(err).Msg("peer stream local dial failed")
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()
	errc := make(chan error, 2)
	localEOF := make(chan struct{})
	go func() {
		for {
			f, e := s.Recv()
			if e != nil {
				if errors.Is(e, io.EOF) {
					// Preserve TCP half-close semantics: the peer may have
					// finished its request while still waiting for a response.
					halfCloseWrite(conn)
					errc <- nil
				} else {
					p.Log.Warn().Err(e).Msg("peer stream receive failed")
					errc <- e
				}
				return
			}
			if e = writeFull(conn, f.Data); e != nil {
				p.Log.Warn().Err(e).Msg("peer stream local write failed")
				errc <- e
				return
			}
		}
	}()
	go func() {
		b := make([]byte, 32*1024)
		for {
			n, e := conn.Read(b)
			if n > 0 {
				if e2 := s.Send(&peerpb.PeerProxyFrame{Data: append([]byte(nil), b[:n]...)}); e2 != nil {
					p.Log.Warn().Err(e2).Msg("peer stream send failed")
					errc <- e2
					return
				}
			}
			if e != nil {
				if errors.Is(e, io.EOF) {
					// A local EOF terminates the server stream. Waiting for the
					// peer's send side would deadlock peers waiting for this EOF.
					close(localEOF)
				} else {
					p.Log.Warn().Err(e).Msg("peer stream local read failed")
					errc <- e
				}
				return
			}
		}
	}()
forwarding:
	for completed := 0; completed < 2; {
		select {
		case <-localEOF:
			break forwarding
		case e := <-errc:
			if e != nil {
				cancel()
				_ = conn.Close()
				p.Log.Warn().Err(e).Msg("peer stream failed")
				if p.Recorder != nil {
					p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "stream", Result: telemetry.ResultError, Duration: time.Since(started)})
				}
				return e
			}
			completed++
		case <-ctx.Done():
			p.Log.Debug().Err(ctx.Err()).Msg("peer stream canceled")
			_ = conn.Close()
			if p.Recorder != nil {
				p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "stream", Result: telemetry.ResultError, Duration: time.Since(started)})
			}
			return ctx.Err()
		}
	}
	p.Log.Debug().Msg("peer stream completed")
	if p.Recorder != nil {
		p.Recorder.RecordPeerIngress(s.Context(), telemetry.PeerIngress{Event: "stream", Result: telemetry.ResultSuccess, Duration: time.Since(started)})
	}
	return nil
}
func ServePeer(ctx context.Context, addr string, tlsCfg *tls.Config, target string, log zerolog.Logger) error {
	l, e := net.Listen("tcp", addr)
	if e != nil {
		log.Error().Err(e).Str("addr", addr).Msg("peer ingress listener failed")
		return e
	}
	defer l.Close()
	return ServePeerListener(ctx, l, tlsCfg, target, log)
}

// ServePeerListener serves peer ingress on an already-bound listener. Binding
// is intentionally performed by the caller so startup failures can be handled
// synchronously before the public proxy begins serving traffic.
func ServePeerListener(ctx context.Context, l net.Listener, tlsCfg *tls.Config, target string, log zerolog.Logger) error {
	return servePeerListener(ctx, l, tlsCfg, target, log, nil, maxPeerStreams)
}

func ServePeerListenerWithRecorder(ctx context.Context, l net.Listener, tlsCfg *tls.Config, target string, log zerolog.Logger, recorder telemetry.Recorder, streamLimit int64) error {
	return servePeerListener(ctx, l, tlsCfg, target, log, recorder, streamLimit)
}

func servePeerListener(ctx context.Context, l net.Listener, tlsCfg *tls.Config, target string, log zerolog.Logger, recorder telemetry.Recorder, streamLimit int64) error {
	s := grpc.NewServer(grpc.MaxRecvMsgSize(maxPeerFrameBytes), grpc.Creds(diagnosticTransportCredentials{TransportCredentials: credentials.NewTLS(tlsCfg), log: log}))
	peerpb.RegisterPeerProxyServer(s, &PeerIngress{Target: target, Log: log, Recorder: recorder, MaxStreams: streamLimit})
	go func() {
		<-ctx.Done()
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(stopped)
		}()
		timer := time.NewTimer(peerShutdownGrace)
		defer timer.Stop()
		select {
		case <-stopped:
		case <-timer.C:
			// GracefulStop does not cancel active streams. Force termination
			// after the bounded drain window so ServePeerListener can return.
			s.Stop()
		}
	}()
	log.Info().Str("addr", l.Addr().String()).Msg("peer ingress started")
	if recorder != nil {
		recorder.RecordPeerIngress(ctx, telemetry.PeerIngress{Event: "listener_start", Result: telemetry.ResultSuccess})
	}
	if err := s.Serve(netutil.LimitListener(l, maxPeerConnections)); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) || errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		// Keep this bounded listener-level diagnostic free of peer identity or
		// stream payload details; per-connection TLS failures are logged by the
		// configured TLS verifier.
		log.Warn().Err(err).Msg("peer ingress serve failed")
		return err
	}
	return nil
}
