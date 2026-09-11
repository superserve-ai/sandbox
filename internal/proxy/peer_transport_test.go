package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"google.golang.org/grpc/connectivity"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/proto/peerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func peerTestCredentials(t *testing.T) PeerTLSConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://example.org/peer")
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := PeerTLSConfig{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), CAFile: filepath.Join(dir, "cert.pem"), ExpectedSPIFFE: uri.String()}
	if err := os.WriteFile(cfg.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type waitingPeerServer struct {
	peerpb.UnimplementedPeerProxyServer
	halfClosed chan struct{}
	canceled   chan struct{}
}

func (s *waitingPeerServer) Forward(stream grpc.BidiStreamingServer[peerpb.PeerProxyFrame, peerpb.PeerProxyFrame]) error {
	_, _ = stream.Recv()
	close(s.halfClosed)
	<-stream.Context().Done()
	close(s.canceled)
	return stream.Context().Err()
}
func TestGRPCPeerURIAuthenticationAndStreamClose(t *testing.T) {
	cfg := peerTestCredentials(t)
	serverTLS, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	handler := &waitingPeerServer{halfClosed: make(chan struct{}), canceled: make(chan struct{})}
	peerpb.RegisterPeerProxyServer(server, handler)
	go server.Serve(listener)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, closer, err := GRPCPeerDialer(cfg.LoadClient)(ctx, "host", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	stream, err := client.OpenPeerStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.halfClosed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-handler.canceled:
		t.Fatal("half-close canceled RPC")
	default:
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.canceled:
	case <-ctx.Done():
		t.Fatal("Close did not cancel RPC")
	}
}
func TestPeerClientRejectsUntrustedOrWrongIdentity(t *testing.T) {
	cfg := peerTestCredentials(t)
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config PeerTLSConfig
	}{
		{"wrong identity", func() PeerTLSConfig { c := cfg; c.ExpectedSPIFFE = "spiffe://example.org/other"; return c }()},
		{"untrusted chain", peerTestCredentials(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := tc.config.LoadClient()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err == nil {
				t.Fatal("unauthorized certificate accepted")
			}
		})
	}
}

type echoPeerServer struct {
	peerpb.UnimplementedPeerProxyServer
}

func (echoPeerServer) Forward(stream grpc.BidiStreamingServer[peerpb.PeerProxyFrame, peerpb.PeerProxyFrame]) error {
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if string(frame.Data) == "reject" {
			return status.Error(codes.PermissionDenied, "denied")
		}
		if string(frame.Data) == "unavailable" {
			return status.Error(codes.Unavailable, "RPC unavailable")
		}
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
}
func TestPeerPoolClosingStreamDoesNotFailSibling(t *testing.T) {
	cfg := peerTestCredentials(t)
	serverTLS, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	peerpb.RegisterPeerProxyServer(server, echoPeerServer{})
	go server.Serve(listener)
	defer server.Stop()
	pool := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(cfg.LoadClient)})
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := pool.OpenStream(ctx, "host", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := pool.OpenStream(ctx, "host", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	readDone := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); readDone <- err }()
	_ = a.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("read succeeded after close")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := b.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "x" {
		t.Fatalf("payload = %q", buf)
	}
}

func TestPeerPoolRPCRejectionDoesNotFailSibling(t *testing.T) {
	for _, tc := range []struct {
		payload string
		code    codes.Code
	}{
		{"reject", codes.PermissionDenied}, {"unavailable", codes.Unavailable},
	} {
		t.Run(tc.payload, func(t *testing.T) {
			cfg := peerTestCredentials(t)
			serverTLS, err := cfg.Load()
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
			peerpb.RegisterPeerProxyServer(server, echoPeerServer{})
			go server.Serve(listener)
			defer server.Stop()
			pool := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(cfg.LoadClient), StreamsPerConnection: 2, MaxConnections: 1})
			defer pool.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			a, err := pool.OpenStream(ctx, "host", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			b, err := pool.OpenStream(ctx, "host", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if _, err := a.Write([]byte(tc.payload)); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Read(make([]byte, 1)); status.Code(err) != tc.code {
				t.Fatalf("error = %v", err)
			}
			if _, err := b.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if _, err := b.Read(buf); err != nil {
				t.Fatal(err)
			}
			c, err := pool.OpenStream(ctx, "host", listener.Addr().String())
			if err != nil {
				t.Fatal("failed RPC did not release capacity:", err)
			}
			_ = c.Close()
		})
	}
}

func TestGRPCPeerLargeWritePreservesByteStream(t *testing.T) {
	cfg := peerTestCredentials(t)
	serverTLS, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	peerpb.RegisterPeerProxyServer(server, echoPeerServer{})
	go server.Serve(listener)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, closer, err := GRPCPeerDialer(cfg.LoadClient)(ctx, "host", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	stream, err := client.OpenPeerStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := make([]byte, 5*1024*1024+17)
	for i := range payload {
		payload[i] = byte(i*31 + i/1024)
	}
	done := make(chan error, 1)
	go func() {
		n, err := stream.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, received); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("large write changed bytes or ordering")
	}
	if _, err := stream.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, len("still open"))
	if _, err := io.ReadFull(stream, tail); err != nil {
		t.Fatal(err)
	}
	if string(tail) != "still open" {
		t.Fatalf("tail = %q", tail)
	}
}

type failingFrameSender struct {
	grpc.BidiStreamingClient[peerpb.PeerProxyFrame, peerpb.PeerProxyFrame]
	frames []*peerpb.PeerProxyFrame
	err    error
}

func (s *failingFrameSender) Send(frame *peerpb.PeerProxyFrame) error {
	if len(s.frames) == 2 {
		return s.err
	}
	s.frames = append(s.frames, frame)
	return nil
}
func TestPeerWriteReportsOnlySuccessfullySentFrames(t *testing.T) {
	sendErr := errors.New("send failed")
	sender := &failingFrameSender{err: sendErr}
	stream := &generatedPeerStream{BidiStreamingClient: sender}
	payload := bytes.Repeat([]byte("x"), 3*peerFrameDataLimit+7)
	n, err := stream.Write(payload)
	if !errors.Is(err, sendErr) || n != 2*peerFrameDataLimit {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	var sent []byte
	for _, frame := range sender.frames {
		if len(frame.Data) > peerFrameDataLimit {
			t.Fatalf("oversize frame: %d", len(frame.Data))
		}
		sent = append(sent, frame.Data...)
	}
	if !bytes.Equal(sent, payload[:n]) {
		t.Fatal("incorrect partial payload")
	}
	payload[0] = 'y'
	if sender.frames[0].Data[0] != 'x' {
		t.Fatal("sent frame aliases caller buffer")
	}
}

type transportFailureTelemetry struct {
	noopPeerTelemetry
	failed chan struct{}
}

func (r *transportFailureTelemetry) PeerFailure() { r.failed <- struct{}{} }

func startPeerEchoServer(t *testing.T, cfg PeerTLSConfig, addr string) (*grpc.Server, string) {
	t.Helper()
	serverTLS, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	peerpb.RegisterPeerProxyServer(server, echoPeerServer{})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	return server, listener.Addr().String()
}

func TestGRPCPeerDisconnectUsesPoolBackoffAndRefreshesCredentials(t *testing.T) {
	cfg := peerTestCredentials(t)
	server, addr := startPeerEchoServer(t, cfg, "127.0.0.1:0")
	var loads atomic.Int32
	secondLoad := make(chan time.Time, 1)
	dial := GRPCPeerDialer(func() (*tls.Config, error) {
		if loads.Add(1) == 2 {
			secondLoad <- time.Now()
		}
		return cfg.LoadClient()
	})
	metrics := &transportFailureTelemetry{failed: make(chan struct{}, 2)}
	pool := NewPeerTransport(PeerPoolConfig{Dial: dial, Telemetry: metrics}).(*peerPool)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := pool.OpenStream(ctx, "host", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	server.Stop()
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded after disconnect")
	}
	select {
	case <-metrics.failed:
	case <-ctx.Done():
		t.Fatal("pool did not observe disconnect")
	}
	pool.mu.Lock()
	h := pool.hosts["host"]
	pool.mu.Unlock()
	if h == nil {
		t.Fatal("lost reconnect state")
	}
	h.mu.Lock()
	retryAt, failures, conns := h.retryAt, h.failures, len(h.conns)
	h.mu.Unlock()
	if failures != 1 || conns != 0 || retryAt.IsZero() {
		t.Fatalf("failure state: failures=%d conns=%d retryAt=%v", failures, conns, retryAt)
	}
	_, _ = startPeerEchoServer(t, cfg, addr)
	recovered, err := pool.OpenStream(ctx, "host", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var refreshedAt time.Time
	select {
	case refreshedAt = <-secondLoad:
	case <-ctx.Done():
		t.Fatal("reconnect did not refresh credentials")
	}
	if loads.Load() != 2 {
		t.Fatalf("credential loads = %d", loads.Load())
	}
	if refreshedAt.Before(retryAt) {
		t.Fatal("reconnected before pool backoff expired")
	}
	if _, err := recovered.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCPeerUnavailableRecordsBackoff(t *testing.T) {
	cfg := peerTestCredentials(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	loads := make(chan time.Time, 2)
	pool := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(func() (*tls.Config, error) { loads <- time.Now(); return cfg.LoadClient() })}).(*peerPool)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = pool.OpenStream(ctx, "host", addr)
	if !errors.Is(err, errPeerUnavailable) || ctx.Err() != nil {
		t.Fatalf("dial error = %v, caller error = %v", err, ctx.Err())
	}
	pool.mu.Lock()
	h := pool.hosts["host"]
	pool.mu.Unlock()
	if h == nil {
		t.Fatal("failed host evicted without backoff")
	}
	h.mu.Lock()
	retryAt, failures := h.retryAt, h.failures
	h.mu.Unlock()
	if failures != 1 || retryAt.IsZero() {
		t.Fatalf("missing backoff: %d, %v", failures, retryAt)
	}
	_, err = pool.OpenStream(ctx, "host", addr)
	if !errors.Is(err, errPeerUnavailable) {
		t.Fatal(err)
	}
	<-loads
	if second := <-loads; second.Before(retryAt) {
		t.Fatalf("retry bypassed backoff: %v", second)
	}
	h.mu.Lock()
	failures = h.failures
	h.mu.Unlock()
	if failures != 2 {
		t.Fatalf("failure count = %d", failures)
	}
}

func TestGRPCPeerDialTimeoutDistinguishesCallerCancellation(t *testing.T) {
	for _, mode := range []string{"attempt timeout", "caller cancel", "caller deadline"} {
		t.Run(mode, func(t *testing.T) {
			cfg := peerTestCredentials(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "caller deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer deadlineCancel()
			}
			pool := NewPeerTransport(PeerPoolConfig{Dial: func(ctx context.Context, _, addr string) (PeerClient, io.Closer, error) {
				tlsCfg, err := cfg.LoadClient()
				if err != nil {
					return nil, nil, err
				}
				return dialGRPCPeer(ctx, addr, tlsCfg, 300*time.Millisecond)
			}}).(*peerPool)
			defer pool.Close()
			result := make(chan error, 1)
			go func() { _, err := pool.OpenStream(ctx, "host", listener.Addr().String()); result <- err }()
			var conn net.Conn
			select {
			case conn = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("connection was not attempted")
			}
			defer conn.Close()
			if mode == "caller cancel" {
				cancel()
			}
			select {
			case err = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("dial exceeded its bound")
			}
			want := errPeerUnavailable
			if mode == "caller cancel" {
				want = context.Canceled
			}
			if mode == "caller deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			pool.mu.Lock()
			h := pool.hosts["host"]
			pool.mu.Unlock()
			if mode == "attempt timeout" {
				if h == nil {
					t.Fatal("attempt timeout lost backoff")
				}
				h.mu.Lock()
				failures := h.failures
				h.mu.Unlock()
				if failures != 1 {
					t.Fatalf("failures = %d", failures)
				}
			} else if h != nil {
				t.Fatal("caller cancellation retained failure state")
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.Copy(io.Discard, conn); err != nil {
				t.Fatalf("canceled dial leaked its socket: %v", err)
			}
		})
	}
}

func TestGRPCPeerClientCannotReconnectInternally(t *testing.T) {
	cfg := peerTestCredentials(t)
	server, addr := startPeerEchoServer(t, cfg, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, closer, err := GRPCPeerDialer(cfg.LoadClient)(ctx, "host", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	c := client.(*generatedPeerClient)
	server.Stop()
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("missing connection-end signal")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c.conn.Connect()
	for {
		state := c.conn.GetState()
		if state == connectivity.TransientFailure {
			break
		}
		if !c.conn.WaitForStateChange(ctx, state) {
			t.Fatal("reconnect attempt did not fail")
		}
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("client opened a second physical connection")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	if _, err := c.OpenPeerStream(ctx); !errors.Is(err, errPeerUnavailable) {
		t.Fatalf("dead client opened a stream: %v", err)
	}
}

func TestGRPCPeerDialerBoundsCredentialLoading(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var loads atomic.Int32
	dial := grpcPeerDialer(func() (*tls.Config, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil, errors.New("credentials unavailable")
	}, 30*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := dial(ctx, "host", "127.0.0.1:1"); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled load: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller waited for credential I/O")
	}
	// A blocked load remains bounded even after successive dial deadlines.
	for i := 0; i < 3; i++ {
		_, _, err := dial(context.Background(), "host", "127.0.0.1:1")
		if !errors.Is(err, errPeerUnavailable) {
			t.Fatalf("attempt deadline: %v", err)
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("concurrent stalled loads = %d, want 1", got)
	}
}

func TestGRPCPeerDialerCredentialLoadDeadline(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	dial := grpcPeerDialer(func() (*tls.Config, error) {
		close(started)
		<-release
		return nil, errors.New("credentials unavailable")
	}, 20*time.Millisecond)
	done := make(chan error, 1)
	go func() { _, _, err := dial(context.Background(), "host", "127.0.0.1:1"); done <- err }()
	<-started
	select {
	case err := <-done:
		if !errors.Is(err, errPeerUnavailable) {
			t.Fatalf("load deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial deadline did not include credential loading")
	}
}

func TestPeerPoolShutdownCancelsCredentialLoading(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	p := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(func() (*tls.Config, error) {
		close(started)
		<-release
		return nil, errors.New("credentials unavailable")
	}), DrainTimeout: time.Second})
	done := make(chan error, 1)
	go func() { _, err := p.OpenStream(context.Background(), "host", "127.0.0.1:1"); done <- err }()
	<-started
	_ = p.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("open succeeded after shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown left the open caller waiting on credential I/O")
	}
}

func TestGRPCPeerCachedCredentialsIsolateStalledRefresh(t *testing.T) {
	cfg := peerTestCredentials(t)
	_, addr := startPeerEchoServer(t, cfg, "127.0.0.1:0")
	initial, err := cfg.LoadClient()
	if err != nil {
		t.Fatal(err)
	}
	rotated := initial.Clone()
	rotated.VerifyConnection = func(tls.ConnectionState) error { return errors.New("rotated trust rejects peer") }
	started, release := make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	defer func() {
		if !released.Swap(true) {
			close(release)
		}
	}()
	var loads atomic.Int32
	dial := GRPCPeerDialer(func() (*tls.Config, error) {
		switch loads.Add(1) {
		case 1:
			return initial, nil
		case 2:
			close(started)
			<-release
		}
		return rotated, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, host := range []string{"first", "refreshing", "unrelated", "another"} {
		client, closer, err := dial(ctx, host, addr)
		if err != nil {
			t.Fatalf("%s blocked by refresh: %v", host, err)
		}
		stream, err := client.OpenPeerStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		_ = closer.Close()
		if host == "refreshing" {
			<-started
		}
	}
	if got := loads.Load(); got != 2 {
		t.Fatalf("loads while refresh stalled = %d, want 2", got)
	}
	released.Store(true)
	close(release)
	// A completed refresh replaces the cache for subsequent handshakes.
	for {
		_, closer, err := dial(ctx, "rotated", addr)
		if err != nil {
			if ctx.Err() != nil {
				t.Fatal("completed refresh was never used")
			}
			break
		}
		_ = closer.Close()
	}
}
