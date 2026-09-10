package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	if _, err := a.Write([]byte("reject")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Read(make([]byte, 1)); status.Code(err) != codes.PermissionDenied {
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
}
