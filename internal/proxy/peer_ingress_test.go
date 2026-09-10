package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/proto/peerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestPeerIngressAuthorizedConcurrentFullDuplexAndWrongIdentity(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	ca, serverCert, serverKey, clientCert, clientKey, wrongCert, wrongKey := testCertificatesWithWrongIdentity(t)
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	writePEM(t, caFile, ca)
	writePEM(t, certFile, serverCert)
	writePEM(t, keyFile, serverKey)
	tlsCfg, err := (PeerTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ExpectedSPIFFE: "spiffe://example.test/vmd-peer-proxy"}).Load()
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServePeerListener(ctx, ln, tlsCfg, target, zerolog.Nop()) }()
	client := func(identity string) (*grpc.ClientConn, error) {
		ccert, ckey := clientCert, clientKey
		if identity != "spiffe://example.test/vmd-peer-proxy" {
			ccert, ckey = wrongCert, wrongKey
		}
		cert, e := tlsCertificate(ccert, ckey)
		if e != nil {
			return nil, e
		}
		return grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool(ca), ServerName: "peer.test", MinVersion: tls.VersionTLS13})))
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cc, e := client("spiffe://example.test/vmd-peer-proxy")
			if e != nil {
				t.Error(e)
				return
			}
			defer cc.Close()
			s, e := peerpb.NewPeerProxyClient(cc).Forward(context.Background())
			if e != nil {
				t.Error(e)
				return
			}
			// Send several independent chunks before reading. This exercises
			// opaque, full-duplex forwarding rather than only a unary-looking
			// request/response exchange.
			for n, msg := range [][]byte{
				[]byte(fmt.Sprintf("stream-%d-a", i)),
				[]byte(fmt.Sprintf("stream-%d-b", i)),
			} {
				if e = s.Send(&peerpb.PeerProxyFrame{Data: msg}); e != nil {
					t.Errorf("send chunk %d: %v", n, e)
					return
				}
				got, recvErr := s.Recv()
				if recvErr != nil || string(got.Data) != string(msg) {
					t.Errorf("echo chunk %d = %q, %v", n, got.GetData(), recvErr)
					return
				}
			}
			_ = s.CloseSend()
		}(i)
	}
	wg.Wait()
	t.Run("oversized frame", func(t *testing.T) {
		cc, err := client("spiffe://example.test/vmd-peer-proxy")
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := peerpb.NewPeerProxyClient(cc).Forward(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.Send(&peerpb.PeerProxyFrame{Data: make([]byte, maxPeerFrameBytes+1)})
		if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("oversized frame returned %v", err)
		}
	})
	bad, err := client("spiffe://example.test/wrong")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	stream, err := peerpb.NewPeerProxyClient(bad).Forward(context.Background())
	if err == nil {
		_ = stream.Send(&peerpb.PeerProxyFrame{Data: []byte("identity-check")})
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("wrong SPIFFE identity unexpectedly authorized")
	}
}

func TestServePeerListenerPropagatesServeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listener unavailable: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	serveErr := ServePeerListener(context.Background(), ln, &tls.Config{}, "127.0.0.1:1", zerolog.Nop())
	if serveErr == nil {
		t.Fatal("ServePeerListener returned nil after listener failure")
	}
}

func TestPeerIngressRejectsClientWithoutCertificate(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	ca, serverCert, serverKey, _, _ := testCertificates(t, "spiffe://example.test/vmd-peer-proxy")
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	writePEM(t, caFile, ca)
	writePEM(t, certFile, serverCert)
	writePEM(t, keyFile, serverKey)
	tlsCfg, err := (PeerTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ExpectedSPIFFE: "spiffe://example.test/vmd-peer-proxy"}).Load()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServePeerListener(ctx, ln, tlsCfg, target, zerolog.Nop()) }()
	cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool(ca), ServerName: "peer.test", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	stream, err := peerpb.NewPeerProxyClient(cc).Forward(context.Background())
	if err == nil {
		if sendErr := stream.Send(&peerpb.PeerProxyFrame{Data: []byte("unauthorized")}); sendErr == nil {
			t.Fatal("client without certificate was accepted")
		}
	}
}

func TestPeerIngressRejectsUntrustedCertificate(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	ca, serverCert, serverKey, _, _ := testCertificates(t, "spiffe://example.test/vmd-peer-proxy")
	// Mint the client from an independent CA. The server trusts only ca above,
	// so a valid certificate with the expected identity must still be rejected.
	_, _, _, clientCert, clientKey := testCertificates(t, "spiffe://example.test/vmd-peer-proxy")
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	writePEM(t, caFile, ca)
	writePEM(t, certFile, serverCert)
	writePEM(t, keyFile, serverKey)
	tlsCfg, err := (PeerTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ExpectedSPIFFE: "spiffe://example.test/vmd-peer-proxy"}).Load()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServePeerListener(ctx, ln, tlsCfg, target, zerolog.Nop()) }()
	cert, err := tlsCertificate(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool(ca), ServerName: "peer.test", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if _, err = peerpb.NewPeerProxyClient(cc).Forward(context.Background()); err == nil {
		t.Fatal("untrusted certificate unexpectedly authorized")
	}
}

func TestPeerIngressCancellationClosesTarget(t *testing.T) {
	lnTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	defer lnTarget.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := lnTarget.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ca, serverCert, serverKey, clientCert, clientKey := testCertificates(t, "spiffe://example.test/vmd-peer-proxy")
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	writePEM(t, caFile, ca)
	writePEM(t, certFile, serverCert)
	writePEM(t, keyFile, serverKey)
	tlsCfg, err := (PeerTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ExpectedSPIFFE: "spiffe://example.test/vmd-peer-proxy"}).Load()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServePeerListener(ctx, ln, tlsCfg, lnTarget.Addr().String(), zerolog.Nop()) }()
	cert, err := tlsCertificate(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool(ca), ServerName: "peer.test", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	sctx, scancel := context.WithCancel(context.Background())
	stream, err := peerpb.NewPeerProxyClient(cc).Forward(sctx)
	if err != nil {
		t.Fatal(err)
	}
	var targetConn net.Conn
	select {
	case targetConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("target was not dialed")
	}
	scancel()
	_, _ = stream.Recv()
	targetConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := targetConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("target connection remained open after cancellation")
	}
	targetConn.Close()
}

func TestServePeerListenerShutdownForcesActiveStreamStop(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := target.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ca, serverCert, serverKey, clientCert, clientKey := testCertificates(t, "spiffe://example.test/vmd-peer-proxy")
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	writePEM(t, caFile, ca)
	writePEM(t, certFile, serverCert)
	writePEM(t, keyFile, serverKey)
	tlsCfg, err := (PeerTLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, ExpectedSPIFFE: "spiffe://example.test/vmd-peer-proxy"}).Load()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServePeerListener(ctx, ln, tlsCfg, target.Addr().String(), zerolog.Nop()) }()
	cert, err := tlsCertificate(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool(ca), ServerName: "peer.test", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	stream, err := peerpb.NewPeerProxyClient(cc).Forward(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("target was not dialed")
	}
	cancel()
	conn.SetReadDeadline(time.Now().Add(peerShutdownGrace + time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active target connection remained open after shutdown")
	}
	conn.Close()
	select {
	case <-serveDone:
	case <-time.After(peerShutdownGrace + time.Second):
		t.Fatal("peer listener did not stop within forced-stop bound")
	}
}

func TestPeerProxyFrameHasNoDestinationSelector(t *testing.T) {
	// The wire contract intentionally exposes only opaque bytes; destination
	// selection is exclusively server-side configuration.
	if (&peerpb.PeerProxyFrame{}).ProtoReflect().Descriptor().Fields().Len() != 1 {
		t.Fatal("peer frame unexpectedly exposes destination fields")
	}
}

func TestHalfCloseWritePreservesResponseDirection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &halfCloseTestConn{Conn: server}

	halfCloseWrite(c)
	if !c.closedWrite {
		t.Fatal("peer EOF did not propagate as a local write half-close")
	}
}

type halfCloseTestConn struct {
	net.Conn
	closedWrite bool
}

func (c *halfCloseTestConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func echoTarget(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network listeners unavailable: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String(), func() { l.Close(); wg.Wait() }
}
func writePEM(t *testing.T, p string, b []byte) {
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func pool(b []byte) *x509.CertPool { p := x509.NewCertPool(); p.AppendCertsFromPEM(b); return p }
func tlsCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}
func testCertificates(t *testing.T, uri string) ([]byte, []byte, []byte, []byte, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validFrom := time.Now().Add(-time.Minute)
	validTo := validFrom.Add(24 * time.Hour)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: validFrom, NotAfter: validTo}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	makeCert := func(serial int64, isCA bool, dns string, uri string) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, URIs: nil, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: validFrom, NotAfter: validTo}
		if uri != "" {
			u, _ := url.Parse(uri)
			tpl.URIs = []*url.URL{u}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, caTpl, &k.PublicKey, caKey)
		kb, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	}
	serverC, serverK := makeCert(2, false, "peer.test", "")
	clientC, clientK := makeCert(3, false, "client.test", uri)
	return caPEM, serverC, serverK, clientC, clientK
}

func testCertificatesWithWrongIdentity(t *testing.T) ([]byte, []byte, []byte, []byte, []byte, []byte, []byte) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validFrom := time.Now().Add(-time.Minute)
	validTo := validFrom.Add(24 * time.Hour)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: validFrom, NotAfter: validTo}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	mint := func(serial int64, dns, identity string) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(identity)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: validFrom, NotAfter: validTo}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, caTpl, &k.PublicKey, caKey)
		kb, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	}
	server, serverKey := mint(2, "peer.test", "")
	client, clientKey := mint(3, "client.test", "spiffe://example.test/vmd-peer-proxy")
	wrong, wrongKey := mint(4, "client.test", "spiffe://example.test/wrong")
	return ca, server, serverKey, client, clientKey, wrong, wrongKey
}

func TestPeerIngressLocalEOFCompletesSuccessfully(t *testing.T) {
	for _, closeSend := range []bool{false, true} {
		t.Run(fmt.Sprintf("closeSend=%t", closeSend), func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if closeSend {
					_, err = io.ReadAll(conn)
				} else {
					_, err = io.ReadFull(conn, make([]byte, len("request")))
				}
				if err == nil {
					_, _ = conn.Write([]byte("response"))
				}
			}()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			recorder := &peerCompletionRecorder{events: make(chan telemetry.PeerIngress, 2)}
			server := grpc.NewServer()
			peerpb.RegisterPeerProxyServer(server, &PeerIngress{Target: target.Addr().String(), Log: zerolog.Nop(), Recorder: recorder})
			defer server.Stop()
			go func() { _ = server.Serve(ln) }()
			cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := peerpb.NewPeerProxyClient(cc).Forward(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(&peerpb.PeerProxyFrame{Data: []byte("request")}); err != nil {
				t.Fatal(err)
			}
			if closeSend {
				if err := stream.CloseSend(); err != nil {
					t.Fatal(err)
				}
			}
			var response []byte
			for {
				frame, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("expected clean stream completion: %v", err)
				}
				response = append(response, frame.Data...)
			}
			if string(response) != "response" {
				t.Fatalf("response = %q", response)
			}
			select {
			case event := <-recorder.events:
				if event.Result != telemetry.ResultSuccess {
					t.Fatalf("stream result = %q", event.Result)
				}
			case <-ctx.Done():
				t.Fatal("missing stream completion telemetry")
			}
		})
	}
}

type peerCompletionRecorder struct {
	telemetry.Recorder
	events chan telemetry.PeerIngress
}

func (r *peerCompletionRecorder) RecordPeerIngress(_ context.Context, event telemetry.PeerIngress) {
	if event.Event == "stream" {
		r.events <- event
	}
}

func TestPeerIngressAdmissionLimitBeforeDial(t *testing.T) {
	p := &PeerIngress{Target: "invalid", Log: zerolog.Nop()}
	p.activeStreams.Store(maxPeerStreams)
	if err := p.Forward(nil); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated ingress returned %v", err)
	}
	if got := p.activeStreams.Load(); got != maxPeerStreams {
		t.Fatalf("rejected stream leaked admission slot: %d", got)
	}
	p.activeStreams.Add(-1)
	stream := &contextPeerStream{ctx: context.Background()}
	if err := p.Forward(stream); err == nil || status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("available slot did not reach dial: %v", err)
	}
	if got := p.activeStreams.Load(); got != maxPeerStreams-1 {
		t.Fatalf("dial failure leaked admission slot: %d", got)
	}
}

type contextPeerStream struct {
	peerpb.PeerProxy_ForwardServer
	ctx context.Context
}

func (s *contextPeerStream) Context() context.Context { return s.ctx }

func TestPeerHandshakeDiagnostics(t *testing.T) {
	for _, failHandshake := range []bool{false, true} {
		t.Run(fmt.Sprintf("failHandshake=%t", failHandshake), func(t *testing.T) {
			var logs bytes.Buffer
			conn := &resetPeerConn{}
			creds := diagnosticTransportCredentials{
				TransportCredentials: &testPeerCredentials{fail: failHandshake},
				log:                  zerolog.New(&logs),
			}
			wrapped, _, err := creds.ServerHandshake(conn)
			if failHandshake {
				if err == nil || !bytes.Contains(logs.Bytes(), []byte("peer TLS handshake failed")) {
					t.Fatalf("handshake failure missing: err=%v logs=%s", err, logs.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _ = wrapped.Read(make([]byte, 1))
			if logs.Len() != 0 {
				t.Fatalf("post-handshake reset logged: %s", logs.String())
			}
		})
	}
}

type testPeerCredentials struct {
	credentials.TransportCredentials
	fail bool
}

func (c *testPeerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.fail {
		return nil, nil, fmt.Errorf("invalid certificate")
	}
	return conn, nil, nil
}

type resetPeerConn struct{ net.Conn }

func (*resetPeerConn) Read([]byte) (int, error) { return 0, fmt.Errorf("connection reset by peer") }

func TestPeerIngressConfiguredLimitRecordsRejection(t *testing.T) {
	recorder := &peerRejectionRecorder{events: make(chan telemetry.PeerIngress, 1)}
	p := &PeerIngress{MaxStreams: 2, Recorder: recorder}
	p.activeStreams.Store(2)
	stream := &contextPeerStream{ctx: context.Background()}
	if err := p.Forward(stream); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("configured limit returned %v", err)
	}
	select {
	case event := <-recorder.events:
		if event.Event != "stream_rejected" || event.Result != telemetry.ResultError {
			t.Fatalf("rejection event = %+v", event)
		}
	default:
		t.Fatal("rejection was not recorded")
	}
	if p.activeStreams.Load() != 2 {
		t.Fatal("rejection leaked capacity")
	}
}

type peerRejectionRecorder struct {
	telemetry.Recorder
	events chan telemetry.PeerIngress
}

func (r *peerRejectionRecorder) RecordPeerIngress(_ context.Context, event telemetry.PeerIngress) {
	r.events <- event
}

func TestPeerIngressBoundsIdleConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, maxPeerConnections+1)
	counted := &countedPeerListener{Listener: ln, accepted: accepted}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ln.Close()
	go func() { _ = ServePeerListener(ctx, counted, &tls.Config{}, "unused", zerolog.Nop()) }()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i <= maxPeerConnections; i++ {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		if i < maxPeerConnections {
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Fatal("connection was not accepted below limit")
			}
		}
	}
	select {
	case <-accepted:
		t.Fatal("idle connections bypassed transport limit")
	case <-time.After(100 * time.Millisecond):
	}
	conns[0].Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("closed transport did not release capacity")
	}
}

type countedPeerListener struct {
	net.Listener
	accepted chan struct{}
}

func (l *countedPeerListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- struct{}{}
	}
	return conn, err
}
