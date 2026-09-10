package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/proto/peerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// The test ingress forwards frames to a real HTTP listener, matching the
// fixed-target Forward RPC contract without interpreting application bytes.
type httpTestPeerIngress struct {
	peerpb.UnimplementedPeerProxyServer
	target string
}

func (s httpTestPeerIngress) Forward(stream grpc.BidiStreamingServer[peerpb.PeerProxyFrame, peerpb.PeerProxyFrame]) error {
	conn, err := net.Dial("tcp", s.target)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				_ = conn.(*net.TCPConn).CloseWrite()
				return
			}
			if _, err := conn.Write(frame.Data); err != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if err := stream.Send(&peerpb.PeerProxyFrame{Data: append([]byte(nil), buffer[:n]...)}); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func TestRoutingHandlerHTTPBodiesOverMTLS(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 0xff, '\r', '\n', 0x80}, 20000)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "invalid body", 400)
			return
		}
		if r.URL.Path == "/chunked" && r.Trailer.Get("X-Checksum") != "complete" {
			http.Error(w, "missing trailer", 400)
			return
		}
		_, _ = w.Write(body)
	}))
	defer target.Close()
	cfg := peerTestCredentials(t)
	tlsConfig, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	peerpb.RegisterPeerProxyServer(server, httpTestPeerIngress{target: strings.TrimPrefix(target.URL, "http://")})
	go server.Serve(listener)
	defer server.Stop()
	peers := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(cfg.LoadClient)})
	defer peers.Close()
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: listener.Addr().String()}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	for _, framing := range []string{"length", "chunked"} {
		t.Run(framing, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, router.URL+"/"+framing, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "sandbox.test"
			req.Header.Set(headerSandboxID, "sandbox-1")
			if framing == "chunked" {
				req.ContentLength = -1
				req.Trailer = http.Header{"X-Checksum": {"complete"}}
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || !bytes.Equal(body, payload) {
				t.Fatalf("status=%d length=%d err=%v", resp.StatusCode, len(body), err)
			}
		})
	}
}

func TestRoutingHandlerUpgradeBufferedBytes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		data := make([]byte, 4)
		if _, err := io.ReadFull(rw, data); err == nil {
			_, _ = conn.Write(data)
		}
	}))
	defer target.Close()
	peers := routePeerFunc(func(ctx context.Context, _, addr string) (PeerStream, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		return pipePeer{conn}, err
	})
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: strings.TrimPrefix(target.URL, "http://")}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(router.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: sandbox.test\r\n"+headerSandboxID+": sandbox-1\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nping")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo=%q err=%v", got, err)
	}
}
