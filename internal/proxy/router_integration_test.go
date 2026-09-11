package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func startRoutingTestPeer(t *testing.T, target string) (PeerTransport, string) {
	t.Helper()
	cfg := peerTestCredentials(t)
	tlsConfig, err := cfg.Load()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServePeerListener(ctx, listener, tlsConfig, target, zerolog.Nop()) }()
	peers := NewPeerTransport(PeerPoolConfig{Dial: GRPCPeerDialer(cfg.LoadClient)})
	t.Cleanup(func() {
		peers.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("peer shutdown: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("peer shutdown timed out")
		}
	})
	return peers, listener.Addr().String()
}

func startRoutingTestOwner(t *testing.T, upstream *httptest.Server) (PeerTransport, string, string) {
	t.Helper()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port
	local := httptest.NewServer(NewHandler([]string{"sandbox.test"}, &stubResolver{
		info: InstanceInfo{VMIP: "127.0.0.1", Status: "running"},
	}, zerolog.Nop()))
	t.Cleanup(local.Close)
	peers, addr := startRoutingTestPeer(t, local.Listener.Addr().String())
	return peers, addr, fmt.Sprintf("%d-12345678-1234-1234-1234-123456789abc.sandbox.test", port)
}

func TestRoutingHandlerHTTPBodiesOverMTLS(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 0xff, '\r', '\n', 0x80}, 20000)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "invalid body", 400)
			return
		}
		if r.URL.Path == "/chunked-with-trailers" && r.Trailer.Get("X-Checksum") != "complete" {
			http.Error(w, "missing trailer", 400)
			return
		}
		_, _ = w.Write(body)
	}))
	defer target.Close()
	peers, peerAddr, sandboxHost := startRoutingTestOwner(t, target)
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: peerAddr}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	directPeers, directAddr := startRoutingTestPeer(t, target.Listener.Addr().String())
	directRouter := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: directAddr}, nil
	}), directPeers, http.NotFoundHandler(), zerolog.Nop()))
	defer directRouter.Close()
	for _, framing := range []string{"length", "chunked", "chunked-with-trailers"} {
		t.Run(framing, func(t *testing.T) {
			routerURL := router.URL
			if framing == "chunked-with-trailers" {
				routerURL = directRouter.URL
			}
			req, err := http.NewRequest(http.MethodPost, routerURL+"/"+framing, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = sandboxHost
			if framing != "length" {
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
	peers, peerAddr := startRoutingTestPeer(t, target.Listener.Addr().String())
	sandboxHost := "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: peerAddr}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(router.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+sandboxHost+"\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nping")
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

func TestRoutingHandlerClientDisconnectCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	stop := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-stop:
		}
	}))
	defer target.Close()
	defer close(stop)
	peers, peerAddr, sandboxHost := startRoutingTestOwner(t, target)
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: peerAddr}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	client, err := net.Dial("tcp", router.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fmt.Fprintf(client, "GET /wait HTTP/1.1\r\nHost: %s\r\n\r\n", sandboxHost)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request did not start")
	}
	client.Close()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("client disconnect did not cancel upstream")
	}
}

func TestRoutingHandlerLongURIOverProductionIngress(t *testing.T) {
	path := "/" + strings.Repeat("a", 128*1024)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.Error(w, "incorrect URI", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	peers, peerAddr, sandboxHost := startRoutingTestOwner(t, target)
	router := httptest.NewServer(NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: peerAddr}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop()))
	defer router.Close()
	req, err := http.NewRequest(http.MethodGet, router.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = sandboxHost
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
