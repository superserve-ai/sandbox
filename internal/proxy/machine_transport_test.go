package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

// A zero-buffer pipe makes backpressure deterministic: the first network
// write cannot complete until the client reads or the server aborts it.
type machineBlockedConn struct {
	net.Conn
	writeStarted chan struct{}
	once         sync.Once
}

func (c *machineBlockedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}

type machinePipeListener struct {
	conn chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *machinePipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *machinePipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *machinePipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

func machineTransportServer(t *testing.T, handler http.Handler) (net.Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	tracked := &machineBlockedConn{Conn: server, writeStarted: make(chan struct{})}
	listener := &machinePipeListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	listener.conn <- tracked
	httpServer := &http.Server{Handler: handler, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = client.Close(); _ = httpServer.Close() })
	return client, tracked.writeStarted
}

type machineTransportRoundTrip func(*http.Request) (*http.Response, error)

func (f machineTransportRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func machineTransportFixture(t *testing.T, lifetime time.Duration) (*Handler, string, auth.MachineCapability) {
	t.Helper()
	key := []byte("transport-cancellation-test-key-1234")
	h := NewHandler([]string{"sandbox.test"}, nil, zerolog.Nop()).WithAuth(key).WithExec()
	h.machineAuthority = func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) { return 1, nil }
	capability := auth.MachineCapability{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), Operations: []auth.MachineOperation{auth.MachineOperationCommandRun}, Audience: "sandbox-proxy", ExpiresAt: time.Now().Add(lifetime), RevocationGeneration: 1}
	token, err := auth.SignMachineCapability(capability, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h, token, capability
}

func TestMachineTransportCancelsBlockedDownstream(t *testing.T) {
	for _, cause := range []string{"revoke", "expiry"} {
		t.Run(cause, func(t *testing.T) {
			lifetime := time.Minute
			if cause == "expiry" {
				lifetime = 200 * time.Millisecond
			}
			h, token, capability := machineTransportFixture(t, lifetime)
			finished := make(chan struct{})
			rp := &httputil.ReverseProxy{
				Director: func(r *http.Request) { r.URL.Scheme = "http"; r.URL.Host = "upstream.test" },
				Transport: machineTransportRoundTrip(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 65536))), Request: r}, nil
				}),
				ErrorLog: log.New(io.Discard, "", 0),
			}
			client, blocked := machineTransportServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(finished)
				bound, cleanup, ok := h.bindMachineRequest(w, r, token)
				if !ok {
					http.Error(w, "admission failed", 503)
					return
				}
				defer cleanup()
				rp.ServeHTTP(w, bound)
			}))
			if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: sandbox.test\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-blocked:
			case <-time.After(time.Second):
				t.Fatal("proxy never attempted downstream write")
			}
			select {
			case <-finished:
				t.Fatal("response completed before client read or cancellation")
			default:
			}
			if cause == "revoke" && h.RevokeMachineCredential(capability.CredentialID, 1) != 1 {
				t.Fatal("missing active machine session")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("authority cancellation did not release blocked downstream write")
			}
		})
	}
}

func TestMachineTransportNormalCleanupPreservesKeepalive(t *testing.T) {
	h, token, _ := machineTransportFixture(t, time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bound, cleanup, ok := h.bindMachineRequest(w, r, token)
		if !ok {
			http.Error(w, "admission failed", 503)
			return
		}
		defer cleanup()
		if bound.Context().Err() != nil {
			http.Error(w, "canceled early", 500)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	var connections atomic.Int32
	transport := &http.Transport{MaxConnsPerHost: 1, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		connections.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for i := 0; i < 3; i++ {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "ok" || response.StatusCode != 200 {
			t.Fatalf("healthy response failed: %s %v", body, err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("normal cleanup poisoned keepalive: %d connections", connections.Load())
	}
}

func TestMachineTransportRemoteEdgeCancelsBlockedDownstream(t *testing.T) {
	local, token, capability := machineTransportFixture(t, time.Minute)
	peer, remote := net.Pipe()
	defer remote.Close()
	peerFinished := make(chan struct{})
	go func() {
		defer close(peerFinished)
		request, err := http.ReadRequest(bufio.NewReader(remote))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_, _ = io.WriteString(remote, "HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n"+strings.Repeat("x", 65536))
	}()
	router := NewRoutingHandler([]string{"sandbox.test"}, "local", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "remote", ProxyAddr: "127.0.0.1:5009", Generation: 1}, nil
	}), routePeerFunc(func(context.Context, string, PeerEndpoint) (PeerStream, error) { return pipePeer{peer}, nil }), local, zerolog.Nop())
	finished := make(chan struct{})
	client, blocked := machineTransportServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); router.ServeHTTP(w, r) }))
	request := fmt.Sprintf("POST /exec HTTP/1.1\r\nHost: boxd-%s.sandbox.test\r\nX-Access-Token: %s\r\nContent-Length: 0\r\n\r\n", capability.SandboxID, token)
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("edge never attempted downstream write")
	}
	if local.RevokeMachineCredential(capability.CredentialID, 1) != 1 {
		t.Fatal("remote edge missing authority registration")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("revocation left edge client write or upload drain blocked")
	}
	select {
	case <-peerFinished:
	case <-time.After(time.Second):
		t.Fatal("revocation left peer transport blocked")
	}
}

func TestMachineTransportCancelsBlockedRequestBody(t *testing.T) {
	h, token, capability := machineTransportFixture(t, time.Minute)
	admitted, finished := make(chan struct{}), make(chan struct{})
	client, _ := machineTransportServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		bound, cleanup, ok := h.bindMachineRequest(w, r, token)
		if !ok {
			http.Error(w, "admission failed", 503)
			return
		}
		defer cleanup()
		close(admitted)
		_, _ = io.Copy(io.Discard, bound.Body)
	}))
	if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: sandbox.test\r\nContent-Length: 1024\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("body stream not admitted")
	}
	if h.RevokeMachineCredential(capability.CredentialID, 1) != 1 {
		t.Fatal("missing active body session")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("revocation did not release downstream body read")
	}
}
