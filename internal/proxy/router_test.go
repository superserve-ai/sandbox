package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type hijackWriter struct {
	conn  net.Conn
	input io.Reader
}

func (w hijackWriter) Header() http.Header       { return make(http.Header) }
func (w hijackWriter) Write([]byte) (int, error) { return 0, errors.New("unexpected HTTP write") }
func (w hijackWriter) WriteHeader(int)           {}
func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	input := w.input
	if input == nil {
		input = w.conn
	}
	conn := w.conn
	if w.input != nil {
		conn = readerConn{Conn: conn, Reader: input}
	}
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

type readerConn struct {
	net.Conn
	io.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

type blockingReader struct{ released chan struct{} }

func (r blockingReader) Read([]byte) (int, error) { <-r.released; return 0, io.EOF }
func (r blockingReader) Close() error             { return nil }

type pipePeer struct{ net.Conn }

func (pipePeer) CloseSend() error { return nil }

func TestBridgeRequestForwardsResponseBeforeUploadCompletes(t *testing.T) {
	client, server := net.Pipe()
	peerConn, peerRemote := net.Pipe()
	peer := pipePeer{Conn: peerConn}
	released := make(chan struct{})
	r := httptest.NewRequest(http.MethodPost, "http://sandbox.test/upload", nil)
	r.TransferEncoding = []string{"chunked"}
	r.ContentLength = -1
	r.Body = forbiddenRequestBody{}
	done := make(chan error, 1)
	go func() {
		done <- bridgeRequest(hijackWriter{conn: server, input: io.MultiReader(blockingReader{released: released}, strings.NewReader("0\r\n\r\n"), server)}, r, peer)
	}()
	go func() {
		defer peerRemote.Close()
		br := bufio.NewReader(peerRemote)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(peerRemote, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), r)
	if err != nil {
		t.Fatalf("response blocked until upload completed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("response body=%q, err=%v", body, err)
	}
	// Wait for the peer's EOF to close the downstream connection before
	// releasing the artificial upload reader, which ignores connection closure.
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("response connection: %v", err)
	}
	close(released)
	if err := <-done; err != nil {
		t.Fatalf("bridgeRequest: %v", err)
	}
}

type failingWritePeer struct {
	PeerStream
	err error
}

func (s failingWritePeer) Write([]byte) (int, error) { return 0, s.err }

func TestBridgeRequestPreservesUploadFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	peer, remote := net.Pipe()
	defer remote.Close()
	want := errors.New("peer upload failed")
	req := httptest.NewRequest(http.MethodPost, "http://sandbox.test/upload", bytes.NewBufferString("payload"))
	err := bridgeRequest(hijackWriter{conn: server}, req, failingWritePeer{PeerStream: pipePeer{peer}, err: want})
	if !errors.Is(err, want) {
		t.Fatalf("bridge error=%v, want %v", err, want)
	}
}

func TestBridgeRequestCancellationSuppressesShutdownErrors(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	peer, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "http://sandbox.test/upload", bytes.NewBufferString("payload")).WithContext(ctx)
	done := make(chan error, 1)
	go func() { done <- bridgeRequest(hijackWriter{conn: server}, req, pipePeer{peer}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridge error after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop after cancellation")
	}
}

type lifecyclePeerStream struct {
	*io.PipeReader
	upload   bytes.Buffer
	sent     chan struct{}
	sentOnce sync.Once
}

func (s *lifecyclePeerStream) Write(p []byte) (int, error) {
	n, err := s.upload.Write(p)
	req, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(s.upload.Bytes())))
	if parseErr == nil {
		body, bodyErr := io.ReadAll(req.Body)
		if bodyErr == nil && int64(len(body)) == req.ContentLength {
			s.sentOnce.Do(func() { close(s.sent) })
		}
	}
	return n, err
}
func (s *lifecyclePeerStream) CloseSend() error {
	return errors.New("HTTP upload must not half-close the destination")
}

type routePeerFunc func(context.Context, string, PeerEndpoint) (PeerStream, error)

func (f routePeerFunc) OpenStream(ctx context.Context, hostID string, endpoint PeerEndpoint) (PeerStream, error) {
	return f(ctx, hostID, endpoint)
}

func TestRoutingHandlerPinsFailedStreamAndLooksUpNextRequest(t *testing.T) {
	oldOwner := SandboxRoute{Generation: 42, HostID: "host-b", ProxyAddr: "192.0.2.2:5009"}
	newOwner := SandboxRoute{Generation: 42, HostID: "host-c", ProxyAddr: "192.0.2.3:5009"}
	var owner atomic.Value
	owner.Store(oldOwner)
	var lookups, opens atomic.Int32
	var stream *lifecyclePeerStream
	var selected SandboxRoute
	var peerFailures, outcomes atomic.Int32
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(_ context.Context, id string) (SandboxRoute, error) {
			lookups.Add(1)
			if id != "12345678-1234-1234-1234-123456789abc" {
				return SandboxRoute{}, errors.New("unexpected sandbox ID")
			}
			return owner.Load().(SandboxRoute), nil
		}), routePeerFunc(func(_ context.Context, hostID string, endpoint PeerEndpoint) (PeerStream, error) {
			opens.Add(1)
			selected = SandboxRoute{Generation: endpoint.Generation, HostID: hostID, ProxyAddr: endpoint.Address}
			return stream, nil
		}), http.NotFoundHandler(), zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
			outcomes.Add(1)
			if outcome.Outcome == "peer_error" {
				peerFailures.Add(1)
			}
		}))

	for i, wantOwner := range []SandboxRoute{oldOwner, newOwner} {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		reader, response := io.Pipe()
		t.Cleanup(func() { reader.Close(); response.Close() })
		stream = &lifecyclePeerStream{PipeReader: reader, sent: make(chan struct{})}
		upload := []byte{byte(i), 0xff, '\r', '\n', 0x80, 0x00}
		r := httptest.NewRequest(http.MethodPost, "http://sandbox.test/exec", bytes.NewReader(upload))
		r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
		r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
		done := make(chan struct{})
		go func() {
			h.ServeHTTP(hijackWriter{conn: server, input: io.MultiReader(bytes.NewReader(upload), server)}, r)
			close(done)
		}()
		select {
		case <-stream.sent:
		case <-time.After(3 * time.Second):
			t.Fatal("upload did not complete")
		}

		// The response remains readable after the framed upload completes.
		forward := func(payload []byte) {
			t.Helper()
			written := make(chan error, 1)
			go func() { _, err := response.Write(payload); written <- err }()
			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatalf("read opaque response: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("response bytes=%x, want %x", got, payload)
			}
			if err := <-written; err != nil {
				t.Fatalf("write peer response: %v", err)
			}
		}
		forward([]byte{0xff, 0x00, '\r', '\n'})
		if i == 0 {
			owner.Store(newOwner)
			forward([]byte("still on the original stream\x00\x80"))
		}
		response.CloseWithError(errors.New("peer stream failed"))
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("handler did not terminate after established stream failure")
		}
		if outcomes.Load() != int32(i+1) {
			t.Fatalf("recorded %d outcomes for %d requests", outcomes.Load(), i+1)
		}
		if peerFailures.Load() != int32(i+1) {
			t.Fatalf("response stream failure was not recorded: %d", peerFailures.Load())
		}
		if lookups.Load() != int32(i+1) || opens.Load() != int32(i+1) {
			t.Fatalf("request %d: lookups=%d opens=%d; stream was retried or lookup was cached", i, lookups.Load(), opens.Load())
		}
		if selected != wantOwner {
			t.Fatalf("request %d: selected %+v, want %+v", i, selected, wantOwner)
		}
		forwarded, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(stream.upload.Bytes())))
		if err != nil {
			t.Fatal(err)
		}
		gotUpload, err := io.ReadAll(forwarded.Body)
		if err != nil || !bytes.Equal(gotUpload, upload) {
			t.Fatalf("upload bytes=%x, want %x", gotUpload, upload)
		}
		if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("failed stream left client open: n=%d err=%v", n, err)
		}
	}
}

type routePeerStub struct{ err error }

func (p routePeerStub) OpenStream(context.Context, string, PeerEndpoint) (PeerStream, error) {
	return nil, p.err
}

func TestRoutingHandlerLocalDelegatesWithoutPeer(t *testing.T) {
	called := false
	recorded := ""
	lookupID := ""
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(_ context.Context, id string) (SandboxRoute, error) {
			lookupID = id
			return SandboxRoute{Generation: 42, HostID: "host-a", ProxyAddr: "127.0.0.1:1"}, nil
		}), routePeerStub{err: errors.New("must not dial")}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}), zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
			recorded = outcome.Outcome
		}))
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
	r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called || w.Code != http.StatusNoContent {
		t.Fatalf("local route: called=%v status=%d", called, w.Code)
	}
	if lookupID != "12345678-1234-1234-1234-123456789abc" {
		t.Fatalf("lookup sandbox ID=%q", lookupID)
	}
	if recorded != "local" {
		t.Fatalf("local route outcome=%q", recorded)
	}
}

func TestRoutingHandlerPeerFailureIsVisible(t *testing.T) {
	recorded := ""
	peers := &routePeerArgsStub{err: errors.New("peer down")}
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
			return SandboxRoute{Generation: 42, HostID: "host-b", ProxyAddr: "127.0.0.1:2"}, nil
		}), peers, http.NotFoundHandler(), zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
			recorded = outcome.Outcome
		}))
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
	r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("peer failure status=%d", w.Code)
	}
	if recorded != "peer_error" {
		t.Fatalf("peer failure outcome=%q", recorded)
	}
	if peers.hostID != "host-b" || peers.proxyAddr != "127.0.0.1:2" || peers.generation != 42 {
		t.Fatalf("OpenStream args=(%q,%q)", peers.hostID, peers.proxyAddr)
	}
}

type routePeerArgsStub struct {
	hostID, proxyAddr string
	generation        uint64
	err               error
}

func (p *routePeerArgsStub) OpenStream(_ context.Context, hostID string, endpoint PeerEndpoint) (PeerStream, error) {
	p.hostID, p.proxyAddr, p.generation = hostID, endpoint.Address, endpoint.Generation
	return nil, p.err
}

func TestRoutingHandlerLookupFailureIsVisible(t *testing.T) {
	recorded := ""
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { return SandboxRoute{}, errors.New("missing") }), nil, http.NotFoundHandler(), zerolog.Nop())
	h.recorder = routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
		recorded = outcome.Outcome
	})
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
	r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("lookup failure status=%d", w.Code)
	}
	if recorded != "ownership_error" {
		t.Fatalf("lookup failure outcome=%q", recorded)
	}
}

func TestRoutingHandlerLookupFailureDoesNotInvokeLocalHandler(t *testing.T) {
	called := false
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { return SandboxRoute{}, errors.New("missing") }), nil,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), zerolog.Nop())
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
	r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called {
		t.Fatal("local handler invoked after ownership lookup failure")
	}
}

func TestRoutingHandlerRejectsInvalidPeerEndpointBeforeOpenStream(t *testing.T) {
	peers := &trackingPeerStub{}
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
			return SandboxRoute{Generation: 42, HostID: "host-b", ProxyAddr: "   "}, nil
		}), peers, http.NotFoundHandler(), zerolog.Nop())
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
	r.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("invalid route status=%d", w.Code)
	}
	if peers.called {
		t.Fatal("OpenStream called for invalid peer endpoint")
	}
}

type trackingPeerStub struct{ called bool }

func (p *trackingPeerStub) OpenStream(context.Context, string, PeerEndpoint) (PeerStream, error) {
	p.called = true
	return nil, errors.New("unexpected dial")
}

type routingOutcomeRecorderFunc func(context.Context, telemetry.RoutingOutcome)

func (f routingOutcomeRecorderFunc) RecordRoutingOutcome(ctx context.Context, outcome telemetry.RoutingOutcome) {
	f(ctx, outcome)
}

func (routePeerFunc) Close() error      { return nil }
func (routePeerStub) Close() error      { return nil }
func (*routePeerArgsStub) Close() error { return nil }
func (*trackingPeerStub) Close() error  { return nil }

type lookupRecorder struct {
	lookup   telemetry.OwnershipLookup
	count    int
	outcomes int
}

func (r *lookupRecorder) RecordRoutingOutcome(context.Context, telemetry.RoutingOutcome) {
	r.outcomes++
}
func (r *lookupRecorder) RecordOwnershipLookup(_ context.Context, lookup telemetry.OwnershipLookup) {
	r.lookup = lookup
	r.count++
}

func TestRoutingHandlerRecordsLookupTiming(t *testing.T) {
	for _, tc := range []struct {
		result string
		err    error
	}{
		{"success", nil}, {"error", errors.New("database unavailable")},
		{"timeout", fmt.Errorf("query: %w", context.DeadlineExceeded)}, {"canceled", context.Canceled},
	} {
		t.Run(tc.result, func(t *testing.T) {
			recorder := &lookupRecorder{}
			router := NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
				return SandboxRoute{Generation: 42, HostID: "host-a", ProxyAddr: "127.0.0.1:5009"}, tc.err
			}), nil, http.NotFoundHandler(), zerolog.Nop(), recorder)
			req := httptest.NewRequest("GET", "http://sandbox.test/", nil)
			req.Header.Set(headerSandboxID, "12345678-1234-1234-1234-123456789abc")
			req.Host = "8080-12345678-1234-1234-1234-123456789abc.sandbox.test"
			router.ServeHTTP(httptest.NewRecorder(), req)
			if recorder.count != 1 || recorder.lookup.Duration <= 0 || recorder.lookup.Result != tc.result {
				t.Fatalf("lookup=%+v count=%d", recorder.lookup, recorder.count)
			}
		})
	}
}

func TestBridgeUpgradeRequiresSwitchingProtocols(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusSwitchingProtocols} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := net.Pipe()
			peer, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = remote.SetDeadline(time.Now().Add(time.Second))
			req := httptest.NewRequest(http.MethodGet, "http://first.example.com/", nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			done := make(chan error, 1)
			go func() { done <- bridgeRequest(hijackWriter{conn: server}, req, pipePeer{peer}) }()
			downstream := []byte("GET / HTTP/1.1\r\nHost: second.example.com\r\n\r\n")
			go func() { _, _ = client.Write(downstream) }()
			upstream := bufio.NewReader(remote)
			initial, err := http.ReadRequest(upstream)
			if err != nil {
				t.Fatal(err)
			}
			_ = initial.Body.Close()
			responseDone := make(chan error, 1)
			go func() {
				if status == http.StatusOK {
					_, err := io.WriteString(remote, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					responseDone <- err
				} else {
					_, err := io.WriteString(remote, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello")
					responseDone <- err
				}
			}()
			reader := bufio.NewReader(client)
			response, err := http.ReadResponse(reader, req)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != status {
				t.Fatalf("status=%d", response.StatusCode)
			}
			if status == http.StatusOK {
				body, err := io.ReadAll(response.Body)
				if err != nil || string(body) != "ok" {
					t.Fatalf("body=%q err=%v", body, err)
				}
				extra, err := io.ReadAll(upstream)
				if err != nil || len(extra) != 0 {
					t.Fatalf("forwarded after rejected upgrade: %q, %v", extra, err)
				}
			} else {
				greeting := make([]byte, 5)
				if _, err := io.ReadFull(reader, greeting); err != nil || string(greeting) != "hello" {
					t.Fatalf("greeting=%q err=%v", greeting, err)
				}
				received := make([]byte, len(downstream))
				if _, err := io.ReadFull(upstream, received); err != nil || !bytes.Equal(received, downstream) {
					t.Fatalf("tunnel=%q err=%v", received, err)
				}
			}
			if err := <-responseDone; err != nil {
				t.Fatal(err)
			}
			_ = remote.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("bridge did not finish")
			}
		})
	}
}

type tunnelReadResultConn struct {
	net.Conn
	ready  <-chan struct{}
	result error
}

func (c tunnelReadResultConn) Read([]byte) (int, error) { <-c.ready; return 0, c.result }

type tunnelHalfClosePeer struct {
	net.Conn
	halfClosed chan struct{}
}

func (s tunnelHalfClosePeer) CloseSend() error { close(s.halfClosed); return nil }
func TestBridgeAcceptedTunnelReadTermination(t *testing.T) {
	for _, orderly := range []bool{false, true} {
		t.Run(fmt.Sprint(orderly), func(t *testing.T) {
			client, server := net.Pipe()
			peer, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = remote.SetDeadline(time.Now().Add(time.Second))
			ready := make(chan struct{})
			halfClosed := make(chan struct{})
			readErr := error(io.EOF)
			if !orderly {
				readErr = errors.New("client reset")
			}
			request := httptest.NewRequest(http.MethodGet, "http://first.example.com/", nil)
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Upgrade", "websocket")
			done := make(chan error, 1)
			go func() {
				done <- bridgeRequest(hijackWriter{conn: tunnelReadResultConn{server, ready, readErr}}, request, tunnelHalfClosePeer{peer, halfClosed})
			}()
			go func() {
				_, err := http.ReadRequest(bufio.NewReader(remote))
				if err == nil {
					_, _ = io.WriteString(remote, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				}
			}()
			reader := bufio.NewReader(client)
			if _, err := http.ReadResponse(reader, request); err != nil {
				t.Fatal(err)
			}
			close(ready)
			if orderly {
				select {
				case <-halfClosed:
				case <-time.After(time.Second):
					t.Fatal("EOF did not half-close")
				}
				select {
				case err := <-done:
					t.Fatalf("EOF closed download: %v", err)
				case <-time.After(10 * time.Millisecond):
				}
				go func() { _, _ = remote.Write([]byte("ok")); _ = remote.Close() }()
				payload := make([]byte, 2)
				if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "ok" {
					t.Fatalf("download=%q err=%v", payload, err)
				}
			}
			select {
			case err := <-done:
				if !orderly && !errors.Is(err, readErr) {
					t.Fatalf("error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("bridge retained terminated client")
			}
		})
	}
}

func TestBridgeRequestEmptyPeerResponseReturns502(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	peer, remote := net.Pipe()
	defer remote.Close()
	req := httptest.NewRequest(http.MethodGet, "http://sandbox.test/", nil)
	done := make(chan error, 1)
	go func() { done <- bridgeRequest(hijackWriter{conn: server}, req, pipePeer{peer}) }()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(remote))
		remote.Close()
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusBadGateway || string(body) != "sandbox forwarding unavailable\n" {
		t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("bridge error=%v", err)
	}
}

func TestRoutingAuthenticatesBoxdBeforeOwnership(t *testing.T) {
	seed := []byte("invented-test-seed-with-at-least-32-bytes")
	id := "12345678-1234-1234-1234-123456789abc"
	local := NewHandler([]string{"sandbox.test"}, &stubResolver{}, zerolog.Nop()).WithAuth(seed).WithFiles().WithExec().WithTerminal([]string{"*"})
	var lookups int
	router := NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		lookups++
		return SandboxRoute{}, ErrInstanceNotFound
	}), nil, local, zerolog.Nop())
	for _, path := range []string{filesPath, execPath, execStreamPath, terminalPath, execConnectPath} {
		for _, valid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/valid=%t", path, valid), func(t *testing.T) {
				lookups = 0
				req := httptest.NewRequest(http.MethodPost, "http://boxd-"+id+".sandbox.test"+path+"?path=/tmp/example", nil)
				token := "invalid"
				if valid {
					token = auth.ComputeAccessToken(seed, id)
				}
				if path == terminalPath || path == execConnectPath {
					req.Method = http.MethodGet
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("Sec-WebSocket-Version", "13")
					req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
					req.Header.Set("Sec-WebSocket-Protocol", "token."+token)
				} else {
					req.Header.Set(accessTokenHeader, token)
				}
				result := httptest.NewRecorder()
				router.ServeHTTP(result, req)
				if valid {
					if lookups != 1 || result.Code != http.StatusNotFound {
						t.Fatalf("lookups=%d status=%d", lookups, result.Code)
					}
				} else if lookups != 0 || result.Code >= 500 {
					t.Fatalf("invalid token reached ownership: lookups=%d status=%d", lookups, result.Code)
				}
			})
		}
	}
	for _, valid := range []bool{false, true} {
		lookups = 0
		req := httptest.NewRequest(http.MethodGet, "http://sandbox.test/files?path=/tmp/example", nil)
		req.Header.Set(headerSandboxID, id)
		token := "invalid"
		want, wantLookups := http.StatusUnauthorized, 0
		if valid {
			token = auth.ComputeAccessToken(seed, id)
			want, wantLookups = http.StatusNotFound, 1
		}
		req.Header.Set(accessTokenHeader, token)
		result := httptest.NewRecorder()
		router.ServeHTTP(result, req)
		if result.Code != want || lookups != wantLookups {
			t.Fatalf("shared host: status=%d lookups=%d", result.Code, lookups)
		}
	}
	lookups = 0
	preflight := httptest.NewRequest(http.MethodOptions, "http://boxd-"+id+".sandbox.test/files", nil)
	preflight.Header.Set("Origin", "https://example.test")
	result := httptest.NewRecorder()
	router.ServeHTTP(result, preflight)
	if lookups != 0 || result.Code != http.StatusNoContent {
		t.Fatalf("preflight lookups=%d status=%d", lookups, result.Code)
	}
}

func TestRoutingOwnershipNotFoundAndUnavailable(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("wrapped: %w", ErrInstanceNotFound), http.StatusNotFound},
		{errors.New("database unavailable"), http.StatusBadGateway},
	} {
		h := NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { return SandboxRoute{}, tc.err }), nil, http.NotFoundHandler(), zerolog.Nop())
		req := httptest.NewRequest(http.MethodGet, "http://8080-12345678-1234-1234-1234-123456789abc.sandbox.test/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("status=%d want=%d", w.Code, tc.want)
		}
	}
}

func TestRoutingHandlerRejectsMissingGenerationBeforeOpenStream(t *testing.T) {
	peers := &trackingPeerStub{}
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		return SandboxRoute{HostID: "host-b", ProxyAddr: "192.0.2.2:5009"}, nil
	}), peers, http.NotFoundHandler(), zerolog.Nop())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://8080-12345678-1234-1234-1234-123456789abc.sandbox.test/", nil))
	if w.Code != http.StatusBadGateway || peers.called {
		t.Fatalf("status=%d peers=%+v", w.Code, peers)
	}
}

func TestRoutingHandlerInvalidInputDoesNotResolveOwnership(t *testing.T) {
	for _, tc := range []struct {
		host   string
		status int
	}{
		{"scanner.example", http.StatusBadRequest},
		{"70000-12345678-1234-1234-1234-123456789abc.sandbox.test", http.StatusBadRequest},
		{"8080-not-a-uuid.sandbox.test", http.StatusBadRequest},
		{"boxd-not-a-uuid.sandbox.test", http.StatusBadRequest},
		{"1-12345678-1234-1234-1234-123456789abc.sandbox.test", http.StatusForbidden},
		{"22-12345678-1234-1234-1234-123456789abc.sandbox.test", http.StatusForbidden},
		{"1023-12345678-1234-1234-1234-123456789abc.sandbox.test", http.StatusForbidden},
		{"22-not-a-uuid.sandbox.test", http.StatusForbidden},
	} {
		t.Run(tc.host, func(t *testing.T) {
			recorder := &lookupRecorder{}
			var lookups int
			peers := &trackingPeerStub{}
			router := NewRoutingHandler([]string{"sandbox.test"}, "host-a", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
				lookups++
				return SandboxRoute{}, errors.New("unexpected lookup")
			}), peers, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected local handler") }), zerolog.Nop(), recorder)
			request := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d", response.Code)
			}
			if lookups != 0 || peers.called || recorder.count != 0 || recorder.outcomes != 0 {
				t.Fatalf("lookups=%d peer=%v lookup metrics=%d routing metrics=%d", lookups, peers.called, recorder.count, recorder.outcomes)
			}
		})
	}
}

// The server-owned body must never be touched once a connection is hijacked.
type forbiddenRequestBody struct{}

func (forbiddenRequestBody) Read([]byte) (int, error) { panic("read original body after hijack") }
func (forbiddenRequestBody) Close() error             { panic("close original body after hijack") }

func TestRequestAfterHijackPreservesBufferedBodyAndFollowingBytes(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://sandbox.test/upload", nil)
			request.Body = forbiddenRequestBody{}
			request.ContentLength = 7
			wire := "payload"
			if chunked {
				request.ContentLength = -1
				request.TransferEncoding = []string{"chunked"}
				request.Trailer = http.Header{"X-Checksum": nil}
				wire = "7\r\npayload\r\n0\r\nX-Checksum: complete\r\n\r\n"
			}
			original := bufio.NewReader(strings.NewReader(wire + "following-upgrade-bytes"))
			if _, err := original.Peek(3); err != nil {
				t.Fatal(err)
			}
			forwarded, remaining, err := requestAfterHijack(request, original)
			if err != nil {
				t.Fatal(err)
			}
			var serialized bytes.Buffer
			if err := forwarded.Write(&serialized); err != nil {
				t.Fatal(err)
			}
			parsed, err := http.ReadRequest(bufio.NewReader(&serialized))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(parsed.Body)
			if err != nil || string(body) != "payload" {
				t.Fatalf("body=%q err=%v", body, err)
			}
			if chunked && parsed.Trailer.Get("X-Checksum") != "complete" {
				t.Fatal("trailer lost")
			}
			rest, err := io.ReadAll(remaining)
			if err != nil || string(rest) != "following-upgrade-bytes" {
				t.Fatalf("following bytes=%q err=%v", rest, err)
			}
		})
	}
}

func TestRequestAfterHijackRejectsTruncatedBody(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://sandbox.test/", nil)
			request.Body = forbiddenRequestBody{}
			request.ContentLength = 7
			wire := "pay"
			if chunked {
				request.ContentLength = -1
				request.TransferEncoding = []string{"chunked"}
				wire = "7\r\npay"
			}
			forwarded, _, err := requestAfterHijack(request, bufio.NewReader(strings.NewReader(wire)))
			if err != nil {
				t.Fatal(err)
			}
			if err := forwarded.Write(io.Discard); err == nil {
				t.Fatal("truncated body accepted")
			}
		})
	}
}

func TestRoutingLocalOwnerBeforePeerNormalization(t *testing.T) {
	for _, localHostID := range []string{"usw2", "use4", "default", "example-region-2-generated"} {
		t.Run(localHostID, func(t *testing.T) { testRoutingLocalOwnerBeforePeerNormalization(t, localHostID) })
	}
}

func testRoutingLocalOwnerBeforePeerNormalization(t *testing.T, localHostID string) {
	for _, owner := range []string{localHostID, " " + localHostID + " ", localHostID + "-2", localHostID + "-2-random", ""} {
		t.Run(owner, func(t *testing.T) {
			localCalls := 0
			router := NewRoutingHandler([]string{"sandbox.test"}, " "+localHostID+" ", RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
				return SandboxRoute{HostID: owner}, nil
			}), routePeerFunc(func(context.Context, string, PeerEndpoint) (PeerStream, error) {
				t.Error("incomplete route attempted peer dial")
				return nil, errors.New("unexpected dial")
			}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { localCalls++; w.WriteHeader(http.StatusNoContent) }), zerolog.Nop())
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://8080-22222222-2222-4222-8222-222222222222.sandbox.test/", nil))
			wantStatus, wantLocal := http.StatusBadGateway, 0
			if strings.TrimSpace(owner) == localHostID {
				wantStatus, wantLocal = http.StatusNoContent, 1
			}
			if response.Code != wantStatus || localCalls != wantLocal {
				t.Fatalf("status=%d local=%d", response.Code, localCalls)
			}
		})
	}
}
