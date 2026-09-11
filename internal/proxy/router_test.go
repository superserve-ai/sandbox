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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type hijackWriter struct{ conn net.Conn }

func (w hijackWriter) Header() http.Header       { return make(http.Header) }
func (w hijackWriter) Write([]byte) (int, error) { return 0, errors.New("unexpected HTTP write") }
func (w hijackWriter) WriteHeader(int)           {}
func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

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
	r := httptest.NewRequest(http.MethodPost, "http://sandbox.test/upload", blockingReader{released: released})
	done := make(chan error, 1)
	go func() { done <- bridgeRequest(hijackWriter{conn: server}, r, peer) }()
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

type routePeerFunc func(context.Context, string, string) (PeerStream, error)

func (f routePeerFunc) OpenStream(ctx context.Context, hostID, addr string) (PeerStream, error) {
	return f(ctx, hostID, addr)
}

func TestRoutingHandlerPinsFailedStreamAndLooksUpNextRequest(t *testing.T) {
	oldOwner := SandboxRoute{HostID: "host-b", ProxyAddr: "192.0.2.2:5009"}
	newOwner := SandboxRoute{HostID: "host-c", ProxyAddr: "192.0.2.3:5009"}
	var owner atomic.Value
	owner.Store(oldOwner)
	var lookups, opens atomic.Int32
	var stream *lifecyclePeerStream
	var selected SandboxRoute
	var peerFailures, outcomes atomic.Int32
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(_ context.Context, id string) (SandboxRoute, error) {
			lookups.Add(1)
			if id != "sandbox-1" {
				return SandboxRoute{}, errors.New("unexpected sandbox ID")
			}
			return owner.Load().(SandboxRoute), nil
		}), routePeerFunc(func(_ context.Context, hostID, addr string) (PeerStream, error) {
			opens.Add(1)
			selected = SandboxRoute{HostID: hostID, ProxyAddr: addr}
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
		r.Header.Set(headerSandboxID, "sandbox-1")
		done := make(chan struct{})
		go func() { h.ServeHTTP(hijackWriter{conn: server}, r); close(done) }()
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

func (p routePeerStub) OpenStream(context.Context, string, string) (PeerStream, error) {
	return nil, p.err
}

func TestRoutingHandlerLocalDelegatesWithoutPeer(t *testing.T) {
	called := false
	recorded := ""
	lookupID := ""
	h := NewRoutingHandler([]string{"sandbox.test"}, "host-a",
		RouteLookupFunc(func(_ context.Context, id string) (SandboxRoute, error) {
			lookupID = id
			return SandboxRoute{HostID: "host-a", ProxyAddr: "127.0.0.1:1"}, nil
		}), routePeerStub{err: errors.New("must not dial")}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}), zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
			recorded = outcome.Outcome
		}))
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "sandbox-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called || w.Code != http.StatusNoContent {
		t.Fatalf("local route: called=%v status=%d", called, w.Code)
	}
	if lookupID != "sandbox-1" {
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
			return SandboxRoute{HostID: "host-b", ProxyAddr: "127.0.0.1:2"}, nil
		}), peers, http.NotFoundHandler(), zerolog.Nop(), routingOutcomeRecorderFunc(func(_ context.Context, outcome telemetry.RoutingOutcome) {
			recorded = outcome.Outcome
		}))
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "sandbox-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("peer failure status=%d", w.Code)
	}
	if recorded != "peer_error" {
		t.Fatalf("peer failure outcome=%q", recorded)
	}
	if peers.hostID != "host-b" || peers.proxyAddr != "127.0.0.1:2" {
		t.Fatalf("OpenStream args=(%q,%q)", peers.hostID, peers.proxyAddr)
	}
}

type routePeerArgsStub struct {
	hostID, proxyAddr string
	err               error
}

func (p *routePeerArgsStub) OpenStream(_ context.Context, hostID, proxyAddr string) (PeerStream, error) {
	p.hostID, p.proxyAddr = hostID, proxyAddr
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
	r.Header.Set(headerSandboxID, "sandbox-1")
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
	r.Header.Set(headerSandboxID, "sandbox-1")
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
			return SandboxRoute{HostID: "host-b", ProxyAddr: "   "}, nil
		}), peers, http.NotFoundHandler(), zerolog.Nop())
	r := httptest.NewRequest(http.MethodGet, "http://sandbox.test", nil)
	r.Header.Set(headerSandboxID, "sandbox-1")
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

func (p *trackingPeerStub) OpenStream(context.Context, string, string) (PeerStream, error) {
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
	lookup telemetry.OwnershipLookup
	count  int
}

func (*lookupRecorder) RecordRoutingOutcome(context.Context, telemetry.RoutingOutcome) {}
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
				return SandboxRoute{HostID: "host-a", ProxyAddr: "127.0.0.1:5009"}, tc.err
			}), nil, http.NotFoundHandler(), zerolog.Nop(), recorder)
			req := httptest.NewRequest("GET", "http://sandbox.test/", nil)
			req.Header.Set(headerSandboxID, "sandbox-1")
			router.ServeHTTP(httptest.NewRecorder(), req)
			if recorder.count != 1 || recorder.lookup.Duration <= 0 || recorder.lookup.Result != tc.result {
				t.Fatalf("lookup=%+v count=%d", recorder.lookup, recorder.count)
			}
		})
	}
}
