package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testPeerStream struct {
	closed atomic.Bool
	fail   *atomic.Bool
}

func (s *testPeerStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *testPeerStream) Write(p []byte) (int, error) {
	if s.closed.Load() || (s.fail != nil && s.fail.Load()) {
		return 0, errors.New("closed")
	}
	return len(p), nil
}
func (s *testPeerStream) CloseSend() error { s.closed.Store(true); return nil }
func (s *testPeerStream) Close() error     { return s.CloseSend() }

type testPeerClient struct {
	streams atomic.Int32
	fail    atomic.Bool
}

func (c *testPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	if c.fail.Load() {
		return nil, errors.New("transport failed")
	}
	c.streams.Add(1)
	return &testPeerStream{fail: &c.fail}, nil
}

type testPeerConn struct {
	client *testPeerClient
	closed atomic.Int32
}

func (c *testPeerConn) Close() error { c.closed.Add(1); return nil }

func testDialer() (PeerDialer, *atomic.Int32, *[]*testPeerConn) {
	var dials atomic.Int32
	var mu sync.Mutex
	conns := make([]*testPeerConn, 0)
	return func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		c := &testPeerConn{client: &testPeerClient{}}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c.client, c, nil
	}, &dials, &conns
}

func TestPeerPoolReusesConnectionAndGrowsLazily(t *testing.T) {
	dial, dials, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, StreamsPerConnection: 1, MaxConnections: 2})
	s1, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials after capacity exhausted = %d, want 2", got)
	}
	_ = s1.Close()
	_ = s2.Close()
	s3, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials after reuse = %d, want 2", got)
	}
	_ = s3.Close()
	_ = p.Close()
}

func TestPeerPoolEvictsHostAfterIdleDialFailure(t *testing.T) {
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		return nil, nil, errors.New("unavailable")
	}})
	if _, err := p.OpenStream(context.Background(), "unbounded-host", "addr"); err == nil {
		t.Fatal("expected dial failure")
	}
	pp := p.(*peerPool)
	pp.mu.Lock()
	if len(pp.hosts) != 0 {
		t.Fatalf("hosts after failed idle dial = %d, want 0", len(pp.hosts))
	}
	pp.mu.Unlock()
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

func TestPeerPoolEndpointReplacementUsesNewEndpoint(t *testing.T) {
	var mu sync.Mutex
	var addrs []string
	p := NewPeerTransport(PeerPoolConfig{Dial: func(_ context.Context, _ string, addr string) (PeerClient, io.Closer, error) {
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "old")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_ = p.Close()
	// A replacement must establish fresh capacity; the old connection cannot be reused.
	if len(addrs) != 2 {
		t.Fatalf("dial count after endpoint replacement = %d, want 2", len(addrs))
	}
	if addrs[0] != "old" || addrs[1] != "new" {
		t.Fatalf("dial endpoints = %v, want [old new]", addrs)
	}
}

func TestPeerPoolCoalescesConcurrentInitialDials(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		close(started)
		<-release
		return &testPeerClient{}, &countingCloser{}, nil
	}, StreamsPerConnection: 100})
	const callers = 8
	results := make(chan PeerStream, callers)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() { s, err := p.OpenStream(context.Background(), "host", "addr"); results <- s; errs <- err }()
	}
	<-started
	time.Sleep(10 * time.Millisecond)
	if got := dials.Load(); got != 1 {
		t.Fatalf("concurrent initial dials = %d, want 1", got)
	}
	close(release)
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if s := <-results; s != nil {
			_ = s.Close()
		}
	}
	_ = p.Close()
}

func TestPeerPoolConcurrentCapacityIsCapped(t *testing.T) {
	dial, dials, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, StreamsPerConnection: 1, MaxConnections: 2})
	const callers = 8
	streams := make(chan PeerStream, callers)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			s, err := p.OpenStream(context.Background(), "host", "addr")
			streams <- s
			errs <- err
		}()
	}
	// Two connections are sufficient for the first two streams; the remaining
	// callers must wait for capacity rather than causing unbounded dials.
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if s := <-streams; s != nil {
			_ = s.Close()
		}
	}
	if got := dials.Load(); got > 2 {
		t.Fatalf("concurrent dials = %d, want at most 2", got)
	}
	_ = p.Close()
}

func TestPeerPoolReplacementDuringDialDiscardsStaleConnection(t *testing.T) {
	oldStarted := make(chan struct{})
	oldRelease := make(chan struct{})
	var mu sync.Mutex
	var addrs []string
	p := NewPeerTransport(PeerPoolConfig{Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		if addr == "old" {
			close(oldStarted)
			<-oldRelease
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}, StreamsPerConnection: 1})
	first := make(chan error, 1)
	go func() {
		s, err := p.OpenStream(context.Background(), "host", "old")
		if s != nil {
			_ = s.Close()
		}
		first <- err
	}()
	<-oldStarted
	second, err := p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	close(oldRelease)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) < 2 || addrs[0] != "old" || addrs[1] != "new" {
		t.Fatalf("dial endpoints = %v, want old then new", addrs)
	}
}

type halfCloseStream struct {
	closedSend atomic.Bool
	canceled   atomic.Bool
}

func (s *halfCloseStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (s *halfCloseStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *halfCloseStream) CloseSend() error            { s.closedSend.Store(true); return nil }
func (s *halfCloseStream) Close() error                { return s.CloseSend() }

type halfCloseClient struct{ stream *halfCloseStream }

func (c *halfCloseClient) OpenPeerStream(context.Context) (PeerStream, error) {
	c.stream = &halfCloseStream{}
	return c.stream, nil
}

func TestPeerPoolPreservesHalfClose(t *testing.T) {
	client := new(halfCloseClient)
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return client, &countingCloser{}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if !client.stream.closedSend.Load() {
		t.Fatal("CloseSend was not propagated")
	}
	_ = s.Close()
	_ = p.Close()
}

func TestPeerPoolStreamFailureRemovesConnection(t *testing.T) {
	var client *testPeerClient
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		client = &testPeerClient{}
		return client, &countingCloser{}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	client.fail.Store(true)
	if _, err = s.Write([]byte("x")); err == nil {
		t.Fatal("Write succeeded, want transport failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client.fail.Store(false)
	s2, err := p.OpenStream(ctx, "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Close()
	_ = p.Close()
	if dials.Load() < 2 {
		t.Fatalf("dials after failure = %d, want reconnect", dials.Load())
	}
}

func TestPeerPoolDrainForceClosesActiveStream(t *testing.T) {
	closer := new(countingCloser)
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: 5 * time.Millisecond, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, closer, nil
	}})
	if _, err := p.OpenStream(context.Background(), "host", "addr"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_ = p.Close()
	if time.Since(started) > time.Second {
		t.Fatal("drain exceeded bounded deadline")
	}
	if closer.closed.Load() != 1 {
		t.Fatalf("transport close count = %d, want 1", closer.closed.Load())
	}
}

func TestPeerPoolDrainAllowsActiveStreamToCloseGracefully(t *testing.T) {
	closer := new(countingCloser)
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, closer, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = p.Close(); close(done) }()
	// Shutdown waits while the active stream is draining.
	select {
	case <-done:
		t.Fatal("shutdown completed before active stream closed")
	case <-time.After(5 * time.Millisecond):
	}
	_ = s.Close()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("graceful drain did not complete after stream close")
	}
	if got := closer.closed.Load(); got != 1 {
		t.Fatalf("transport close count = %d, want 1", got)
	}
}

type failingPeerClient struct{}

func (failingPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	return nil, errors.New("stream open failed")
}

type canceledOpenPeerClient struct{}

func (canceledOpenPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	return nil, context.Canceled
}

func TestPeerStreamOpenCallerCancellationKeepsConnectionUsable(t *testing.T) {
	var dials atomic.Int32
	closer := new(countingCloser)
	p := NewPeerTransport(PeerPoolConfig{
		Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
			dials.Add(1)
			return canceledOpenPeerClient{}, closer, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.OpenStream(ctx, "host", "addr"); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenStream error = %v, want context.Canceled", err)
	}
	// The canceled open must not retire/close the reusable transport.
	if got := closer.closed.Load(); got != 0 {
		t.Fatalf("transport close count after caller cancellation = %d, want 0", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial count after caller cancellation = %d, want 1", got)
	}
	_ = p.Close()
}

type countingCloser struct{ closed atomic.Int32 }

func (c *countingCloser) Close() error { c.closed.Add(1); return nil }

func TestPeerStreamOpenFailureClosesTransport(t *testing.T) {
	closer := new(countingCloser)
	p := NewPeerTransport(PeerPoolConfig{
		Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
			return failingPeerClient{}, closer, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.OpenStream(ctx, "host", "addr")
	if err == nil {
		t.Fatal("OpenStream succeeded, want stream-open failure")
	}
	if got := closer.closed.Load(); got != 1 {
		t.Fatalf("transport close count = %d, want 1", got)
	}
}

func TestPeerReconnectBackoffIsBoundedAndJittered(t *testing.T) {
	for failures := 1; failures <= 12; failures++ {
		got := peerReconnectBackoff(failures)
		base := peerReconnectBaseBackoff * time.Duration(1<<min(failures-1, 5))
		if base > peerReconnectMaxBackoff {
			base = peerReconnectMaxBackoff
		}
		if got < base/2 || got >= base {
			t.Fatalf("failures=%d: delay %v outside [%v, %v)", failures, got, base/2, base)
		}
	}
	seen := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		seen[peerReconnectBackoff(1)] = true
	}
	if len(seen) < 2 {
		t.Fatal("reconnect jitter did not vary delays")
	}
}

// opaqueStream models the generated bidi stream closely enough to catch
// lifecycle regressions: bytes are preserved, CloseSend is half-close only,
// and transport failure terminates reads without replaying data.
type opaqueStream struct {
	failed atomic.Bool
	closed atomic.Bool
	mu     sync.Mutex
	data   [][]byte
}

func (s *opaqueStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) == 0 {
		if s.failed.Load() {
			return 0, errors.New("transport failed")
		}
		if s.closed.Load() {
			return 0, io.EOF
		}
		return 0, io.EOF
	}
	b := s.data[0]
	n := copy(p, b)
	if n == len(b) {
		s.data = s.data[1:]
	} else {
		s.data[0] = b[n:]
	}
	return n, nil
}
func (s *opaqueStream) Write(p []byte) (int, error) {
	if s.failed.Load() || s.closed.Load() {
		return 0, errors.New("transport failed")
	}
	s.mu.Lock()
	s.data = append(s.data, append([]byte(nil), p...))
	s.mu.Unlock()
	return len(p), nil
}
func (s *opaqueStream) CloseSend() error { s.closed.Store(true); return nil }
func (s *opaqueStream) Close() error     { return s.CloseSend() }

type failingTransportClient struct {
	done    chan struct{}
	mu      sync.Mutex
	streams []*opaqueStream
}

func (c *failingTransportClient) OpenPeerStream(context.Context) (PeerStream, error) {
	s := &opaqueStream{}
	c.mu.Lock()
	c.streams = append(c.streams, s)
	c.mu.Unlock()
	return s, nil
}
func (c *failingTransportClient) Done() <-chan struct{} { return c.done }
func (c *failingTransportClient) fail() {
	c.mu.Lock()
	for _, s := range c.streams {
		s.failed.Store(true)
	}
	c.mu.Unlock()
	close(c.done)
}

func TestPeerPoolOpaqueStreamsAreIsolatedAndPreserveEOFAndCancellation(t *testing.T) {
	client := &failingTransportClient{done: make(chan struct{})}
	p := NewPeerTransport(PeerPoolConfig{StreamsPerConnection: 8, Dial: func(ctx context.Context, _ string, _ string) (PeerClient, io.Closer, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return client, &countingCloser{}, nil
	}})
	a, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	const payload = "\\x00\\xffopaque"
	if _, err := a.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("payload = %q, want %q", buf, payload)
	}
	if _, err := b.Write([]byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("late")); err == nil {
		t.Fatal("write after CloseSend succeeded")
	}
	if _, err := io.ReadAll(a); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.OpenStream(ctx, "other", "addr"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open error = %v", err)
	}
	_ = b.Close()
	_ = a.Close()
	_ = p.Close()
}

func TestPeerPoolFailureTerminatesActiveStreamsWithoutReplayAndRecovers(t *testing.T) {
	var mu sync.Mutex
	var clients []*failingTransportClient
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{StreamsPerConnection: 8, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		c := &failingTransportClient{done: make(chan struct{})}
		mu.Lock()
		clients = append(clients, c)
		mu.Unlock()
		dials.Add(1)
		return c, &countingCloser{}, nil
	}})
	s1, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	first := clients[0]
	mu.Unlock()
	first.fail()
	if _, err := s1.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed stream read succeeded")
	}
	if _, err := s2.Read(make([]byte, 1)); err == nil {
		t.Fatal("second failed stream read succeeded")
	}
	// The next stream must use repaired capacity, never replay either failed stream.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s3, err := p.OpenStream(ctx, "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if dials.Load() < 2 {
		t.Fatalf("dials after failure = %d, want at least 2", dials.Load())
	}
	_ = s1.Close()
	_ = s2.Close()
	_ = s3.Close()
	_ = p.Close()
}
