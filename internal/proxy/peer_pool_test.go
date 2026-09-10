package proxy

import (
	"context"
	"errors"
	"fmt"
	"github.com/superserve-ai/sandbox/internal/telemetry"
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

func TestPeerPoolRetainsBackoffAfterIdleDialFailure(t *testing.T) {
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
	if len(pp.hosts) != 1 {
		t.Fatalf("hosts after failed idle dial = %d, want 1", len(pp.hosts))
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
	pp := p.(*peerPool)
	pp.mu.Lock()
	pp.hosts["host"].replaceLocked("new")
	pp.mu.Unlock()
	close(oldRelease)
	second, err := p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
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

func TestPeerPoolFailedDialBackoffAppliesToNextCaller(t *testing.T) {
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		return nil, nil, errors.New("unavailable")
	}})
	defer p.Close()
	_, _ = p.OpenStream(context.Background(), "host", "addr")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.OpenStream(ctx, "host", "addr"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("retried before backoff: %d", dials.Load())
	}
}

func TestPeerPoolShutdownUsesOneDeadline(t *testing.T) {
	dial, _, conns := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, DrainTimeout: 100 * time.Millisecond})
	for _, host := range []string{"a", "b", "c", "d"} {
		if _, err := p.OpenStream(context.Background(), host, "old"); err != nil {
			t.Fatal(err)
		}
		if _, err := p.OpenStream(context.Background(), host, "new"); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	_ = p.Close()
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("shutdown took %v", elapsed)
	}
	for _, conn := range *conns {
		if conn.closed.Load() != 1 {
			t.Fatalf("connection closed %d times", conn.closed.Load())
		}
	}
}

func TestPeerPoolReplacementRemainsRegistered(t *testing.T) {
	dial, dials, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, MaxConnections: 1}).(*peerPool)
	defer p.Close()
	stream, err := p.OpenStream(context.Background(), "host", "old")
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	p.mu.Lock()
	original := p.hosts["host"]
	original.mu.Lock()
	original.openers++
	original.mu.Unlock()
	original.replaceLocked("new")
	p.mu.Unlock()
	original.evictIfEmpty()
	p.mu.Lock()
	same := p.hosts["host"] == original
	p.mu.Unlock()
	if !same {
		t.Fatal("pending replacement was evicted")
	}
	original.mu.Lock()
	original.openers--
	original.mu.Unlock()
	for i := 0; i < 10; i++ {
		stream, err = p.OpenStream(context.Background(), "host", "new")
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d", dials.Load())
	}
}

func TestPeerPoolCancelsObsoleteDials(t *testing.T) {
	for _, operation := range []string{"replace", "close"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(ctx context.Context, _, addr string) (PeerClient, io.Closer, error) {
				if addr == "old" {
					close(started)
					<-ctx.Done()
					return nil, nil, ctx.Err()
				}
				return &testPeerClient{}, &countingCloser{}, nil
			}})
			done := make(chan error, 1)
			go func() {
				s, err := p.OpenStream(context.Background(), "host", "old")
				if s != nil {
					_ = s.Close()
				}
				done <- err
			}()
			<-started
			if operation == "replace" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				s, err := p.OpenStream(ctx, "host", "new")
				if err != nil {
					t.Fatal(err)
				}
				_ = s.Close()
			} else {
				_ = p.Close()
			}
			select {
			case err := <-done:
				if operation == "replace" && err != nil {
					t.Fatal(err)
				}
				if operation == "close" && err == nil {
					t.Fatal("open succeeded after shutdown")
				}
			case <-time.After(time.Second):
				t.Fatal("obsolete dial was not canceled")
			}
			_ = p.Close()
		})
	}
}

type pendingPeerClient struct{ started, release chan struct{} }

func (c *pendingPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	close(c.started)
	<-c.release
	return &testPeerStream{}, nil
}
func TestPeerPoolReclaimsStalePendingOpen(t *testing.T) {
	old := &pendingPeerClient{started: make(chan struct{}), release: make(chan struct{})}
	oldCloser := &countingCloser{}
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
		if addr == "old" {
			return old, oldCloser, nil
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	defer p.Close()
	done := make(chan error, 1)
	go func() {
		s, err := p.OpenStream(context.Background(), "host", "old")
		if s != nil {
			if s.(*countedPeerStream).conn.closer == oldCloser {
				err = errors.New("pending open published the obsolete endpoint")
			}
			_ = s.Close()
		}
		done <- err
	}()
	<-old.started
	s, err := p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	close(old.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending open stuck")
	}
	if oldCloser.closed.Load() != 1 {
		t.Fatal("idle retired connection was not reclaimed")
	}
}

type eofWritePeerStream struct{ testPeerStream }

func (*eofWritePeerStream) Write([]byte) (int, error) { return 0, io.EOF }

type eofWritePeerClient struct{}

func (eofWritePeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	return &eofWritePeerStream{}, nil
}
func TestPeerPoolWriteEOFReleasesCapacity(t *testing.T) {
	var dials atomic.Int32
	closer := &countingCloser{}
	p := NewPeerTransport(PeerPoolConfig{MaxConnections: 1, StreamsPerConnection: 1, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		return eofWritePeerClient{}, closer, nil
	}})
	defer p.Close()
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("x")); err != io.EOF {
		t.Fatalf("write error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	next, err := p.OpenStream(ctx, "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	_ = next.Close()
	if dials.Load() != 1 || closer.closed.Load() != 0 {
		t.Fatal("EOF retired the shared connection")
	}
}

type peerEventRecorder struct{ events []telemetry.PeerEvent }

func (r *peerEventRecorder) RecordPeerEvent(_ context.Context, e telemetry.PeerEvent) {
	r.events = append(r.events, e)
}
func TestPeerPoolHandshakeOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, telemetry.ResultSuccess},
		{"failure", errors.New("unavailable"), telemetry.ResultError},
		{"canceled", context.Canceled, telemetry.ResultError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &peerEventRecorder{}
			p := NewPeerTransport(PeerPoolConfig{Telemetry: RecorderPeerTelemetry{Recorder: recorder}, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
				if tc.err != nil {
					return nil, nil, tc.err
				}
				return &testPeerClient{}, &countingCloser{}, nil
			}})
			s, _ := p.OpenStream(context.Background(), "host", "addr")
			if s != nil {
				_ = s.Close()
			}
			_ = p.Close()
			found := false
			for _, e := range recorder.events {
				if e.Kind == "handshake" {
					found = true
					if e.Result != tc.want {
						t.Fatalf("result = %s, want %s", e.Result, tc.want)
					}
				}
			}
			if !found {
				t.Fatal("missing handshake event")
			}
		})
	}
}

type drainStreamTelemetry struct {
	noopPeerTelemetry
	total    atomic.Int64
	negative atomic.Bool
	drained  chan struct{}
}

func (t *drainStreamTelemetry) PeerStream(delta int) {
	if t.total.Add(int64(delta)) < 0 {
		t.negative.Store(true)
	}
}
func (t *drainStreamTelemetry) PeerDrain(bool) { t.drained <- struct{}{} }

type mixedPendingPeerClient struct {
	published        int32
	calls            atomic.Int32
	started, release chan struct{}
}

func (c *mixedPendingPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	if c.calls.Add(1) > c.published {
		close(c.started)
		<-c.release
	}
	return &testPeerStream{}, nil
}
func TestPeerPoolForcedDrainCountsOnlyPublishedStreams(t *testing.T) {
	for _, operation := range []string{"shutdown", "replacement"} {
		for _, published := range []int32{0, 1} {
			t.Run(fmt.Sprintf("%s/published=%d", operation, published), func(t *testing.T) {
				client := &mixedPendingPeerClient{published: published, started: make(chan struct{}), release: make(chan struct{})}
				var release sync.Once
				defer release.Do(func() { close(client.release) })
				metrics := &drainStreamTelemetry{drained: make(chan struct{}, 16)}
				p := NewPeerTransport(PeerPoolConfig{DrainTimeout: 10 * time.Millisecond, Telemetry: metrics, Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
					if addr == "old" {
						return client, &countingCloser{}, nil
					}
					return &testPeerClient{}, &countingCloser{}, nil
				}})
				defer p.Close()
				var old PeerStream
				if published > 0 {
					var err error
					old, err = p.OpenStream(context.Background(), "host", "old")
					if err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan PeerStream, 1)
				go func() { s, _ := p.OpenStream(context.Background(), "host", "old"); done <- s }()
				<-client.started
				if got := metrics.total.Load(); got != int64(published) {
					t.Fatalf("before drain = %d", got)
				}
				var replacement PeerStream
				want := int64(0)
				if operation == "shutdown" {
					_ = p.Close()
				} else {
					var err error
					replacement, err = p.OpenStream(context.Background(), "host", "new")
					if err != nil {
						t.Fatal(err)
					}
					want = 1
				}
				select {
				case <-metrics.drained:
				case <-time.After(time.Second):
					t.Fatal("drain did not complete")
				}

				if got := metrics.total.Load(); got != want {
					t.Fatalf("after drain = %d, want %d", got, want)
				}
				if old != nil {
					_ = old.Close()
				}
				if replacement != nil {
					_ = replacement.Close()
					_ = p.Close()
				}
				release.Do(func() { close(client.release) })
				select {
				case late := <-done:
					if late != nil {
						_ = late.Close()
					}
				case <-time.After(time.Second):
					t.Fatal("pending open did not finish")
				}
				if got := metrics.total.Load(); got != 0 || metrics.negative.Load() {
					t.Fatalf("unbalanced stream metric: total=%d, negative=%v", got, metrics.negative.Load())
				}
			})
		}
	}
}

func waitPeerWaiter(t *testing.T, h *hostPool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		waiting := h.changed != nil
		h.mu.Unlock()
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("caller did not subscribe to host changes")
}

func TestPeerPoolWakesWaiters(t *testing.T) {
	for _, state := range []string{"backoff", "saturated"} {
		for _, operation := range []string{"close", "replace", "cancel", "release"} {
			if state == "backoff" && operation == "release" {
				continue
			}
			t.Run(state+"/"+operation, func(t *testing.T) {
				dial, dials, _ := testDialer()
				p := NewPeerTransport(PeerPoolConfig{Dial: dial, MaxConnections: 1, StreamsPerConnection: 1, DrainTimeout: 10 * time.Millisecond}).(*peerPool)
				defer p.Close()
				first, err := p.OpenStream(context.Background(), "host", "old")
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				h := p.hosts["host"]
				if state == "backoff" {
					h.markFailed(first.(*countedPeerStream).conn)
					h.mu.Lock()
					h.retryAt = time.Now().Add(time.Hour)
					h.mu.Unlock()
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					s, err := p.OpenStream(ctx, "host", "old")
					if s != nil {
						_ = s.Close()
					}
					done <- err
				}()
				waitPeerWaiter(t, h)
				select {
				case err := <-done:
					t.Fatalf("waiter returned before state changed: %v", err)
				default:
				}
				switch operation {
				case "close":
					_ = p.Close()
				case "replace":
					p.mu.Lock()
					h.replaceLocked("new")
					p.mu.Unlock()
				case "cancel":
					cancel()
				case "release":
					_ = first.Close()
				}
				select {
				case err := <-done:
					if (operation == "close" || operation == "cancel") != (err != nil) {
						t.Fatalf("unexpected waiter result: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("state change did not wake caller")
				}
				if operation == "release" && dials.Load() != 1 {
					t.Fatal("released capacity was not reused")
				}
			})
		}
	}
}

func TestPeerPoolAsyncFailureReleasesIdleStreamAccounting(t *testing.T) {
	client := &failingTransportClient{done: make(chan struct{})}
	metrics := &drainStreamTelemetry{drained: make(chan struct{}, 16)}
	p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return client, &countingCloser{}, nil
	}})
	defer p.Close()
	var streams []PeerStream
	for i := 0; i < 3; i++ {
		s, err := p.OpenStream(context.Background(), "host", "addr")
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, s)
	}
	client.fail()
	deadline := time.Now().Add(time.Second)
	for metrics.total.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := metrics.total.Load(); got != 0 {
		t.Fatalf("failed idle streams still counted: %d", got)
	}
	c := streams[0].(*countedPeerStream).conn
	c.mu.Lock()
	active, published, registered := c.active, c.published, len(c.streams)
	c.mu.Unlock()
	if active != 0 || published != 0 || registered != 0 {
		t.Fatalf("remaining accounting: active=%d published=%d registered=%d", active, published, registered)
	}
	for _, s := range streams {
		_ = s.Close()
	}
	if metrics.total.Load() != 0 || metrics.negative.Load() {
		t.Fatal("late closes double-decremented stream metrics")
	}
}
