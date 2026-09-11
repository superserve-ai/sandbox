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
	waitPeerCondition(t, func() bool { return closer.closed.Load() == 1 })
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
		waitPeerCondition(t, func() bool { return conn.closed.Load() == 1 })
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

type peerEventRecorder struct {
	mu     sync.Mutex
	events []telemetry.PeerEvent
}

func (r *peerEventRecorder) RecordPeerEvent(_ context.Context, e telemetry.PeerEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
			waitPeerCondition(t, func() bool {
				recorder.mu.Lock()
				defer recorder.mu.Unlock()
				for _, e := range recorder.events {
					if e.Kind == "handshake" {
						return true
					}
				}
				return false
			})
			found := false
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
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
				waitPeerStreamTelemetry(t, old)
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

				waitPeerStreamTelemetry(t, old)
				waitPeerStreamTelemetry(t, replacement)
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
						waitPeerStreamTelemetry(t, late)
					}
				case <-time.After(time.Second):
					t.Fatal("pending open did not finish")
				}
				waitPeerStreamTelemetry(t, old)
				waitPeerStreamTelemetry(t, replacement)
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
	waitPeerStreamTelemetry(t, streams[0])
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

type peerShutdownTelemetry struct {
	noopPeerTelemetry
	failures         atomic.Int32
	drains           atomic.Int32
	closing, release chan struct{}
}

func (t *peerShutdownTelemetry) PeerFailure()   { t.failures.Add(1) }
func (t *peerShutdownTelemetry) PeerDrain(bool) { t.drains.Add(1) }
func (t *peerShutdownTelemetry) PeerStream(delta int) {
	if delta < 0 && t.closing != nil {
		close(t.closing)
		<-t.release
	}
}

func TestPeerPoolLastCloseClaimsDrainBeforeDeadline(t *testing.T) {
	metrics := &peerShutdownTelemetry{closing: make(chan struct{}), release: make(chan struct{})}
	dial, _, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, Telemetry: metrics, DrainTimeout: 10 * time.Millisecond}).(*peerPool)
	defer p.Close()
	s, err := p.OpenStream(context.Background(), "host", "old")
	if err != nil {
		t.Fatal(err)
	}
	waitPeerStreamTelemetry(t, s)
	h := p.hosts["host"]
	p.mu.Lock()
	h.replaceLocked("new")
	p.mu.Unlock()
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	<-metrics.closing
	// Hold stream cleanup past the timer deadline, after accounting is updated.
	time.Sleep(30 * time.Millisecond)
	close(metrics.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream cleanup stuck")
	}
	waitPeerCondition(t, func() bool { return metrics.drains.Load() == 1 })
	if got := metrics.drains.Load(); got != 1 {
		t.Fatalf("drain events = %d, want 1", got)
	}
}

type callbackPeerCloser struct{ close func() }

func (c callbackPeerCloser) Close() error { c.close(); return nil }

func TestPeerPoolIntentionalCloseDoesNotRecordFailure(t *testing.T) {
	metrics := &peerShutdownTelemetry{}
	var onClose func()
	p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, callbackPeerCloser{close: func() { onClose() }}, nil
	}}).(*peerPool)
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	cs := s.(*countedPeerStream)
	onClose = func() { cs.host.markFailed(cs.conn) }
	_ = s.Close()
	done := make(chan struct{})
	go func() { _ = p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("intentional close was handled as transport failure")
	}
	if metrics.failures.Load() != 0 {
		t.Fatal("intentional close recorded a failure")
	}
	cs.host.mu.Lock()
	failures := cs.host.failures
	cs.host.mu.Unlock()
	if failures != 0 {
		t.Fatal("intentional close scheduled reconnect backoff")
	}
}

func TestPeerPoolShutdownClosesTransportDuringClaimedCleanup(t *testing.T) {
	metrics := &peerShutdownTelemetry{closing: make(chan struct{}), release: make(chan struct{})}
	closer := &countingCloser{}
	p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, closer, nil
	}}).(*peerPool)
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	waitPeerStreamTelemetry(t, s)
	cs := s.(*countedPeerStream)
	cs.conn.mu.Lock()
	cs.conn.draining = true
	cs.conn.mu.Unlock()
	streamDone := make(chan struct{})
	go func() { _ = s.Close(); close(streamDone) }()
	<-metrics.closing
	shutdownDone := make(chan struct{})
	go func() { _ = p.Close(); close(shutdownDone) }()
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		close(metrics.release)
		t.Fatal("shutdown waited for blocked stream telemetry")
	}
	closed := closer.closed.Load()
	close(metrics.release)
	<-streamDone
	if closed != 1 {
		t.Fatalf("transport close count at shutdown return = %d, want 1", closed)
	}
	waitPeerCondition(t, func() bool { return metrics.drains.Load() == 1 })
	if closer.closed.Load() != 1 || metrics.drains.Load() != 1 {
		t.Fatal("cleanup was performed more than once")
	}
}

func TestPeerPoolObsoleteEvictionPreservesFreshRetryState(t *testing.T) {
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return nil, nil, errors.New("unavailable")
	}}).(*peerPool)
	defer p.Close()
	_, _ = p.OpenStream(context.Background(), "host", "addr")
	h := p.hosts["host"]
	h.mu.Lock()
	oldGeneration := h.evictionGeneration
	h.eviction.Stop()
	h.retryAt = time.Now().Add(time.Hour)
	h.mu.Unlock()
	// A new failure reschedules eviction while the old callback is queued.
	h.evictIfEmpty()
	h.mu.Lock()
	currentGeneration := h.evictionGeneration
	h.eviction.Stop()
	h.mu.Unlock()
	h.evictIdle(oldGeneration)
	if p.hosts["host"] != h {
		t.Fatal("obsolete eviction removed fresh retry state")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.OpenStream(ctx, "host", "addr"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fresh backoff was bypassed: %v", err)
	}
	// The open above reschedules again; only its current callback may evict.
	h.mu.Lock()
	currentGeneration = h.evictionGeneration
	h.eviction.Stop()
	h.mu.Unlock()
	h.evictIdle(currentGeneration)
	if p.hosts["host"] != nil {
		t.Fatal("current idle eviction did not remove host")
	}
}

type peerConnectionTelemetry struct {
	noopPeerTelemetry
	total atomic.Int32
}

func (t *peerConnectionTelemetry) PeerConnection(delta int) { t.total.Add(int32(delta)) }

func TestPeerPoolCountsRetiredConnectionsUntilDrainCompletes(t *testing.T) {
	dial, _, conns := testDialer()
	metrics := &peerConnectionTelemetry{}
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, Telemetry: metrics})
	defer p.Close()
	old, err := p.OpenStream(context.Background(), "host", "old")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	replacement, err := p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	waitPeerConnectionTelemetry(t, old)
	waitPeerConnectionTelemetry(t, replacement)
	if got := metrics.total.Load(); got != 2 {
		t.Fatalf("overlapping connections = %d, want 2", got)
	}
	if (*conns)[0].closed.Load() != 0 {
		t.Fatal("old connection closed before drain")
	}
	_ = old.Close()
	waitPeerConnectionTelemetry(t, old)
	if got := metrics.total.Load(); got != 1 {
		t.Fatalf("connections after old drain = %d, want 1", got)
	}
	if (*conns)[0].closed.Load() != 1 {
		t.Fatal("old transport was not closed")
	}
	_ = replacement.Close()
	_ = p.Close()
	waitPeerConnectionTelemetry(t, replacement)
	if got := metrics.total.Load(); got != 0 {
		t.Fatalf("connections after shutdown = %d, want 0", got)
	}
}

type selfClosingPeerClient struct {
	testPeerClient
	closed atomic.Int32
}

func (c *selfClosingPeerClient) Close() error { c.closed.Add(1); return nil }

func TestPeerPoolClosesClientWithoutSeparateCloser(t *testing.T) {
	for _, operation := range []string{"shutdown", "replacement", "failure"} {
		t.Run(operation, func(t *testing.T) {
			client := &selfClosingPeerClient{}
			p := NewPeerTransport(PeerPoolConfig{Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
				if addr == "old" {
					return client, nil, nil
				}
				return &testPeerClient{}, &countingCloser{}, nil
			}}).(*peerPool)
			defer p.Close()
			s, err := p.OpenStream(context.Background(), "host", "old")
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			switch operation {
			case "shutdown":
				_ = p.Close()
			case "replacement":
				next, err := p.OpenStream(context.Background(), "host", "new")
				if err != nil {
					t.Fatal(err)
				}
				_ = next.Close()
			case "failure":
				cs := s.(*countedPeerStream)
				cs.host.markFailed(cs.conn)
			}
			_ = p.Close()
			if got := client.closed.Load(); got != 1 {
				t.Fatalf("client closed %d times, want 1", got)
			}
		})
	}
}

func TestPeerPoolShutdownWaitsForDrainNotification(t *testing.T) {
	dial, _, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, DrainTimeout: time.Second}).(*peerPool)
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	h := p.hosts["host"]
	done := make(chan struct{})
	go func() { _ = p.Close(); close(done) }()
	waitPeerWaiter(t, h)
	select {
	case <-done:
		t.Fatal("shutdown did not wait for active stream")
	default:
	}
	_ = s.Close()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("stream completion did not wake shutdown")
	}
}

func TestPeerPoolConcurrentCloseWaitsForShutdown(t *testing.T) {
	dial, _, _ := testDialer()
	p := NewPeerTransport(PeerPoolConfig{Dial: dial, DrainTimeout: time.Second}).(*peerPool)
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	h := p.hosts["host"]
	first, second := make(chan struct{}), make(chan struct{})
	go func() { _ = p.Close(); close(first) }()
	waitPeerWaiter(t, h)
	go func() { _ = p.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("concurrent Close returned before drain completed")
	case <-time.After(20 * time.Millisecond):
	}
	_ = s.Close()
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not finish after drain")
		}
	}
	_ = p.Close()
}

func TestPeerPoolSlowIdleCloseDoesNotBlockOpens(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p := NewPeerTransport(PeerPoolConfig{Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
		if addr == "old" {
			return &testPeerClient{}, callbackPeerCloser{close: func() { close(started); <-release }}, nil
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "old")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	done := make(chan error, 2)
	open := func(host string) {
		s, err := p.OpenStream(context.Background(), host, "new")
		if s != nil {
			_ = s.Close()
		}
		done <- err
	}
	go open("host")
	<-started
	go open("unrelated")
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("slow retired transport blocked opens")
		}
	}
	once.Do(func() { close(release) })
	_ = p.Close()
}

type contextPoolPeerStream struct {
	testPeerStream
	ctx context.Context
}
type cancelablePendingPeerClient struct {
	calls   atomic.Int32
	started chan struct{}
}

func (c *cancelablePendingPeerClient) OpenPeerStream(ctx context.Context) (PeerStream, error) {
	if c.calls.Add(1) == 1 {
		return &contextPoolPeerStream{ctx: ctx}, nil
	}
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPeerPoolCancelsRetiredPendingStreamOpens(t *testing.T) {
	for _, operation := range []string{"replacement", "shutdown"} {
		t.Run(operation, func(t *testing.T) {
			client := &cancelablePendingPeerClient{started: make(chan struct{})}
			p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
				if addr == "old" {
					return client, &countingCloser{}, nil
				}
				return &testPeerClient{}, &countingCloser{}, nil
			}})
			defer p.Close()
			established, err := p.OpenStream(context.Background(), "host", "old")
			if err != nil {
				t.Fatal(err)
			}
			defer established.Close()
			streamCtx := established.(*countedPeerStream).PeerStream.(*contextPoolPeerStream).ctx
			done := make(chan error, 1)
			go func() {
				s, err := p.OpenStream(context.Background(), "host", "old")
				if s != nil {
					_ = s.Close()
				}
				done <- err
			}()
			<-client.started
			if operation == "replacement" {
				s, err := p.OpenStream(context.Background(), "host", "new")
				if err != nil {
					t.Fatal(err)
				}
				_ = s.Close()
				if streamCtx.Err() != nil {
					t.Fatal("replacement canceled an established stream")
				}
			} else {
				_ = established.Close()
				_ = p.Close()
			}
			select {
			case err := <-done:
				if (operation == "shutdown") != (err != nil) {
					t.Fatalf("unexpected open result: %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("pending stream open was not canceled")
			}
			_ = established.Close()
			if streamCtx.Err() == nil {
				t.Fatal("stream close did not cancel its context")
			}
		})
	}
}

type blockedPublicationTelemetry struct {
	noopPeerTelemetry
	started, release chan struct{}
	total            atomic.Int32
	negative         atomic.Bool
}

func (t *blockedPublicationTelemetry) PeerStream(delta int) {
	if delta > 0 {
		close(t.started)
		<-t.release
	}
	if t.total.Add(int32(delta)) < 0 {
		t.negative.Store(true)
	}
}

func TestPeerPoolBlockedPublicationTelemetryDoesNotBlockShutdown(t *testing.T) {
	metrics := &blockedPublicationTelemetry{started: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(metrics.release) })
	closer := &countingCloser{}
	p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, DrainTimeout: 10 * time.Millisecond, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, closer, nil
	}})
	opened := make(chan PeerStream, 1)
	go func() { s, _ := p.OpenStream(context.Background(), "host", "addr"); opened <- s }()
	<-metrics.started
	var stream PeerStream
	select {
	case stream = <-opened:
	case <-time.After(time.Second):
		t.Fatal("telemetry blocked stream publication")
	}
	for i := 0; i < 20; i++ {
		next, err := p.OpenStream(context.Background(), "host", "addr")
		if err != nil {
			t.Fatal(err)
		}
		_ = next.Close()
	}
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("telemetry callback blocked shutdown locks")
	}
	waitPeerCondition(t, func() bool { return closer.closed.Load() == 1 })
	if closer.closed.Load() != 1 {
		t.Fatal("shutdown did not close transport")
	}
	once.Do(func() { close(metrics.release) })
	if stream != nil {
		_ = stream.Close()
	}
	waitPeerStreamTelemetry(t, stream)
	if metrics.total.Load() != 0 || metrics.negative.Load() {
		t.Fatal("stream telemetry was unbalanced or emitted out of order")
	}
}

type blockedDialTelemetry struct {
	noopPeerTelemetry
	kind             string
	started, release chan struct{}
	total            atomic.Int32
	blockOnce        sync.Once
}

func (t *blockedDialTelemetry) block(kind string) {
	if kind == t.kind {
		t.blockOnce.Do(func() { close(t.started); <-t.release })
	}
}
func (t *blockedDialTelemetry) PeerHandshake(time.Duration, string) { t.block("handshake") }
func (t *blockedDialTelemetry) PeerConnection(delta int) {
	if delta > 0 {
		t.block("connection")
	}
	t.total.Add(int32(delta))
}
func (t *blockedDialTelemetry) PeerReconnect(result string) {
	if result == telemetry.ResultSuccess {
		t.block("reconnect")
	}
}

func TestPeerPoolDialTelemetryDoesNotBlockOpenOrShutdown(t *testing.T) {
	for _, kind := range []string{"handshake", "connection", "reconnect"} {
		t.Run(kind, func(t *testing.T) {
			metrics := &blockedDialTelemetry{kind: kind, started: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			defer once.Do(func() { close(metrics.release) })
			closer := &countingCloser{}
			p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, DrainTimeout: 10 * time.Millisecond, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
				return &testPeerClient{}, closer, nil
			}})
			if kind == "reconnect" {
				pool := p.(*peerPool)
				pool.hosts["host"] = &hostPool{parent: pool, host: "host", addr: "addr", failures: 1}
			}
			opened := make(chan PeerStream, 1)
			go func() {
				s, _ := p.OpenStream(context.Background(), "host", "addr")
				if s != nil {
					_ = s.Close()
				}
				opened <- s
			}()
			<-metrics.started
			var stream PeerStream
			select {
			case stream = <-opened:
				if stream == nil {
					t.Fatal("open failed")
				}
			case <-time.After(time.Second):
				t.Fatal("dial telemetry blocked opening request")
			}
			closed := make(chan struct{})
			go func() { _ = p.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("dial telemetry held shutdown locks")
			}
			if closer.closed.Load() != 1 {
				t.Fatal("transport not closed")
			}
			once.Do(func() { close(metrics.release) })
			waitPeerConnectionTelemetry(t, stream)
			if metrics.total.Load() != 0 {
				t.Fatal("connection telemetry unbalanced")
			}
		})
	}
}

type retiringFailurePeerClient struct {
	failingTransportClient
	retiring chan struct{}
}

func (c *retiringFailurePeerClient) Retiring() <-chan struct{} { return c.retiring }

func TestPeerPoolTerminalFailurePrecedesRetirement(t *testing.T) {
	client := &retiringFailurePeerClient{failingTransportClient: failingTransportClient{done: make(chan struct{})}, retiring: make(chan struct{})}
	metrics := &transportFailureTelemetry{failed: make(chan struct{}, 2)}
	p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return client, &countingCloser{}, nil
	}}).(*peerPool)
	defer p.Close()
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cs := s.(*countedPeerStream)
	cs.host.mu.Lock()
	close(client.done)
	close(client.retiring)
	cs.host.mu.Unlock()
	cs.host.retire(cs.conn)
	select {
	case <-metrics.failed:
	case <-time.After(time.Second):
		t.Fatal("terminal failure was treated as graceful retirement")
	}
	cs.host.mu.Lock()
	failures, retryAt := cs.host.failures, cs.host.retryAt
	cs.host.mu.Unlock()
	if failures != 1 || retryAt.IsZero() {
		t.Fatal("terminal failure did not establish reconnect backoff")
	}
}

func TestPeerPoolShutdownJoinsFailedConnectionCleanup(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, callbackPeerCloser{close: func() { close(started); <-release }}, nil
	}}).(*peerPool)
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	cs := s.(*countedPeerStream)
	failed := make(chan struct{})
	go func() { cs.host.markFailed(cs.conn); close(failed) }()
	<-started
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("shutdown forgot connection whose closer was still running")
	case <-time.After(20 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	for _, done := range []chan struct{}{failed, closed} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not finish")
		}
	}
	_ = s.Close()
}

func waitPeerStreamTelemetry(t *testing.T, stream PeerStream) {
	t.Helper()
	if stream == nil {
		return
	}
	metric := &stream.(*countedPeerStream).conn.streamMetrics
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		metric.mu.Lock()
		done := !metric.emitting
		metric.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stream telemetry did not finish")
}

type retirementOnlyPeerClient struct {
	testPeerClient
	retiring chan struct{}
}

func (c *retirementOnlyPeerClient) Retiring() <-chan struct{} { return c.retiring }

func TestPeerPoolWatchesRetirementWithoutFailureSignal(t *testing.T) {
	client := &retirementOnlyPeerClient{retiring: make(chan struct{})}
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{MaxConnections: 1, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		if dials.Add(1) == 1 {
			return client, &countingCloser{}, nil
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	defer p.Close()
	old, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	c := old.(*countedPeerStream).conn
	close(client.retiring)
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		draining := c.draining
		c.mu.Unlock()
		if draining {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retirement-only client was not retired")
		}
		time.Sleep(time.Millisecond)
	}
	next, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.(*countedPeerStream).conn == c {
		t.Fatal("retired connection was reused")
	}
	if _, err := old.Write([]byte("draining")); err != nil {
		t.Fatal("retirement canceled established stream")
	}
}

func waitPeerCondition(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not complete")
}
func waitPeerConnectionTelemetry(t *testing.T, stream PeerStream) {
	t.Helper()
	metric := &stream.(*countedPeerStream).conn.connectionMetrics
	waitPeerCondition(t, func() bool {
		metric.mu.Lock()
		defer metric.mu.Unlock()
		return !metric.emitting
	})
}

func TestPeerPoolStaleDialCloserDoesNotBlockReplacement(t *testing.T) {
	started, closing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p := NewPeerTransport(PeerPoolConfig{Dial: func(ctx context.Context, _, addr string) (PeerClient, io.Closer, error) {
		if addr == "old" {
			close(started)
			<-ctx.Done()
			return &testPeerClient{}, callbackPeerCloser{close: func() { close(closing); <-release }}, nil
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	done := make(chan error, 2)
	open := func(addr string) {
		s, err := p.OpenStream(context.Background(), "host", addr)
		if s != nil {
			_ = s.Close()
		}
		done <- err
	}
	go open("old")
	<-started
	go open("new")
	<-closing
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale dial cleanup blocked replacement")
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("original opener did not complete")
	}
	_ = p.Close()
}

func TestPeerPoolDialTelemetryQueueIsBounded(t *testing.T) {
	metrics := &blockedDialTelemetry{kind: "handshake", started: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(metrics.release) })
	var queue peerObservations
	queue.record(metrics, peerObservation{result: telemetry.ResultSuccess})
	<-metrics.started
	for i := 0; i < 1000; i++ {
		queue.record(metrics, peerObservation{})
	}
	queue.mu.Lock()
	pending := len(queue.pending)
	queue.mu.Unlock()
	if pending != 64 {
		t.Fatalf("pending = %d, want 64", pending)
	}
	once.Do(func() { close(metrics.release) })
	waitPeerCondition(t, func() bool {
		queue.mu.Lock()
		defer queue.mu.Unlock()
		return !queue.emitting
	})
}

type blockedDrainTelemetry struct {
	noopPeerTelemetry
	started, release chan struct{}
}

func (t *blockedDrainTelemetry) PeerDrain(bool) { close(t.started); <-t.release }

func TestPeerPoolBlockedDrainTelemetryDoesNotBlockShutdown(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "active"}[active], func(t *testing.T) {
			metrics := &blockedDrainTelemetry{started: make(chan struct{}), release: make(chan struct{})}
			defer close(metrics.release)
			closer := &countingCloser{}
			p := NewPeerTransport(PeerPoolConfig{Telemetry: metrics, DrainTimeout: 10 * time.Millisecond, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
				return &testPeerClient{}, closer, nil
			}})
			s, err := p.OpenStream(context.Background(), "host", "addr")
			if err != nil {
				t.Fatal(err)
			}
			if !active {
				_ = s.Close()
			}
			done := make(chan struct{})
			go func() { _ = p.Close(); close(done) }()
			select {
			case <-metrics.started:
			case <-time.After(time.Second):
				t.Fatal("drain callback did not start")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("drain telemetry blocked shutdown")
			}
			if closer.closed.Load() != 1 {
				t.Fatal("transport was not closed exactly once")
			}
			_ = s.Close()
		})
	}
}

type failedOpenPeerClient struct{ calls atomic.Int32 }

func (c *failedOpenPeerClient) OpenPeerStream(context.Context) (PeerStream, error) {
	c.calls.Add(1)
	return nil, errors.New("transport failed")
}
func TestPeerPoolFailedOpenRetiresBeforeSlowClose(t *testing.T) {
	closing, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	client := &failedOpenPeerClient{}
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{MaxConnections: 1, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		if dials.Add(1) == 1 {
			return client, callbackPeerCloser{close: func() { close(closing); <-release }}, nil
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan error, 1)
	go func() {
		s, err := p.OpenStream(ctx, "host", "addr")
		if s != nil {
			_ = s.Close()
		}
		opened <- err
	}()
	<-closing
	cancel()
	select {
	case err := <-opened:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("open returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed transport cleanup blocked cancellation")
	}
	replacement := make(chan error, 1)
	go func() {
		s, err := p.OpenStream(context.Background(), "host", "addr")
		if s != nil {
			_ = s.Close()
		}
		replacement <- err
	}()
	select {
	case err := <-replacement:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed transport cleanup blocked replacement")
	}
	if client.calls.Load() != 1 {
		t.Fatal("failed connection was reused")
	}
	once.Do(func() { close(release) })
	_ = p.Close()
}

func TestPeerPoolReconnectObservationsExcludeOrdinaryDials(t *testing.T) {
	recorder := &peerEventRecorder{}
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{Telemetry: RecorderPeerTelemetry{Recorder: recorder}, StreamsPerConnection: 1, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		if dials.Add(1) <= 2 {
			return nil, nil, errors.New("offline")
		}
		return &testPeerClient{}, &countingCloser{}, nil
	}}).(*peerPool)
	defer p.Close()
	for i := 0; i < 2; i++ {
		if _, err := p.OpenStream(context.Background(), "host", "addr"); err == nil {
			t.Fatal("dial succeeded")
		}
	}
	first, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	cold, err := p.OpenStream(context.Background(), "other", "addr")
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	other := cold.(*countedPeerStream).host
	waitPeerCondition(t, func() bool {
		other.observations.mu.Lock()
		defer other.observations.mu.Unlock()
		return !other.observations.emitting
	})
	h := first.(*countedPeerStream).host
	waitPeerCondition(t, func() bool {
		h.observations.mu.Lock()
		defer h.observations.mu.Unlock()
		return !h.observations.emitting
	})
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	var results []string
	for _, e := range recorder.events {
		if e.Kind == "reconnect" {
			results = append(results, e.Result)
		}
	}
	if fmt.Sprint(results) != fmt.Sprint([]string{telemetry.ResultError, telemetry.ResultSuccess}) {
		t.Fatalf("reconnects=%v", results)
	}
}

func TestPeerPoolShutdownBoundsBlockedCloser(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: 20 * time.Millisecond, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return &testPeerClient{}, callbackPeerCloser{close: func() { close(started); <-release }}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	done := make(chan struct{})
	go func() { _ = p.Close(); close(done) }()
	<-started
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on closer")
	}
}

type failingIOPeer struct{ testPeerStream }

func (*failingIOPeer) Read([]byte) (int, error)  { return 0, errors.New("transport failed") }
func (*failingIOPeer) Write([]byte) (int, error) { return 0, errors.New("transport failed") }

type fixedPeerClient struct{ stream PeerStream }

func (c fixedPeerClient) OpenPeerStream(context.Context) (PeerStream, error) { return c.stream, nil }
func TestPeerPoolEstablishedFailureReturnsBeforeCleanup(t *testing.T) {
	for _, op := range []string{"read", "write"} {
		t.Run(op, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
				return fixedPeerClient{&failingIOPeer{}}, callbackPeerCloser{close: func() { close(started); <-release }}, nil
			}})
			s, err := p.OpenStream(context.Background(), "host", "addr")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if op == "read" {
					_, err = s.Read(make([]byte, 1))
				} else {
					_, err = s.Write([]byte("x"))
				}
				done <- err
			}()
			<-started
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("missing error")
				}
			case <-time.After(time.Second):
				t.Fatal("stream operation blocked on cleanup")
			}
			cs := s.(*countedPeerStream)
			cs.host.mu.Lock()
			remaining := len(cs.host.conns)
			cs.host.mu.Unlock()
			if remaining != 0 {
				t.Fatal("failed connection still selectable")
			}
			once.Do(func() { close(release) })
			_ = p.Close()
		})
	}
}
func TestPeerPoolSaturatedBurstMakesProgress(t *testing.T) {
	var dials atomic.Int32
	p := NewPeerTransport(PeerPoolConfig{MaxConnections: 4, StreamsPerConnection: 8, Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		dials.Add(1)
		return &testPeerClient{}, &countingCloser{}, nil
	}})
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	done := make(chan error, 128)
	for i := 0; i < 128; i++ {
		go func() {
			<-start
			s, err := p.OpenStream(ctx, "host", "addr")
			if err == nil {
				time.Sleep(5 * time.Millisecond)
				_ = s.Close()
			}
			done <- err
		}()
	}
	close(start)
	for i := 0; i < 128; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got < 1 || got > 4 {
		t.Fatalf("dials=%d", got)
	}
}

type singleClosePeerStream struct {
	failingIOPeer
	calls            atomic.Int32
	started, release chan struct{}
	err              error
}

func (s *singleClosePeerStream) Close() error {
	if s.calls.Add(1) == 1 {
		close(s.started)
	}
	<-s.release
	return s.err
}
func TestPeerPoolFailedStreamClosesPhysicallyOnce(t *testing.T) {
	raw := &singleClosePeerStream{started: make(chan struct{}), release: make(chan struct{}), err: errors.New("close result")}
	var once sync.Once
	defer once.Do(func() { close(raw.release) })
	p := NewPeerTransport(PeerPoolConfig{Dial: func(context.Context, string, string) (PeerClient, io.Closer, error) {
		return fixedPeerClient{raw}, &countingCloser{}, nil
	}})
	s, err := p.OpenStream(context.Background(), "host", "addr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("missing transport error")
	}
	<-raw.started
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { results <- s.Close() }()
	}
	once.Do(func() { close(raw.release) })
	for i := 0; i < 16; i++ {
		if err := <-results; err != raw.err {
			t.Fatalf("close error=%v", err)
		}
	}
	_ = p.Close()
	if raw.calls.Load() != 1 {
		t.Fatalf("physical closes=%d", raw.calls.Load())
	}
}

type lateCanceledPeerClient struct {
	started chan struct{}
	stream  PeerStream
}

func (c lateCanceledPeerClient) OpenPeerStream(ctx context.Context) (PeerStream, error) {
	close(c.started)
	<-ctx.Done()
	return c.stream, nil
}

type heldClosePeerStream struct {
	testPeerStream
	started, release, closed chan struct{}
}

func (s *heldClosePeerStream) Close() error {
	close(s.started)
	<-s.release
	_ = s.testPeerStream.Close()
	close(s.closed)
	return nil
}
func TestPeerPoolStaleOpenCleanupDoesNotBlockRetry(t *testing.T) {
	raw := &heldClosePeerStream{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	started, closing, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var streamOnce, transportOnce sync.Once
	defer streamOnce.Do(func() { close(raw.release) })
	defer transportOnce.Do(func() { close(release) })
	p := NewPeerTransport(PeerPoolConfig{DrainTimeout: time.Second, Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
		if addr == "old" {
			return lateCanceledPeerClient{started, raw}, callbackPeerCloser{close: func() { <-raw.closed; close(closing); <-release }}, nil
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
	replacement, err := p.OpenStream(context.Background(), "host", "new")
	if err != nil {
		t.Fatal(err)
	}
	_ = replacement.Close()
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("stale stream was not closed before connection cleanup")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale cleanup blocked original request retry")
	}
	streamOnce.Do(func() { close(raw.release) })
	select {
	case <-closing:
	case <-time.After(time.Second):
		t.Fatal("transport closer did not follow stream close")
	}
	transportOnce.Do(func() { close(release) })
	_ = p.Close()
}

type contextRecordingPeerClient struct{ streams []*contextPoolPeerStream }

func (c *contextRecordingPeerClient) OpenPeerStream(ctx context.Context) (PeerStream, error) {
	s := &contextPoolPeerStream{ctx: ctx}
	c.streams = append(c.streams, s)
	return s, nil
}
func TestPeerPoolForcedDrainClosesCustomStreams(t *testing.T) {
	for _, operation := range []string{"shutdown", "replacement"} {
		t.Run(operation, func(t *testing.T) {
			client := &contextRecordingPeerClient{}
			closer := &countingCloser{}
			p := NewPeerTransport(PeerPoolConfig{DrainTimeout: 10 * time.Millisecond, Dial: func(_ context.Context, _, addr string) (PeerClient, io.Closer, error) {
				if addr == "old" {
					return client, closer, nil
				}
				return &testPeerClient{}, &countingCloser{}, nil
			}})
			var streams []PeerStream
			for i := 0; i < 3; i++ {
				s, err := p.OpenStream(context.Background(), "host", "old")
				if err != nil {
					t.Fatal(err)
				}
				streams = append(streams, s)
			}
			if operation == "shutdown" {
				_ = p.Close()
			} else {
				s, err := p.OpenStream(context.Background(), "host", "new")
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
			}
			waitPeerCondition(t, func() bool {
				for _, s := range client.streams {
					if !s.closed.Load() {
						return false
					}
				}
				return true
			})
			for _, s := range client.streams {
				if s.ctx.Err() == nil {
					t.Fatal("forced drain did not cancel stream context")
				}
				if _, err := s.Write([]byte("obsolete")); err == nil {
					t.Fatal("forced stream remains usable")
				}
			}
			c := streams[0].(*countedPeerStream).conn
			waitPeerCondition(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.streams) == 0 })
			waitPeerCondition(t, func() bool { return closer.closed.Load() == 1 })
			_ = p.Close()
		})
	}
}
