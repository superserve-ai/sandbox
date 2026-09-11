package proxy

import (
	"context"
	"errors"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"math/rand"
	"sync"
	"time"
)

type PeerPoolConfig struct {
	MaxConnections, StreamsPerConnection int
	DrainTimeout                         time.Duration
	Dial                                 PeerDialer
	Telemetry                            PeerPoolTelemetry
}
type PeerPoolTelemetry interface {
	PeerConnection(delta int)
	PeerStream(delta int)
	PeerFailure()
	PeerReconnect(result string)
	PeerDrain(forced bool)
	PeerHandshake(time.Duration, string)
}

// RecorderPeerTelemetry adapts the shared telemetry Recorder to pool events.
// It is optional so existing callers and test fakes remain source-compatible.
type RecorderPeerTelemetry struct {
	Recorder interface {
		RecordPeerEvent(context.Context, telemetry.PeerEvent)
	}
	HostID, Region string
}

func (t RecorderPeerTelemetry) emit(kind string, delta int64, forced bool) {
	t.emitResult(kind, delta, forced, telemetry.ResultSuccess)
}
func (t RecorderPeerTelemetry) emitResult(kind string, delta int64, forced bool, result string) {
	if t.Recorder == nil {
		return
	}
	t.Recorder.RecordPeerEvent(context.Background(), telemetry.PeerEvent{Kind: kind, Delta: delta, Forced: forced, HostID: t.HostID, Region: t.Region, Result: result})
}
func (t RecorderPeerTelemetry) PeerConnection(d int) { t.emit("connection", int64(d), false) }
func (t RecorderPeerTelemetry) PeerStream(d int)     { t.emit("stream", int64(d), false) }
func (t RecorderPeerTelemetry) PeerFailure() {
	t.emitResult("failure", 0, false, telemetry.ResultError)
}
func (t RecorderPeerTelemetry) PeerReconnect(result string) {
	t.emitResult("reconnect", 0, false, result)
}
func (t RecorderPeerTelemetry) PeerDrain(f bool) { t.emit("drain", 0, f) }
func (t RecorderPeerTelemetry) PeerHandshake(d time.Duration, result string) {
	if t.Recorder == nil {
		return
	}
	t.Recorder.RecordPeerEvent(context.Background(), telemetry.PeerEvent{Kind: "handshake", Duration: d, HostID: t.HostID, Region: t.Region, Result: result})
}

type noopPeerTelemetry struct{}

func (noopPeerTelemetry) PeerConnection(int)                  {}
func (noopPeerTelemetry) PeerStream(int)                      {}
func (noopPeerTelemetry) PeerFailure()                        {}
func (noopPeerTelemetry) PeerReconnect(string)                {}
func (noopPeerTelemetry) PeerDrain(bool)                      {}
func (noopPeerTelemetry) PeerHandshake(time.Duration, string) {}

type peerPool struct {
	mu     sync.Mutex
	cfg    PeerPoolConfig
	hosts  map[string]*hostPool
	closed bool
}

func NewPeerTransport(cfg PeerPoolConfig) PeerTransport {
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 4
	}
	if cfg.StreamsPerConnection <= 0 {
		cfg.StreamsPerConnection = 100
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = 30 * time.Second
	}
	if cfg.Telemetry == nil {
		cfg.Telemetry = noopPeerTelemetry{}
	}
	return &peerPool{cfg: cfg, hosts: make(map[string]*hostPool)}
}
func (p *peerPool) OpenStream(ctx context.Context, host, addr string) (PeerStream, error) {
	if p.cfg.Dial == nil {
		return nil, errors.New("peer dialer is required")
	}
	if host == "" || addr == "" {
		return nil, errors.New("peer host and address required")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("peer transport closed")
	}
	h := p.hosts[host]
	if h == nil {
		h = &hostPool{parent: p, host: host, addr: addr}
		p.hosts[host] = h
	}
	// The endpoint is owned by hostPool and protected by h.mu. Keep the
	// comparison under that lock as replacement mutates it while holding h.mu.
	h.mu.Lock()
	h.openers++
	endpointChanged := h.addr != addr
	h.mu.Unlock()
	if endpointChanged {
		h.replaceLocked(addr)
	}
	p.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.openers--
		h.mu.Unlock()
		h.evictIfEmpty()
	}()
	return h.open(ctx)
}
func (p *peerPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	hs := make([]*hostPool, 0, len(p.hosts))
	for _, h := range p.hosts {
		hs = append(hs, h)
	}
	p.mu.Unlock()
	deadline := time.Now().Add(p.cfg.DrainTimeout)
	var drains sync.WaitGroup
	for _, h := range hs {
		h.mu.Lock()
		h.closed = true
		h.notifyLocked()
		if h.dialCancel != nil {
			h.dialCancel()
		}
		h.mu.Unlock()
	}
	for _, h := range hs {
		drains.Add(1)
		go func() { defer drains.Done(); h.close(deadline) }()
	}
	drains.Wait()
	return nil
}

type hostPool struct {
	mu                 sync.Mutex
	parent             *peerPool
	host, addr         string
	conns              []*peerConn
	dialing            bool
	dialDone           chan struct{}
	changed            chan struct{}
	dialCancel         context.CancelFunc
	closed             bool
	endpointGeneration uint64
	failures           int
	retryAt            time.Time
	retired            int
	replacing          bool
	openers            int
	eviction           *time.Timer
	evictionGeneration uint64
	retiredConns       map[*peerConn]struct{}
}

const (
	peerReconnectBaseBackoff = 100 * time.Millisecond
	peerReconnectMaxBackoff  = 5 * time.Second
)

// peerReconnectBackoff returns an exponentially increasing, one-sided jittered
// delay. The lower bound is intentional: failures never cause a tighter retry
// loop, while the ceiling bounds pressure on an unavailable peer.
func peerReconnectBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := peerReconnectBaseBackoff * time.Duration(1<<min(failures-1, 5))
	if d > peerReconnectMaxBackoff {
		d = peerReconnectMaxBackoff
	}
	return d/2 + time.Duration(rand.Int63n(int64(d/2)))
}

type peerConn struct {
	mu             sync.Mutex
	client         PeerClient
	closer         io.Closer
	closeOnce      sync.Once
	active         int // Includes reserved capacity for pending opens.
	published      int // Streams whose telemetry increment has been emitted.
	draining       bool
	removed        bool
	drainScheduled bool
	drainCancel    chan struct{}
	detached       bool
	max            int
	streams        map[*countedPeerStream]struct{}
}

// peerFailureWatcher is optionally implemented by clients whose underlying
// transport can report an asynchronous terminal failure.  Watching this
// signal ensures failures are handled even when callers are not currently
// reading or writing an attached stream.
type peerFailureWatcher interface {
	Done() <-chan struct{}
}

// peerStreamFailureWatcher is implemented by stream adapters that can report
// an asynchronous terminal transport error (for example, a gRPC recv loop).
// It complements the connection-level watcher: a stream may terminate while
// the underlying client connection still appears healthy to grpc-go.
type peerStreamFailureWatcher interface {
	Done() <-chan struct{}
}

// closeDialResult releases a connection returned by a dial that can no
// longer be published (for example, when its endpoint generation is stale).
// Dialers normally return the transport closer separately, but accepting a
// closer client as a fallback keeps discarded transports from leaking.
func closeDialResult(client PeerClient, closer io.Closer) {
	if closer != nil {
		_ = closer.Close()
		return
	}
	if c, ok := client.(io.Closer); ok {
		_ = c.Close()
	}
}

func (c *peerConn) close() {
	c.closeOnce.Do(func() {
		if c.closer != nil {
			_ = c.closer.Close()
		}
	})
}

func (h *hostPool) replaceLocked(addr string) {
	h.mu.Lock()
	h.replacing = true
	h.addr = addr
	h.endpointGeneration++
	h.notifyLocked()
	if h.dialCancel != nil {
		h.dialCancel()
	}
	h.failures = 0
	h.retryAt = time.Time{}
	// Detach the old endpoint connections from capacity accounting immediately.
	// They remain alive only to drain their existing streams; retaining them in
	// h.conns would consume the replacement endpoint's connection slots.
	old := h.conns
	h.conns = nil
	var idle []*peerConn
	for _, c := range old {
		c.mu.Lock()
		c.draining = true
		c.detached = true
		isIdle := c.active == 0
		c.mu.Unlock()
		h.retired++
		if h.retiredConns == nil {
			h.retiredConns = make(map[*peerConn]struct{})
		}
		h.retiredConns[c] = struct{}{}
		if isIdle {
			idle = append(idle, c)
		} else {
			h.scheduleDrain(c)
		}
	}
	h.mu.Unlock()
	for _, c := range idle {
		c.close()
		h.remove(c)
		h.parent.cfg.Telemetry.PeerDrain(false)
	}
	h.mu.Lock()
	h.replacing = false
	h.mu.Unlock()
}
func (h *hostPool) open(ctx context.Context) (PeerStream, error) {
retry:
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return nil, errors.New("peer host closed")
		}
		for _, c := range h.conns {
			c.mu.Lock()
			if !c.draining && c.active < c.max {
				c.active++
				c.mu.Unlock()
				generation := h.endpointGeneration
				h.mu.Unlock()
				s, e := c.client.OpenPeerStream(ctx)
				if e == nil {
					// Endpoint replacement may have started while the stream
					// was being opened. Re-check the generation before exposing
					// it so no new stream can escape on a stale connection.
					h.mu.Lock()
					c.mu.Lock()
					if h.closed || generation != h.endpointGeneration || c.draining || c.removed {
						c.mu.Unlock()
						h.mu.Unlock()
						h.releaseOpen(c)
						_ = s.Close()
						continue retry
					}
					cs := &countedPeerStream{PeerStream: s, conn: c, host: h, tele: h.parent.cfg.Telemetry}
					if c.streams == nil {
						c.streams = make(map[*countedPeerStream]struct{})
					}
					c.streams[cs] = struct{}{}
					c.published++
					h.parent.cfg.Telemetry.PeerStream(1)
					c.mu.Unlock()
					h.mu.Unlock()
					if watcher, ok := s.(peerStreamFailureWatcher); ok {
						go func() {
							<-watcher.Done()
							// A stream-level terminal signal is transport failure
							// unless the connection was already removed/draining.
							h.markFailed(c)
						}()
					}
					return cs, nil
				}
				h.releaseOpen(c)
				if peerRPCError(e) {
					return nil, e
				}
				// Opening a stream can fail before the connection is removed
				// from the pool. Close the transport at this failure boundary so
				// a failed open cannot retain its underlying socket or TLS state.
				c.close()
				// markFailed acquires the host lock and records bounded reconnect
				// backoff for subsequent callers.
				h.markFailed(c)
				h.mu.Lock()
				break
			} else {
				c.mu.Unlock()
			}
		}
		usable := 0
		for _, c := range h.conns {
			c.mu.Lock()
			if !c.draining {
				usable++
			}
			c.mu.Unlock()
		}
		if h.dialing {
			// Coalesce concurrent callers behind the in-flight dial instead of
			// polling every millisecond while an endpoint is unavailable.
			done := h.dialDone
			changed := h.changedLocked()
			h.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
			case <-changed:
			}
			continue
		}
		if usable >= h.parent.cfg.MaxConnections {
			changed := h.changedLocked()
			h.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
			}
			continue
		}
		if wait := time.Until(h.retryAt); wait > 0 {
			changed := h.changedLocked()
			h.mu.Unlock()
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			case <-changed:
				t.Stop()
			}
			continue
		}
		h.dialing = true
		h.dialDone = make(chan struct{})
		dialDone := h.dialDone
		dialCtx, dialCancel := context.WithCancel(ctx)
		h.dialCancel = dialCancel
		addr := h.addr
		generation := h.endpointGeneration
		h.mu.Unlock()
		started := time.Now()
		client, closer, e := h.parent.cfg.Dial(dialCtx, h.host, addr)
		dialCancel()
		duration := time.Since(started)
		h.mu.Lock()
		h.dialing = false
		h.dialCancel = nil
		result := telemetry.ResultSuccess
		if e != nil || h.closed || generation != h.endpointGeneration || addr != h.addr {
			result = telemetry.ResultError
		}
		h.parent.cfg.Telemetry.PeerHandshake(duration, result)
		// Shutdown may have started while the dial was out of lock.  A
		// failed dial must not enter the reconnect/backoff path after the
		// host has been closed, and a successful one must never be published.
		if h.closed {
			closeDialResult(client, closer)
			close(dialDone)
			h.dialDone = nil
			h.mu.Unlock()
			return nil, errors.New("peer host closed")
		}
		// The endpoint may have been replaced while dialing was out of lock.
		// Never publish a result (including an error) established against that
		// stale endpoint: otherwise a failed old-endpoint dial would poison the
		// retry backoff for the new endpoint.
		stale := generation != h.endpointGeneration || addr != h.addr
		if stale {
			closeDialResult(client, closer)
			close(dialDone)
			h.dialDone = nil
			h.mu.Unlock()
			continue
		}
		if e == nil {
			c := &peerConn{client: client, closer: closer, max: h.parent.cfg.StreamsPerConnection}
			h.conns = append(h.conns, c)
			if watcher, ok := client.(peerFailureWatcher); ok {
				go func() {
					<-watcher.Done()
					h.markFailed(c)
				}()
			}
			h.failures = 0
			h.retryAt = time.Time{}
			h.parent.cfg.Telemetry.PeerConnection(1)
			h.parent.cfg.Telemetry.PeerReconnect(telemetry.ResultSuccess)
		} else {
			// Caller cancellation is not a transport failure and must not
			// poison reconnect backoff for later callers.
			if !peerCallerCanceled(e) {
				// Publish the retry deadline before waking coalesced callers so a
				// failed dial cannot trigger an immediate second attempt.
				h.setBackoffLocked()
			}
		}
		close(dialDone)
		h.dialDone = nil
		h.mu.Unlock()
		if e != nil {
			if !peerCallerCanceled(e) {
				h.parent.cfg.Telemetry.PeerReconnect(telemetry.ResultError)
			}
			h.evictIfEmpty()
			return nil, e
		}
	}
}

// Waiters subscribe under the host lock so capacity and endpoint changes cannot
// be lost between checking the state and going to sleep.
func (h *hostPool) changedLocked() <-chan struct{} {
	if h.changed == nil {
		h.changed = make(chan struct{})
	}
	return h.changed
}

func (h *hostPool) notifyLocked() {
	if h.changed != nil {
		close(h.changed)
		h.changed = nil
	}
}

func (h *hostPool) notify() {
	h.mu.Lock()
	h.notifyLocked()
	h.mu.Unlock()
}

func (h *hostPool) evictIfEmpty() {
	h.parent.mu.Lock()
	defer h.parent.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.replacing || h.openers != 0 || len(h.conns) != 0 || h.retired != 0 || h.dialing {
		return
	}
	// Retain failed-host retry state for a bounded idle period. Active callers
	// pin the entry so eviction cannot orphan an in-flight open.
	if h.failures > 0 {
		if h.eviction != nil {
			h.eviction.Stop()
		}
		h.evictionGeneration++
		generation := h.evictionGeneration
		h.eviction = time.AfterFunc(peerReconnectMaxBackoff, func() { h.evictIdle(generation) })
		return
	}
	if h.parent.hosts[h.host] == h {
		delete(h.parent.hosts, h.host)
	}
}

func (h *hostPool) evictIdle(generation uint64) {
	h.parent.mu.Lock()
	defer h.parent.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if generation != h.evictionGeneration || h.closed {
		return
	}
	if h.openers == 0 && !h.dialing && len(h.conns) == 0 && h.retired == 0 && h.parent.hosts[h.host] == h {
		delete(h.parent.hosts, h.host)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *hostPool) setBackoff() {
	h.mu.Lock()
	h.setBackoffLocked()
	h.mu.Unlock()
}

func (h *hostPool) setBackoffLocked() {
	h.failures++
	h.retryAt = time.Now().Add(peerReconnectBackoff(h.failures))
}

func (h *hostPool) markFailed(c *peerConn) {
	h.mu.Lock()
	c.mu.Lock()
	intentional := c.draining || c.removed
	c.mu.Unlock()
	if intentional {
		h.mu.Unlock()
		return
	}
	found := false
	for i, x := range h.conns {
		if x == c {
			h.conns = append(h.conns[:i], h.conns[i+1:]...)
			found = true
			break
		}
	}
	if found {
		h.parent.cfg.Telemetry.PeerConnection(-1)
		h.failures++
		h.retryAt = time.Now().Add(peerReconnectBackoff(h.failures))
		c.mu.Lock()
		c.draining = true
		c.removed = true
		c.mu.Unlock()
		h.notifyLocked()
	}
	h.mu.Unlock()
	if found {
		c.mu.Lock()
		streams := make([]*countedPeerStream, 0, len(c.streams))
		for s := range c.streams {
			streams = append(streams, s)
		}
		c.mu.Unlock()
		// Close outside the connection lock and exactly once. This is also
		// safe when read/write failures race with stream-open or drain cleanup.
		c.close()
		// Force attached streams to observe the transport failure immediately.
		// Wrapper cleanup also releases their capacity and telemetry.
		for _, s := range streams {
			_ = s.Close()
		}
		h.parent.cfg.Telemetry.PeerFailure()
		h.evictIfEmpty()
	}
}

func (h *hostPool) remove(target *peerConn) {
	h.mu.Lock()
	for i, c := range h.conns {
		if c == target {
			h.conns = append(h.conns[:i], h.conns[i+1:]...)
			h.parent.cfg.Telemetry.PeerConnection(-1)
			break
		}
	}
	if target.detached {
		h.parent.cfg.Telemetry.PeerConnection(-1)
		target.detached = false
		delete(h.retiredConns, target)
		if h.retired > 0 {
			h.retired--
		}
	}
	target.mu.Lock()
	if target.drainCancel != nil {
		close(target.drainCancel)
		target.drainCancel = nil
	}
	target.drainScheduled = false
	target.mu.Unlock()
	replacing := h.replacing
	h.notifyLocked()
	h.mu.Unlock()
	target.close()
	if !replacing {
		h.evictIfEmpty()
	}
}
func (h *hostPool) scheduleDrain(c *peerConn) {
	// A connection can be observed by several endpoint swaps (or by shutdown)
	// while it is already draining. Keep one bounded timer per connection.
	c.mu.Lock()
	if c.drainScheduled || c.removed {
		c.mu.Unlock()
		return
	}
	c.drainScheduled = true
	c.drainCancel = make(chan struct{})
	cancel := c.drainCancel
	idle := c.active == 0
	if idle {
		c.removed = true
	}
	c.mu.Unlock()
	if idle {
		// The caller may hold h.mu during endpoint replacement.
		go func() {
			c.close()
			h.remove(c)
			h.parent.cfg.Telemetry.PeerDrain(false)
		}()
		return
	}
	go func() {
		t := time.NewTimer(h.parent.cfg.DrainTimeout)
		defer t.Stop()
		select {
		case <-t.C:
		case <-cancel:
			return
		}
		c.mu.Lock()
		if c.removed {
			c.mu.Unlock()
			return
		}
		active := c.active
		c.draining = true
		c.removed = true
		// Pending opens reserve capacity without publishing a stream metric.
		// Balance only published streams; late wrapper cleanup is idempotent.
		forcedStreams := c.published
		c.published = 0
		c.active = 0
		c.mu.Unlock()
		c.close()
		// Reclaim the slot at the deadline even if attached streams have not
		// closed yet; their subsequent cleanup is idempotent.
		h.remove(c)
		if forcedStreams > 0 {
			h.parent.cfg.Telemetry.PeerStream(-forcedStreams)
		}
		h.parent.cfg.Telemetry.PeerDrain(active > 0)
	}()
}
func (h *hostPool) releaseOpen(c *peerConn) {
	defer h.notify()
	c.mu.Lock()
	if c.active > 0 {
		c.active--
	}
	reclaim := c.draining && c.active == 0 && !c.removed
	if reclaim {
		c.removed = true
	}
	c.mu.Unlock()
	if reclaim {
		c.close()
		h.remove(c)
		h.parent.cfg.Telemetry.PeerDrain(false)
	}
}

func (h *hostPool) close(deadline time.Time) {
	h.mu.Lock()
	h.closed = true
	if h.dialCancel != nil {
		h.dialCancel()
	}
	dialDone := h.dialDone
	cs := append([]*peerConn(nil), h.conns...)
	for c := range h.retiredConns {
		cs = append(cs, c)
	}
	if h.eviction != nil {
		h.eviction.Stop()
	}
	h.mu.Unlock()
	// A stream may have claimed removal but still be finishing callbacks.
	// Shutdown must close its transport even while that cleanup is pending.
	defer func() {
		for _, c := range cs {
			c.close()
		}
	}()
	if dialDone != nil {
		timer := time.NewTimer(max(time.Until(deadline), 0))
		select {
		case <-dialDone:
		case <-timer.C:
		}
		timer.Stop()
	}
	for _, c := range cs {
		c.mu.Lock()
		c.draining = true
		reclaim := c.active == 0 && !c.removed
		if reclaim {
			c.removed = true
		}
		c.mu.Unlock()
		if reclaim {
			c.close()
			h.remove(c)
			h.parent.cfg.Telemetry.PeerDrain(false)
		}
	}
	// Give active streams the configured grace period to close naturally.
	// Polling is intentionally bounded by the manager deadline; a wedged
	// stream must never hold process shutdown indefinitely.
	for time.Now().Before(deadline) {
		active := false
		for _, c := range cs {
			c.mu.Lock()
			if c.active > 0 && !c.removed {
				active = true
			}
			c.mu.Unlock()
		}
		if !active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	// Deadline exceeded: force-close and reclaim every remaining transport.
	for _, c := range cs {
		c.mu.Lock()
		if c.removed {
			c.mu.Unlock()
			continue
		}
		c.draining = true
		forcedStreams := c.published
		c.published = 0
		c.active = 0
		c.removed = true
		c.mu.Unlock()
		c.close()
		h.remove(c)
		if forcedStreams > 0 {
			h.parent.cfg.Telemetry.PeerStream(-forcedStreams)
		}
		h.parent.cfg.Telemetry.PeerDrain(true)
	}
}

type countedPeerStream struct {
	PeerStream
	host *hostPool
	conn *peerConn
	tele PeerPoolTelemetry
	once sync.Once
}

func (s *countedPeerStream) Read(p []byte) (int, error) {
	n, e := s.PeerStream.Read(p)
	if e != nil {
		if e != io.EOF && !peerRPCError(e) {
			s.host.markFailed(s.conn)
		}
		_ = s.Close()
	}
	return n, e
}
func (s *countedPeerStream) Write(p []byte) (int, error) {
	n, e := s.PeerStream.Write(p)
	if e != nil {
		if e != io.EOF && !peerRPCError(e) {
			s.host.markFailed(s.conn)
		}
		_ = s.Close()
	}
	return n, e
}

func (s *countedPeerStream) Close() error {
	e := s.PeerStream.Close()
	s.once.Do(func() {
		s.conn.mu.Lock()
		delete(s.conn.streams, s)
		if s.conn.active > 0 {
			s.conn.active--
		}
		decremented := s.conn.published > 0
		if decremented {
			s.conn.published--
		}
		reclaim := s.conn.draining && s.conn.active == 0 && !s.conn.removed
		if reclaim {
			s.conn.removed = true
		}
		s.conn.mu.Unlock()
		s.host.notify()
		if decremented {
			s.tele.PeerStream(-1)
		}
		if reclaim {
			s.conn.close()
			s.host.remove(s.conn)
			s.tele.PeerDrain(false)
		}
	})
	return e
}

func peerCallerCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded
}

// A gRPC status belongs to one RPC. The connection watcher is authoritative
// for transport failures; application statuses must not retire sibling RPCs.
func peerRPCError(err error) bool {
	if peerCallerCanceled(err) {
		return true
	}
	_, ok := status.FromError(err)
	return ok
}
