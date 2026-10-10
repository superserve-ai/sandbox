package network

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func capacityProxy(t *testing.T, limit int) *EgressProxy {
	t.Helper()
	p := NewEgressProxy(0, 0, 0, 2, zerolog.Nop())
	if err := p.ConfigureCapacity(EgressCapacity{MaxConnections: limit, Enforce: true}, nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEgressDispatchRejectsBeforeHandlerAndPreservesStream(t *testing.T) {
	p := capacityProxy(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	entered := make(chan struct{})
	if !p.dispatch(ctx, a, func(ctx context.Context, c net.Conn) {
		close(entered)
		buf := make([]byte, 1)
		for {
			if _, e := c.Read(buf); e != nil {
				return
			}
			if _, e := c.Write(buf); e != nil {
				return
			}
		}
	}) {
		t.Fatal("first rejected")
	}
	<-entered
	denied, peer := net.Pipe()
	defer peer.Close()
	if p.dispatch(ctx, denied, func(context.Context, net.Conn) { t.Error("denied handler started") }) {
		t.Fatal("exceeded host limit")
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("rejected socket not closed: %v", err)
	}
	b.SetDeadline(time.Now().Add(time.Second))
	go b.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != nil || buf[0] != 'x' {
		t.Fatalf("existing stream disrupted: %q %v", buf, err)
	}
	cancel()
	p.workers.Wait()
	if p.active.Load() != 0 {
		t.Fatal("permit leaked on cancellation")
	}
}

func TestEgressConcurrentDispatchBound(t *testing.T) {
	p := capacityProxy(t, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, b := net.Pipe()
			defer b.Close()
			if p.dispatch(ctx, a, func(ctx context.Context, c net.Conn) { <-ctx.Done() }) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 5 || p.active.Load() != 5 {
		t.Fatalf("accepted=%d active=%d", accepted.Load(), p.active.Load())
	}
	cancel()
	p.workers.Wait()
	if p.active.Load() != 0 {
		t.Fatal("host permits leaked")
	}
}

type fixtureConn struct {
	closed  atomic.Bool
	data    []byte
	readErr error
}

func (c *fixtureConn) Read(b []byte) (int, error) {
	if len(c.data) > 0 {
		n := copy(b, c.data)
		c.data = c.data[n:]
		return n, nil
	}
	return 0, c.readErr
}
func (c *fixtureConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fixtureConn) Close() error                { c.closed.Store(true); return nil }
func (c *fixtureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 19080}
}
func (c *fixtureConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 3456}
}
func (c *fixtureConn) SetDeadline(time.Time) error      { return nil }
func (c *fixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixtureConn) SetWriteDeadline(time.Time) error { return nil }

func TestEgressFailurePathsReturnAdmission(t *testing.T) {
	for _, scenario := range []string{"original_destination", "policy", "inspection", "dial", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			p := capacityProxy(t, 1)
			p.RegisterSandbox("192.0.2.2", "sandbox-a")
			c := &fixtureConn{data: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), readErr: io.EOF}
			p.originalDst = func(net.Conn) (net.IP, int, error) { return net.ParseIP("127.0.0.1"), 443, nil }
			handler := p.handleHTTP
			switch scenario {
			case "original_destination":
				p.originalDst = func(net.Conn) (net.IP, int, error) { return nil, 0, errors.New("no destination") }
			case "policy":
				p.SetRules("192.0.2.2", &EgressRules{SandboxID: "sandbox-a", DeniedCIDRs: []string{"0.0.0.0/0"}})
			case "inspection":
				c.data = nil
			case "panic":
				handler = func(context.Context, net.Conn) { panic("fixture") }
			}
			if !p.dispatch(context.Background(), c, handler) {
				t.Fatal("unexpected rejection")
			}
			p.workers.Wait()
			if !c.closed.Load() || p.active.Load() != 0 || p.limiter.Count("192.0.2.2") != 0 {
				t.Fatal("socket or permit leaked")
			}
		})
	}
}

func TestEgressPolicyEditAndReassignmentAccounting(t *testing.T) {
	p := capacityProxy(t, 4)
	ip := "192.0.2.2"
	p.RegisterSandbox(ip, "sandbox-a")
	_, original, done, ok := p.acquireSandbox(ip)
	if !ok {
		t.Fatal("acquire")
	}
	p.SetRules(ip, &EgressRules{SandboxID: "sandbox-a", AllowedDomains: []string{"example.test"}})
	_, same, done2, ok := p.acquireSandbox(ip)
	if !ok || same != original {
		t.Fatal("policy edit changed registration")
	}
	if _, _, _, ok := p.acquireSandbox(ip); ok {
		t.Fatal("policy edit reset capacity")
	}
	p.RegisterSandbox(ip, "sandbox-b")
	_, replacement, newDone, ok := p.acquireSandbox(ip)
	if !ok || replacement == original {
		t.Fatal("replacement not isolated")
	}
	done()
	done2()
	if p.limiter.Count(ip) != 1 {
		t.Fatal("old registration changed new count")
	}
	newDone()
}

func TestEgressCancellationClosesUpstreamBeforeRelease(t *testing.T) {
	p := capacityProxy(t, 1)
	p.originalDst = func(net.Conn) (net.IP, int, error) { return net.ParseIP("192.0.2.9"), 80, nil }
	upstream, remote := net.Pipe()
	defer remote.Close()
	dialed := make(chan struct{})
	p.dialUpstream = func(context.Context, *net.Dialer, string) (net.Conn, error) { close(dialed); return upstream, nil }
	client, guest := net.Pipe()
	defer guest.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if !p.dispatch(ctx, client, p.handleOther) {
		t.Fatal("rejected")
	}
	<-dialed
	cancel()
	done := make(chan struct{})
	go func() { p.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown stuck in relay")
	}
	if p.active.Load() != 0 {
		t.Fatal("host permit leaked")
	}
	if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("upstream not closed: %v", err)
	}
}

type failedWriteConn struct{ fixtureConn }

func (c *failedWriteConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEgressInitialWriteFailureReturnsBothPermits(t *testing.T) {
	p := capacityProxy(t, 1)
	p.RegisterSandbox("192.0.2.2", "sandbox-a")
	p.originalDst = func(net.Conn) (net.IP, int, error) { return net.ParseIP("192.0.2.9"), 80, nil }
	upstream := &failedWriteConn{}
	p.dialUpstream = func(context.Context, *net.Dialer, string) (net.Conn, error) { return upstream, nil }
	client := &fixtureConn{data: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), readErr: io.EOF}
	p.dispatch(context.Background(), client, p.handleHTTP)
	p.workers.Wait()
	if !upstream.closed.Load() || !client.closed.Load() || p.active.Load() != 0 || p.limiter.Count("192.0.2.2") != 0 {
		t.Fatal("initial write leaked sockets or capacity")
	}
}
