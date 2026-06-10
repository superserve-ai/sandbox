package network

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// tcpPair returns a connected pair of TCP loopback conns: the dialer side and
// the accepted side. Real TCP (not net.Pipe) so relay's CloseWrite half-close
// works and writes are buffered rather than synchronous.
func tcpPair(t *testing.T) (dial, accept net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	dial, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return dial, r.c
}

func TestRelayCountsBytesBothDirections(t *testing.T) {
	sandboxClient, a := tcpPair(t) // a is relay's sandbox side
	b, upstream := tcpPair(t)      // b is relay's upstream side

	var up, down int64
	done := make(chan struct{})
	go func() {
		up, down = relay(a, b)
		close(done)
	}()

	// Upstream reads the request, replies, then closes (EOF to relay's b→a).
	go func() {
		buf := make([]byte, 5)
		io.ReadFull(upstream, buf)
		upstream.Write([]byte("world-reply"))
		upstream.Close()
	}()

	// Sandbox sends 5 bytes, half-closes (EOF to relay's a→b), reads the reply.
	sandboxClient.Write([]byte("hello"))
	sandboxClient.(*net.TCPConn).CloseWrite()
	io.ReadAll(sandboxClient)
	sandboxClient.Close()

	<-done
	if up != 5 {
		t.Errorf("bytes sandbox→upstream = %d, want 5", up)
	}
	if down != 11 {
		t.Errorf("bytes upstream→sandbox = %d, want 11", down)
	}
}

func TestFlowParams(t *testing.T) {
	sb := uuid.New()
	team := uuid.New()

	t.Run("full event maps every field", func(t *testing.T) {
		ev := FlowEvent{
			Protocol: "tls", Host: "api.example.com", DstIP: "1.2.3.4",
			DstPort: 443, Verdict: "allowed", MatchRule: "domain",
			BytesSent: 100, BytesRecv: 200, DurationMs: 12,
		}
		p, ok := flowParams(ev, sb, team)
		if !ok {
			t.Fatal("flowParams returned !ok for valid event")
		}
		if p.TeamID != team || p.SandboxID != sb || p.Protocol != "tls" ||
			p.DstPort != 443 || p.Verdict != "allowed" {
			t.Errorf("scalar fields mismatch: %+v", p)
		}
		if p.Host == nil || *p.Host != "api.example.com" {
			t.Errorf("host = %v, want api.example.com", p.Host)
		}
		if p.DstIp.String() != "1.2.3.4" {
			t.Errorf("dst_ip = %s, want 1.2.3.4", p.DstIp)
		}
		if p.BytesSent == nil || *p.BytesSent != 100 || p.DurationMs == nil || *p.DurationMs != 12 {
			t.Errorf("byte/duration pointers wrong: %+v", p)
		}
	})

	t.Run("empty host and zero metrics become nil", func(t *testing.T) {
		ev := FlowEvent{Protocol: "other", DstIP: "10.0.0.1", DstPort: 22, Verdict: "blocked"}
		p, ok := flowParams(ev, sb, team)
		if !ok {
			t.Fatal("!ok for valid blocked event")
		}
		if p.Host != nil || p.MatchRule != nil || p.BytesSent != nil ||
			p.BytesRecv != nil || p.DurationMs != nil {
			t.Errorf("expected nil optionals, got %+v", p)
		}
	})

	t.Run("bad dst ip rejected", func(t *testing.T) {
		ev := FlowEvent{Protocol: "tls", DstIP: "not-an-ip", DstPort: 443, Verdict: "allowed"}
		if _, ok := flowParams(ev, sb, team); ok {
			t.Error("expected !ok for malformed dst ip")
		}
	})
}

func TestTeamCacheResolvesAndBounds(t *testing.T) {
	var calls int64
	known := uuid.New()
	team := uuid.New()
	s := &SQLFlowSink{
		teams: make(map[uuid.UUID]uuid.UUID),
		resolveTeam: func(_ context.Context, id uuid.UUID) (uuid.UUID, error) {
			atomic.AddInt64(&calls, 1)
			if id == known {
				return team, nil
			}
			return uuid.UUID{}, errors.New("not found")
		},
	}

	// First lookup hits the resolver; second is cached.
	if got, ok := s.teamFor(context.Background(), known); !ok || got != team {
		t.Fatalf("teamFor(known) = %v, %v", got, ok)
	}
	if _, ok := s.teamFor(context.Background(), known); !ok {
		t.Fatal("second teamFor(known) should hit cache")
	}
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Errorf("resolver called %d times, want 1 (second should be cached)", n)
	}

	// Unresolvable sandbox is dropped (not cached).
	if _, ok := s.teamFor(context.Background(), uuid.New()); ok {
		t.Error("teamFor for unknown sandbox should return !ok")
	}

	// Cache stays bounded at maxTeamCache.
	s.resolveTeam = func(_ context.Context, id uuid.UUID) (uuid.UUID, error) {
		return uuid.New(), nil
	}
	for i := 0; i < maxTeamCache*2; i++ {
		s.teamFor(context.Background(), uuid.New())
	}
	s.teamMu.Lock()
	n := len(s.teams)
	s.teamMu.Unlock()
	if n > maxTeamCache {
		t.Errorf("team cache size = %d, exceeds bound %d", n, maxTeamCache)
	}
}

func TestNopFlowSink(t *testing.T) {
	sink := NewNopFlowSink()
	// Must not panic or block.
	sink.Emit(FlowEvent{SandboxID: "x"})
	if err := sink.Shutdown(context.Background()); err != nil {
		t.Errorf("nop Shutdown returned %v", err)
	}
}

func TestSQLFlowSinkEmitNonBlockingDrops(t *testing.T) {
	// A sink whose buffer is full must drop rather than block the caller.
	s := &SQLFlowSink{ch: make(chan FlowEvent, 1)}
	s.ch <- FlowEvent{} // fill the single slot

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Emit(FlowEvent{}) // would block if Emit weren't non-blocking
	}()
	wg.Wait() // returns only because Emit dropped instead of blocking

	if s.Dropped() != 1 {
		t.Errorf("Dropped = %d, want 1", s.Dropped())
	}
}
