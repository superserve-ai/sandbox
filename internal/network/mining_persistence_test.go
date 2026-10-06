package network

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

type miningSubmitFunc func(abuse.MiningIncident) error

func (f miningSubmitFunc) Submit(i abuse.MiningIncident) error { return f(i) }

type miningPolicyFunc func(uuid.UUID, string) (abuse.SandboxPolicy, bool)

func (f miningPolicyFunc) MiningPolicy(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
	return f(id, ip)
}

func assertMiningStreamOpen(t *testing.T, conn, peer net.Conn) {
	t.Helper()
	sent := make(chan error, 1)
	go func() { _, err := conn.Write([]byte{1}); sent <- err }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatalf("stream closed or stalled: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestMiningBlockedPersistenceDoesNotLockTrafficOrCloseStreamsOnFailure(t *testing.T) {
	c, s, g, _ := miningFixture()
	p := s.p
	entered := make(chan abuse.MiningIncident, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	c.submit = miningSubmitFunc(func(i abuse.MiningIncident) error {
		calls.Add(1)
		entered <- i
		<-release
		return errors.New("storage unavailable")
	})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done, ok := c.Track(p.SandboxID, p.HostIP, a)
	if !ok {
		t.Fatal("initial stream rejected")
	}
	defer done()
	observed := make(chan bool, 1)
	go func() { observed <- c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) }()
	<-entered
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	progress := make(chan error, 1)
	go func() {
		if !c.Blocked(p.SandboxID, p.HostIP) {
			progress <- errors.New("pending slot lost immediate containment")
			return
		}
		if c.Blocked(uuid.New(), "10.11.0.9") {
			progress <- errors.New("unrelated sandbox blocked")
			return
		}
		other, peer := net.Pipe()
		defer other.Close()
		defer peer.Close()
		finish, allowed := c.Track(uuid.New(), "10.11.0.9", other)
		defer finish()
		if !allowed {
			progress <- errors.New("unrelated traffic rejected")
			return
		}
		if !c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) {
			progress <- errors.New("duplicate lost pending gate")
			return
		}
		progress <- nil
	}()
	select {
	case err := <-progress:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("spool I/O held the global traffic lock")
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate observation submitted another incident")
	}
	assertMiningStreamOpen(t, a, b)
	close(release)
	released = true
	if <-observed || c.Blocked(p.SandboxID, p.HostIP) || g.on[p.HostIP] {
		t.Fatal("persistence failure left containment active")
	}
	assertMiningStreamOpen(t, a, b)
}

func TestMiningReceiptOrReconcileWinsOverLatePersistence(t *testing.T) {
	for _, action := range []string{"release", "trust", "replacement", "applied"} {
		t.Run(action, func(t *testing.T) {
			c, s, g, _ := miningFixture()
			p := s.p
			entered := make(chan abuse.MiningIncident, 1)
			release := make(chan struct{})
			c.submit = miningSubmitFunc(func(i abuse.MiningIncident) error { entered <- i; <-release; return nil })
			result := make(chan bool, 1)
			go func() { result <- c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) }()
			i := <-entered
			switch action {
			case "release":
				if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: abuse.IncidentReleased}); err != nil {
					t.Fatal(err)
				}
			case "trust":
				s.change(func(p *abuse.SandboxPolicy) { p.Trusted = true })
				if err := c.Reconcile(); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				s.change(func(p *abuse.SandboxPolicy) { p.Assignment = "replacement" })
				c.submit = miningSubmitFunc(func(abuse.MiningIncident) error { return nil })
				if !c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) {
					t.Fatal("replacement not contained")
				}
			case "applied":
				if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: abuse.IncidentApplied}); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			blocked := <-result
			if action == "applied" {
				if !blocked || !g.on[p.HostIP] {
					t.Fatal("late persistence undid applied receipt")
				}
				return
			}
			if blocked {
				t.Fatal("late persistence resurrected retired incident")
			}
			if action == "replacement" {
				if !c.Blocked(p.SandboxID, p.HostIP) || !g.on[p.HostIP] {
					t.Fatal("old completion changed replacement gate")
				}
			} else if g.on[p.HostIP] {
				t.Fatal("retired tentative gate remained")
			}
		})
	}
}

func TestMiningPacketPersistenceQueueIsBoundedAndDoesNotWaitForStorage(t *testing.T) {
	c, s, _, _ := miningFixture()
	p := s.p
	policies := map[uuid.UUID]abuse.SandboxPolicy{p.SandboxID: p}
	for _, ip := range []string{"10.11.0.8", "10.11.0.9"} {
		other := p
		other.SandboxID = uuid.New()
		other.HostIP = ip
		policies[other.SandboxID] = other
	}
	c.source = miningPolicyFunc(func(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
		p, ok := policies[id]
		return p, ok && p.HostIP == ip
	})
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	c.submit = miningSubmitFunc(func(abuse.MiningIncident) error { entered <- struct{}{}; <-release; return nil })
	queue := make(chan abuse.MiningIncident, 1)
	ctx, cancel := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { c.runPersistence(ctx, queue); close(workerDone) }()
	defer func() { cancel(); close(release); <-workerDone }()
	if !c.observeQueued(p.SandboxID, p.HostIP, abuse.MiningEvidence{}, p.Assignment, queue) {
		t.Fatal("initial packet not gated")
	}
	<-entered
	others := make([]abuse.SandboxPolicy, 0, 2)
	for id, p := range policies {
		if id != s.p.SandboxID {
			others = append(others, p)
		}
	}
	progress := make(chan bool, 1)
	go func() {
		progress <- c.observeQueued(others[0].SandboxID, others[0].HostIP, abuse.MiningEvidence{}, others[0].Assignment, queue)
	}()
	select {
	case ok := <-progress:
		if !ok {
			t.Fatal("bounded free queue entry rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("packet verdict waited for spool")
	}
	if !c.Blocked(others[0].SandboxID, others[0].HostIP) {
		t.Fatal("queued packet lost tentative gate")
	}
	if c.observeQueued(others[1].SandboxID, others[1].HostIP, abuse.MiningEvidence{}, others[1].Assignment, queue) || c.Blocked(others[1].SandboxID, others[1].HostIP) {
		t.Fatal("full queue did not roll back new gate")
	}
	if len(queue) != 1 {
		t.Fatal("queue exceeded its bound")
	}
}

func TestMiningPersistenceCancellationJoinsWriteAndClearsQueuedReservations(t *testing.T) {
	c, s, g, _ := miningFixture()
	first := s.p
	second := first
	second.SandboxID = uuid.New()
	second.HostIP = "10.11.0.8"
	c.source = miningPolicyFunc(func(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
		for _, p := range []abuse.SandboxPolicy{first, second} {
			if p.SandboxID == id && p.HostIP == ip {
				return p, true
			}
		}
		return abuse.SandboxPolicy{}, false
	})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	finish, ok := c.Track(first.SandboxID, first.HostIP, a)
	if !ok {
		t.Fatal("initial stream rejected")
	}
	defer finish()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	c.submit = miningSubmitFunc(func(abuse.MiningIncident) error {
		entered <- struct{}{}
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan abuse.MiningIncident, 2)
	done := make(chan struct{})
	go func() { c.runPersistence(ctx, queue); close(done) }()
	if !c.observeQueued(first.SandboxID, first.HostIP, abuse.MiningEvidence{}, first.Assignment, queue) {
		t.Fatal("initial reservation rejected")
	}
	<-entered
	if !c.observeQueued(second.SandboxID, second.HostIP, abuse.MiningEvidence{}, second.Assignment, queue) {
		t.Fatal("queued reservation rejected")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("worker abandoned its in-flight storage operation")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after storage returned")
	}
	if len(entered) != 0 || len(queue) != 0 {
		t.Fatal("shutdown persisted a queued incident or failed to drain reservations")
	}
	for _, p := range []abuse.SandboxPolicy{first, second} {
		if c.Blocked(p.SandboxID, p.HostIP) || g.on[p.HostIP] {
			t.Fatal("shutdown left a tentative reservation active")
		}
	}
	assertMiningStreamOpen(t, a, b)
}
