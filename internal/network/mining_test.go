package network

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

type miningTestSource struct {
	mu sync.Mutex
	p  abuse.SandboxPolicy
}

func (s *miningTestSource) MiningPolicy(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p, s.p.SandboxID == id && s.p.HostIP == ip
}
func (s *miningTestSource) change(f func(*abuse.SandboxPolicy)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.p)
}

type miningTestGate struct {
	on  map[string]bool
	err error
}

func (g *miningTestGate) SetContained(ip string, on bool) error {
	if g.err != nil {
		return g.err
	}
	g.on[ip] = on
	return nil
}

type miningTestSubmit struct {
	items []abuse.MiningIncident
	err   error
}

func (s *miningTestSubmit) Submit(i abuse.MiningIncident) error {
	s.items = append(s.items, i)
	return s.err
}
func miningFixture() (*MiningContainment, *miningTestSource, *miningTestGate, *miningTestSubmit) {
	p := abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: uuid.New(), Known: true, Mode: abuse.ModeEnforce}, SandboxID: uuid.New(), HostID: "host-test", HostIP: "10.11.0.7", Assignment: "test-assignment"}
	s := &miningTestSource{p: p}
	g := &miningTestGate{on: make(map[string]bool)}
	d := &miningTestSubmit{}
	return NewMiningContainment(s, g, d, zerolog.Nop()), s, g, d
}
func TestMiningImmediateContainmentClosesExistingAndLateStreams(t *testing.T) {
	c, s, g, d := miningFixture()
	p := s.p
	a, b := net.Pipe()
	defer b.Close()
	done, ok := c.Track(p.SandboxID, p.HostIP, a)
	if !ok {
		t.Fatal("initial stream denied")
	}
	defer done()
	if !c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{Kind: "domain", Indicator: "mining.example"}) {
		t.Fatal("not contained")
	}
	if !g.on[p.HostIP] || len(d.items) != 1 {
		t.Fatal("gate and durable event missing")
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("existing stream remained open")
	}
	mirror, peer := net.Pipe()
	defer peer.Close()
	_, allowed := c.Track(p.SandboxID, p.HostIP, mirror)
	if allowed {
		t.Fatal("late dial escaped containment")
	}
	// Refresh lag must not reopen the sandbox before a durable terminal receipt.
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !c.Blocked(p.SandboxID, p.HostIP) {
		t.Fatal("cache propagation lag cleared containment")
	}
	if !c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) || len(d.items) != 1 {
		t.Fatal("repeated packets duplicated incident")
	}
}
func TestMiningTrustModesUnknownAndAttributionFailOpen(t *testing.T) {
	for _, name := range []string{"trusted", "off", "observe", "unknown", "wrong-sandbox", "wrong-address"} {
		t.Run(name, func(t *testing.T) {
			c, s, g, d := miningFixture()
			id, ip := s.p.SandboxID, s.p.HostIP
			switch name {
			case "trusted":
				s.p.Trusted = true
			case "off":
				s.p.Mode = abuse.ModeOff
			case "observe":
				s.p.Mode = abuse.ModeObserve
			case "unknown":
				s.p.Known = false
			case "wrong-sandbox":
				id = uuid.New()
			case "wrong-address":
				ip = "10.11.0.8"
			}
			if c.Observe(id, ip, abuse.MiningEvidence{}) || len(d.items) > 0 || len(g.on) > 0 {
				t.Fatal("exempt or unattributed event escalated")
			}
		})
	}
}
func TestMiningReleaseAndAssignmentFencing(t *testing.T) {
	c, s, g, d := miningFixture()
	p := s.p
	c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{})
	old := d.items[0]
	s.change(func(p *abuse.SandboxPolicy) { p.Assignment = "replacement"; p.SandboxID = uuid.New() })
	if c.Blocked(s.p.SandboxID, s.p.HostIP) {
		t.Fatal("old IP gate blocked new assignment")
	}
	if c.observeAssignment(s.p.SandboxID, s.p.HostIP, abuse.MiningEvidence{}, old.Assignment) {
		t.Fatal("queued old packet accused replacement")
	}
	c.Observe(s.p.SandboxID, s.p.HostIP, abuse.MiningEvidence{})
	if err := c.Receipt(context.Background(), old, abuse.IncidentReceipt{Disposition: abuse.IncidentReleased}); err != nil {
		t.Fatal(err)
	}
	if !g.on[p.HostIP] || !c.Blocked(s.p.SandboxID, s.p.HostIP) {
		t.Fatal("old release removed replacement incident")
	}
	current := d.items[1]
	if err := c.Receipt(context.Background(), current, abuse.IncidentReceipt{Disposition: abuse.IncidentReleased}); err != nil {
		t.Fatal(err)
	}
	if g.on[p.HostIP] || c.Blocked(s.p.SandboxID, s.p.HostIP) {
		t.Fatal("release did not clear gate")
	}
}
func TestMiningPersistenceFailureRollsBackAndTrustReleases(t *testing.T) {
	c, s, g, d := miningFixture()
	p := s.p
	d.err = errors.New("full")
	if c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{}) || g.on[p.HostIP] || c.Blocked(p.SandboxID, p.HostIP) {
		t.Fatal("spool failure did not fail open")
	}
	d.err = nil
	c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{})
	s.change(func(p *abuse.SandboxPolicy) { p.Trusted = true })
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if g.on[p.HostIP] {
		t.Fatal("trust did not clear containment")
	}
}
func TestMiningProxyRegistrationRace(t *testing.T) {
	p := NewEgressProxy(0, 0, 0, 10, zerolog.Nop())
	id := uuid.New().String()
	ip := "10.11.0.7"
	p.RegisterSandbox(ip, id)
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				p.RegisterSandbox(ip, id)
				r := p.getRules(ip)
				if r.SandboxID != id {
					t.Error("registration changed")
				}
			}
		}()
	}
	wg.Wait()
}

func TestMiningReleasePreservesOverlappingRestrictions(t *testing.T) {
	for _, disposition := range []abuse.IncidentDisposition{abuse.IncidentReleased, abuse.IncidentIgnored} {
		t.Run(string(disposition), func(t *testing.T) {
			c, s, g, d := miningFixture()
			p := s.p
			c.Observe(p.SandboxID, p.HostIP, abuse.MiningEvidence{})
			i := d.items[0]
			s.change(func(p *abuse.SandboxPolicy) { p.Restricted = true })
			if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: disposition}); err != abuse.ErrMiningCleanupPending {
				t.Fatalf("remaining restriction lost local receipt: %v", err)
			}
			if !g.on[p.HostIP] || !c.Blocked(p.SandboxID, p.HostIP) {
				t.Fatal("remaining restriction lost containment")
			}
			s.change(func(p *abuse.SandboxPolicy) { p.Restricted = false })
			if err := c.Receipt(context.Background(), i, abuse.IncidentReceipt{Disposition: disposition}); err != nil {
				t.Fatal(err)
			}
			if g.on[p.HostIP] {
				t.Fatal("last restriction release did not clear containment")
			}
		})
	}
}
