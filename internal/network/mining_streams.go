package network

import (
	"net"
	"sync"

	"github.com/superserve-ai/sandbox/internal/abuse"
)

type earlyMiningStream struct {
	id           string
	registration *EgressRules
	conn         net.Conn
}
type miningProxyStreams struct {
	mu   sync.Mutex
	byIP map[string]map[*earlyMiningStream]struct{}
}

// EnableMiningStreamTracking is called before proxy listeners start. It also
// covers relays accepted while authoritative policy is still bootstrapping.
func (p *EgressProxy) EnableMiningStreamTracking() {
	p.miningStreams = &miningProxyStreams{byIP: make(map[string]map[*earlyMiningStream]struct{})}
}
func (p *EgressProxy) trackEarlyMining(ip, id string, registration *EgressRules, conn net.Conn) func() {
	s := p.miningStreams
	if s == nil || registration == nil {
		return func() {}
	}
	stream := &earlyMiningStream{id: id, registration: registration, conn: conn}
	s.mu.Lock()
	if s.byIP[ip] == nil {
		s.byIP[ip] = make(map[*earlyMiningStream]struct{})
	}
	s.byIP[ip][stream] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.byIP[ip], stream)
		if len(s.byIP[ip]) == 0 {
			delete(s.byIP, ip)
		}
		s.mu.Unlock()
	}
}
func (s *HostMiningSource) CloseMiningStreams(p abuse.SandboxPolicy) {
	current := s.ready.Load()
	if current == nil {
		return
	}
	published, ok := current.policies[p.SandboxID]
	if !ok || !sameMiningAssignment(p, published) {
		return
	}
	streams := s.proxy.miningStreams
	if streams == nil {
		return
	}
	registration := current.bindings[p.SandboxID]
	streams.mu.Lock()
	defer streams.mu.Unlock()
	for stream := range streams.byIP[p.HostIP] {
		if stream.id == p.SandboxID.String() && stream.registration == registration {
			_ = stream.conn.Close()
		}
	}
}
