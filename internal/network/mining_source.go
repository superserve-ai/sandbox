package network

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/db"
)

type miningAssignments map[uuid.UUID]abuse.SandboxPolicy
type miningReady struct {
	policies miningAssignments
	bindings map[uuid.UUID]*EgressRules
}

// HostMiningSource joins background database ownership with the existing
// host-local registration. Neither side alone can authorize an incident.
type HostMiningSource struct {
	q                   db.DBTX
	teams               abuse.TeamPolicySource
	proxy               *EgressProxy
	hostID, incarnation string
	cur                 atomic.Pointer[miningAssignments]
	ready               atomic.Pointer[miningReady]
	curBindings         map[uuid.UUID]*EgressRules
	incarnationOf       func(uuid.UUID) (string, bool)
	disabled            atomic.Bool
}

func NewHostMiningSource(q db.DBTX, teams abuse.TeamPolicySource, proxy *EgressProxy, hostID, incarnation string) *HostMiningSource {
	return &HostMiningSource{q: q, teams: teams, proxy: proxy, hostID: hostID, incarnation: incarnation}
}

// Refresh and the following gate synchronization have one serialized background owner.
func (s *HostMiningSource) Refresh(ctx context.Context) error {
	rows, err := s.q.Query(ctx, `SELECT id,team_id,host(ip_address),routing_version FROM sandbox WHERE host_id=$1 AND destroyed_at IS NULL AND ip_address IS NOT NULL AND (status IN ('starting','active','pausing','resuming','migrating') OR pause_op_id IS NOT NULL) LIMIT $2`, s.hostID, MaxSlots+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	assignments := make(miningAssignments)
	bindings := make(map[uuid.UUID]*EgressRules)
	for rows.Next() {
		var id, team uuid.UUID
		var ip string
		var version int64
		if err := rows.Scan(&id, &team, &ip, &version); err != nil {
			return err
		}
		if len(assignments) >= MaxSlots {
			return fmt.Errorf("host assignment capacity exceeded")
		}
		assignment := fmt.Sprintf("%s/%s/%s/%d", s.incarnation, id, ip, version)
		if s.incarnationOf != nil {
			if key, known := s.incarnationOf(id); known {
				assignment += "/" + key
			} else {
				assignment = ""
			}
		}
		localID, registration := s.proxy.miningRegistration(ip)
		if localID == id.String() {
			bindings[id] = registration
		}
		assignments[id] = abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: team}, SandboxID: id, HostID: s.hostID, HostIP: ip, Assignment: assignment}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.curBindings = bindings
	s.cur.Store(&assignments)
	return nil
}
func (s *HostMiningSource) MiningPolicy(id uuid.UUID, ip string) (abuse.SandboxPolicy, bool) {
	if s.disabled.Load() {
		return abuse.SandboxPolicy{}, false
	}
	current := s.ready.Load()
	if current == nil {
		return abuse.SandboxPolicy{}, false
	}
	p, ok := current.policies[id]
	if !ok || p.HostIP != ip {
		return abuse.SandboxPolicy{}, false
	}
	localID, registration := s.proxy.miningRegistration(ip)
	if localID != id.String() || registration == nil || current.bindings[id] != registration {
		return abuse.SandboxPolicy{}, false
	}
	p.TeamPolicy = s.teams.TeamPolicy(p.TeamID)
	return p, p.Known
}
func (p *EgressProxy) MiningSandbox(ip string) (uuid.UUID, bool) {
	r := p.getRules(ip)
	if r == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(r.SandboxID)
	return id, err == nil
}

// Disable prevents escalation after its host attribution guard is lost.
func (s *HostMiningSource) Disable() { s.disabled.Store(true) }

// AssignmentRetired uses authoritative ownership, never policy readiness or
// transient host reattachment, to decide whether a persisted local receipt can
// be discarded while its team restriction remains durable.
func (s *HostMiningSource) AssignmentRetired(i abuse.MiningIncident) bool {
	current := s.cur.Load()
	if current == nil {
		return false
	}
	p, exists := (*current)[i.SandboxID]
	return !exists || (p.Assignment != "" && !sameMiningAssignment(p, incidentPolicy(i)))
}

// SetIncarnationResolver supplies the manager's already-persisted lifecycle
// key. It runs only during background projection, never on lifecycle or egress.
func (s *HostMiningSource) SetIncarnationResolver(fn func(uuid.UUID) (string, bool)) {
	s.incarnationOf = fn
}
func (p *EgressProxy) miningRegistration(ip string) (string, *EgressRules) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r := p.rules[ip]
	if r == nil {
		return "", nil
	}
	return r.SandboxID, r
}
