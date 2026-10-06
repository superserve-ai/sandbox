package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

// MiningSubmitter persists incidents independently of the lossy flow audit sink.
type MiningSubmitter interface {
	Submit(abuse.MiningIncident) error
}

// MiningGate queues contained addresses for a current-assignment decision. It
// must not install unconditional address drops: pooled slots reuse addresses.
type MiningGate interface {
	SetContained(hostIP string, contained bool) error
}

type localMiningIncident struct {
	incident abuse.MiningIncident
	pending  bool
}
type miningStream struct {
	policy abuse.SandboxPolicy
	conn   net.Conn
}

// MiningContainment owns only egress/background work. Its locks and durable
// writes are never acquired by sandbox registration or lifecycle operations.
type MiningContainment struct {
	mu           sync.Mutex
	source       abuse.MiningPolicySource
	gate         MiningGate
	submit       MiningSubmitter
	log          zerolog.Logger
	incidents    map[string]localMiningIncident
	streams      map[string]map[*miningStream]struct{}
	observations miningObservations
	lastReport   time.Time
}

func NewMiningContainment(source abuse.MiningPolicySource, gate MiningGate, submit MiningSubmitter, log zerolog.Logger) *MiningContainment {
	return &MiningContainment{source: source, gate: gate, submit: submit, log: log.With().Str("component", "mining-containment").Logger(), incidents: make(map[string]localMiningIncident), streams: make(map[string]map[*miningStream]struct{})}
}

func enforceMining(p abuse.SandboxPolicy, ok bool) bool {
	return ok && p.Known && !p.Trusted && p.Mode == abuse.ModeEnforce && p.Assignment != "" && p.SandboxID != uuid.Nil && p.TeamID != uuid.Nil
}
func sameMiningAssignment(a, b abuse.SandboxPolicy) bool {
	return a.SandboxID == b.SandboxID && a.TeamID == b.TeamID && a.HostID == b.HostID && a.HostIP == b.HostIP && a.Assignment == b.Assignment
}
func incidentPolicy(i abuse.MiningIncident) abuse.SandboxPolicy {
	return abuse.SandboxPolicy{TeamPolicy: abuse.TeamPolicy{TeamID: i.TeamID}, SandboxID: i.SandboxID, HostID: i.HostID, HostIP: i.HostIP, Assignment: i.Assignment}
}

// Observe runs after a private mining match, before the offending connection
// can continue. Persistence runs outside the shared traffic lock. A failed
// durable write rolls back its tentative gate without closing existing streams.
func (c *MiningContainment) Observe(id uuid.UUID, ip string, evidence abuse.MiningEvidence) bool {
	return c.observeAssignment(id, ip, evidence, "")
}
func (c *MiningContainment) observeAssignment(id uuid.UUID, ip string, evidence abuse.MiningEvidence, assignment string) bool {
	i, reserved, blocked := c.reserveObservation(id, ip, evidence, assignment)
	if !reserved {
		return blocked
	}
	return c.persistObservation(i)
}
func (c *MiningContainment) persistObservation(i abuse.MiningIncident) bool {
	return c.completeObservation(i, c.submit.Submit(i))
}

// Raw packet decisions cannot wait for spool I/O. One bounded worker drains
// reservations; saturation rolls back only the new tentative reservation.
func (c *MiningContainment) observeQueued(id uuid.UUID, ip string, evidence abuse.MiningEvidence, assignment string, queue chan<- abuse.MiningIncident) bool {
	i, reserved, blocked := c.reserveObservation(id, ip, evidence, assignment)
	if !reserved {
		return blocked
	}
	select {
	case queue <- i:
		return true
	default:
		return c.completeObservation(i, fmt.Errorf("mining persistence queue full"))
	}
}
func (c *MiningContainment) runPersistence(ctx context.Context, queue <-chan abuse.MiningIncident) {
	// Run owns the producer and joins this worker before closing the gate.
	// On shutdown queued reservations have never been persisted and must be
	// rolled back; an in-flight durable write may finish but cannot close streams.
	defer func() {
		for {
			select {
			case i := <-queue:
				c.completeObservation(i, context.Canceled)
			default:
				return
			}
		}
	}()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case i := <-queue:
			if ctx.Err() != nil {
				c.completeObservation(i, ctx.Err())
				return
			}
			err := c.submit.Submit(i)
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			c.completeObservation(i, err)
		}
	}
}
func (c *MiningContainment) reserveObservation(id uuid.UUID, ip string, evidence abuse.MiningEvidence, assignment string) (abuse.MiningIncident, bool, bool) {
	c.mu.Lock()
	p, ok := c.source.MiningPolicy(id, ip)
	if assignment != "" && p.Assignment != assignment {
		c.observations.Unknown++
		c.mu.Unlock()
		return abuse.MiningIncident{}, false, false
	}
	if !enforceMining(p, ok) {
		switch {
		case !ok || !p.Known:
			c.observations.Unknown++
		case p.Trusted:
			c.observations.Trusted++
		case p.Mode == abuse.ModeObserve:
			c.observations.Observed++
		default:
			c.observations.Disabled++
		}
		c.mu.Unlock()
		return abuse.MiningIncident{}, false, false
	}
	if existing, exists := c.incidents[ip]; exists && sameMiningAssignment(p, incidentPolicy(existing.incident)) {
		c.mu.Unlock()
		return abuse.MiningIncident{}, false, true
	}
	if c.submit == nil || c.gate == nil {
		c.mu.Unlock()
		return abuse.MiningIncident{}, false, false
	}
	if err := c.gate.SetContained(ip, true); err != nil {
		c.observations.Failed++
		c.mu.Unlock()
		return abuse.MiningIncident{}, false, false
	}
	i := abuse.MiningIncident{ID: uuid.New(), SandboxID: id, TeamID: p.TeamID, HostID: p.HostID, HostIP: ip, Assignment: p.Assignment, Generation: p.Generation, ObservedAt: time.Now().UTC(), Evidence: evidence}
	c.incidents[ip] = localMiningIncident{incident: i, pending: true}
	c.mu.Unlock()

	return i, true, true
}
func (c *MiningContainment) completeObservation(i abuse.MiningIncident, err error) bool {
	id, ip := i.SandboxID, i.HostIP
	var p abuse.SandboxPolicy
	var ok bool

	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.incidents[ip]
	if !exists {
		return false
	}
	if current.incident.ID != i.ID {
		// Another durable receipt may now own the same assignment. The late
		// local result cannot remove it or change a replacement assignment.
		p, ok = c.source.MiningPolicy(id, ip)
		return !current.pending && enforceMining(p, ok) && sameMiningAssignment(p, incidentPolicy(i)) && sameMiningAssignment(p, incidentPolicy(current.incident))
	}
	if !current.pending {
		// An authoritative receipt may arrive before Submit returns. It already
		// made the current-state decision; a late local result must not undo it.
		p, ok = c.source.MiningPolicy(id, ip)
		return enforceMining(p, ok) && sameMiningAssignment(p, incidentPolicy(i))
	}
	p, ok = c.source.MiningPolicy(id, ip)
	if err != nil || !enforceMining(p, ok) || !sameMiningAssignment(p, incidentPolicy(i)) {
		delete(c.incidents, ip)
		_ = c.gate.SetContained(ip, false)
		if err != nil {
			c.observations.Failed++
		}
		return false
	}
	current.pending = false
	c.incidents[ip] = current
	c.observations.Contained++
	c.closeStreamsLocked(p)
	return true
}

// Blocked always resolves current attribution. A stale kernel queue entry for
// a reused IP can add latency but cannot isolate its new owner.
func (c *MiningContainment) Blocked(id uuid.UUID, ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.source.MiningPolicy(id, ip)
	if !enforceMining(p, ok) {
		return false
	}
	i, exists := c.incidents[ip]
	return exists && sameMiningAssignment(p, incidentPolicy(i.incident))
}

// Track closes the dial/containment race: registration and the local decision
// share one lock. Both ends are tracked so existing relays stop immediately.
func (c *MiningContainment) Track(id uuid.UUID, ip string, conn net.Conn) (func(), bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.source.MiningPolicy(id, ip)
	if !ok {
		p.SandboxID = id
		p.HostIP = ip
	}
	if i, exists := c.incidents[ip]; exists && !i.pending && enforceMining(p, ok) && sameMiningAssignment(p, incidentPolicy(i.incident)) {
		_ = conn.Close()
		return func() {}, false
	}
	s := &miningStream{policy: p, conn: conn}
	if c.streams[ip] == nil {
		c.streams[ip] = make(map[*miningStream]struct{})
	}
	c.streams[ip][s] = struct{}{}
	return func() {
		c.mu.Lock()
		delete(c.streams[ip], s)
		if len(c.streams[ip]) == 0 {
			delete(c.streams, ip)
		}
		c.mu.Unlock()
	}, true
}
func (c *MiningContainment) closeStreamsLocked(p abuse.SandboxPolicy) {
	if closer, ok := c.source.(interface{ CloseMiningStreams(abuse.SandboxPolicy) }); ok {
		closer.CloseMiningStreams(p)
	}
	for s := range c.streams[p.HostIP] {
		if sameMiningAssignment(s.policy, p) || (s.policy.Assignment == "" && s.policy.SandboxID == p.SandboxID && s.policy.HostIP == p.HostIP) {
			_ = s.conn.Close()
		}
	}
}

// Receipt is retryable and assignment-fenced. An old release cannot remove a
// new incident at the same pooled address, and an applied receipt cannot
// reconstruct containment against a new assignment after restart.
func (c *MiningContainment) Receipt(_ context.Context, i abuse.MiningIncident, r abuse.IncidentReceipt) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.source.MiningPolicy(i.SandboxID, i.HostIP)
	current, exists := c.incidents[i.HostIP]
	keep := (r.Disposition == abuse.IncidentApplied || ((r.Disposition == abuse.IncidentReleased || r.Disposition == abuse.IncidentIgnored) && p.Restricted)) && enforceMining(p, ok) && sameMiningAssignment(p, incidentPolicy(i))
	if exists && current.incident.ID != i.ID && !(r.Disposition == abuse.IncidentApplied && keep && sameMiningAssignment(p, incidentPolicy(current.incident))) {
		if c.assignmentRetired(i) {
			return abuse.ErrMiningLocalCleanupComplete
		}
		return nil
	}
	if keep {
		if err := c.gate.SetContained(i.HostIP, true); err != nil {
			return err
		}
		c.incidents[i.HostIP] = localMiningIncident{incident: i}
		c.closeStreamsLocked(p)
		if r.Disposition != abuse.IncidentApplied {
			return abuse.ErrMiningCleanupPending
		}
		return nil
	}
	if exists {
		if err := c.gate.SetContained(i.HostIP, false); err != nil {
			return err
		}
		delete(c.incidents, i.HostIP)
	}
	if c.assignmentRetired(i) {
		return abuse.ErrMiningLocalCleanupComplete
	}
	return nil
}

func (c *MiningContainment) assignmentRetired(i abuse.MiningIncident) bool {
	source, ok := c.source.(interface {
		AssignmentRetired(abuse.MiningIncident) bool
	})
	return ok && source.AssignmentRetired(i)
}

// Reconcile removes trust/mode/assignment changes even while receipt delivery
// is unavailable. Durable status owns release and expiry decisions.
func (c *MiningContainment) Reconcile() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.reportLocked()
	for ip, i := range c.incidents {
		p, ok := c.source.MiningPolicy(i.incident.SandboxID, ip)
		if enforceMining(p, ok) && sameMiningAssignment(p, incidentPolicy(i.incident)) {
			continue
		}
		if err := c.gate.SetContained(ip, false); err != nil {
			return fmt.Errorf("clear containment: %w", err)
		}
		delete(c.incidents, ip)
	}
	return nil
}

type miningObservations struct{ Unknown, Trusted, Observed, Disabled, Contained, Failed uint64 }

func (c *MiningContainment) reportLocked() {
	if c.observations == (miningObservations{}) || time.Since(c.lastReport) < 30*time.Second {
		return
	}
	o := c.observations
	c.observations = miningObservations{}
	c.lastReport = time.Now()
	c.log.Info().Uint64("unattributed", o.Unknown).Uint64("trusted", o.Trusted).Uint64("would_contain", o.Observed).Uint64("disabled", o.Disabled).Uint64("contained", o.Contained).Uint64("failed_open", o.Failed).Msg("mining observation summary")
}

// ObserveForAssignment fences observations buffered on a pre-existing proxy
// connection against a later replacement of that same sandbox and address.
func (c *MiningContainment) ObserveForAssignment(id uuid.UUID, ip string, evidence abuse.MiningEvidence, assignment string) bool {
	if assignment == "" {
		c.mu.Lock()
		c.observations.Unknown++
		c.mu.Unlock()
		return false
	}
	return c.observeAssignment(id, ip, evidence, assignment)
}
