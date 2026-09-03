package api

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

const abuseEnforcementTTL = time.Hour
const abuseEnforcementMaxEntries = 4096

// AbuseEnforcementStats is a point-in-time snapshot intended for asynchronous
// telemetry; lifecycle evaluation never collects it.
type AbuseEnforcementStats struct {
	DenyEntries         int
	DenyCapacity        int
	Utilization         float64
	TrustedTeams        int
	TTLEvictions        uint64
	CapacityEvictions   uint64
	AdmissionRejections uint64
	AlertLevel          string
}

type abuseEnforcementMode string

const (
	abuseEnforcementModeOff     abuseEnforcementMode = "off"
	abuseEnforcementModeObserve abuseEnforcementMode = "observe"
	abuseEnforcementModeEnforce abuseEnforcementMode = "enforce"
	// Short aliases keep configuration and tests readable.
	abuseModeOff     = abuseEnforcementModeOff
	abuseModeObserve = abuseEnforcementModeObserve
	abuseModeEnforce = abuseEnforcementModeEnforce
)

type abuseEnforcementRequest struct {
	TeamID uuid.UUID
	UserID uuid.UUID
	IP     string
	Domain string
	Action abuse.Action
}

type abuseEnforcementRestriction struct {
	SubjectType string // team, user, ip, or domain
	SubjectID   uuid.UUID
	Value       string
	Actions     []abuse.Action
	ExpiresAt   time.Time
}

type abuseEnforcementEntry struct {
	trusted                bool
	team, user, ip, domain map[string]time.Time
	lastUsed               time.Time
}

// abuseEnforcementSnapshot is immutable after publication. The activity
// pointers are the sole mutable fields and are updated atomically by readers
// to preserve the sliding TTL without republishing on every request.
type abuseEnforcementSnapshot struct {
	mode                abuseEnforcementMode
	entries             map[uuid.UUID]abuseEnforcementSnapshotEntry
	users, ips, domains abuseEnforcementGlobalIndex
	trustedTeams        map[uuid.UUID]struct{}
	globalLastUsed      map[uuid.UUID]*atomic.Int64
	globalAggregated    map[string]globalAggregate
	capacity            int
}

type globalAggregate struct {
	actions  map[string]time.Time
	activity *atomic.Int64
}

type abuseEnforcementSnapshotEntry struct {
	abuseEnforcementEntry
	activity *atomic.Int64
}

// Global restrictions are indexed by canonical subject and retain the team
// that supplied them so targeted replacement/invalidation can remove them.
type abuseEnforcementGlobalIndex map[string]map[uuid.UUID]map[string]time.Time

// abuseEnforcementCache is process-local by design. Its zero value is ready
// for use and misses always allow; authoritative state is populated by a
// background writer, never read from this request-path cache.
type abuseEnforcementCache struct {
	mu                  sync.RWMutex
	mode                abuseEnforcementMode
	entries             map[uuid.UUID]abuseEnforcementEntry
	users               abuseEnforcementGlobalIndex
	ips                 abuseEnforcementGlobalIndex
	domains             abuseEnforcementGlobalIndex
	globalUserKeys      map[uuid.UUID]map[string]struct{}
	globalIPKeys        map[uuid.UUID]map[string]struct{}
	globalDomainKeys    map[uuid.UUID]map[string]struct{}
	globalLastUsed      map[uuid.UUID]time.Time
	trustedTeams        map[uuid.UUID]struct{}
	ttlEvictions        atomic.Uint64
	capacityEvictions   atomic.Uint64
	admissionRejections atomic.Uint64
	maxEntries          int
	published           atomic.Pointer[abuseEnforcementSnapshot]
}

func (c *abuseEnforcementCache) SetMode(mode abuseEnforcementMode) {
	c.mu.Lock()
	c.mode = mode
	c.publishLocked()
	c.mu.Unlock()
}

func (c *abuseEnforcementCache) SetCapacity(n int) {
	if n < 1 {
		return
	}
	c.mu.Lock()
	c.maxEntries = n
	c.publishLocked()
	c.mu.Unlock()
}

func (c *abuseEnforcementCache) capacity() int {
	if c.maxEntries > 0 {
		return c.maxEntries
	}
	return abuseEnforcementMaxEntries
}

func (c *abuseEnforcementCache) Replace(teamID uuid.UUID, trusted bool, restrictions ...abuseEnforcementRestriction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publishLocked()
	if c.entries == nil {
		c.entries = make(map[uuid.UUID]abuseEnforcementEntry)
	}
	c.ensureGlobalMaps()
	if c.trustedTeams == nil {
		c.trustedTeams = make(map[uuid.UUID]struct{})
	}
	// Admission must not charge restrictions that are already expired. Stats
	// may be disabled, so reclaim them synchronously before sizing a write.
	c.pruneExpiredRestrictionsLocked(time.Now())
	admissionNow := time.Now()
	if trusted {
		c.trustedTeams[teamID] = struct{}{}
	} else {
		delete(c.trustedTeams, teamID)
	}
	previousCost := entryCost(c.entries[teamID])
	candidateCost := restrictionCost(teamID, restrictions, admissionNow)
	if candidateCost > c.capacity() {
		c.admissionRejections.Add(1)
		return
	}
	required := c.denyEntryCount() - previousCost + candidateCost
	for required > c.capacity() {
		if !c.evictOne(teamID) {
			c.admissionRejections.Add(1)
			return
		}
		required = c.denyEntryCount() - previousCost + candidateCost
	}
	c.removeGlobalOwner(teamID)
	e := abuseEnforcementEntry{trusted: trusted, lastUsed: time.Now()}
	if previous := c.published.Load(); previous != nil {
		if old, ok := previous.entries[teamID]; ok && old.activity != nil {
			old.activity.Store(e.lastUsed.UnixNano())
		}
	}
	for _, r := range restrictions {
		st := strings.ToLower(r.SubjectType)
		if !r.ExpiresAt.IsZero() && !admissionNow.Before(r.ExpiresAt) {
			continue
		}
		actions := normalizedLifecycleActions(r.Actions)
		if len(r.Actions) > 0 && len(actions) == 0 {
			continue
		}
		normalized := r
		normalized.Actions = actions
		var m *map[string]time.Time
		var global abuseEnforcementGlobalIndex
		var reverse map[uuid.UUID]map[string]struct{}
		switch st {
		case "team":
			m = &e.team
		case "user":
			m = &e.user
			global = c.users
			reverse = c.globalUserKeys
		case "ip":
			m = &e.ip
			global = c.ips
			reverse = c.globalIPKeys
		case "domain":
			m = &e.domain
			global = c.domains
			reverse = c.globalDomainKeys
		default:
			continue
		}
		key := r.Value
		if st == "team" {
			key = teamID.String()
		}
		if st == "user" {
			key = r.SubjectID.String()
		}
		if st == "ip" {
			if normalized, err := abuse.NormalizeIP(key); err != nil {
				continue
			} else {
				key = normalized
			}
		}
		if st == "domain" {
			if normalized, err := abuse.NormalizeDomain(key); err != nil {
				continue
			} else {
				key = normalized
			}
		}
		if global != nil {
			c.addGlobal(global, reverse, key, teamID, normalized)
		}
		if *m == nil {
			*m = make(map[string]time.Time)
		}
		if len(actions) == 0 {
			mergeExpiry(*m, key+"|*", r.ExpiresAt)
		} else {
			for _, a := range actions {
				mergeExpiry(*m, key+"|"+string(a), r.ExpiresAt)
			}
		}
	}
	if !trusted && entryCost(e) == 0 {
		delete(c.entries, teamID)
		delete(c.globalLastUsed, teamID)
		return
	}
	c.entries[teamID] = e
	if c.ownerHasGlobalRestrictions(teamID) {
		c.globalLastUsed[teamID] = time.Now()
	} else {
		delete(c.globalLastUsed, teamID)
	}
}

func (c *abuseEnforcementCache) Update(teamID uuid.UUID, trusted *bool, restrictions ...abuseEnforcementRestriction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publishLocked()
	if c.entries == nil {
		c.entries = make(map[uuid.UUID]abuseEnforcementEntry)
	}
	c.ensureGlobalMaps()
	if c.trustedTeams == nil {
		c.trustedTeams = make(map[uuid.UUID]struct{})
	}
	c.pruneExpiredRestrictionsLocked(time.Now())
	admissionNow := time.Now()
	if trusted != nil {
		if *trusted {
			c.trustedTeams[teamID] = struct{}{}
		} else {
			delete(c.trustedTeams, teamID)
		}
	}
	current := c.entries[teamID]
	delta := restrictionDelta(teamID, current, restrictions, admissionNow)
	if entryCost(current)+delta > c.capacity() {
		c.admissionRejections.Add(1)
		return
	}
	if delta > c.capacity() {
		c.admissionRejections.Add(1)
		return
	}
	for c.denyEntryCount()+delta > c.capacity() {
		if !c.evictOne(teamID) {
			c.admissionRejections.Add(1)
			return
		}
	}
	updated := abuseEnforcementEntry{
		trusted:  current.trusted,
		team:     cloneTimeMap(current.team),
		user:     cloneTimeMap(current.user),
		ip:       cloneTimeMap(current.ip),
		domain:   cloneTimeMap(current.domain),
		lastUsed: time.Now(),
	}
	if _, sticky := c.trustedTeams[teamID]; sticky {
		updated.trusted = true
	}
	if trusted != nil {
		updated.trusted = *trusted
	}
	if len(restrictions) == 0 {
		if !updated.trusted && entryCost(updated) == 0 {
			delete(c.entries, teamID)
			delete(c.globalLastUsed, teamID)
			return
		}
		c.entries[teamID] = updated
		if c.ownerHasGlobalRestrictions(teamID) {
			c.globalLastUsed[teamID] = updated.lastUsed
		} else {
			delete(c.globalLastUsed, teamID)
		}
		return
	}
	// Updates are additive for the targeted subjects; Replace remains the
	// primitive used when a reconciler has a complete snapshot.
	for _, r := range restrictions {
		st := strings.ToLower(r.SubjectType)
		if !r.ExpiresAt.IsZero() && !admissionNow.Before(r.ExpiresAt) {
			continue
		}
		actions := normalizedLifecycleActions(r.Actions)
		if len(r.Actions) > 0 && len(actions) == 0 {
			continue
		}
		normalized := r
		normalized.Actions = actions
		var m *map[string]time.Time
		var global abuseEnforcementGlobalIndex
		var reverse map[uuid.UUID]map[string]struct{}
		switch st {
		case "team":
			m = &updated.team
		case "user":
			m = &updated.user
			global = c.users
			reverse = c.globalUserKeys
		case "ip":
			m = &updated.ip
			global = c.ips
			reverse = c.globalIPKeys
		case "domain":
			m = &updated.domain
			global = c.domains
			reverse = c.globalDomainKeys
		default:
			continue
		}
		key := r.Value
		if st == "team" {
			key = teamID.String()
		}
		if st == "user" {
			key = r.SubjectID.String()
		}
		if st == "ip" {
			if normalized, err := abuse.NormalizeIP(key); err != nil {
				continue
			} else {
				key = normalized
			}
		}
		if st == "domain" {
			if normalized, err := abuse.NormalizeDomain(key); err != nil {
				continue
			} else {
				key = normalized
			}
		}
		if global != nil {
			c.addGlobal(global, reverse, key, teamID, normalized)
		}
		if *m == nil {
			*m = make(map[string]time.Time)
		}
		if len(actions) == 0 {
			mergeExpiry(*m, key+"|*", r.ExpiresAt)
		} else {
			for _, a := range actions {
				mergeExpiry(*m, key+"|"+string(a), r.ExpiresAt)
			}
		}
	}
	if !updated.trusted && entryCost(updated) == 0 {
		delete(c.entries, teamID)
		delete(c.globalLastUsed, teamID)
		return
	}
	c.entries[teamID] = updated
	if c.ownerHasGlobalRestrictions(teamID) {
		c.globalLastUsed[teamID] = updated.lastUsed
	} else {
		delete(c.globalLastUsed, teamID)
	}
}

func (c *abuseEnforcementCache) Invalidate(teamID uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publishLocked()
	delete(c.entries, teamID)
	c.removeGlobalOwner(teamID)
	delete(c.globalLastUsed, teamID)
	delete(c.trustedTeams, teamID)
}

// Evaluate returns allowed and whether a restriction matched. It performs no
// I/O and bounds work to the indexed subjects for the request.
func (c *abuseEnforcementCache) Evaluate(req abuseEnforcementRequest) (bool, bool) {
	s := c.published.Load()
	if s == nil {
		return true, false
	}
	mode := s.mode
	if _, trusted := s.trustedTeams[req.TeamID]; trusted {
		return true, false
	}
	e, ok := s.entries[req.TeamID]
	writerClock := false
	var activity *atomic.Int64
	if ok {
		activity = e.activity
		lastUsed := e.lastUsed
		// Keep compatibility with internal maintenance/tests that adjust the
		// writer-side clock under the cache lock without publishing.
		if c.mu.TryRLock() {
			globalClock, hasGlobalClock := c.globalLastUsed[req.TeamID]
			legacyExpired := hasGlobalClock && time.Since(globalClock) >= abuseEnforcementTTL
			if current, exists := c.entries[req.TeamID]; exists && legacyExpired && current.lastUsed.Before(lastUsed) {
				lastUsed = current.lastUsed
				writerClock = true
			}
			if global, exists := c.globalLastUsed[req.TeamID]; exists && global.Before(lastUsed) {
				lastUsed = global
				writerClock = true
				atomicMax(activity, global.UnixNano())
			}
			c.mu.RUnlock()
		}
		if !writerClock {
			if v := activity.Load(); v > 0 {
				lastUsed = time.Unix(0, v)
			}
		}
		if time.Since(lastUsed) >= abuseEnforcementTTL {
			ok = false
		}
	}
	if mode == "" || mode == abuseEnforcementModeOff {
		return true, false
	}
	if writerClock && !ok {
		return true, false
	}
	ip, _ := abuse.NormalizeIP(req.IP)
	domain, _ := abuse.NormalizeDomain(req.Domain)
	keyUser := req.UserID.String()
	now := time.Now()
	localMatched := ok && hasAction(e.team, req.TeamID.String()+"|"+string(req.Action), now)
	userMatched := hasGlobal(s, "u|", keyUser, req.Action, now)
	ipMatched := hasGlobal(s, "i|", ip, req.Action, now)
	domainMatched := hasGlobal(s, "d|", domain, req.Action, now)
	matched := localMatched || userMatched || ipMatched || domainMatched
	if localMatched {
		atomicMax(activity, now.UnixNano())
	}
	if !matched {
		return true, false
	}
	if mode == abuseEnforcementModeObserve {
		return true, true
	}
	return false, true
}

func (c *abuseEnforcementCache) publishLocked() {
	s := &abuseEnforcementSnapshot{mode: c.mode, capacity: c.capacity(), entries: make(map[uuid.UUID]abuseEnforcementSnapshotEntry, len(c.entries)), users: cloneGlobal(c.users), ips: cloneGlobal(c.ips), domains: cloneGlobal(c.domains), trustedTeams: make(map[uuid.UUID]struct{}, len(c.trustedTeams)), globalLastUsed: make(map[uuid.UUID]*atomic.Int64), globalAggregated: make(map[string]globalAggregate)}
	previous := c.published.Load()
	for id, e := range c.entries {
		var a *atomic.Int64
		if previous != nil {
			if old, ok := previous.entries[id]; ok && old.activity != nil && equalEntryRestrictions(e, old.abuseEnforcementEntry) {
				a = old.activity
			}
		}
		if a == nil {
			a = &atomic.Int64{}
			a.Store(e.lastUsed.UnixNano())
		}
		atomicMax(a, e.lastUsed.UnixNano())
		e.team = cloneTimeMap(e.team)
		e.user = cloneTimeMap(e.user)
		e.ip = cloneTimeMap(e.ip)
		e.domain = cloneTimeMap(e.domain)
		s.entries[id] = abuseEnforcementSnapshotEntry{abuseEnforcementEntry: e, activity: a}
	}
	for id := range c.trustedTeams {
		s.trustedTeams[id] = struct{}{}
	}
	for id := range c.globalLastUsed {
		if entry, ok := s.entries[id]; ok {
			s.globalLastUsed[id] = entry.activity
		} else if previous != nil {
			if old, ok := previous.globalLastUsed[id]; ok {
				a := &atomic.Int64{}
				a.Store(old.Load())
				s.globalLastUsed[id] = a
			}
		}
	}
	aggregateWriterUsed := make(map[string]time.Time)
	for prefix, index := range map[string]abuseEnforcementGlobalIndex{"u|": s.users, "i|": s.ips, "d|": s.domains} {
		for key, owners := range index {
			for owner, actions := range owners {
				id := prefix + key
				out := s.globalAggregated[id]
				if out.actions == nil {
					out.actions = make(map[string]time.Time)
				}
				for action, expiry := range actions {
					mergeExpiry(out.actions, action, expiry)
				}
				if entry, ok := c.entries[owner]; ok && entry.lastUsed.After(aggregateWriterUsed[id]) {
					aggregateWriterUsed[id] = entry.lastUsed
				}
				if used, ok := c.globalLastUsed[owner]; ok && used.After(aggregateWriterUsed[id]) {
					aggregateWriterUsed[id] = used
				}
				s.globalAggregated[id] = out
			}
		}
	}
	publishNow := time.Now().UnixNano()
	for id, aggregate := range s.globalAggregated {
		var activity *atomic.Int64
		if previous != nil {
			if old, exists := previous.globalAggregated[id]; exists && old.activity != nil && equalExpiryMaps(old.actions, aggregate.actions) {
				activity = old.activity
			}
		}
		if activity == nil {
			activity = &atomic.Int64{}
			activity.Store(publishNow)
		}
		if writerUsed := aggregateWriterUsed[id].UnixNano(); writerUsed > 0 {
			atomicMax(activity, writerUsed)
		}
		aggregate.activity = activity
		s.globalAggregated[id] = aggregate
	}
	c.published.Store(s)
}

func equalEntryRestrictions(a, b abuseEnforcementEntry) bool {
	return equalExpiryMaps(a.team, b.team) && equalExpiryMaps(a.user, b.user) && equalExpiryMaps(a.ip, b.ip) && equalExpiryMaps(a.domain, b.domain)
}

func cloneGlobal(src abuseEnforcementGlobalIndex) abuseEnforcementGlobalIndex {
	if len(src) == 0 {
		return nil
	}
	dst := make(abuseEnforcementGlobalIndex, len(src))
	for key, owners := range src {
		om := make(map[uuid.UUID]map[string]time.Time, len(owners))
		for owner, acts := range owners {
			om[owner] = cloneTimeMap(acts)
		}
		dst[key] = om
	}
	return dst
}

func (c *abuseEnforcementCache) ensureGlobalMaps() {
	if c.users == nil {
		c.users = make(abuseEnforcementGlobalIndex)
	}
	if c.ips == nil {
		c.ips = make(abuseEnforcementGlobalIndex)
	}
	if c.domains == nil {
		c.domains = make(abuseEnforcementGlobalIndex)
	}
	if c.globalLastUsed == nil {
		c.globalLastUsed = make(map[uuid.UUID]time.Time)
	}
	if c.globalUserKeys == nil {
		c.globalUserKeys = make(map[uuid.UUID]map[string]struct{})
	}
	if c.globalIPKeys == nil {
		c.globalIPKeys = make(map[uuid.UUID]map[string]struct{})
	}
	if c.globalDomainKeys == nil {
		c.globalDomainKeys = make(map[uuid.UUID]map[string]struct{})
	}
	if c.trustedTeams == nil {
		c.trustedTeams = make(map[uuid.UUID]struct{})
	}
}

func (c *abuseEnforcementCache) addGlobal(index abuseEnforcementGlobalIndex, reverse map[uuid.UUID]map[string]struct{}, key string, owner uuid.UUID, r abuseEnforcementRestriction) {
	c.ensureGlobalMaps()
	if index[key] == nil {
		index[key] = make(map[uuid.UUID]map[string]time.Time)
	}
	if index[key][owner] == nil {
		index[key][owner] = make(map[string]time.Time)
	}
	if reverse[owner] == nil {
		reverse[owner] = make(map[string]struct{})
	}
	reverse[owner][key] = struct{}{}
	if len(r.Actions) == 0 {
		mergeExpiry(index[key][owner], "*", r.ExpiresAt)
	} else {
		for _, a := range r.Actions {
			mergeExpiry(index[key][owner], string(a), r.ExpiresAt)
		}
	}
}

func (c *abuseEnforcementCache) removeGlobalOwner(owner uuid.UUID) {
	for key := range c.globalUserKeys[owner] {
		if owners := c.users[key]; owners != nil {
			delete(owners, owner)
			if len(owners) == 0 {
				delete(c.users, key)
			}
		}
	}
	for key := range c.globalIPKeys[owner] {
		if owners := c.ips[key]; owners != nil {
			delete(owners, owner)
			if len(owners) == 0 {
				delete(c.ips, key)
			}
		}
	}
	for key := range c.globalDomainKeys[owner] {
		if owners := c.domains[key]; owners != nil {
			delete(owners, owner)
			if len(owners) == 0 {
				delete(c.domains, key)
			}
		}
	}
	delete(c.globalUserKeys, owner)
	delete(c.globalIPKeys, owner)
	delete(c.globalDomainKeys, owner)
}

func (c *abuseEnforcementCache) ownerHasGlobalRestrictions(owner uuid.UUID) bool {
	return len(c.globalUserKeys[owner]) > 0 || len(c.globalIPKeys[owner]) > 0 || len(c.globalDomainKeys[owner]) > 0
}

func cloneTimeMap(src map[string]time.Time) map[string]time.Time {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]time.Time, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (c *abuseEnforcementCache) evictOne(exclude uuid.UUID) bool {
	var victim uuid.UUID
	var oldest time.Time
	for id, entry := range c.entries {
		if id == exclude {
			continue
		}
		if _, trusted := c.trustedTeams[id]; trusted {
			continue
		}
		used := c.effectiveOwnerActivity(id, entry)
		if victim == uuid.Nil || used.Before(oldest) {
			victim, oldest = id, used
		}
	}
	if victim != uuid.Nil {
		delete(c.entries, victim)
		c.removeGlobalOwner(victim)
		delete(c.globalLastUsed, victim)
		c.capacityEvictions.Add(1)
		return true
	}
	return false
}

// effectiveOwnerActivity combines local request activity with activity from
// any shared global subject restrictions owned by the team. It is used only
// by bounded writer-side eviction, never by lifecycle evaluation.
func (c *abuseEnforcementCache) effectiveOwnerActivity(owner uuid.UUID, entry abuseEnforcementEntry) time.Time {
	used := entry.lastUsed
	if snap := c.published.Load(); snap != nil {
		if current, ok := snap.entries[owner]; ok && current.activity.Load() > 0 {
			used = time.Unix(0, current.activity.Load())
		}
		for prefix, keys := range map[string]map[uuid.UUID]map[string]struct{}{"u|": c.globalUserKeys, "i|": c.globalIPKeys, "d|": c.globalDomainKeys} {
			for key := range keys[owner] {
				if aggregate, ok := snap.globalAggregated[prefix+key]; ok && aggregate.activity != nil {
					if activity := time.Unix(0, aggregate.activity.Load()); activity.After(used) {
						used = activity
					}
				}
			}
		}
	}
	if global := c.globalLastUsed[owner]; !global.IsZero() && global.After(used) {
		used = global
	}
	return used
}

// Stats returns cache-pressure state for background telemetry and alerting.
func (c *abuseEnforcementCache) Stats() AbuseEnforcementStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publishLocked()
	c.pruneExpiredRestrictionsLocked(time.Now())
	c.cleanupExpiredLocked(time.Now())
	deny := c.denyEntryCount()
	return AbuseEnforcementStats{
		DenyEntries: deny, DenyCapacity: c.capacity(),
		Utilization:  float64(deny) / float64(c.capacity()),
		TrustedTeams: len(c.trustedTeams), TTLEvictions: c.ttlEvictions.Load(), CapacityEvictions: c.capacityEvictions.Load(), AdmissionRejections: c.admissionRejections.Load(),
	}
}

func (c *abuseEnforcementCache) pruneExpiredRestrictionsLocked(now time.Time) {
	for id, e := range c.entries {
		for _, m := range []*map[string]time.Time{&e.team, &e.user, &e.ip, &e.domain} {
			for key, expiry := range *m {
				if !expiry.IsZero() && !now.Before(expiry) {
					delete(*m, key)
				}
			}
		}
		if !e.trusted && entryCost(e) == 0 {
			delete(c.entries, id)
			c.removeGlobalOwner(id)
			delete(c.globalLastUsed, id)
		} else {
			c.entries[id] = e
		}
	}
	for _, index := range []abuseEnforcementGlobalIndex{c.users, c.ips, c.domains} {
		for key, owners := range index {
			for owner, actions := range owners {
				for action, expiry := range actions {
					if !expiry.IsZero() && !now.Before(expiry) {
						delete(actions, action)
					}
				}
				if len(actions) == 0 {
					delete(owners, owner)
				}
			}
			if len(owners) == 0 {
				delete(index, key)
			}
		}
	}
	c.globalUserKeys, c.globalIPKeys, c.globalDomainKeys = make(map[uuid.UUID]map[string]struct{}), make(map[uuid.UUID]map[string]struct{}), make(map[uuid.UUID]map[string]struct{})
	for _, pair := range []struct {
		index   abuseEnforcementGlobalIndex
		reverse map[uuid.UUID]map[string]struct{}
	}{{c.users, c.globalUserKeys}, {c.ips, c.globalIPKeys}, {c.domains, c.globalDomainKeys}} {
		for key, owners := range pair.index {
			for owner := range owners {
				if pair.reverse[owner] == nil {
					pair.reverse[owner] = make(map[string]struct{})
				}
				pair.reverse[owner][key] = struct{}{}
			}
		}
	}
}

func (c *abuseEnforcementCache) cleanupExpiredLocked(now time.Time) {
	for teamID, entry := range c.entries {
		lastUsed := entry.lastUsed
		if snap := c.published.Load(); snap != nil {
			if current, ok := snap.entries[teamID]; ok && current.activity.Load() > 0 {
				lastUsed = time.Unix(0, current.activity.Load())
			}
		}
		if globalUsed, exists := c.globalLastUsed[teamID]; exists && globalUsed.After(lastUsed) {
			lastUsed = globalUsed
		}
		if now.Sub(lastUsed) < abuseEnforcementTTL {
			continue
		}
		if c.globalOwnerRecentlyUsed(teamID, now) {
			continue
		}
		delete(c.entries, teamID)
		c.removeGlobalOwner(teamID)
		delete(c.globalLastUsed, teamID)
		c.ttlEvictions.Add(1)
	}
}

func (c *abuseEnforcementCache) globalOwnerRecentlyUsed(owner uuid.UUID, now time.Time) bool {
	s := c.published.Load()
	if s == nil {
		return false
	}
	for prefix, keys := range map[string]map[uuid.UUID]map[string]struct{}{"u|": c.globalUserKeys, "i|": c.globalIPKeys, "d|": c.globalDomainKeys} {
		for key := range keys[owner] {
			if a, ok := s.globalAggregated[prefix+key]; ok && a.activity != nil && now.Sub(time.Unix(0, a.activity.Load())) < abuseEnforcementTTL {
				return true
			}
		}
	}
	return false
}

func (c *abuseEnforcementCache) denyEntryCount() int {
	count := 0
	for _, entry := range c.entries {
		count += len(entry.team) + len(entry.user) + len(entry.ip) + len(entry.domain)
	}
	return count
}

func entryCost(entry abuseEnforcementEntry) int {
	return len(entry.team) + len(entry.user) + len(entry.ip) + len(entry.domain)
}

func restrictionCost(teamID uuid.UUID, restrictions []abuseEnforcementRestriction, now time.Time) int {
	keys := make(map[string]struct{})
	for _, r := range restrictions {
		st, entries, ok := normalizedRestrictionEntriesAt(teamID, r, now)
		if !ok {
			continue
		}
		for _, key := range entries {
			keys[st+"|"+key] = struct{}{}
		}
	}
	return len(keys)
}

func restrictionDelta(teamID uuid.UUID, current abuseEnforcementEntry, restrictions []abuseEnforcementRestriction, now time.Time) int {
	seen := make(map[string]struct{})
	delta := 0
	for _, r := range restrictions {
		st, entries, ok := normalizedRestrictionEntriesAt(teamID, r, now)
		if !ok {
			continue
		}
		var existing map[string]time.Time
		switch st {
		case "team":
			existing = current.team
		case "user":
			existing = current.user
		case "ip":
			existing = current.ip
		case "domain":
			existing = current.domain
		}
		for _, key := range entries {
			signature := st + "|" + key
			if _, ok := seen[signature]; ok {
				continue
			}
			seen[signature] = struct{}{}
			if _, exists := existing[key]; !exists {
				delta++
			}
		}
	}
	return delta
}

func normalizedRestrictionEntries(teamID uuid.UUID, r abuseEnforcementRestriction) (string, []string, bool) {
	return normalizedRestrictionEntriesAt(teamID, r, time.Now())
}

func normalizedRestrictionEntriesAt(teamID uuid.UUID, r abuseEnforcementRestriction, now time.Time) (string, []string, bool) {
	if !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
		return "", nil, false
	}
	st := strings.ToLower(r.SubjectType)
	key := r.Value
	switch st {
	case "team":
		key = teamID.String()
	case "user":
		key = r.SubjectID.String()
	case "ip":
		normalized, err := abuse.NormalizeIP(key)
		if err != nil {
			return "", nil, false
		}
		key = normalized
	case "domain":
		normalized, err := abuse.NormalizeDomain(key)
		if err != nil {
			return "", nil, false
		}
		key = normalized
	default:
		return "", nil, false
	}
	if len(r.Actions) == 0 {
		return st, []string{key + "|*"}, true
	}
	actions := normalizedLifecycleActions(r.Actions)
	if len(actions) == 0 {
		return "", nil, false
	}
	entries := make([]string, 0, len(actions))
	seen := make(map[string]struct{})
	for _, action := range actions {
		entry := key + "|" + string(action)
		if _, exists := seen[entry]; !exists {
			seen[entry] = struct{}{}
			entries = append(entries, entry)
		}
	}
	return st, entries, len(entries) > 0
}

func normalizedLifecycleActions(actions []abuse.Action) []abuse.Action {
	if len(actions) == 0 {
		return nil
	}
	result := make([]abuse.Action, 0, len(actions))
	seen := make(map[abuse.Action]struct{}, len(actions))
	for _, action := range actions {
		if action != abuse.ActionCreate && action != abuse.ActionResume {
			continue
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		result = append(result, action)
	}
	return result
}

func mergeExpiry(m map[string]time.Time, key string, expiry time.Time) {
	if existing, ok := m[key]; ok {
		if existing.IsZero() {
			return
		}
		if expiry.IsZero() || expiry.After(existing) {
			m[key] = expiry
		}
		return
	}
	m[key] = expiry
}

func equalExpiryMaps(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for key, expiry := range a {
		if other, ok := b[key]; !ok || !other.Equal(expiry) {
			return false
		}
	}
	return true
}

func atomicMax(value *atomic.Int64, candidate int64) {
	for {
		current := value.Load()
		if candidate <= current || value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func hasGlobal(s *abuseEnforcementSnapshot, prefix, key string, action abuse.Action, now time.Time) bool {
	actions := s.globalAggregated[prefix+key]
	if actions.activity == nil || now.Sub(time.Unix(0, actions.activity.Load())) >= abuseEnforcementTTL {
		return false
	}
	if expires, ok := actions.actions[string(action)]; ok && (expires.IsZero() || now.Before(expires)) {
		atomicMax(actions.activity, now.UnixNano())
		return true
	}
	if expires, ok := actions.actions["*"]; ok && (expires.IsZero() || now.Before(expires)) {
		atomicMax(actions.activity, now.UnixNano())
		return true
	}
	return false
}

func hasAction(m map[string]time.Time, key string, now time.Time) bool {
	if expires, ok := m[key]; ok && (expires.IsZero() || now.Before(expires)) {
		return true
	}
	// Action-agnostic restrictions are stored as <subject>|*, so the
	// wildcard lookup must replace (rather than append to) the action suffix.
	if subject, _, found := strings.Cut(key, "|"); found {
		if expires, ok := m[subject+"|*"]; ok && (expires.IsZero() || now.Before(expires)) {
			return true
		}
	}
	return false
}
