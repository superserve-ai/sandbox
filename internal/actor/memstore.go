package actor

import (
	"context"
	"sync"
	"time"
)

// MemStore is an in-memory Store. It is the reference implementation of the
// lease/fencing semantics (the bar the Postgres store must match) and is used
// directly for tests and single-node/dev runs. Every method takes the lock for
// the whole operation, which is what makes each lease transition atomic — the
// same guarantee the Postgres store gets from a single UPDATE.
type MemStore struct {
	mu     sync.Mutex
	byID   map[string]*Actor
	byName map[string]string // "team\x00name" -> id
	idSeq  int64
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{byID: map[string]*Actor{}, byName: map[string]string{}}
}

func nameKey(teamID, name string) string { return teamID + "\x00" + name }

func (s *MemStore) GetOrCreate(_ context.Context, teamID, name string, defaults Actor, now time.Time) (Actor, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byName[nameKey(teamID, name)]; ok {
		return *s.byID[id], false, nil
	}
	s.idSeq++
	a := defaults
	a.ID = "act-" + itoa(s.idSeq)
	a.TeamID = teamID
	a.Name = name
	if a.Tier == "" {
		a.Tier = TierCold
	}
	a.CreatedAt = now
	a.UpdatedAt = now
	cp := a
	s.byID[a.ID] = &cp
	s.byName[nameKey(teamID, name)] = a.ID
	return a, true, nil
}

func (s *MemStore) Get(_ context.Context, id string) (Actor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return Actor{}, ErrNotFound
	}
	return *a, nil
}

func (s *MemStore) TryAcquireLease(_ context.Context, id, holder string, now time.Time, ttl time.Duration) (LeaseOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return LeaseOutcome{}, ErrNotFound
	}
	// Grant iff free, expired, or already ours.
	free := a.LeaseHolder == "" || !now.Before(a.LeaseExpires)
	if !free && a.LeaseHolder != holder {
		return LeaseOutcome{Granted: false, CurrentHolder: a.LeaseHolder}, nil
	}
	// Increment the fence on every (re)grant. A holder reacquiring after expiry
	// gets a NEW token, which fences any in-flight write from its previous life.
	a.LeaseToken++
	a.LeaseHolder = holder
	a.LeaseExpires = now.Add(ttl)
	a.UpdatedAt = now
	return LeaseOutcome{Granted: true, Token: a.LeaseToken, Expires: a.LeaseExpires}, nil
}

func (s *MemStore) RenewLease(_ context.Context, id, holder string, token int64, now time.Time, ttl time.Duration) (LeaseOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return LeaseOutcome{}, ErrNotFound
	}
	// Renew only if we still hold it with the same token and it hasn't lapsed.
	if a.LeaseHolder != holder || a.LeaseToken != token || !now.Before(a.LeaseExpires) {
		return LeaseOutcome{Granted: false, CurrentHolder: a.LeaseHolder}, ErrFenced
	}
	a.LeaseExpires = now.Add(ttl)
	a.UpdatedAt = now
	return LeaseOutcome{Granted: true, Token: a.LeaseToken, Expires: a.LeaseExpires}, nil
}

func (s *MemStore) ReleaseLease(_ context.Context, id, holder string, token int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	// Only the current holder with the current token can release. Otherwise the
	// lease was already stolen/expired — releasing is a no-op (idempotent).
	if a.LeaseHolder == holder && a.LeaseToken == token {
		a.LeaseHolder = ""
		a.LeaseExpires = time.Time{}
	}
	return nil
}

func (s *MemStore) CheckFence(_ context.Context, id string, token int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if a.LeaseToken != token || a.LeaseHolder == "" || !now.Before(a.LeaseExpires) {
		return ErrFenced
	}
	return nil
}

func (s *MemStore) SetTier(_ context.Context, id string, tier Tier, host string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	a.Tier = tier
	if host != "" {
		a.HomeHost = host
	}
	a.UpdatedAt = now
	return nil
}

// itoa is a tiny dependency-free int64→string for ids.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
