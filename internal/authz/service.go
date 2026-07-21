package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/db"
)

var (
	ErrPermissionDenied   = errors.New("permission denied")
	ErrSessionNotEligible = errors.New("platform admin session not eligible")
	ErrScopeMismatch      = errors.New("permission scope does not match request scope")
)

// SessionClaims captures the subset of session identity information needed to
// validate platform-admin eligibility.
type SessionClaims struct {
	Provider      string
	Email         string
	EmailVerified *bool
}

// AuditEvent is a generic, append-only audit record for sensitive actions.
type AuditEvent struct {
	ActorUserID  *uuid.UUID
	TargetUserID *uuid.UUID
	TeamID       *uuid.UUID
	EventType    string
	OldValue     []byte
	NewValue     []byte
	Metadata     []byte
}

// Service evaluates RBAC permissions against the database. Instances from New
// are plain pass-throughs — safe for per-transaction use, where checks must see
// the tx's own state and honor the caller's context. NewCached adds the
// permission cache and is meant for one process-lifetime singleton.
type Service struct {
	store db.DBTX
	cache *teamPermCache // nil = uncached (per-tx instances)
}

func New(store db.DBTX) *Service {
	return &Service{store: store}
}

// NewCached returns a Service that caches positive team-permission results for
// teamPermCacheTTL. Use for one process-lifetime singleton only.
func NewCached(store db.DBTX) *Service {
	return &Service{store: store, cache: &teamPermCache{
		ttl: teamPermCacheTTL,
		m:   make(map[teamPermCacheKey]teamPermCacheEntry),
		gen: make(map[uuid.UUID]uint64),
	}}
}

// teamPermCache caches positive results only, so denials always re-query and
// probes can't grow the map. One mutex guards both maps (mirrors apiKeyCache);
// gen is a per-team generation that InvalidateTeam bumps so stale entries fail
// the read check and in-flight stores from pre-bump queries are discarded. gen
// is only ever written on invalidation, so it stays bounded by mutated teams.
type teamPermCache struct {
	ttl   time.Duration
	group singleflight.Group // coalesces concurrent identical misses
	mu    sync.Mutex
	m     map[teamPermCacheKey]teamPermCacheEntry
	gen   map[uuid.UUID]uint64
}

type teamPermCacheKey struct {
	userID     uuid.UUID
	teamID     uuid.UUID
	permission string
}

type teamPermCacheEntry struct {
	expiry     time.Time
	epoch      uint64
	refreshing bool // a stale-serve refresh is in flight; cleared when the entry is replaced or the refresh fails
}

// teamPermResult is the singleflight payload: the grant, the generation
// observed before the query, and the query start time (expiry is stamped from
// it so a slow query can't extend the revocation window past the TTL).
type teamPermResult struct {
	allowed bool
	epoch   uint64
	start   time.Time
}

// teamPermCacheTTL plus teamPermStaleGrace is the revocation contract: a role
// or membership change takes effect within ttl+grace, everywhere. The cache is
// per-process and instances don't coordinate, so InvalidateTeam can only
// tighten the instance that handled the change — other instances, and RBAC
// writes that bypass the API entirely (team-migration tooling, support SQL,
// the DB-trigger cascade on membership rows), converge once their entries
// expire and the stale-serve refresh observes the change. Same accepted window
// as the API-key cache. If a permission ever requires immediate cross-instance
// revocation, replace this cache with a DB-backed per-team generation.
const teamPermCacheTTL = 10 * time.Second

// teamPermCacheMaxEntries bounds the map so churned user/team/permission
// triples can't grow process memory; a backstop, not an expected operating
// point (mirrors apiKeyCacheMaxEntries).
const teamPermCacheMaxEntries = 4096

// teamPermStaleGrace: a TTL-expired grant is still served for this long while
// one background flight refreshes it, so a burst landing on an expired entry
// never queues behind the refresh. Widens the worst-case revocation window to
// ttl+grace; an invalidated (generation-bumped) entry is never stale-served.
const teamPermStaleGrace = 2 * time.Second

// Can checks either team-scoped or platform-scoped access depending on teamID.
// Team permissions require a non-nil teamID. Platform permissions must use the
// platform:* naming convention and must not pass a teamID.
func (s *Service) Can(ctx context.Context, userID uuid.UUID, permission string, teamID *uuid.UUID) (bool, error) {
	if teamID == nil {
		return s.CanPlatform(ctx, userID, permission)
	}
	return s.CanTeam(ctx, userID, *teamID, permission)
}

// CanTeam checks team-scoped access for a specific team.
func (s *Service) CanTeam(ctx context.Context, userID, teamID uuid.UUID, permission string) (bool, error) {
	if s == nil || s.store == nil {
		return false, fmt.Errorf("rbac store is not configured")
	}
	if strings.HasPrefix(permission, "platform:") {
		return false, ErrScopeMismatch
	}
	// Uncached (per-tx) instances query directly with the caller's context:
	// checks inside a mutation transaction must see the tx's own state, and a
	// client disconnect must cancel the query so the tx's advisory lock releases.
	if s.cache == nil {
		return s.canTeamQuery(ctx, userID, teamID, permission)
	}
	c := s.cache

	key := teamPermCacheKey{userID: userID, teamID: teamID, permission: permission}
	now := time.Now()
	c.mu.Lock()
	observed := c.gen[teamID]
	if e, ok := c.m[key]; ok && e.epoch == observed {
		switch {
		case now.Before(e.expiry):
			c.mu.Unlock()
			return true, nil
		case now.Before(e.expiry.Add(teamPermStaleGrace)):
			// Serve the just-expired grant; the first observer arms the one
			// background refresh. A revocation lands via the refresh (a
			// refreshed denial deletes the entry) or via the generation bump.
			spawn := !e.refreshing
			if spawn {
				e.refreshing = true
				c.m[key] = e
			}
			c.mu.Unlock()
			if spawn {
				go s.refreshTeamPerm(key, observed)
			}
			return true, nil
		}
	}
	delete(c.m, key) // wrong generation or past grace
	c.mu.Unlock()

	return s.flightTeamPerm(ctx, key, observed)
}

// refreshTeamPerm runs the background refresh behind a stale serve. On success
// the flight replaces (or, on denial, deletes) the entry, which re-arms the
// trigger; on a transient error the trigger re-arms here so a later request
// inside the grace window retries, and the stale entry stays servable.
func (s *Service) refreshTeamPerm(key teamPermCacheKey, observed uint64) {
	if _, err := s.flightTeamPerm(context.Background(), key, observed); err != nil {
		log.Warn().Err(err).Msg("team permission refresh failed; serving stale until the grace window expires")
		c := s.cache
		c.mu.Lock()
		if e, ok := c.m[key]; ok && e.epoch == observed {
			e.refreshing = false
			c.m[key] = e
		}
		c.mu.Unlock()
	}
}

// flightTeamPerm runs the coalesced permission query and stores a positive
// result. The generation is in the singleflight key: a request that observes a
// newer generation (post-revocation) will not coalesce onto an in-flight
// pre-revocation query, so it can't be handed that query's stale grant.
func (s *Service) flightTeamPerm(ctx context.Context, key teamPermCacheKey, observed uint64) (bool, error) {
	c := s.cache
	sfKey := fmt.Sprintf("%s|%s|%s|%d", key.userID, key.teamID, key.permission, observed)
	result, err, _ := c.group.Do(sfKey, func() (interface{}, error) {
		// Expiry is stamped from the query start so a slow query can't stretch
		// the revocation window past the TTL.
		start := time.Now()
		// Detach: coalesced waiters may outlive the triggering caller, and a
		// fresh deadline keeps a slow check from hanging.
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		allowed, err := s.canTeamQuery(qctx, key.userID, key.teamID, key.permission)
		if err != nil {
			return nil, err
		}
		return teamPermResult{allowed: allowed, epoch: observed, start: start}, nil
	})
	if err != nil {
		return false, err
	}
	res := result.(teamPermResult)
	c.mu.Lock()
	// Store only if the generation is still current: a revocation that landed
	// while the query was in flight makes this result stale, and storing it
	// would clobber a fresher post-revocation entry. A refreshed denial drops
	// the entry so a revoked grant stops being stale-servable immediately.
	if c.gen[key.teamID] == res.epoch {
		if res.allowed {
			if len(c.m) >= teamPermCacheMaxEntries {
				c.sweepLocked(time.Now())
			}
			c.m[key] = teamPermCacheEntry{expiry: res.start.Add(c.ttl), epoch: res.epoch}
		} else {
			delete(c.m, key)
		}
	}
	c.mu.Unlock()
	return res.allowed, nil
}

// sweepLocked drops expired entries; if the map is still full (all live), it is
// reset — costing one query per live triple to refill; unreachable in practice.
// Caller holds c.mu.
func (c *teamPermCache) sweepLocked(now time.Time) {
	for k, e := range c.m {
		if now.After(e.expiry) {
			delete(c.m, k)
		}
	}
	if len(c.m) >= teamPermCacheMaxEntries {
		c.m = make(map[teamPermCacheKey]teamPermCacheEntry)
	}
}

// InvalidateTeam makes a team's cached grants stale on THIS instance after a
// role or membership change. Bumping the generation is the correctness
// mechanism — in-flight misses that observed the old generation are discarded
// at store time; the deletes just reclaim memory. Other instances converge
// within ttl+grace (the cross-instance contract lives on teamPermCacheTTL and
// teamPermStaleGrace). No-op on uncached instances.
func (s *Service) InvalidateTeam(teamID uuid.UUID) {
	if s == nil || s.cache == nil {
		return
	}
	c := s.cache
	c.mu.Lock()
	c.gen[teamID]++
	for k := range c.m {
		if k.teamID == teamID {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

// canTeamQuery runs the permission JOIN. Kept free of caching/HTTP side effects
// so it can sit safely under singleflight.Group.
func (s *Service) canTeamQuery(ctx context.Context, userID, teamID uuid.UUID, permission string) (bool, error) {
	var ok bool
	err := s.store.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_role_assignments ura
			JOIN roles r
			  ON r.id = ura.role_id
			 AND r.scope_type = 'team'
			JOIN role_permissions rp
			  ON rp.role_id = r.id
			JOIN permissions p
			  ON p.id = rp.permission_id
			JOIN team_memberships tm
			  ON tm.team_id = ura.team_id
			 AND tm.user_id = ura.user_id
			 AND tm.status = 'active'
			WHERE ura.user_id = $1
			  AND ura.team_id = $2
			  AND ura.scope_type = 'team'
			  AND ura.revoked_at IS NULL
			  AND p.name = $3
		)
	`, userID, teamID, permission).Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// CanPlatform checks platform-scoped access.
func (s *Service) CanPlatform(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if s == nil || s.store == nil {
		return false, fmt.Errorf("rbac store is not configured")
	}
	if !strings.HasPrefix(permission, "platform:") {
		return false, ErrScopeMismatch
	}

	var ok bool
	err := s.store.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_role_assignments ura
			JOIN roles r
			  ON r.id = ura.role_id
			 AND r.scope_type = 'platform'
			JOIN role_permissions rp
			  ON rp.role_id = r.id
			JOIN permissions p
			  ON p.id = rp.permission_id
			WHERE ura.user_id = $1
			  AND ura.scope_type = 'platform'
			  AND ura.team_id IS NULL
			  AND ura.revoked_at IS NULL
			  AND p.name = $2
		)
	`, userID, permission).Scan(&ok)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (s *Service) RequireTeamPermission(ctx context.Context, userID, teamID uuid.UUID, permission string) error {
	ok, err := s.CanTeam(ctx, userID, teamID, permission)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPermissionDenied
	}
	return nil
}

func (s *Service) RequirePlatformPermission(ctx context.Context, userID uuid.UUID, permission string) error {
	ok, err := s.CanPlatform(ctx, userID, permission)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPermissionDenied
	}
	return nil
}

// RequirePlatformAdminGoogleSession validates the session identity used for
// platform-admin actions. It only checks claims available in the session
// object; callers still need to verify the user holds a platform permission.
func RequirePlatformAdminGoogleSession(_ context.Context, session SessionClaims) error {
	provider := strings.TrimSpace(session.Provider)
	if !strings.EqualFold(provider, "google") {
		return ErrSessionNotEligible
	}

	email := strings.TrimSpace(session.Email)
	if email == "" {
		return ErrSessionNotEligible
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		return ErrSessionNotEligible
	}
	if !strings.EqualFold(domain, "superserve.ai") {
		return ErrSessionNotEligible
	}
	if session.EmailVerified != nil && !*session.EmailVerified {
		return ErrSessionNotEligible
	}
	return nil
}

// CanRevokeLastTeamOwner returns false when removing the supplied owner would
// leave the team without any active team_owner.
func (s *Service) CanRevokeLastTeamOwner(ctx context.Context, teamID, targetUserID uuid.UUID) (bool, error) {
	if s == nil || s.store == nil {
		return false, fmt.Errorf("rbac store is not configured")
	}

	var remaining int64
	err := s.store.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM user_role_assignments ura
		JOIN roles r
		  ON r.id = ura.role_id
		 AND r.scope_type = 'team'
		JOIN team_memberships tm
		  ON tm.team_id = ura.team_id
		 AND tm.user_id = ura.user_id
		 AND tm.status = 'active'
		WHERE ura.team_id = $1
		  AND ura.scope_type = 'team'
		  AND ura.revoked_at IS NULL
		  AND r.name = 'team_owner'
		  AND ura.user_id <> $2
	`, teamID, targetUserID).Scan(&remaining)
	if err != nil {
		return false, err
	}
	return remaining > 0, nil
}

// WriteAuditLog inserts one audit row. Callers can pass a transaction to keep
// the audit record atomic with the sensitive mutation.
func (s *Service) WriteAuditLog(ctx context.Context, tx db.DBTX, ev AuditEvent) error {
	if tx == nil {
		return fmt.Errorf("rbac audit write requires a database handle")
	}
	if strings.TrimSpace(ev.EventType) == "" {
		return fmt.Errorf("audit event type is required")
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO audit_logs (
			actor_user_id, target_user_id, team_id, event_type,
			old_value, new_value, metadata
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, COALESCE($7::jsonb, '{}'::jsonb))
	`,
		uuidToPGType(ev.ActorUserID),
		uuidToPGType(ev.TargetUserID),
		uuidToPGType(ev.TeamID),
		ev.EventType,
		jsonOrNull(ev.OldValue),
		jsonOrNull(ev.NewValue),
		jsonOrNull(ev.Metadata),
	)
	return err
}

func uuidToPGType(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

func jsonOrNull(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}
