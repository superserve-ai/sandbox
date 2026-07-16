package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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

// Service evaluates RBAC permissions against the database.
type Service struct {
	store db.DBTX

	// teamPermCache caches positive results (teamPermCacheKey -> *teamPermCacheEntry);
	// denials always re-query so probes can't grow the map. teamPermGroup coalesces
	// concurrent identical misses. teamPermGen is a per-team epoch (teamID ->
	// *atomic.Uint64) that InvalidateTeam bumps to make stale entries fail the
	// read-side check. Zero values are ready to use.
	teamPermCache sync.Map
	teamPermGroup singleflight.Group
	teamPermGen   sync.Map
}

func New(store db.DBTX) *Service {
	return &Service{store: store}
}

type teamPermCacheKey struct {
	userID     uuid.UUID
	teamID     uuid.UUID
	permission string
}

type teamPermCacheEntry struct {
	expiry time.Time
	epoch  uint64
}

// teamPermResult is the singleflight payload: grant plus the epoch observed at
// query time, so all coalesced waiters cache under the same epoch.
type teamPermResult struct {
	allowed bool
	epoch   uint64
}

// teamPermCacheTTL backstops epoch invalidation: a grant is served at most this
// long even without an explicit invalidation.
const teamPermCacheTTL = 30 * time.Second

// teamEpoch returns the per-team epoch counter, creating it on first use.
func (s *Service) teamEpoch(teamID uuid.UUID) *atomic.Uint64 {
	if v, ok := s.teamPermGen.Load(teamID); ok {
		return v.(*atomic.Uint64)
	}
	v, _ := s.teamPermGen.LoadOrStore(teamID, new(atomic.Uint64))
	return v.(*atomic.Uint64)
}

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

	epoch := s.teamEpoch(teamID)
	key := teamPermCacheKey{userID: userID, teamID: teamID, permission: permission}
	if v, ok := s.teamPermCache.Load(key); ok {
		e := v.(*teamPermCacheEntry)
		if e.epoch == epoch.Load() && time.Now().Before(e.expiry) {
			return true, nil
		}
		// Stale epoch or expired — drop it. CompareAndDelete so a concurrent
		// fresh Store isn't clobbered.
		s.teamPermCache.CompareAndDelete(key, v)
	}

	sfKey := userID.String() + "|" + teamID.String() + "|" + permission
	result, err, _ := s.teamPermGroup.Do(sfKey, func() (interface{}, error) {
		// Capture the epoch inside the query so all coalesced waiters cache under
		// the epoch it observed; a later revocation bump makes the store stale on read.
		observed := epoch.Load()
		// Detach: coalesced waiters may outlive the triggering caller, and a fresh
		// deadline keeps a slow check from hanging.
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		allowed, err := s.canTeamQuery(qctx, userID, teamID, permission)
		if err != nil {
			return nil, err
		}
		return teamPermResult{allowed: allowed, epoch: observed}, nil
	})
	if err != nil {
		return false, err
	}
	res := result.(teamPermResult)
	if res.allowed {
		s.teamPermCache.Store(key, &teamPermCacheEntry{
			expiry: time.Now().Add(teamPermCacheTTL),
			epoch:  res.epoch,
		})
	}
	return res.allowed, nil
}

// InvalidateTeam makes a team's cached grants stale immediately after a role or
// membership change. Bumping the epoch is the correctness mechanism — in-flight
// misses stored under the old epoch fail the read check; the Range only reclaims
// memory.
func (s *Service) InvalidateTeam(teamID uuid.UUID) {
	if s == nil {
		return
	}
	s.teamEpoch(teamID).Add(1)
	s.teamPermCache.Range(func(k, _ any) bool {
		if key, ok := k.(teamPermCacheKey); ok && key.teamID == teamID {
			s.teamPermCache.Delete(k)
		}
		return true
	})
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
