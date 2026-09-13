package qm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// The console mints an impersonation key for support staff; as in the
// control plane it is recognised by name and is read-only here.
const consoleImpersonationKeyName = "__console_impersonation__"

// Team permissions, aliased the way the control plane's sandbox routes
// alias them: reads need settings:read, mutations settings:write.
const (
	PermissionRead  = "settings:read"
	PermissionWrite = "settings:write"
)

// ImpersonationReadScope is the platform scope the console's impersonation
// key must carry to read hosted-QM tenants. It is QM's own, as the control
// plane keys each resource's impersonation read to its own scope; a key
// scoped to sandboxes or templates does not see tenants.
const ImpersonationReadScope = "platform:qm:read"

const principalKey = "qm_principal"

var ErrKeyNotFound = errors.New("api key not found")

// Principal is an authenticated caller.
type Principal struct {
	KeyID   uuid.UUID
	TeamID  uuid.UUID
	KeyName string
	Scopes  []string
	// ActorID is the member the key was minted for (api_key.created_by).
	// Authorization is decided on the actor's roles; a key with no actor
	// can authenticate but holds no permissions, as in the control plane.
	ActorID *uuid.UUID
	// ReadOnly is the console's impersonation key: it may list and inspect
	// (given ImpersonationReadScope) but never create, delete, retry or
	// mint sign-in links.
	ReadOnly bool
}

// KeyResolver authenticates a key hash and answers permission checks.
type KeyResolver interface {
	Resolve(ctx context.Context, keyHash string) (Principal, error)
	// Can reports whether the principal's actor holds permission in the
	// principal's team.
	Can(ctx context.Context, p Principal, permission string) (bool, error)
	// Touch records that the key was just used. Best effort; callers do
	// not wait on it.
	Touch(ctx context.Context, p Principal)
}

// HashAPIKey is the control plane's key hashing: hex SHA-256 of the raw key.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// PostgresKeyResolver goes through the definer functions that stand in for
// the api_key and RBAC grants qm_api does not have (see the
// qm_api_key_resolver migration). No cache: qm-api traffic is a few console
// calls per session, and revocation is then immediate.
type PostgresKeyResolver struct {
	pool *pgxpool.Pool

	// last_used_at is written at most once per key per touchInterval, as
	// the control plane throttles it, so a busy console tab is one write
	// a minute rather than one per request.
	mu      sync.Mutex
	touched map[uuid.UUID]time.Time
	now     func() time.Time
}

const (
	touchInterval    = time.Minute
	touchMapMax      = 4096
	touchTimeout     = 5 * time.Second
	resolveAPIKeySQL = `SELECT id, team_id, name, scopes, created_by FROM qm.resolve_api_key($1)`
	actorCanTeamSQL  = `SELECT qm.actor_can_team($1, $2, $3)`
	touchAPIKeySQL   = `SELECT qm.touch_api_key($1)`
)

func NewPostgresKeyResolver(pool *pgxpool.Pool) *PostgresKeyResolver {
	return &PostgresKeyResolver{pool: pool, touched: map[uuid.UUID]time.Time{}, now: time.Now}
}

func (r *PostgresKeyResolver) Resolve(ctx context.Context, keyHash string) (Principal, error) {
	var p Principal
	var createdBy pgtype.UUID
	err := r.pool.QueryRow(ctx, resolveAPIKeySQL, keyHash).Scan(&p.KeyID, &p.TeamID, &p.KeyName, &p.Scopes, &createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrKeyNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("resolve api key: %w", err)
	}
	p.ReadOnly = p.KeyName == consoleImpersonationKeyName
	if createdBy.Valid && !p.ReadOnly {
		actor := uuid.UUID(createdBy.Bytes)
		p.ActorID = &actor
	}
	return p, nil
}

func (r *PostgresKeyResolver) Can(ctx context.Context, p Principal, permission string) (bool, error) {
	if p.ActorID == nil {
		return false, nil
	}
	var ok bool
	if err := r.pool.QueryRow(ctx, actorCanTeamSQL, *p.ActorID, p.TeamID, permission).Scan(&ok); err != nil {
		return false, fmt.Errorf("check team permission: %w", err)
	}
	return ok, nil
}

// Touch updates last_used_at through the definer function, detached from
// the request so its teardown cannot cancel the write.
func (r *PostgresKeyResolver) Touch(ctx context.Context, p Principal) {
	if !r.shouldTouch(p.KeyID) {
		return
	}
	go func() {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), touchTimeout)
		defer cancel()
		if _, err := r.pool.Exec(tctx, touchAPIKeySQL, p.KeyID); err != nil {
			log.Warn().Err(err).Msg("touch api key last_used_at")
		}
	}()
}

func (r *PostgresKeyResolver) shouldTouch(keyID uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if last, ok := r.touched[keyID]; ok && now.Sub(last) < touchInterval {
		return false
	}
	if len(r.touched) >= touchMapMax {
		// Bounded: a flood of distinct keys costs a few extra writes, not
		// unbounded memory.
		r.touched = map[uuid.UUID]time.Time{}
	}
	r.touched[keyID] = now
	return true
}

// APIKeyAuth authenticates X-API-Key and stores the Principal on the
// context. The raw key is hashed here and never logged.
func APIKeyAuth(resolver KeyResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("X-API-Key")
		if raw == "" {
			respondError(c, http.StatusUnauthorized, "Invalid or missing X-API-Key header.")
			c.Abort()
			return
		}
		p, err := resolver.Resolve(c.Request.Context(), HashAPIKey(raw))
		switch {
		case err == nil:
		case errors.Is(err, ErrKeyNotFound):
			respondError(c, http.StatusUnauthorized, "Invalid or missing X-API-Key header.")
			c.Abort()
			return
		default:
			log.Error().Err(err).Msg("API key lookup failed")
			respondError(c, http.StatusServiceUnavailable, "Authentication is temporarily unavailable. Please retry.")
			c.Abort()
			return
		}
		resolver.Touch(c.Request.Context(), p)
		c.Set(principalKey, p)
		c.Next()
	}
}

// RequirePermission gates a route on a team permission of the key's actor,
// resolved through the same RBAC tables the control plane uses. The
// impersonation key is allowed reads if it carries ImpersonationReadScope
// and nothing else, which is why admin-link minting is a POST.
func RequirePermission(resolver KeyResolver, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := principalFrom(c)
		if p.ReadOnly {
			if permission == PermissionRead && slices.Contains(p.Scopes, ImpersonationReadScope) {
				c.Next()
				return
			}
			respondError(c, http.StatusForbidden, "This API key is read-only.")
			c.Abort()
			return
		}
		ok, err := resolver.Can(c.Request.Context(), p, permission)
		if err != nil {
			log.Error().Err(err).Str("permission", permission).Msg("permission check failed")
			respondError(c, http.StatusServiceUnavailable, "Authorization is temporarily unavailable. Please retry.")
			c.Abort()
			return
		}
		if !ok {
			respondError(c, http.StatusForbidden, "You do not have permission to perform this action.")
			c.Abort()
			return
		}
		c.Next()
	}
}

func principalFrom(c *gin.Context) Principal {
	p, _ := c.Get(principalKey)
	principal, _ := p.(Principal)
	return principal
}
