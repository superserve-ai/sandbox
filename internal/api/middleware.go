package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const consoleImpersonationKeyName = "__console_impersonation__"

func isConsoleImpersonation(c *gin.Context) bool {
	return c.GetString("api_key_name") == consoleImpersonationKeyName
}

func apiKeyHasScope(c *gin.Context, scope string) bool {
	raw, ok := c.Get("api_key_scopes")
	if !ok {
		return false
	}
	scopes, ok := raw.([]string)
	if !ok {
		return false
	}
	return slices.Contains(scopes, scope)
}

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header
// by hashing the provided key and looking it up in the api_key table.
// On success, sets "team_id" and "api_key_id" in the Gin context.
//
// Successful lookups are cached in-process for API_KEY_CACHE_TTL (default
// 30s), so steady-state requests skip the DB round trip entirely. Revocation
// therefore takes up to one TTL to propagate; key expiry (expires_at) is
// exact because it is checked on every cache hit.
func APIKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	cache := newAPIKeyCache(apiKeyCacheTTLFromEnv())
	touchLastUsed := func(ctx context.Context, id string) {
		// Fire and forget. The context is extracted by the caller before
		// spawning so the goroutine does not capture c — gin recycles
		// *Context back to the pool after ServeHTTP returns, causing a
		// data race if the goroutine reads c.Request later.
		go func() {
			_, _ = pool.Exec(ctx,
				"UPDATE api_key SET last_used_at = now() WHERE id = $1", id)
		}()
	}
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		if entry, needTouch, ok := cache.get(keyHash, time.Now()); ok {
			if needTouch {
				touchLastUsed(context.WithoutCancel(c.Request.Context()), entry.id)
			}
			c.Set("api_key_id", entry.id)
			c.Set("api_key_name", entry.name)
			c.Set("api_key_scopes", entry.scopes)
			c.Set("team_id", entry.teamID)
			if entry.createdBy.Valid && !isConsoleImpersonation(c) {
				c.Set("actor_id", uuid.UUID(entry.createdBy.Bytes))
			}
			c.Next()
			return
		}

		var id, teamID, name string
		var scopes []string
		var createdBy pgtype.UUID
		var expiresAt pgtype.Timestamptz
		err := pool.QueryRow(c.Request.Context(),
			"SELECT id, team_id, name, scopes, created_by, expires_at FROM api_key WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
			keyHash,
		).Scan(&id, &teamID, &name, &scopes, &createdBy, &expiresAt)
		if err != nil {
			// Lookup failed — usually a bad key, but with per-cell databases
			// it is also how a valid key presented to the wrong cell fails.
			// respondAuthFailed names the right region when the key says so.
			respondAuthFailed(c, apiKey)
			c.Abort()
			return
		}

		cache.put(keyHash, apiKeyCacheEntry{
			id:        id,
			teamID:    teamID,
			name:      name,
			scopes:    scopes,
			createdBy: createdBy,
			expiresAt: expiresAt,
		}, time.Now())
		touchLastUsed(context.WithoutCancel(c.Request.Context()), id)

		c.Set("api_key_id", id)
		c.Set("api_key_name", name)
		c.Set("api_key_scopes", scopes)
		c.Set("team_id", teamID)
		if createdBy.Valid && !isConsoleImpersonation(c) {
			c.Set("actor_id", uuid.UUID(createdBy.Bytes))
		}
		c.Next()
	}
}

// RequestLogger returns a Gin middleware that logs each request using zerolog,
// including method, path, status code, and latency.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if raw != "" {
			path = path + "?" + raw
		}

		evt := log.Info()
		if status >= 500 {
			evt = log.Error()
		} else if status >= 400 {
			evt = log.Warn()
		}

		evt.
			Str("method", method).
			Str("path", path).
			Int("status", status).
			Dur("latency", latency).
			Str("client_ip", clientIP).
			Int("body_size", c.Writer.Size()).
			Msg("request")
	}
}

// SecurityHeaders returns a Gin middleware that sets standard security headers
// on all responses.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		c.Next()
	}
}

// ErrorHandler returns a Gin middleware that recovers from panics and returns
// a structured JSON error response.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				zerolog.Ctx(c.Request.Context()).Error().
					Interface("panic", r).
					Str("path", c.Request.URL.Path).
					Msg("panic recovered")

				respondErrorMsg(c, "internal_error",
					"A problem occurred. Please try again, or contact the team if it persists.",
					http.StatusInternalServerError,
				)
				c.Abort()
			}
		}()

		c.Next()
	}
}
