package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
// 10s), so steady-state requests skip the DB round trip entirely. Revocation
// therefore takes up to one TTL to propagate; key expiry (expires_at) is
// exact because it is checked on every cache hit.
func APIKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	cache := newAPIKeyCache(apiKeyCacheTTLFromEnv())
	touchLastUsed := func(ctx context.Context, id string) {
		// Fire and forget: detach here, not at call sites — the caller's ctx
		// may be cancelled the moment it returns (request teardown, or fetch's
		// deferred cancel on the flight ctx), which would kill the update
		// before it runs. The ctx is extracted by the caller before spawning
		// so the goroutine does not capture c — gin recycles *Context back to
		// the pool after ServeHTTP returns.
		ctx = context.WithoutCancel(ctx)
		go func() {
			_, _ = pool.Exec(ctx,
				"UPDATE api_key SET last_used_at = now() WHERE id = $1", id)
		}()
	}
	return func(c *gin.Context) {
		authStart := time.Now()
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
				touchLastUsed(c.Request.Context(), entry.id)
			}
			setAPIKeyContext(c, entry)
			c.Set("auth_ms", time.Since(authStart).Milliseconds())
			c.Next()
			return
		}

		// Miss: fetch coalesces concurrent identical lookups, so a burst
		// arriving on an expired entry runs one query, not one per request.
		// The touch and put happen inside fn so only the executing caller
		// performs them — waiters share the entry without re-touching.
		entry, err := cache.fetch(c.Request.Context(), keyHash, func(qctx context.Context) (apiKeyCacheEntry, error) {
			var e apiKeyCacheEntry
			err := pool.QueryRow(qctx,
				"SELECT id, team_id, name, scopes, created_by, expires_at FROM api_key WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
				keyHash,
			).Scan(&e.id, &e.teamID, &e.name, &e.scopes, &e.createdBy, &e.expiresAt)
			if err != nil {
				return apiKeyCacheEntry{}, err
			}
			if cache.put(keyHash, e, time.Now()) {
				touchLastUsed(qctx, e.id)
			}
			return e, nil
		})
		if err != nil {
			switch {
			case c.Request.Context().Err() != nil:
				// Caller gone or its deadline fired; abort without an Error
				// log. Keyed on the request context, not the error value: the
				// shared flight's own timeout also surfaces DeadlineExceeded
				// and must fall through to the cases below.
				respondErrorMsg(c, "service_unavailable",
					"Authentication is temporarily unavailable. Please retry.",
					http.StatusServiceUnavailable)
			case errors.Is(err, pgx.ErrNoRows):
				// The real bad-key case — with per-cell databases it is also
				// how a valid key presented to the wrong cell fails;
				// respondAuthFailed names the right region when the key says so.
				respondAuthFailed(c, apiKey)
			case respondWrongRegion(c, apiKey):
				// A key tagged for another cell can never authenticate here,
				// whatever the lookup said — the redirect hint already went out.
			default:
				// Infrastructure failure, shared by every coalesced waiter —
				// a 401 here would read as mass key invalidation to SDKs.
				// 503 is honest and retryable.
				log.Error().Err(err).Msg("API key lookup failed")
				respondErrorMsg(c, "service_unavailable",
					"Authentication is temporarily unavailable. Please retry.",
					http.StatusServiceUnavailable)
			}
			c.Abort()
			return
		}

		// A shared flight's result was evaluated at the executing caller's
		// time; re-check key expiry at THIS request's time, exactly like the
		// cache-hit path does on every get.
		if entry.expiresAt.Valid && !time.Now().Before(entry.expiresAt.Time) {
			respondAuthFailed(c, apiKey)
			c.Abort()
			return
		}

		setAPIKeyContext(c, entry)
		c.Set("auth_ms", time.Since(authStart).Milliseconds())
		c.Next()
	}
}

// setAPIKeyContext copies an authenticated key's identity into the request
// context, shared by the cache-hit and lookup paths. The impersonation check
// reads entry.name directly (not the gin key) so it cannot depend on Set order.
func setAPIKeyContext(c *gin.Context, entry apiKeyCacheEntry) {
	c.Set("api_key_id", entry.id)
	c.Set("api_key_name", entry.name)
	c.Set("api_key_scopes", entry.scopes)
	c.Set("team_id", entry.teamID)
	if entry.createdBy.Valid && entry.name != consoleImpersonationKeyName {
		c.Set("actor_id", uuid.UUID(entry.createdBy.Bytes))
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
