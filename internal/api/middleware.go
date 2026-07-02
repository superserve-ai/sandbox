package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/region"
)

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header
// by hashing the provided key and looking it up in the api_key table.
// On success, sets "team_id" and "api_key_id" in the Gin context.
func APIKeyAuth(pool *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		var id, teamID, teamHomeRegion string
		var apiKeyRegion *string
		var createdBy pgtype.UUID
		err := pool.QueryRow(c.Request.Context(),
			`SELECT k.id, k.team_id, k.created_by, k.region, t.home_region
			FROM api_key k
			JOIN team t ON t.id = k.team_id
			WHERE k.key_hash = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())`,
			keyHash,
		).Scan(&id, &teamID, &createdBy, &apiKeyRegion, &teamHomeRegion)
		if err != nil {
			respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		apiKeyRegionParse := region.ParseAPIKeyRegion(apiKey)
		requestHost := stripPort(c.Request.Host)
		if cfg != nil {
			c.Set("request_region", cfg.Region)
		}
		c.Set("team_home_region", teamHomeRegion)
		c.Set("wrong_region", false)
		if apiKeyRegion != nil {
			c.Set("api_key_region", *apiKeyRegion)
		} else if apiKeyRegionParse.Known || apiKeyRegionParse.Unknown {
			c.Set("api_key_region", apiKeyRegionParse.Region)
		}

		if cfg != nil && teamHomeRegion != "" && teamHomeRegion != cfg.Region && !cfg.IsDefaultAPIHost(requestHost) {
			endpoint := cfg.RegionalAPIBaseURL(teamHomeRegion)
			msg := fmt.Sprintf("This team is hosted in %s. Use %s.", teamHomeRegion, endpoint)
			c.Set("wrong_region", true)
			respondErrorFields(c, "wrong_region", msg, http.StatusConflict, gin.H{
				"region":   teamHomeRegion,
				"endpoint": endpoint,
			})
			c.Abort()
			return
		}

		// Update last_used_at (fire and forget). Extract the context
		// before spawning so the goroutine does not capture c — gin
		// recycles *Context back to the pool after ServeHTTP returns,
		// causing a data race if the goroutine reads c.Request later.
		lastUsedCtx := context.WithoutCancel(c.Request.Context())
		go func() {
			_, _ = pool.Exec(lastUsedCtx,
				"UPDATE api_key SET last_used_at = now() WHERE id = $1", id)
		}()

		c.Set("api_key_id", id)
		c.Set("team_id", teamID)
		if createdBy.Valid {
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
			Str("request_region", stringValue(c, "request_region")).
			Str("team_home_region", stringValue(c, "team_home_region")).
			Str("api_key_region", stringValue(c, "api_key_region")).
			Str("sandbox_region", stringValue(c, "sandbox_region")).
			Bool("wrong_region", boolValue(c, "wrong_region")).
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

func stripPort(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

func stringValue(c *gin.Context, key string) string {
	if v, ok := c.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolValue(c *gin.Context, key string) bool {
	if v, ok := c.Get(key); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
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
