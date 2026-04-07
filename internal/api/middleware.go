package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header
// by hashing the provided key and looking it up in the api_key table.
// On success, sets "team_id" and "api_key_id" in the Gin context.
func APIKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		var id, teamID string
		err := pool.QueryRow(c.Request.Context(),
			"SELECT id, team_id FROM api_key WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
			keyHash,
		).Scan(&id, &teamID)
		if err != nil {
			respondErrorMsg(c, "auth_failed", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		// Update last_used_at (fire and forget)
		go func() {
			_, _ = pool.Exec(c.Request.Context(),
				"UPDATE api_key SET last_used_at = now() WHERE id = $1", id)
		}()

		c.Set("api_key_id", id)
		c.Set("team_id", teamID)
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
					"An internal error occurred. Please try again or contact support.",
					http.StatusInternalServerError,
				)
				c.Abort()
			}
		}()

		c.Next()
	}
}
