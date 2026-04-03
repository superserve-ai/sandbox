package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header.
// It hashes the key with SHA-256, looks it up in the api_keys table (checking
// revoked/expired), stores the team_id in the Gin context, and updates
// last_used_at asynchronously.
func APIKeyAuth(queries *db.Queries) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondErrorMsg(c, "unauthorized", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		key, err := queries.GetAPIKeyByHash(c.Request.Context(), keyHash)
		if err != nil {
			respondErrorMsg(c, "unauthorized", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		c.Set("api_key_id", key.ID.String())
		c.Set("team_id", key.TeamID.String())
		c.Set("scopes", key.Scopes)

		// Update last_used_at in a background goroutine to avoid adding latency.
		go func() {
			_ = queries.TouchAPIKeyLastUsed(c.Request.Context(), key.ID)
		}()

		c.Next()
	}
}

// RequireScope returns a Gin middleware that checks whether the authenticated
// API key has the required scope. Must be used after APIKeyAuth.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("scopes")
		if !exists {
			respondErrorMsg(c, "unauthorized", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		scopeList, ok := scopes.([]string)
		if !ok || (len(scopeList) > 0 && !slices.Contains(scopeList, "*") && !slices.Contains(scopeList, scope)) {
			respondErrorMsg(c, "forbidden", "API key does not have the required scope.", http.StatusForbidden)
			c.Abort()
			return
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
