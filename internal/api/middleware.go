package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header
// by hashing the provided key and looking it up in the api_keys table.
// It checks that the key is not revoked or expired, validates scopes,
// sets team_id in context, and updates last_used_at.
func APIKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	queries := db.New(pool)

	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondError(c, ErrUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		key, err := queries.GetAPIKeyByHash(c.Request.Context(), keyHash)
		if err != nil {
			respondError(c, ErrUnauthorized)
			c.Abort()
			return
		}

		c.Set("api_key_id", key.ID.String())
		c.Set("team_id", key.TeamID.String())
		c.Set("scopes", key.Scopes)

		// Update last_used_at in the background so it doesn't add latency.
		// Use context.WithoutCancel so the update isn't cancelled when the
		// request finishes.
		go func() {
			_ = queries.UpdateAPIKeyLastUsed(context.WithoutCancel(c.Request.Context()), key.ID)
		}()

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
