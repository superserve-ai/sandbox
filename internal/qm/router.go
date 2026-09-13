package qm

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// SetupRouter builds the service router. /health is open; everything
// under /v1/qm requires a team API key.
func SetupRouter(h *Handlers, resolver KeyResolver, log zerolog.Logger) *gin.Engine {
	r := gin.New()
	r.Use(securityHeaders(), requestLogger(log), recovery(log))

	r.NoRoute(func(c *gin.Context) { respondError(c, http.StatusNotFound, "Not found.") })
	r.GET("/health", h.Health)

	read := RequirePermission(resolver, PermissionRead)
	write := RequirePermission(resolver, PermissionWrite)
	v1 := r.Group("/v1/qm", APIKeyAuth(resolver))
	{
		v1.GET("/tenants", read, h.ListTenants)
		v1.POST("/tenants", write, h.CreateTenant)
		v1.GET("/tenants/:id", read, h.GetTenant)
		v1.DELETE("/tenants/:id", write, h.DeleteTenant)
		v1.POST("/tenants/:id/retry", write, h.RetryTenant)
		v1.POST("/tenants/:id/admin-link", write, h.AdminLink)
		v1.GET("/slugs/:slug/availability", read, h.SlugAvailability)
	}
	return r
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		c.Next()
	}
}

// requestLogger logs method, path and status; the query string is dropped
// so nothing a caller puts in a URL lands in logs.
func requestLogger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		status := c.Writer.Status()
		evt := log.Info()
		if status >= 500 {
			evt = log.Error()
		} else if status >= 400 {
			evt = log.Warn()
		}
		evt.Str("method", c.Request.Method).Str("path", c.Request.URL.Path).Int("status", status).
			Dur("latency", time.Since(start)).Msg("request")
	}
}

func recovery(log zerolog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		log.Error().Interface("panic", recovered).Str("path", c.Request.URL.Path).Msg("panic recovered")
		respondError(c, http.StatusInternalServerError, internalErrorMsg)
		c.Abort()
	})
}
