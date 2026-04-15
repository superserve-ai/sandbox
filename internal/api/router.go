package api

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SetupRouter creates and configures the Gin router with all route groups.
// The supplied context scopes background goroutines (rate limiter cleanup)
// so they exit when the context is cancelled. In production this is the
// process lifetime context; in tests it's the per-test context so each
// router instance doesn't leak a cleanup goroutine.
func SetupRouter(ctx context.Context, h *Handlers, pool *pgxpool.Pool) *gin.Engine {
	r := gin.New()
	// Global middleware: security headers, coarse per-IP rate limit
	// (unauthenticated flood protection), logging, panic recovery.
	r.Use(
		SecurityHeaders(),
		RateLimit(ctx, DefaultIPRateLimitConfig()),
		RequestLogger(),
		ErrorHandler(),
	)

	api := r.Group("/")
	// Authenticate first, then apply per-team rate limit — so each
	// customer gets a dedicated bucket regardless of source IP. Behind a
	// load balancer the per-IP limit collapses tenants onto one bucket
	// and becomes meaningless for fairness.
	api.Use(APIKeyAuth(pool), TeamRateLimit(ctx, DefaultTeamRateLimitConfig()))
	{
		// Sandbox lifecycle.
		api.POST("/sandboxes", h.CreateSandbox)
		api.GET("/sandboxes", h.ListSandboxes)
		api.GET("/sandboxes/:sandbox_id", h.GetSandboxByID)
		api.POST("/sandboxes/:sandbox_id/resume", h.ResumeSandbox)
		api.POST("/sandboxes/:sandbox_id/pause", h.PauseSandbox)
		api.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
		api.PATCH("/sandboxes/:sandbox_id", h.PatchSandbox)

		// Sandbox operations. Sandbox must already be active — paused
		// sandboxes must be resumed explicitly via /resume.
		api.POST("/sandboxes/:sandbox_id/exec", h.ExecSandbox)
		api.POST("/sandboxes/:sandbox_id/exec/stream", h.ExecSandboxStream)

		// Template lifecycle. Builds run async via the build supervisor;
		// the POST /templates/:id/builds endpoint just enqueues a row.
		api.GET("/templates", h.ListTemplates)
		api.POST("/templates", h.CreateTemplate)
		api.GET("/templates/:template_id", h.GetTemplate)
		api.DELETE("/templates/:template_id", h.DeleteTemplate)
		api.GET("/templates/:template_id/builds", h.ListTemplateBuilds)
		api.POST("/templates/:template_id/builds", h.CreateTemplateBuild)
		api.GET("/templates/:template_id/builds/:build_id", h.GetTemplateBuild)
		api.DELETE("/templates/:template_id/builds/:build_id", h.CancelTemplateBuild)
		api.GET("/templates/:template_id/builds/:build_id/logs", h.StreamTemplateBuildLogs)
	}

	r.GET("/health", h.Health)

	// Internal endpoints — authenticated via a shared token (not per-team
	// API keys). Called by infrastructure components (VMD heartbeat) and
	// not exposed to customers. The token is checked by InternalAuth
	// middleware; if INTERNAL_API_TOKEN is unset, the middleware rejects
	// all requests (fail-closed).
	internal := r.Group("/internal")
	internal.Use(InternalAuth())
	{
		internal.POST("/hosts/:host_id/heartbeat", h.HostHeartbeat)
	}

	return r
}
