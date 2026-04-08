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
		api.POST("/instances", h.CreateInstance)
		api.GET("/instances", h.ListInstances)
		api.GET("/instances/:instance_id", h.GetInstance)
		api.DELETE("/instances/:instance_id", h.DeleteInstance)
		api.POST("/instances/:instance_id/pause", h.PauseInstance)
		api.POST("/instances/:instance_id/resume", h.ResumeInstance)

		api.POST("/instances/:instance_id/exec", h.ExecCommand)
		api.POST("/instances/:instance_id/exec/stream", h.ExecCommandStream)

		api.PUT("/instances/:instance_id/files/*path", h.UploadFile)
		api.GET("/instances/:instance_id/files/*path", h.DownloadFile)

		// Sandbox lifecycle (no auto-wake).
		api.POST("/sandboxes", h.CreateSandbox)
		api.GET("/sandboxes", h.ListSandboxes)
		api.GET("/sandboxes/:sandbox_id", h.GetSandboxByID)
		api.POST("/sandboxes/:sandbox_id/resume", h.ResumeSandbox)
		api.POST("/sandboxes/:sandbox_id/pause", h.PauseSandbox)
		api.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
		api.PATCH("/sandboxes/:sandbox_id", h.PatchSandbox)
		// Terminal-token mint gets a dedicated, much tighter per-team
		// rate limit on top of the general TeamRateLimit. Each minted
		// token is a stateful capability — it consumes a nonce slot at
		// the proxy and grants a live PTY — so it deserves a stricter
		// ceiling than the general read-heavy API surface.
		api.POST("/sandboxes/:sandbox_id/terminal-token",
			TeamRateLimit(ctx, DefaultTerminalTokenRateLimitConfig()),
			h.IssueTerminalToken)

		// Sandbox operations with auto-wake middleware.
		sandboxOps := api.Group("/sandboxes/:sandbox_id")
		sandboxOps.Use(h.AutoWake())
		{
			sandboxOps.POST("/exec", h.ExecSandbox)
			sandboxOps.POST("/exec/stream", h.ExecSandboxStream)
			sandboxOps.PUT("/files/*path", h.UploadSandboxFile)
			sandboxOps.GET("/files/*path", h.DownloadSandboxFile)
		}
	}

	r.GET("/health", h.Health)

	return r
}
