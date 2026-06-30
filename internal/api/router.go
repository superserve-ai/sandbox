package api

import (
	"context"

	sentrygin "github.com/getsentry/sentry-go/gin"
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
		sentrygin.New(sentrygin.Options{Repanic: true}),
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
		api.POST("/sandboxes/:sandbox_id/activate", h.ActivateSandbox)
		api.POST("/sandboxes/:sandbox_id/pause", h.PauseSandbox)
		api.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
		api.PATCH("/sandboxes/:sandbox_id", h.PatchSandbox)
		api.POST("/sandboxes/:sandbox_id/secrets", h.AttachSandboxSecret)
		api.DELETE("/sandboxes/:sandbox_id/secrets/:env_key", h.DetachSandboxSecret)

		// Directory listing (metadata) flows through the control plane via
		// boxd's FilesystemService.ListDir, so it works on every sandbox
		// regardless of boxd version. Paused sandboxes are resumed transparently.
		api.GET("/sandboxes/:sandbox_id/files", h.ListSandboxFiles)

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

		api.POST("/secrets", h.CreateSecret)
		api.GET("/secrets", h.ListSecrets)
		api.GET("/secrets/:name", h.GetSecret)
		api.PATCH("/secrets/:name", h.PatchSecret)
		api.DELETE("/secrets/:name", h.DeleteSecret)
		api.GET("/secrets/:name/audit", h.GetSecretAudit)
		api.GET("/secrets/:name/sandboxes", h.GetSecretSandboxes)

		api.GET("/providers", h.ListProviders)

		api.GET("/sandboxes/:sandbox_id/network", h.GetSandboxNetwork)

		api.GET("/billing/pricing", h.GetBillingPricing)

		// RBAC Phase 2b customer-facing team management.
		api.GET("/teams/:team_id/management", h.GetTeamManagement)
		api.GET("/teams/:team_id/members", h.ListTeamMembers)
		api.POST("/teams/:team_id/members", h.AddTeamMember)
		api.DELETE("/teams/:team_id/members/:user_id", h.DeactivateTeamMember)
		api.GET("/teams/:team_id/roles", h.ListTeamRoleAssignments)
		api.POST("/teams/:team_id/roles", h.AssignTeamRole)
		api.DELETE("/teams/:team_id/roles/:assignment_id", h.RevokeTeamRole)
	}

	r.GET("/health", h.Health)
	// Public pricing is intentionally unauthenticated so the marketing site can render current PAYG rates from the same source as billing.
	r.GET("/billing/pricing/public", h.GetPublicBillingPricing)

	// Internal endpoints — authenticated via a shared token (not per-team
	// API keys). Called by infrastructure components (VMD heartbeat) and
	// not exposed to customers. The token is checked by InternalAuth
	// middleware; if INTERNAL_API_TOKEN is unset, the middleware rejects
	// all requests (fail-closed).
	internal := r.Group("/internal")
	internal.Use(InternalAuth(), InternalActorFromHeader())
	{
		internal.POST("/hosts/:host_id/heartbeat", h.HostHeartbeat)
		internal.POST("/secrets/decrypt", h.DecryptSecret)
		internal.GET("/jwks", h.JWKS)
		internal.GET("/sandbox_revocations", h.ListSandboxRevocations)
		internal.GET("/sandboxes/:sandbox_id/egress_rules", h.GetSandboxEgressRules)
		internal.GET("/teams/:team_id/sandboxes", h.ListPlatformTeamSandboxes)
		internal.GET("/teams/:team_id/sandboxes/:sandbox_id", h.GetPlatformTeamSandbox)

		// RBAC Phase 2b platform recovery and internal team administration.
		internal.GET("/teams/:team_id/members", h.ListPlatformTeamMembers)
		internal.POST("/teams/:team_id/members", h.AddPlatformTeamMember)
		internal.DELETE("/teams/:team_id/members/:user_id", h.DeactivatePlatformTeamMember)
		internal.GET("/teams/:team_id/roles", h.ListPlatformTeamRoleAssignments)
		internal.POST("/teams/:team_id/roles", h.AssignPlatformTeamRole)
		internal.DELETE("/teams/:team_id/roles/:assignment_id", h.RevokePlatformTeamRole)
		internal.POST("/teams/:team_id/recover", h.RecoverTeam)
	}

	return r
}
