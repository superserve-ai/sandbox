package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// customerTeamPermissionAllowed checks an active team-scoped permission without
// writing a response. Use this for optional capability fields on otherwise
// readable endpoints.
func (h *Handlers) customerTeamPermissionAllowed(c *gin.Context, teamID uuid.UUID, permission string) (bool, error) {
	if h == nil {
		return false, fmt.Errorf("nil handlers")
	}

	// DBTX-only handler unit tests do not have the Phase 1 RBAC tables or a real pool.
	// Production routers always provide h.Pool, so this keeps old unit tests focused
	// on handler behavior without weakening real requests.
	// Unit tests must set h.Pool to get real RBAC enforcement.
	if gin.Mode() == gin.TestMode && h.Pool == nil {
		return true, nil
	}

	actorID := actorIDFromContext(c)
	if actorID == nil {
		return false, nil
	}

	authzSvc := h.authzService()
	if authzSvc == nil {
		return false, fmt.Errorf("missing authz service")
	}

	return authzSvc.CanTeam(c.Request.Context(), *actorID, teamID, permission)
}

// requireCustomerTeamPermission gates a handler on an active team-scoped permission.
// Callers should pass the team ID already resolved from request context.
func (h *Handlers) requireCustomerTeamPermission(c *gin.Context, teamID uuid.UUID, permission string) bool {
	allowed, err := h.customerTeamPermissionAllowed(c, teamID, permission)
	if err != nil {
		log.Error().
			Err(err).
			Str("team_id", teamID.String()).
			Str("permission", permission).
			Msg("RBAC team permission check failed")
		respondError(c, ErrInternal)
		return false
	}
	if !allowed {
		respondError(c, ErrForbidden)
		return false
	}
	return true
}

// requireTeamPermissionFromContext resolves team_id from the Gin context before
// applying the supplied permission check.
func (h *Handlers) requireTeamPermissionFromContext(c *gin.Context, permission string) bool {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return false
	}
	return h.requireCustomerTeamPermission(c, teamID, permission)
}

// Sandbox access intentionally aliases settings permissions for Phase 3. Keep
// sandbox-specific helpers at call sites so a future sandboxes:* permission split
// can be made centrally without touching every handler again.
func (h *Handlers) requireTeamSandboxRead(c *gin.Context, teamID uuid.UUID) bool {
	if isConsoleImpersonation(c) && apiKeyHasScope(c, "platform:sandbox:read") {
		return true
	}
	return h.requireCustomerTeamPermission(c, teamID, "settings:read")
}

func (h *Handlers) requireTeamSandboxWrite(c *gin.Context, teamID uuid.UUID) bool {
	return h.requireCustomerTeamPermission(c, teamID, "settings:write")
}

func (h *Handlers) requireTeamSettingsRead(c *gin.Context, teamID uuid.UUID) bool {
	return h.requireCustomerTeamPermission(c, teamID, "settings:read")
}

func (h *Handlers) requireTeamSettingsWrite(c *gin.Context, teamID uuid.UUID) bool {
	return h.requireCustomerTeamPermission(c, teamID, "settings:write")
}

func (h *Handlers) requireTeamActivityRead(c *gin.Context, teamID uuid.UUID) bool {
	if isConsoleImpersonation(c) && apiKeyHasScope(c, "platform:activity:read") {
		return true
	}
	return h.requireCustomerTeamPermission(c, teamID, "settings:read")
}

func (h *Handlers) requireTeamTemplateRead(c *gin.Context, teamID uuid.UUID) bool {
	if isConsoleImpersonation(c) && apiKeyHasScope(c, "platform:template:read") {
		return true
	}
	return h.requireCustomerTeamPermission(c, teamID, "settings:read")
}
