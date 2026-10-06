package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

const machineCallerContextKey = "machine_caller"

// MachineCredentialResolver is implemented by the owning control-plane
// integration. It returns verified durable identity; it must not return raw
// credential material or derive authority from human membership.
type MachineCredentialResolver interface {
	ResolveMachineCredential(context.Context, string) (auth.CallerContext, error)
}

func MachineCredentialAuth(resolver MachineCredentialResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start the shared auth phase before resolving the durable machine
		// authority so machine lookup latency and failure paths remain visible
		// to lifecycle instrumentation.
		authStart := time.Now()
		c.Set("auth_start", authStart)
		raw := strings.TrimSpace(c.GetHeader("X-QM-Machine-Credential"))
		if raw == "" {
			c.Next()
			return
		}
		if resolver == nil {
			c.Set("auth_duration", time.Since(authStart))
			recordMachineAuthFailure(c, authStart)
			respondError(c, ErrUnauthorized)
			c.Abort()
			return
		}
		caller, err := resolver.ResolveMachineCredential(c.Request.Context(), raw)
		if errors.Is(err, ErrMachineAuthorityUnavailable) {
			c.Set("auth_duration", time.Since(authStart))
			recordMachineAuthFailure(c, authStart)
			respondErrorMsg(c, "service_unavailable", "Machine authority is not ready.", http.StatusServiceUnavailable)
			c.Abort()
			return
		}
		if err != nil || caller.ValidateAt(time.Now()) != nil {
			c.Set("auth_duration", time.Since(authStart))
			recordMachineAuthFailure(c, authStart)
			respondError(c, ErrUnauthorized)
			c.Abort()
			return
		}
		op, mapped := auth.OperationForHTTP(c.Request.Method, c.Request.URL.Path)
		if !mapped || !caller.Policy.Allows(op) || !containsMachinePermission(caller.Permissions, op) {
			c.Set("auth_duration", time.Since(authStart))
			recordMachineAuthFailure(c, authStart)
			respondError(c, ErrForbidden)
			c.Abort()
			return
		}
		setMachineCaller(c, caller)
		c.Set("team_id", caller.TeamID.String())
		c.Set("auth_duration", time.Since(authStart))
		c.Next()
	}
}

func recordMachineAuthFailure(c *gin.Context, started time.Time) {
	op, ok := sandboxLifecycleOperation(c.Request.Method, c.FullPath())
	if !ok {
		return
	}
	RecordLatencyPhases(c.Request.Context(), op, "", map[string]time.Duration{
		"auth": time.Since(started), "total": time.Since(started),
	})
}

func setMachineCaller(c *gin.Context, caller auth.CallerContext) {
	c.Set(machineCallerContextKey, caller)
}

func machineCallerFromContext(c *gin.Context) (auth.CallerContext, bool) {
	v, ok := c.Get(machineCallerContextKey)
	if !ok {
		return auth.CallerContext{}, false
	}
	caller, ok := v.(auth.CallerContext)
	return caller, ok
}

func machineOperationForRequest(c *gin.Context) (auth.MachineOperation, bool) {
	return auth.OperationForHTTP(c.Request.Method, c.Request.URL.Path)
}

// requireMachineOperation is deliberately separate from human RBAC. Unknown
// routes and missing caller context are denied; human requests continue down
// the existing permission path.
func (h *Handlers) requireMachineOperation(c *gin.Context, operation auth.MachineOperation) bool {
	caller, machine := machineCallerFromContext(c)
	if !machine {
		return true
	}
	if caller.ValidateAt(timeNow(h)) != nil || !caller.Policy.Allows(operation) || !containsMachinePermission(caller.Permissions, operation) {
		respondError(c, ErrForbidden)
		return false
	}
	return true
}

func containsMachinePermission(permissions []auth.MachineOperation, want auth.MachineOperation) bool {
	for _, permission := range permissions {
		if permission == want {
			return true
		}
	}
	return false
}

func timeNow(h *Handlers) time.Time {
	if h != nil && h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func machineOwnerMatches(caller auth.CallerContext, owner db.MachineSandboxOwnerRow, sandboxID uuid.UUID, teamID uuid.UUID) bool {
	return owner.SandboxID == sandboxID && owner.TeamID == teamID && owner.OwnerPrincipalID == caller.PrincipalID && caller.TeamID == teamID
}

func (h *Handlers) requireMachineSandboxOwner(c *gin.Context, sandboxID, teamID uuid.UUID) bool {
	caller, machine := machineCallerFromContext(c)
	if !machine {
		return true
	}
	if h == nil || h.DB == nil {
		respondError(c, ErrForbidden)
		return false
	}
	owner, err := h.DB.GetMachineSandboxOwner(c.Request.Context(), sandboxID, teamID)
	if err != nil || !machineOwnerMatches(caller, owner, sandboxID, teamID) {
		respondError(c, ErrForbidden)
		return false
	}
	return true
}

// machineCreateHeaders is an explicit deny-list for the public header paths
// that previously acted as caller metadata. It is kept here so future route
// additions cannot accidentally make those headers authoritative.
func machineCreateHeaders(c *gin.Context) bool {
	for _, header := range []string{"X-Actor-User-Id", "X-Machine-Principal", "X-Machine-Team", "X-Sandbox-Owner"} {
		if strings.TrimSpace(c.GetHeader(header)) != "" {
			respondErrorMsg(c, "forbidden", "machine identity is server-authenticated", http.StatusForbidden)
			return false
		}
	}
	return true
}
