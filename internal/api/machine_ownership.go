package api

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type requestOwnerResult struct {
	sandboxID, teamID uuid.UUID
	owner             db.MachineSandboxOwnerRow
	err               error
}

// Ownership is immutable, so one bounded lookup can serve recovery and response
// generation within this request. Errors are retained to prevent fail-open retries.
func (h *Handlers) requestSandboxOwner(c *gin.Context, sandboxID, teamID uuid.UUID) (db.MachineSandboxOwnerRow, error) {
	if value, ok := c.Get("machine_resource_owner"); ok {
		if cached, ok := value.(requestOwnerResult); ok && cached.sandboxID == sandboxID && cached.teamID == teamID {
			return cached.owner, cached.err
		}
	}
	if h.DB == nil {
		return db.MachineSandboxOwnerRow{}, fmt.Errorf("ownership unavailable")
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	owner, err := h.DB.GetMachineSandboxOwner(ctx, sandboxID, teamID)
	c.Set("machine_resource_owner", requestOwnerResult{sandboxID: sandboxID, teamID: teamID, owner: owner, err: err})
	return owner, err
}

// Only successful resume claims may seed ownership. An absent left-joined
// row is authoritative ordinary ownership, not an unverified lookup failure.
func cacheClaimedSandboxOwner(c *gin.Context, sandboxID, teamID uuid.UUID, claimed db.ClaimResumeRow) (db.MachineSandboxOwnerRow, error) {
	var owner db.MachineSandboxOwnerRow
	var err error
	switch {
	case claimed.Sandbox.ID != sandboxID || claimed.Sandbox.TeamID != teamID:
		err = fmt.Errorf("resume ownership resource mismatch")
	case !claimed.MachineOwnershipPresent:
		if claimed.MachineOwnerPrincipalID.Valid || claimed.MachineOwnerTeamID.Valid {
			err = fmt.Errorf("resume ownership presence mismatch")
		} else {
			err = pgx.ErrNoRows
		}
	case !claimed.MachineOwnerPrincipalID.Valid || !claimed.MachineOwnerTeamID.Valid || uuid.UUID(claimed.MachineOwnerPrincipalID.Bytes) == uuid.Nil || uuid.UUID(claimed.MachineOwnerTeamID.Bytes) != teamID:
		err = fmt.Errorf("resume ownership identity mismatch")
	default:
		owner = db.MachineSandboxOwnerRow{SandboxID: sandboxID, OwnerPrincipalID: uuid.UUID(claimed.MachineOwnerPrincipalID.Bytes), TeamID: teamID}
	}
	c.Set("machine_resource_owner", requestOwnerResult{sandboxID: sandboxID, teamID: teamID, owner: owner, err: err})
	return owner, err
}
