package api

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	return cacheJoinedSandboxOwner(c, sandboxID, teamID, claimed.Sandbox, claimed.MachineOwnershipPresent, claimed.MachineOwnerPrincipalID, claimed.MachineOwnerTeamID)
}

func cacheJoinedSandboxOwner(c *gin.Context, sandboxID, teamID uuid.UUID, sandbox db.Sandbox, present bool, principalID, ownerTeamID pgtype.UUID) (db.MachineSandboxOwnerRow, error) {
	var owner db.MachineSandboxOwnerRow
	var err error
	switch {
	case sandbox.ID != sandboxID || sandbox.TeamID != teamID:
		err = fmt.Errorf("sandbox ownership resource mismatch")
	case !present:
		if principalID.Valid || ownerTeamID.Valid {
			err = fmt.Errorf("sandbox ownership presence mismatch")
		} else {
			err = pgx.ErrNoRows
		}
	case !principalID.Valid || !ownerTeamID.Valid || uuid.UUID(principalID.Bytes) == uuid.Nil || uuid.UUID(ownerTeamID.Bytes) != teamID:
		err = fmt.Errorf("sandbox ownership identity mismatch")
	default:
		owner = db.MachineSandboxOwnerRow{SandboxID: sandboxID, OwnerPrincipalID: uuid.UUID(principalID.Bytes), TeamID: teamID}
	}
	c.Set("machine_resource_owner", requestOwnerResult{sandboxID: sandboxID, teamID: teamID, owner: owner, err: err})
	return owner, err
}
