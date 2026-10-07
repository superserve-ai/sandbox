//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestMachineResumeClaimCarriesImmutableOwnership(t *testing.T) {
	ctx := context.Background()
	for _, machine := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "machine"}[machine], func(t *testing.T) {
			teamID, _ := seedTeamAndKey(t)
			sandboxID := seedPausedSandbox(t, teamID)
			var principalID uuid.UUID
			if machine {
				principal := machineRepairPrincipal(t, testQueries, teamID)
				principalID = principal.ID
				if err := testQueries.CreateMachineSandboxOwner(ctx, sandboxID, principalID, teamID); err != nil {
					t.Fatal(err)
				}
			}
			params := db.ClaimResumeParams{ID: sandboxID, TeamID: teamID, LockKey: sandboxID.String()}
			claim, err := testQueries.ClaimResume(ctx, params)
			if err != nil {
				t.Fatal(err)
			}
			if claim.Sandbox.ID != sandboxID || claim.Sandbox.TeamID != teamID || claim.Sandbox.Status != db.SandboxStatusResuming || claim.MachineOwnershipPresent != machine {
				t.Fatalf("claim identity mismatch: %+v", claim)
			}
			if machine {
				if !claim.MachineOwnerPrincipalID.Valid || uuid.UUID(claim.MachineOwnerPrincipalID.Bytes) != principalID || !claim.MachineOwnerTeamID.Valid || uuid.UUID(claim.MachineOwnerTeamID.Bytes) != teamID {
					t.Fatalf("claim lost immutable owner: %+v", claim)
				}
			} else if claim.MachineOwnerPrincipalID.Valid || claim.MachineOwnerTeamID.Valid {
				t.Fatal("ordinary claim fabricated machine identity")
			}
			if _, err := testQueries.ClaimResume(ctx, params); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("already claimed row was authorized again: %v", err)
			}
		})
	}
}
