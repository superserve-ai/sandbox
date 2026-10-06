package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeriveCapabilityCannotBroadenCaller(t *testing.T) {
	now := time.Unix(100, 0)
	principalID, teamID, tenantID, credentialID, lineageID, sandboxID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	caller := CallerContext{
		PrincipalID: principalID, CredentialID: credentialID, LineageID: lineageID, TeamID: teamID, HostedTenantID: tenantID,
		Permissions: []MachineOperation{MachineOperationRead}, Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 1,
	}
	ownership := SandboxOwnership{SandboxID: sandboxID, OwnerPrincipalID: principalID, TeamID: teamID}
	if _, err := DeriveCapability(caller, ownership, sandboxID, "sandbox-proxy", []MachineOperation{MachineOperationDelete}, now.Add(30*time.Second), now); err == nil {
		t.Fatal("expected a child operation outside the caller policy to be denied")
	}
	capability, err := DeriveCapability(caller, ownership, sandboxID, "sandbox-proxy", []MachineOperation{MachineOperationRead}, now.Add(30*time.Second), now)
	if err != nil || !capability.Allows(MachineOperationRead) || capability.Allows(MachineOperationDelete) {
		t.Fatalf("unexpected capability: %#v, %v", capability, err)
	}
}

func TestDeriveCapabilityRejectsOwnershipMismatchAndExpiryExtension(t *testing.T) {
	now := time.Unix(100, 0)
	principalID, teamID, tenantID, credentialID, lineageID, sandboxID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	caller := CallerContext{PrincipalID: principalID, CredentialID: credentialID, LineageID: lineageID, TeamID: teamID, HostedTenantID: tenantID, Permissions: []MachineOperation{MachineOperationRead}, Audience: "proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 7}
	wrongOwner := SandboxOwnership{SandboxID: sandboxID, OwnerPrincipalID: uuid.New(), TeamID: teamID}
	if _, err := DeriveCapability(caller, wrongOwner, sandboxID, "proxy", []MachineOperation{MachineOperationRead}, now.Add(10*time.Second), now); err == nil {
		t.Fatal("expected owner mismatch to fail closed")
	}
	ownership := SandboxOwnership{SandboxID: sandboxID, OwnerPrincipalID: principalID, TeamID: teamID}
	if _, err := DeriveCapability(caller, ownership, sandboxID, "proxy", []MachineOperation{MachineOperationRead}, now.Add(2*time.Minute), now); err == nil {
		t.Fatal("expected child expiry extension to fail closed")
	}
}

func TestMachinePolicyDefaultsToDeny(t *testing.T) {
	policy := NewMachinePolicy(MachineOperationRead)
	if !policy.Allows(MachineOperationRead) || policy.Allows(MachineOperationDelete) || policy.Allows(MachineOperation("future:operation")) {
		t.Fatal("machine policy must explicitly allow only configured operations")
	}
}
