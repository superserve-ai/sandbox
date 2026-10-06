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
		Permissions: []MachineOperation{MachineOperationRead}, Policy: NewMachinePolicy(MachineOperationRead), Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 1,
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
	caller := CallerContext{PrincipalID: principalID, CredentialID: credentialID, LineageID: lineageID, TeamID: teamID, HostedTenantID: tenantID, Permissions: []MachineOperation{MachineOperationRead}, Policy: NewMachinePolicy(MachineOperationRead), Audience: "proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 7}
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

func TestDeriveCapabilityPreservesCallerAudience(t *testing.T) {
	now := time.Unix(100, 0)
	principalID, teamID, tenantID, credentialID, lineageID, sandboxID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	caller := CallerContext{
		PrincipalID: principalID, CredentialID: credentialID, LineageID: lineageID, TeamID: teamID, HostedTenantID: tenantID,
		Permissions: []MachineOperation{MachineOperationRead}, Policy: NewMachinePolicy(MachineOperationRead), Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 1,
	}
	ownership := SandboxOwnership{SandboxID: sandboxID, OwnerPrincipalID: principalID, TeamID: teamID}
	if _, err := DeriveCapability(caller, ownership, sandboxID, "peer-proxy", []MachineOperation{MachineOperationRead}, now.Add(30*time.Second), now); err == nil {
		t.Fatal("expected audience substitution to be denied")
	}
	capability, err := DeriveCapability(caller, ownership, sandboxID, caller.Audience, []MachineOperation{MachineOperationRead}, now.Add(30*time.Second), now)
	if err != nil || capability.Audience != caller.Audience {
		t.Fatalf("expected caller audience to be preserved, got %#v, %v", capability, err)
	}
}

func TestCallerContextRejectsUnknownPermission(t *testing.T) {
	now := time.Unix(100, 0)
	caller := CallerContext{
		PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), HostedTenantID: uuid.New(),
		Permissions: []MachineOperation{MachineOperation("future:operation")}, Policy: NewMachinePolicy(MachineOperation("future:operation")), Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 1,
	}
	if err := caller.ValidateAt(now); err == nil {
		t.Fatal("expected unknown machine operation to be rejected")
	}
}

func TestMachineCapabilityRejectsUnknownOperation(t *testing.T) {
	now := time.Unix(100, 0)
	capability := MachineCapability{
		PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(),
		Operations: []MachineOperation{MachineOperation("future:operation")}, Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 1,
	}
	if err := capability.ValidateAt(now); err == nil {
		t.Fatal("expected unknown capability operation to be rejected")
	}
}
