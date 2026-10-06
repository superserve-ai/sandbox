package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
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

func TestMachineCapabilityRoundTripAndTamperRejection(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	capability := MachineCapability{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), Operations: []MachineOperation{MachineOperationRead}, Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 3}
	token, err := SignMachineCapability(capability, []byte("test-signing-key"), now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyMachineCapability(token, []byte("test-signing-key"), now)
	if err != nil || !reflect.DeepEqual(got, capability) {
		t.Fatalf("round trip mismatch: %#v, %v", got, err)
	}
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	parts[3] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := VerifyMachineCapability(strings.Join(parts, "."), []byte("test-signing-key"), now); err == nil {
		t.Fatal("expected a tampered signature to be rejected")
	}
}

func TestSessionRegistryRevokesCredentialAndPrincipal(t *testing.T) {
	now := time.Unix(100, 0)
	principal, credential := uuid.New(), uuid.New()
	r := NewSessionRegistry(1)
	state := RevocationState{PrincipalID: principal, CredentialID: credential, RevocationGeneration: 2, ExpiresAt: now.Add(time.Minute)}
	if err := r.Register("stream-1", state); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("stream-2", state); err != ErrSessionLimit {
		t.Fatalf("expected bounded registry, got %v", err)
	}
	capability := MachineCapability{PrincipalID: principal, CredentialID: credential, RevocationGeneration: 2, ExpiresAt: now.Add(time.Minute)}
	if !r.Allows("stream-1", capability, now) {
		t.Fatal("active session should be allowed")
	}
	if removed := r.RevokeCredential(credential, 2); removed != 1 || r.Allows("stream-1", capability, now) {
		t.Fatal("credential revocation did not close the session")
	}
}

func TestOperationForHTTPDefaultsToDeny(t *testing.T) {
	if op, ok := OperationForHTTP("GET", "/sandboxes"); !ok || op != MachineOperationList {
		t.Fatalf("list operation = %q, %v", op, ok)
	}
	if op, ok := OperationForHTTP("POST", "/teams/anything/members"); ok || op != "" {
		t.Fatalf("management route must not be machine-authorized: %q, %v", op, ok)
	}
}

func TestValidateMachineCreateRejectsIndirectSources(t *testing.T) {
	now := time.Now().Add(time.Minute)
	templateID := uuid.New()
	caller := CallerContext{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), HostedTenantID: uuid.New(), Permissions: []MachineOperation{MachineOperationCreate}, Policy: NewMachinePolicy(MachineOperationCreate), Audience: "api", ExpiresAt: now, RevocationGeneration: 1, ApprovedTemplateID: &templateID}
	if err := ValidateMachineCreate(caller, &templateID, nil, 0); err != nil {
		t.Fatalf("approved machine create rejected: %v", err)
	}
	if err := ValidateMachineCreate(caller, &templateID, uuidPtr(uuid.New()), 0); err == nil {
		t.Fatal("snapshot source must be rejected")
	}
}

func TestMachineCapabilityAuthorityFailureFailsClosed(t *testing.T) {
	now := time.Unix(100, 0)
	capability := MachineCapability{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), SandboxID: uuid.New(), Operations: []MachineOperation{MachineOperationRead}, Audience: "sandbox-proxy", ExpiresAt: now.Add(time.Minute), RevocationGeneration: 4}
	token, err := SignMachineCapability(capability, []byte("authority-key"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMachineCapabilityWithAuthority(t.Context(), token, []byte("authority-key"), now, func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) {
		return 0, errors.New("authority unavailable")
	}); err == nil {
		t.Fatal("authority failure must deny capability")
	}
	if _, err := VerifyMachineCapabilityWithAuthority(t.Context(), token, []byte("authority-key"), now, func(context.Context, uuid.UUID, uuid.UUID) (uint64, error) {
		return 4, nil
	}); err != nil {
		t.Fatalf("current authority rejected capability: %v", err)
	}
}

func uuidPtr(id uuid.UUID) *uuid.UUID { return &id }
