package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMachineRepairCapabilityPolicy(t *testing.T) {
	now := time.Now()
	actor, team, sandbox := uuid.New(), uuid.New(), uuid.New()
	capability, err := DeriveHumanCapability(actor, team, sandbox, "sandbox-proxy", []MachineOperation{MachineOperationRead}, now.Add(time.Minute), now)
	if err != nil || capability.CallerKind != "human" || capability.ActorID != actor {
		t.Fatalf("human capability = %#v, err=%v", capability, err)
	}
	if _, err := SignMachineCapability(capability, []byte("repair-key"), now); err != nil {
		t.Fatalf("sign human capability: %v", err)
	}
	policy := NewTrustedIssuancePolicy([]MachineOperation{MachineOperationRead}, "sandbox-api", "sandbox-proxy")
	if !policy.Allows(MachineOperationRead) || !policy.AllowsAudience("sandbox-proxy") || policy.Allows(MachineOperationDelete) || policy.AllowsAudience("arbitrary") {
		t.Fatalf("policy did not narrow operations/audiences: %#v", policy)
	}
}

func TestMachineRepairVerifiedHumanCapability(t *testing.T) {
	now := time.Now()
	capability, err := DeriveHumanCapability(uuid.New(), uuid.New(), uuid.New(), "sandbox-proxy", []MachineOperation{MachineOperationRead}, now.Add(time.Minute), now)
	if err != nil || capability.CallerKind != "human" {
		t.Fatalf("human capability unavailable: %v", err)
	}
}

func TestMachineRepairSessionFencing(t *testing.T) {
	r := NewSessionRegistry(2)
	principal, credential := uuid.New(), uuid.New()
	epoch := r.CurrentEpoch()
	state := RevocationState{PrincipalID: principal, CredentialID: credential, RevocationGeneration: 1, ExpiresAt: time.Now().Add(time.Minute)}
	if err := r.RegisterWithCancelEpoch("stale", state, nil, epoch); err != nil {
		t.Fatal(err)
	}
	r.RevokeCredential(credential, 1)
	if err := r.RegisterWithCancelEpoch("late", state, nil, epoch); err == nil {
		t.Fatal("stale verify/register epoch was admitted")
	}
	r.RevokePrincipal(uuid.New(), 1)
	unrelated := RevocationState{PrincipalID: uuid.New(), CredentialID: uuid.New(), RevocationGeneration: 1, ExpiresAt: time.Now().Add(time.Minute)}
	if err := r.RegisterWithCancelEpoch("unrelated", unrelated, nil, epoch); err != nil {
		t.Fatalf("unrelated revocation rejected a verified session: %v", err)
	}
}
