package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/auth"
)

func TestMachineRepairActivationGate(t *testing.T) {
	if (AuthorityEligibility{}).Valid() {
		t.Fatal("empty activation eligibility enabled issuance")
	}
	if !(AuthorityEligibility{ContractRevision: "machine-identity-v1", Environment: "staging", ConfiguredEnvironment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true}).Valid() {
		t.Fatal("complete activation eligibility was rejected")
	}
}

func TestMachineRepairActivationEnvironment(t *testing.T) {
	base := AuthorityEligibility{ContractRevision: "machine-identity-v1", Environment: "staging", ConfiguredEnvironment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true}
	if !base.Valid() {
		t.Fatal("supported configured environment should enable eligibility")
	}
	for _, bad := range []AuthorityEligibility{
		{ContractRevision: "v1", Environment: "staging", ConfiguredEnvironment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true},
		{ContractRevision: "machine-identity-v1", Environment: "prod", ConfiguredEnvironment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true},
		{ContractRevision: "machine-identity-v1", Environment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true},
	} {
		if bad.Valid() {
			t.Fatalf("unsupported or unbound eligibility accepted: %#v", bad)
		}
	}
}

func TestMachineRepairProducerConsumer(t *testing.T) {
	now := time.Now()
	principal, credential, lineage, team, tenant, sandbox := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	caller := auth.CallerContext{PrincipalID: principal, CredentialID: credential, LineageID: lineage, TeamID: team, HostedTenantID: tenant, Permissions: []auth.MachineOperation{auth.MachineOperationRead}, Policy: auth.NewMachinePolicy(auth.MachineOperationRead), Audience: "sandbox-api", AllowedAudiences: []string{"sandbox-proxy"}, ExpiresAt: now.Add(time.Minute), RevocationGeneration: 2}
	capability, err := auth.DeriveCapability(caller, auth.SandboxOwnership{SandboxID: sandbox, OwnerPrincipalID: principal, TeamID: team}, sandbox, "sandbox-proxy", caller.Permissions, now.Add(30*time.Second), now)
	if err != nil || capability.Audience != "sandbox-proxy" {
		t.Fatalf("child audience not narrowed for production consumer: %#v %v", capability, err)
	}
	token, err := auth.SignMachineCapability(capability, []byte("producer-consumer-key"), now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := auth.VerifyMachineCapability(token, []byte("producer-consumer-key"), now)
	if err != nil || verified.PrincipalID != principal || verified.TeamID != team || verified.LineageID != lineage {
		t.Fatalf("consumer lost caller binding: %#v %v", verified, err)
	}
}

func TestMachineRepairResourceOwnershipRecovery(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	principal := uuid.New()
	c.Set(machineCallerContextKey, auth.CallerContext{PrincipalID: principal})
	if got := ownerIDFromContext(c); got != "machine:"+principal.String() {
		t.Fatalf("restore ownership changed: %q", got)
	}
}

func TestMachineRepairLifecycleRetryBoundaries(t *testing.T) {
	first := lifecycleExpiry(time.Date(2026, 10, 6, 10, 15, 0, 0, time.UTC))
	second := lifecycleExpiry(time.Date(2026, 10, 6, 10, 59, 59, 0, time.UTC))
	if first != second {
		t.Fatalf("same-window lifecycle expiry changed across retry: %v != %v", first, second)
	}
}

func TestMachineRepairIssuancePolicyRoundTrip(t *testing.T) {
	ops := trustedMachineOperations()
	policy := auth.NewTrustedIssuancePolicy(func() []auth.MachineOperation {
		out := make([]auth.MachineOperation, len(ops))
		for i, op := range ops {
			out[i] = auth.MachineOperation(op)
		}
		return out
	}(), trustedChildAudiences("sandbox-api")...)
	if !policy.Allows(auth.MachineOperationCommandRun) || !policy.AllowsAudience("sandbox-proxy") || policy.AllowsAudience("untrusted") {
		t.Fatalf("issuance policy is not compatible with proxy child: %#v", policy)
	}
}

func TestMachineRepairOwnershipTokenResponses(t *testing.T) {
	actor, parent, team, sandbox := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	capability, err := auth.DeriveHumanCapabilityWithParent(actor, parent, team, sandbox, "sandbox-proxy", []auth.MachineOperation{auth.MachineOperationRead}, now.Add(-time.Second), now)
	if err == nil || capability.CallerKind != "" {
		t.Fatal("human capability accepted an expired parent-bound window")
	}
}

func TestMachineRepairCreateOwnershipPublication(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	principal := uuid.New()
	c.Set(machineCallerContextKey, auth.CallerContext{PrincipalID: principal, Audience: "sandbox-api", Permissions: []auth.MachineOperation{auth.MachineOperationCreate}, Policy: auth.NewMachinePolicy(auth.MachineOperationCreate), TeamID: uuid.New(), HostedTenantID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), RevocationGeneration: 1, ExpiresAt: timeNowForRepair().Add(time.Hour)})
	if got := ownerIDFromContext(c); got != "machine:"+principal.String() {
		t.Fatalf("machine owner publication ID = %q", got)
	}
}

func timeNowForRepair() time.Time { return time.Now() }
