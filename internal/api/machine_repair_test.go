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
	if !(AuthorityEligibility{ContractRevision: "v1", Environment: "staging", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true}).Valid() {
		t.Fatal("complete activation eligibility was rejected")
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
