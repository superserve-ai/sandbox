//go:build integration

package integration

import (
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

type teamLimits struct {
	sandboxes          int32
	vcpu, memory, disk *int32
	customized         bool
}

func readTeamLimits(t *testing.T, team uuid.UUID) teamLimits {
	t.Helper()
	var l teamLimits
	if err := testPool.QueryRow(t.Context(), `SELECT max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, limits_customized FROM team WHERE id = $1`, team).
		Scan(&l.sandboxes, &l.vcpu, &l.memory, &l.disk, &l.customized); err != nil {
		t.Fatal(err)
	}
	return l
}

func assertTeamLimits(t *testing.T, team uuid.UUID, sandboxes int32, vcpu, memory, disk *int32) {
	t.Helper()
	got := readTeamLimits(t, team)
	eq := func(a, b *int32) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	if got.sandboxes != sandboxes || !eq(got.vcpu, vcpu) || !eq(got.memory, memory) || !eq(got.disk, disk) {
		t.Fatalf("limits = %d/%v/%v/%v, want %d/%v/%v/%v", got.sandboxes, got.vcpu, got.memory, got.disk, sandboxes, vcpu, memory, disk)
	}
}

func endContract(t *testing.T, c db.BillingCommercialContract) {
	t.Helper()
	if _, err := testQueries.EndCommercialContract(t.Context(), db.EndCommercialContractParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_PlanLimitsFollowContract(t *testing.T) {
	vcpu, memory, disk := int32(16), int32(65536), int32(65536)
	for _, annual := range []bool{false, true} {
		c := commercialFixture(t, annual)
		assertTeamLimits(t, c.TeamID, 20, nil, nil, nil)
		c = commercialActivate(t, c)
		assertTeamLimits(t, c.TeamID, 1000, &vcpu, &memory, &disk)
		endContract(t, c)
		assertTeamLimits(t, c.TeamID, 20, nil, nil, nil)
		if readTeamLimits(t, c.TeamID).customized {
			t.Fatal("plan changes marked the team as customized")
		}
	}
}

func TestIntegration_PlanLimitsKeepManualOverrides(t *testing.T) {
	c := commercialFixture(t, true)
	correctionExec(t, `UPDATE team SET max_sandboxes = 150, max_template_vcpu = 4 WHERE id = $1`, c.TeamID)
	if !readTeamLimits(t, c.TeamID).customized {
		t.Fatal("manual limit change was not recorded as an override")
	}
	vcpu := int32(4)
	c = commercialActivate(t, c)
	assertTeamLimits(t, c.TeamID, 150, &vcpu, nil, nil)
	endContract(t, c)
	assertTeamLimits(t, c.TeamID, 150, &vcpu, nil, nil)
}

func TestIntegration_PlanLimitsEndWithLapsedTerm(t *testing.T) {
	c := commercialActivate(t, commercialFixture(t, false))
	correctionExec(t, `UPDATE billing_commercial_contract SET ends_at = clock_timestamp() - interval '1 second', revision = revision + 1 WHERE id = $1`, c.ID)
	if n, err := testQueries.EndLapsedCommercialContracts(t.Context()); err != nil || n < 1 {
		t.Fatalf("ended %d lapsed contracts: %v", n, err)
	}
	assertTeamLimits(t, c.TeamID, 20, nil, nil, nil)
}
