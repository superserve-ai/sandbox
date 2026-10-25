package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// legacyLimits applies the pay-as-you-go plan's caps where a team row
// leaves them open, as team_effective_limits does.
func legacyLimits(team db.Team) teamLimits {
	l := teamLimits{MaxVCPU: 2, MaxMemoryMiB: 2048, MaxDiskMiB: 8192, MaxTemplates: 10}
	if team.MaxTemplateVcpu != nil {
		l.MaxVCPU = *team.MaxTemplateVcpu
	}
	if team.MaxTemplateMemoryMib != nil {
		l.MaxMemoryMiB = *team.MaxTemplateMemoryMib
	}
	if team.MaxTemplateDiskMib != nil {
		l.MaxDiskMiB = *team.MaxTemplateDiskMib
	}
	return l
}

func TestValidateTemplateShapeDiskLimits(t *testing.T) {
	systemID := uuid.New()
	customerID := uuid.New()
	limit32 := int32(32768)
	limit128 := int32(131072)
	limitAbove := int32(131073)
	system := db.Team{ID: systemID}
	customer := db.Team{ID: customerID}
	cases := []struct {
		name string
		team db.Team
		disk int32
		want string
	}{
		{"below minimum", system, 1023, "disk_mib must be 1024-131072"},
		{"minimum", system, 1024, ""},
		{"previous ceiling", system, 30720, ""},
		{"32 GiB", system, 32768, ""},
		{"64 GiB", system, 65536, ""},
		{"128 GiB", system, 131072, ""},
		{"above ceiling", system, 131073, "disk_mib must be 1024-131072"},
		{"default team limit", customer, 8192, ""},
		{"default team limit unchanged", customer, 8193, "disk_mib must be 1024-8192 (your team's limit); contact support@superserve.ai for higher"},
		{"explicit team limit", db.Team{ID: customerID, MaxTemplateDiskMib: &limit32}, 32768, ""},
		{"explicit team limit enforced", db.Team{ID: customerID, MaxTemplateDiskMib: &limit32}, 32769, "disk_mib must be 1024-32768 (your team's limit); contact support@superserve.ai for higher"},
		{"team at platform ceiling", db.Team{ID: customerID, MaxTemplateDiskMib: &limit128}, 131072, ""},
		{"team cannot exceed platform ceiling", db.Team{ID: customerID, MaxTemplateDiskMib: &limitAbove}, 131073, "disk_mib must be 1024-131072"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateTemplateShape(tc.team.ID, systemID, legacyLimits(tc.team), 1, 1024, tc.disk); got != tc.want {
				t.Fatalf("validateTemplateShape() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateTemplateShapeComputeCeilings(t *testing.T) {
	systemID := uuid.New()
	vcpuAbove, memAbove := int32(33), int32(131073)
	customer := db.Team{ID: uuid.New(), MaxTemplateVcpu: &vcpuAbove, MaxTemplateMemoryMib: &memAbove}
	cases := []struct {
		name      string
		team      db.Team
		vcpu, mem int32
		want      string
	}{
		{"previous vcpu ceiling", db.Team{ID: systemID}, 10, 1024, ""},
		{"vcpu ceiling", db.Team{ID: systemID}, 32, 1024, ""},
		{"above vcpu ceiling", db.Team{ID: systemID}, 33, 1024, "vcpu must be 1-32"},
		{"previous memory ceiling", db.Team{ID: systemID}, 1, 20480, ""},
		{"memory ceiling", db.Team{ID: systemID}, 1, 131072, ""},
		{"above memory ceiling", db.Team{ID: systemID}, 1, 131073, "memory_mib must be 256-131072"},
		{"team at both ceilings", customer, 32, 131072, ""},
		{"team limit cannot exceed vcpu ceiling", customer, 33, 1024, "vcpu must be 1-32"},
		{"team limit cannot exceed memory ceiling", customer, 1, 131073, "memory_mib must be 256-131072"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateTemplateShape(tc.team.ID, systemID, legacyLimits(tc.team), tc.vcpu, tc.mem, 4096); got != tc.want {
				t.Fatalf("validateTemplateShape() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTemplateShapeDefaultsStayWithinTeamLimits(t *testing.T) {
	team, systemID := uuid.New(), uuid.New()
	small := teamLimits{MaxVCPU: 1, MaxMemoryMiB: 512, MaxDiskMiB: 2048}
	two := int32(2)
	cases := []struct {
		name    string
		team    uuid.UUID
		limits  teamLimits
		vcpu    *int32
		want    [3]int32
		invalid bool
	}{
		{"legacy defaults", team, legacyLimits(db.Team{ID: team}), nil, [3]int32{1, 1024, 4096}, false},
		{"capped at a smaller plan", team, small, nil, [3]int32{1, 512, 2048}, false},
		{"explicit sizes are not capped", team, small, &two, [3]int32{2, 512, 2048}, true},
		{"system team keeps the defaults", systemID, small, nil, [3]int32{1, 1024, 4096}, false},
	}
	for _, tc := range cases {
		vcpu, mem, disk := templateShape(tc.team, systemID, tc.limits, tc.vcpu, nil, nil)
		if got := [3]int32{vcpu, mem, disk}; got != tc.want {
			t.Errorf("%s: shape = %v, want %v", tc.name, got, tc.want)
		}
		if msg := validateTemplateShape(tc.team, systemID, tc.limits, vcpu, mem, disk); (msg != "") != tc.invalid {
			t.Errorf("%s: validation = %q", tc.name, msg)
		}
	}
}
