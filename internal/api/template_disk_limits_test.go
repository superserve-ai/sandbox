package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

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
			if got := validateTemplateShape(tc.team, systemID, 1, 1024, tc.disk); got != tc.want {
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
			if got := validateTemplateShape(tc.team, systemID, tc.vcpu, tc.mem, 4096); got != tc.want {
				t.Fatalf("validateTemplateShape() = %q, want %q", got, tc.want)
			}
		})
	}
}
