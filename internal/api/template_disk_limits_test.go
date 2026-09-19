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
	limit64 := int32(65536)
	limitAbove := int32(65537)
	system := db.Team{ID: systemID}
	customer := db.Team{ID: customerID}
	cases := []struct {
		name string
		team db.Team
		disk int32
		want string
	}{
		{"below minimum", system, 1023, "disk_mib must be 1024-65536"},
		{"minimum", system, 1024, ""},
		{"previous ceiling", system, 30720, ""},
		{"32 GiB", system, 32768, ""},
		{"64 GiB", system, 65536, ""},
		{"above ceiling", system, 65537, "disk_mib must be 1024-65536"},
		{"default team limit", customer, 8192, ""},
		{"default team limit unchanged", customer, 8193, "disk_mib must be 1024-8192 (your team's limit); contact support@superserve.ai for higher"},
		{"explicit team limit", db.Team{ID: customerID, MaxTemplateDiskMib: &limit32}, 32768, ""},
		{"explicit team limit enforced", db.Team{ID: customerID, MaxTemplateDiskMib: &limit32}, 32769, "disk_mib must be 1024-32768 (your team's limit); contact support@superserve.ai for higher"},
		{"team at platform ceiling", db.Team{ID: customerID, MaxTemplateDiskMib: &limit64}, 65536, ""},
		{"team cannot exceed platform ceiling", db.Team{ID: customerID, MaxTemplateDiskMib: &limitAbove}, 65537, "disk_mib must be 1024-65536"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateTemplateShape(tc.team, systemID, 1, 1024, tc.disk); got != tc.want {
				t.Fatalf("validateTemplateShape() = %q, want %q", got, tc.want)
			}
		})
	}
}
