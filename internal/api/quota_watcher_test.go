package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

func ptrInt32(v int32) *int32 { return &v }

func TestComputeQuotaAlerts(t *testing.T) {
	atThreshold := uuid.New()  // sandboxes 80/100 = 80% -> alert
	below := uuid.New()        // sandboxes 79/100 = 79% -> no
	tmplDefault := uuid.New()  // templates 8/10 via default 10 = 80% -> alert
	tmplOverride := uuid.New() // templates 10/200 (override) = 5% -> no
	zeroLimit := uuid.New()    // max 0 -> must not alert or panic

	rows := []db.ListTeamQuotaUsageRow{
		{ID: atThreshold, Name: "at", ActiveSandboxCount: 80, MaxSandboxes: 100},
		{ID: below, Name: "below", ActiveSandboxCount: 79, MaxSandboxes: 100, TemplateCount: 1},
		{ID: tmplDefault, Name: "tdefault", MaxSandboxes: 100, TemplateCount: 8}, // MaxTemplates nil -> default
		{ID: tmplOverride, Name: "toverride", MaxSandboxes: 100, MaxTemplates: ptrInt32(200), TemplateCount: 10},
		{ID: zeroLimit, Name: "zero", ActiveSandboxCount: 5, MaxSandboxes: 0},
	}

	got := computeQuotaAlerts(rows)

	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2: %+v", len(got), got)
	}
	if a, ok := got[quotaKey{atThreshold, "sandboxes"}]; !ok {
		t.Error("expected sandbox alert at 80%")
	} else if a.Pct != 80 || a.Used != 80 || a.Limit != 100 {
		t.Errorf("sandbox alert = %+v, want 80%% 80/100", a)
	}
	if a, ok := got[quotaKey{tmplDefault, "templates"}]; !ok {
		t.Error("expected template alert at 80% (default limit)")
	} else if a.Pct != 80 {
		t.Errorf("template alert pct = %d, want 80", a.Pct)
	}

	for _, neg := range []quotaKey{
		{below, "sandboxes"},
		{tmplOverride, "templates"},
		{zeroLimit, "sandboxes"},
	} {
		if _, ok := got[neg]; ok {
			t.Errorf("%v should not have alerted", neg)
		}
	}
}
