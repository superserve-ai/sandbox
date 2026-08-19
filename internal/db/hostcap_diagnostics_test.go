package db

import (
	"strings"
	"testing"
)

func TestHostCapabilityDiagnosticsUsesSameSnapshotAsDecision(t *testing.T) {
	for _, want := range []string{
		"WITH target_host AS MATERIALIZED",
		"capability_rows AS MATERIALIZED",
		"hc.heartbeat_at = h.last_heartbeat_at",
		"matches_current_heartbeat",
		"jsonb_agg",
		"r.has_capabilities",
	} {
		if !strings.Contains(checkHostCapabilitiesWithDiagnostics, want) {
			t.Errorf("diagnostic capability query missing %q", want)
		}
	}
	if strings.Contains(checkHostCapabilitiesWithDiagnostics, "FOR SHARE") {
		t.Fatal("standalone diagnostic preflight must remain unlocked")
	}
}
