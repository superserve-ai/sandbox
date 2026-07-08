package vm

import "testing"

// TestCollectStartupSlots pins the reservation input: every record that has a
// namespace is reserved under its own vmID (so a later cleanup can identity-match
// and release exactly its slot), and records without one are skipped.
func TestCollectStartupSlots(t *testing.T) {
	recs := []VMRecord{
		{ID: "paused", Namespace: "ns-1", Status: StatusPaused},
		{ID: "running", Namespace: "ns-2", Status: StatusRunning},
		{ID: "dead-running", Namespace: "ns-3", Status: StatusRunning},
		{ID: "no-ns", Namespace: "", Status: StatusRunning},
	}

	got := collectStartupSlots(recs)

	want := map[string]string{"paused": "ns-1", "running": "ns-2", "dead-running": "ns-3"}
	if len(got) != len(want) {
		t.Fatalf("got %d reservations, want %d: %v", len(got), len(want), got)
	}
	for vmID, ns := range want {
		if got[vmID] != ns {
			t.Errorf("reservation[%q] = %q, want %q", vmID, got[vmID], ns)
		}
	}
	if _, ok := got["no-ns"]; ok {
		t.Error("record without a namespace must be skipped")
	}
}
