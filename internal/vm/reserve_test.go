package vm

import "testing"

// TestCollectStartupSlots pins the reservation input: every record that has a
// namespace is reserved (unconditionally, dead or alive), and records without
// one are skipped. Reserving all records — rather than trying to free dead ones
// up front — is what keeps the pool from ever colliding with a record's slot.
func TestCollectStartupSlots(t *testing.T) {
	recs := []VMRecord{
		{ID: "paused", Namespace: "ns-1", Status: StatusPaused},
		{ID: "running", Namespace: "ns-2", Status: StatusRunning},
		{ID: "dead-running", Namespace: "ns-3", Status: StatusRunning},
		{ID: "no-ns", Namespace: "", Status: StatusRunning},
	}

	got := collectStartupSlots(recs)

	for _, ns := range []string{"ns-1", "ns-2", "ns-3"} {
		if !contains(got, ns) {
			t.Errorf("%s must be reserved (all records reserve their slot); got %v", ns, got)
		}
	}
	if contains(got, "") {
		t.Errorf("record without a namespace must be skipped; got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("want exactly 3 reserved namespaces, got %d: %v", len(got), got)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
