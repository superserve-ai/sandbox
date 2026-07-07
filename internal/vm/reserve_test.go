package vm

import "testing"

// TestClassifyStartupSlots pins the reserve/relinquish policy — most importantly
// awille's edge case: a running VM with an active unit but a missing /run/netns
// bind mount must be reserved (resumable), never relinquished, because the FC
// still holds the namespace.
func TestClassifyStartupSlots(t *testing.T) {
	recs := []VMRecord{
		{ID: "paused", Namespace: "ns-1", Status: StatusPaused},
		{ID: "running-active", Namespace: "ns-2", Status: StatusRunning},
		{ID: "running-dead", Namespace: "ns-3", Status: StatusRunning},
		{ID: "no-ns", Namespace: "", Status: StatusRunning},
	}
	// running-active has a live unit even though its netns bind mount is gone;
	// running-dead has no active unit.
	active := map[string]bool{"running-active": true}

	resumable, liveOnly := classifyStartupSlots(recs, active, false)

	if !contains(resumable, "ns-1") {
		t.Errorf("paused ns-1 must be resumable; got %v", resumable)
	}
	if !contains(resumable, "ns-2") {
		t.Errorf("active-unit running ns-2 must be resumable (not relinquished) despite missing netns; got %v", resumable)
	}
	if len(liveOnly) != 1 || liveOnly[0] != "ns-3" {
		t.Errorf("only dead-unit running ns-3 may be a relinquish candidate; liveOnly = %v", liveOnly)
	}
	if contains(resumable, "") || contains(liveOnly, "") {
		t.Error("empty namespace must be skipped")
	}

	// Fail closed: liveness unknown → every running record reserved, none
	// relinquished.
	resumable2, liveOnly2 := classifyStartupSlots(recs, nil, true)
	if len(liveOnly2) != 0 {
		t.Errorf("liveOnly = %v, want [] when liveness unknown (fail closed)", liveOnly2)
	}
	if !contains(resumable2, "ns-3") {
		t.Errorf("running-dead must be reserved when liveness unknown; resumable = %v", resumable2)
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
