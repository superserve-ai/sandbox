package api

import "testing"

func TestSponsoredScheduleBoundaries(t *testing.T) {
	r := sponsoredRequest{Key: "approval-1", Start: "now", Reason: "pilot", Reference: "approval", Schedule: []sponsoredPhase{{3, 3000000}, {9, 100000}}}
	amounts, err := r.amounts()
	if err != nil || len(amounts) != 12 {
		t.Fatal(amounts, err)
	}
	if amounts[2] != 3000000 || amounts[3] != 100000 || amounts[11] != 100000 {
		t.Fatal("phase boundary changed", amounts)
	}
	for _, schedule := range [][]sponsoredPhase{{{0, 1}}, {{25, 1}}, {{1, 0}}, {{1, 100000001}}, {{24, 1}, {1, 1}}} {
		r.Schedule = schedule
		if _, err = r.amounts(); err == nil {
			t.Fatal("unbounded schedule accepted", schedule)
		}
	}
}
