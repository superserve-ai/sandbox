package api

import (
	"testing"
	"time"
)

func TestIncrementalBacklogSamplingCadence(t *testing.T) {
	start := time.Unix(0, 0)
	var schedule billingBacklogSchedule
	last := start
	samples := 0
	for now := start; now.Before(start.Add(time.Hour)); now = now.Add(10 * time.Second) {
		if !schedule.due(now) {
			continue
		}
		if elapsed := now.Sub(last); elapsed < 5*time.Minute || elapsed > 6*time.Minute {
			t.Fatalf("sample spacing = %s; want 5–6 minutes", elapsed)
		}
		last = now
		samples++
	}
	if samples < 9 || samples > 12 {
		t.Fatalf("samples per hour = %d; want 9–12", samples)
	}
}

func TestIncrementalBacklogSamplingDeadline(t *testing.T) {
	start := time.Unix(0, 0)
	var schedule billingBacklogSchedule
	if schedule.due(start) {
		t.Fatal("startup must defer the first sample")
	}
	for range 10 {
		deadline := schedule.next
		if delay := deadline.Sub(start); delay < 5*time.Minute || delay >= 6*time.Minute {
			t.Fatalf("sample delay = %s; want [5m, 6m)", delay)
		}
		if schedule.due(deadline.Add(-time.Nanosecond)) || schedule.next != deadline {
			t.Fatal("early poll sampled or changed the deadline")
		}
		if !schedule.due(deadline) {
			t.Fatal("sample not due at deadline")
		}
		// No success acknowledgement is needed: failures use the same cadence.
		if schedule.due(deadline) || schedule.due(deadline.Add(10*time.Second)) {
			t.Fatal("sample attempt retried before the next deadline")
		}
		start = deadline
	}
	late := schedule.next.Add(time.Hour)
	if !schedule.due(late) || schedule.due(late.Add(10*time.Second)) {
		t.Fatal("delayed worker must sample once without catching up missed samples")
	}
}
