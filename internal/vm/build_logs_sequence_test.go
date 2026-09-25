package vm

import (
	"testing"
	"time"
)

func TestBuildLogBufferSequencesFollowAppendOrder(t *testing.T) {
	b := newBuildLogBuffer()
	b.Append(BuildLogEvent{Timestamp: time.Unix(2, 0), Text: "first"})
	b.Append(BuildLogEvent{Timestamp: time.Unix(1, 0), Text: "second"})
	b.Close(BuildStatusFailed)

	events := b.Snapshot()
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	for i, ev := range events {
		if ev.Sequence != uint64(i+1) {
			t.Fatalf("event %d has sequence %d, want %d", i, ev.Sequence, i+1)
		}
	}
}
