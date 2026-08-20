package backup

import (
	"testing"
	"time"
)

// An unchanged re-pause converges on the same content-addressed
// generation but is a NEW logical pause: the control plane stores the new
// pause's token on the snapshot row, so the queued task — and the outbox
// entry the eventual ack writes — must carry the newest token, or the
// report is refused as another pause's and the sandbox reads unbacked
// despite durable bytes.
func TestEnqueueDedupeRefreshesPauseToken(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	first := Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-old", EnqueuedAt: base}
	if err := j.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	// Same generation, new pause.
	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-new", EnqueuedAt: base.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	task, ok, err := j.Next(base.Add(2 * time.Minute))
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if task.PauseToken != "tok-new" {
		t.Fatalf("queued token = %q, want tok-new (newest pause wins)", task.PauseToken)
	}

	// A tokenless enqueue (backfill mint) must not erase the real token.
	if err := j.Nack(task, base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		EnqueuedAt: base.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	task, ok, err = j.Next(base.Add(4 * time.Minute))
	if err != nil || !ok {
		t.Fatalf("Next after nack: ok=%v err=%v", ok, err)
	}
	if task.PauseToken != "tok-new" {
		t.Fatalf("queued token = %q, want tok-new (tokenless enqueue must not erase)", task.PauseToken)
	}
}

// A re-pause that lands while the generation's upload is mid-claim
// refreshes the ROW; the ack's outbox entry must adopt the row's token
// over the worker's claim-time copy.
func TestAckOutboxAdoptsRefreshedPauseToken(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-old", EnqueuedAt: base}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := j.Next(base.Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	// Mid-upload, the sandbox re-pauses on identical content.
	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-new", EnqueuedAt: base.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Ack(claimed, "cell-bucket", true); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingNotifications(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending notifications = %d, want 1", len(pending))
	}
	if pending[0].PauseToken != "tok-new" {
		t.Fatalf("outbox token = %q, want tok-new (row's refreshed token)", pending[0].PauseToken)
	}
}
