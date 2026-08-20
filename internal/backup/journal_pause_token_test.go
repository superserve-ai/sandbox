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

// A refresh that lands while the upload is claimed must also survive a
// FAILED attempt: Nack's write-back merges the row, and losing the token
// there would make the eventual successful retry report the stale pause.
func TestNackPreservesRefreshedPauseToken(t *testing.T) {
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
	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-new", EnqueuedAt: base.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := j.Nack(claimed, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	retry, ok, err := j.Next(base.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("Next after nack: ok=%v err=%v", ok, err)
	}
	if retry.PauseToken != "tok-new" {
		t.Fatalf("retry token = %q, want tok-new (nack write-back must not revert the refresh)", retry.PauseToken)
	}
}

// Clearing a delivered notification must not delete a NEWER one that
// overwrote the same outbox key while the stale delivery was in flight.
func TestClearNotificationKeepsNewerToken(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-old", EnqueuedAt: base}); err != nil {
		t.Fatal(err)
	}
	first, ok, err := j.Next(base.Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if _, err := j.Ack(first, "cell-bucket", true); err != nil {
		t.Fatal(err)
	}
	delivered, err := j.PendingNotifications(0)
	if err != nil || len(delivered) != 1 {
		t.Fatalf("pending = %v err=%v, want 1 entry", delivered, err)
	}

	// While tok-old's notification is mid-delivery, the re-pause's upload
	// completes and overwrites the outbox key with tok-new.
	if err := j.Enqueue(Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause,
		PauseToken: "tok-new", EnqueuedAt: base.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	second, ok, err := j.Next(base.Add(3 * time.Second))
	if err != nil || !ok {
		t.Fatalf("Next second: ok=%v err=%v", ok, err)
	}
	if _, err := j.Ack(second, "cell-bucket", true); err != nil {
		t.Fatal(err)
	}

	// The stale delivery confirms: the newer entry must survive.
	if err := j.ClearNotification(delivered[0]); err != nil {
		t.Fatal(err)
	}
	remaining, err := j.PendingNotifications(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].PauseToken != "tok-new" {
		t.Fatalf("remaining = %+v, want the tok-new notification to survive", remaining)
	}
	// Its own delivery clears it.
	if err := j.ClearNotification(remaining[0]); err != nil {
		t.Fatal(err)
	}
	if final, _ := j.PendingNotifications(0); len(final) != 0 {
		t.Fatalf("outbox not empty after matching clear: %+v", final)
	}
}
