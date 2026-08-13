package backup

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func testJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	j, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	return j, path
}

func TestJournalPriorityAndFIFO(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)

	// Enqueue out of order: checkpoint first, then two pauses.
	for _, task := range []Task{
		{SandboxID: "sb-c", Generation: "ccc", Priority: PriorityCheckpoint, EnqueuedAt: base},
		{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base.Add(2 * time.Second)},
		{SandboxID: "sb-b", Generation: "bbb", Priority: PriorityPause, EnqueuedAt: base.Add(time.Second)},
	} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	now := base.Add(time.Minute)
	var got []string
	for {
		task, ok, err := j.Next(now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, task.Generation)
		if err := j.Ack(task, "", false); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"bbb", "aaa", "ccc"} // pauses first (FIFO within), checkpoint last
	if len(got) != len(want) {
		t.Fatalf("drained %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("drained %v, want %v", got, want)
		}
	}
}

func TestJournalNackBackoffAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb", Generation: "gen1", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	got, ok, err := j.Next(base)
	if err != nil || !ok {
		t.Fatalf("next: ok=%v err=%v", ok, err)
	}
	if err := j.Nack(got, base); err != nil {
		t.Fatal(err)
	}
	// Immediately after a nack the task is in backoff: not runnable.
	if _, ok, _ := j.Next(base.Add(time.Second)); ok {
		t.Fatal("task runnable during backoff window")
	}

	// Survives a reopen (vmd restart), and becomes runnable after backoff.
	db.Close()
	db, err = bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err = NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err = j.Next(base.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("after reopen: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.Generation != "gen1" {
		t.Fatalf("task after reopen = %+v", got)
	}
	counts, err := j.Pending()
	if err != nil || counts[PriorityPause] != 1 {
		t.Fatalf("pending = %v err=%v", counts, err)
	}
}

// Ack with completed=true leaves a durable owner+generation record that
// survives the queue row's deletion: it is what recovery sweeps consult
// to avoid re-uploading generations that already reached the bucket.
func TestJournalRecordsCompletions(t *testing.T) {
	j, _ := testJournal(t)
	task := Task{TemplateID: "tpl", BuildID: "b1", Generation: "gen-1", EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if covered, err := j.Covered("test-bucket", task); err != nil || !covered {
		t.Fatalf("pending task not covered: %v err=%v", covered, err)
	}
	if done, err := j.WasCompleted("test-bucket", task); err != nil || done {
		t.Fatalf("WasCompleted before ack = %v err=%v", done, err)
	}
	if err := j.Ack(task, "test-bucket", false); err != nil {
		t.Fatal(err)
	}
	if done, err := j.WasCompleted("test-bucket", task); err != nil || !done {
		t.Fatalf("WasCompleted after completed ack = %v err=%v", done, err)
	}
	if covered, err := j.Covered("test-bucket", task); err != nil || !covered {
		t.Fatalf("completed task not covered: %v err=%v", covered, err)
	}

	// An abandoned ack records nothing: the generation never became
	// durable, so recovery must be free to retry it.
	abandoned := Task{TemplateID: "tpl", BuildID: "b1", Generation: "gen-2", EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 1, 0, time.UTC)}
	if err := j.Enqueue(abandoned); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(abandoned, "", false); err != nil {
		t.Fatal(err)
	}
	if done, _ := j.WasCompleted("test-bucket", abandoned); done {
		t.Fatal("abandoned ack recorded a completion")
	}
	if covered, _ := j.Covered("test-bucket", abandoned); covered {
		t.Fatal("abandoned generation reported covered")
	}
}

// Generations are content-addressed, so distinct owners can legitimately
// share one generation. Queue keys must stay unique per owner even at the
// same enqueue tick, or one owner's backup would be silently overwritten.
func TestJournalQueueKeysScopedByOwner(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	tasks := []Task{
		{SandboxID: "sb-1", Generation: "shared-gen", Priority: PriorityPause, EnqueuedAt: base},
		{TemplateID: "tpl-a", BuildID: "build-tpl-a", Generation: "shared-gen", Priority: PriorityPause, EnqueuedAt: base},
		{TemplateID: "tpl-b", BuildID: "build-tpl-b", Generation: "shared-gen", Priority: PriorityPause, EnqueuedAt: base},
	}

	keys := make(map[string]int, len(tasks))
	for i, task := range tasks {
		k := string(task.key())
		if prev, dup := keys[k]; dup {
			t.Fatalf("tasks %d and %d collide on queue key %q", prev, i, k)
		}
		keys[k] = i
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	// All three survive as distinct pending entries and drain independently.
	counts, err := j.Pending()
	if err != nil || counts[PriorityPause] != 3 {
		t.Fatalf("pending = %v err=%v, want 3 pause tasks", counts, err)
	}
	owners := make(map[string]bool, len(tasks))
	now := base.Add(time.Minute)
	for {
		task, ok, err := j.Next(now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		owners[task.owner()] = true
		if err := j.Ack(task, "", false); err != nil {
			t.Fatal(err)
		}
	}
	if len(owners) != 3 {
		t.Fatalf("drained owners = %v, want 3 distinct owners", owners)
	}
}

func TestJournalEnqueueRequiresExactlyOneOwner(t *testing.T) {
	j, _ := testJournal(t)
	cases := []struct {
		name    string
		task    Task
		wantErr bool
	}{
		{"sandbox task", Task{SandboxID: "sb", Generation: "g1"}, false},
		{"template task", Task{TemplateID: "tpl", BuildID: "b1", Generation: "g2"}, false},
		{"both owners", Task{SandboxID: "sb", TemplateID: "tpl", BuildID: "b1", Generation: "g3"}, true},
		{"no owner", Task{Generation: "g4"}, true},
		{"template without build id", Task{TemplateID: "tpl", Generation: "g5"}, true},
		{"no generation", Task{SandboxID: "sb"}, true},
	}
	for _, tc := range cases {
		err := j.Enqueue(tc.task)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v, wantErr = %v", tc.name, err, tc.wantErr)
		}
	}
	// Template tasks dedupe on their own identity like sandbox tasks do.
	if err := j.Enqueue(Task{TemplateID: "tpl", BuildID: "b1", Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityBestEffort]+counts[PriorityCheckpoint]+counts[PriorityPause] != 2 {
		t.Fatalf("pending after dedupe = %v", counts)
	}
}

func TestJournalOldestEnqueuedAt(t *testing.T) {
	j, _ := testJournal(t)

	if _, ok, err := j.OldestEnqueuedAt(); err != nil || ok {
		t.Fatalf("empty queue: ok=%v err=%v, want no oldest", ok, err)
	}

	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	newer := Task{SandboxID: "sb-new", Generation: "gen-1", Priority: PriorityPause, EnqueuedAt: base.Add(time.Hour)}
	older := Task{SandboxID: "sb-old", Generation: "gen-2", Priority: PriorityBestEffort, EnqueuedAt: base}
	for _, task := range []Task{newer, older} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	oldest, ok, err := j.OldestEnqueuedAt()
	if err != nil || !ok {
		t.Fatalf("oldest: ok=%v err=%v", ok, err)
	}
	if !oldest.Equal(base) {
		t.Fatalf("oldest = %s, want %s (priority must not mask an older low-priority task)", oldest, base)
	}

	// A Nack defers readiness but the task is still backlog: age keeps
	// counting from the original enqueue.
	if err := j.Nack(older, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	oldest, ok, err = j.OldestEnqueuedAt()
	if err != nil || !ok || !oldest.Equal(base) {
		t.Fatalf("post-nack oldest = %s ok=%v err=%v, want %s", oldest, ok, err, base)
	}
}

func TestJournalOutboxDepth(t *testing.T) {
	j, _ := testJournal(t)

	if depth, err := j.OutboxDepth(); err != nil || depth != 0 {
		t.Fatalf("empty outbox depth = %d err=%v, want 0", depth, err)
	}

	task := Task{SandboxID: "sb-1", Generation: "gen-1", Priority: PriorityPause, EnqueuedAt: time.Now().UTC()}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(task, "bucket", true); err != nil {
		t.Fatal(err)
	}
	if depth, err := j.OutboxDepth(); err != nil || depth != 1 {
		t.Fatalf("outbox depth after notify ack = %d err=%v, want 1", depth, err)
	}
	if err := j.ClearNotification(task); err != nil {
		t.Fatal(err)
	}
	if depth, err := j.OutboxDepth(); err != nil || depth != 0 {
		t.Fatalf("outbox depth after clear = %d err=%v, want 0", depth, err)
	}
}

// Concurrent drain workers must each receive a distinct task: Next
// claims what it returns until Ack or Nack resolves it.
func TestNextClaimsTasksForConcurrentWorkers(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	for _, task := range []Task{
		{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base},
		{SandboxID: "sb-b", Generation: "bbb", Priority: PriorityPause, EnqueuedAt: base.Add(time.Second)},
	} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}
	now := base.Add(time.Minute)
	first, ok, err := j.Next(now)
	if err != nil || !ok || first.SandboxID != "sb-a" {
		t.Fatalf("first Next = %+v/%v/%v, want sb-a", first, ok, err)
	}
	// A second worker draining while the first is mid-upload gets the
	// NEXT task, not the same one.
	second, ok, err := j.Next(now)
	if err != nil || !ok || second.SandboxID != "sb-b" {
		t.Fatalf("second Next = %+v/%v/%v, want sb-b", second, ok, err)
	}
	// Both claimed: a third worker finds nothing runnable.
	if _, ok, err := j.Next(now); err != nil || ok {
		t.Fatalf("third Next = %v/%v, want nothing runnable", ok, err)
	}
}

// Ack and Nack release the claim: an acked task's slot frees for the
// tier behind it, a nacked task returns (deferred) rather than staying
// claim-locked forever.
func TestAckAndNackReleaseClaims(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	got, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	if err := j.Nack(got, now); err != nil {
		t.Fatal(err)
	}
	// The nacked task is deferred by backoff, not claim-locked: past its
	// NotBefore it drains again.
	redo, ok, err := j.Next(now.Add(time.Hour))
	if err != nil || !ok || redo.Attempts != 1 {
		t.Fatalf("Next after Nack = %+v/%v/%v, want attempts=1", redo, ok, err)
	}
	if err := j.Ack(redo, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := j.Next(now.Add(2 * time.Hour)); err != nil || ok {
		t.Fatalf("Next after Ack = %v/%v, want empty queue", ok, err)
	}
	// The claim table must not leak resolved entries.
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.claims) != 0 {
		t.Fatalf("claims after resolution = %v, want empty", j.claims)
	}
}

// A claimed pause task must not wall off the rest of the queue: the scan
// skips it individually (unlike a deferred head, which proves its whole
// tier unready) and continues into lower tiers when the claimant's tier
// is exhausted.
func TestClaimedHeadDoesNotBlockTierOrQueue(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	for _, task := range []Task{
		{SandboxID: "sb-pause", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base},
		{TemplateID: "tpl", BuildID: "b1", Generation: "ccc", Priority: PriorityCheckpoint, EnqueuedAt: base},
	} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}
	now := base.Add(time.Minute)
	first, ok, err := j.Next(now)
	if err != nil || !ok || first.SandboxID != "sb-pause" {
		t.Fatalf("first Next = %+v/%v/%v, want the pause task", first, ok, err)
	}
	// With the only pause task claimed, a second worker reaches the
	// checkpoint tier instead of idling behind the claim.
	second, ok, err := j.Next(now)
	if err != nil || !ok || second.TemplateID != "tpl" {
		t.Fatalf("second Next = %+v/%v/%v, want the checkpoint task", second, ok, err)
	}
}

// A claim left unresolved past its lease (wedged worker) expires and the
// task becomes drainable again.
func TestClaimExpiryReclaims(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	if _, ok, err := j.Next(now); err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	if _, ok, err := j.Next(now.Add(claimTTL - time.Second)); err != nil || ok {
		t.Fatalf("Next within lease = %v/%v, want claim held", ok, err)
	}
	redo, ok, err := j.Next(now.Add(claimTTL))
	if err != nil || !ok || redo.SandboxID != "sb-a" {
		t.Fatalf("Next past lease = %+v/%v/%v, want the task reclaimed", redo, ok, err)
	}
}

// Release frees a claim without resolving the task: the retained-row
// drain outcome leaves the row queued, and it must be drainable
// immediately rather than after the lease expires.
func TestReleaseFreesUnresolvedClaim(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	got, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	if _, ok, err := j.Next(now); err != nil || ok {
		t.Fatalf("Next while claimed = %v/%v, want nothing", ok, err)
	}
	j.Release(got)
	redo, ok, err := j.Next(now)
	if err != nil || !ok || redo.Attempts != 0 {
		t.Fatalf("Next after Release = %+v/%v/%v, want the task back untouched", redo, ok, err)
	}
}

// A worker that outlives its lease is fenced: once another worker claims
// the row, the stale worker's Ack, Nack, and Release are all refused,
// and the thief's resolution is the one that lands.
func TestStaleWorkerIsFencedAfterLeaseSteal(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	stale, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	// The lease lapses and a second worker claims the same row.
	thief, ok, err := j.Next(now.Add(claimTTL))
	if err != nil || !ok || thief.ClaimToken == stale.ClaimToken {
		t.Fatalf("steal Next = %+v/%v/%v, want a fresh claim", thief, ok, err)
	}
	// Every stale resolution is refused and leaves the row alone.
	if err := j.Ack(stale, "bucket", false); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Ack err = %v, want errClaimStolen", err)
	}
	if err := j.Nack(stale, now.Add(claimTTL)); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Nack err = %v, want errClaimStolen", err)
	}
	j.Release(stale)
	if counts, err := j.Pending(); err != nil || counts[PriorityPause] != 1 {
		t.Fatalf("pending after stale resolutions = %v/%v, want the row intact", counts, err)
	}
	// The row stays claimed by the thief despite the stale Release.
	if _, ok, err := j.Next(now.Add(claimTTL + time.Minute)); err != nil || ok {
		t.Fatalf("Next while thief holds claim = %v/%v, want nothing", ok, err)
	}
	// The thief's resolution is authoritative.
	if err := j.Ack(thief, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("pending after thief Ack = %v, want empty", counts)
	}
}

// The claim token only fences while the claim is live; once the
// replacement worker resolves the row, the durable row state must keep
// fencing the stale worker. A stale Ack after the thief's Nack must not
// delete the index now pointing at the re-keyed row, and a stale Nack
// after the thief's Ack must not resurrect the acked row.
func TestStaleResolutionFencedAfterThiefResolves(t *testing.T) {
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Minute)

	// Thief nacks (row re-keyed), then the stale worker's Ack is refused
	// and the index still resolves the pending generation.
	j, _ := testJournal(t)
	task := Task{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	stale, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	thief, ok, err := j.Next(now.Add(claimTTL))
	if err != nil || !ok {
		t.Fatalf("steal Next = %v/%v", ok, err)
	}
	if err := j.Nack(thief, now.Add(claimTTL)); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(stale, "bucket", false); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Ack after thief Nack = %v, want errClaimStolen", err)
	}
	if pending, err := j.HasPending("sb-a", "aaa"); err != nil || !pending {
		t.Fatalf("HasPending = %v/%v, want the re-keyed row still indexed", pending, err)
	}

	// Thief acks (row gone), then the stale worker's Nack is refused
	// rather than resurrecting a zombie row.
	j2, _ := testJournal(t)
	if err := j2.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	stale2, ok, err := j2.Next(now)
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	thief2, ok, err := j2.Next(now.Add(claimTTL))
	if err != nil || !ok {
		t.Fatalf("steal Next = %v/%v", ok, err)
	}
	if err := j2.Ack(thief2, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if err := j2.Nack(stale2, now.Add(claimTTL)); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Nack after thief Ack = %v, want errClaimStolen", err)
	}
	if counts, _ := j2.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("pending after refused zombie Nack = %v, want empty", counts)
	}
}
