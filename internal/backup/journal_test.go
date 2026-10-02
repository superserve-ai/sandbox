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
		if _, err := j.Ack(task, "", false); err != nil {
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
	if _, err := j.Ack(task, "test-bucket", false); err != nil {
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
	if _, err := j.Ack(abandoned, "", false); err != nil {
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
		if _, err := j.Ack(task, "", false); err != nil {
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

// A live pause re-enqueueing a generation the backfill already queued at
// best-effort promotes the row: the queue key re-sorts under the pause
// tier while attempts and backoff stay with the task, and promotion is
// one-way (a later best-effort enqueue never demotes).
func TestEnqueueDedupePromotesPriority(t *testing.T) {
	j, _ := testJournal(t)
	gen := "promote-gen"
	if err := j.Enqueue(Task{SandboxID: "sb", Generation: gen,
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/p", SHA256: "aa", Size: 1}},
		Priority: PriorityBestEffort, EnqueuedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	// A checkpoint task would outrank the best-effort row.
	if err := j.Enqueue(Task{SandboxID: "other", Generation: "ck",
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/q", SHA256: "bb", Size: 1}},
		Priority: PriorityCheckpoint, EnqueuedAt: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}
	next, ok, err := j.Next(time.Unix(10, 0))
	if err != nil || !ok || next.Generation != "ck" {
		t.Fatalf("pre-promotion Next = %+v ok=%v err=%v, want the checkpoint task", next, ok, err)
	}

	// The live pause claims the same generation.
	if err := j.Enqueue(Task{SandboxID: "sb", Generation: gen,
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/p", SHA256: "aa", Size: 1}},
		Priority: PriorityPause, EnqueuedAt: time.Unix(3, 0)}); err != nil {
		t.Fatal(err)
	}
	next, ok, err = j.Next(time.Unix(10, 0))
	if err != nil || !ok || next.Generation != gen {
		t.Fatalf("post-promotion Next = %+v ok=%v err=%v, want the promoted pause generation", next, ok, err)
	}
	if next.Priority != PriorityPause {
		t.Fatalf("promoted priority = %d, want pause", next.Priority)
	}

	// One-way: re-enqueueing at best-effort does not demote.
	if err := j.Enqueue(Task{SandboxID: "sb", Generation: gen,
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/p", SHA256: "aa", Size: 1}},
		Priority: PriorityBestEffort, EnqueuedAt: time.Unix(4, 0)}); err != nil {
		t.Fatal(err)
	}
	next, _, err = j.Next(time.Unix(10, 0))
	if err != nil || next.Priority != PriorityPause {
		t.Fatalf("after best-effort re-enqueue priority = %d (err %v), want pause kept", next.Priority, err)
	}
	// The index still points at a live row: exactly one pending entry for
	// the owner+generation.
	if pending, err := j.HasPending("sb", gen); err != nil || !pending {
		t.Fatalf("HasPending = %v err=%v, want true", pending, err)
	}
}

// Promotion can re-key a row while the uploader holds the task from
// Next. Every mutator must resolve the row through the index, or acks
// orphan the promoted row, nacks fork the task into two rows, and
// verification recreates the stale key.
func TestPromotionWhileTaskInFlight(t *testing.T) {
	newTask := func(gen string) Task {
		return Task{SandboxID: "sb", Generation: gen,
			Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/p", SHA256: "aa", Size: 1}},
			Priority: PriorityBestEffort, EnqueuedAt: time.Unix(1, 0)}
	}
	promote := func(j *Journal, gen string) {
		p := newTask(gen)
		p.Priority = PriorityPause
		if err := j.Enqueue(p); err != nil {
			t.Fatal(err)
		}
	}
	pendingTotal := func(j *Journal) int {
		counts, err := j.Pending()
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		return total
	}

	t.Run("ack removes the promoted row", func(t *testing.T) {
		j, _ := testJournal(t)
		if err := j.Enqueue(newTask("gen-ack")); err != nil {
			t.Fatal(err)
		}
		inflight, ok, err := j.Next(time.Unix(10, 0))
		if err != nil || !ok {
			t.Fatalf("Next: %v %v", ok, err)
		}
		promote(j, "gen-ack")
		if _, err := j.Ack(inflight, "bucket", false); err != nil {
			t.Fatal(err)
		}
		if n := pendingTotal(j); n != 0 {
			t.Fatalf("pending after ack = %d, want 0 (promoted row orphaned)", n)
		}
		if _, ok, _ := j.Next(time.Unix(20, 0)); ok {
			t.Fatal("Next returned a task after ack; promoted row survived")
		}
	})

	t.Run("nack keeps one promoted row with backoff", func(t *testing.T) {
		j, _ := testJournal(t)
		if err := j.Enqueue(newTask("gen-nack")); err != nil {
			t.Fatal(err)
		}
		inflight, ok, err := j.Next(time.Unix(10, 0))
		if err != nil || !ok {
			t.Fatalf("Next: %v %v", ok, err)
		}
		promote(j, "gen-nack")
		if err := j.Nack(inflight, time.Unix(10, 0)); err != nil {
			t.Fatal(err)
		}
		if n := pendingTotal(j); n != 1 {
			t.Fatalf("pending after nack = %d, want exactly one row", n)
		}
		// Backoff holds: nothing runnable immediately after the nack.
		if _, ok, _ := j.Next(time.Unix(11, 0)); ok {
			t.Fatal("Next returned the task before its backoff elapsed")
		}
		later, ok, err := j.Next(time.Unix(600, 0))
		if err != nil || !ok {
			t.Fatalf("Next after backoff: %v %v", ok, err)
		}
		if later.Priority != PriorityPause {
			t.Fatalf("retry priority = %d, want the promotion kept", later.Priority)
		}
	})

	t.Run("verification does not fork the row", func(t *testing.T) {
		j, _ := testJournal(t)
		if err := j.Enqueue(newTask("gen-verify")); err != nil {
			t.Fatal(err)
		}
		inflight, ok, err := j.Next(time.Unix(10, 0))
		if err != nil || !ok {
			t.Fatalf("Next: %v %v", ok, err)
		}
		promote(j, "gen-verify")
		if err := j.RecordVerification(inflight, "obj-1", time.Unix(12, 0)); err != nil {
			t.Fatal(err)
		}
		if n := pendingTotal(j); n != 1 {
			t.Fatalf("pending after verification = %d, want exactly one row", n)
		}
		// Mid-flight verification keeps the caller's claim (the worker is
		// still uploading), so the row stays invisible to other workers
		// until resolution or lease expiry; scan past the TTL to observe
		// the single surviving row.
		reclaimAt := time.Unix(20, 0).Add(claimTTL)
		got, ok, err := j.Next(reclaimAt)
		if err != nil || !ok {
			t.Fatalf("Next: %v %v", ok, err)
		}
		if got.Priority != PriorityPause {
			t.Fatalf("row priority = %d, want the promotion kept", got.Priority)
		}
		if verified, err := j.WasVerified("obj-1", reclaimAt); err != nil || !verified {
			t.Fatalf("WasVerified = %v (err %v), want the history recorded", verified, err)
		}
	})
}

func TestJournalOldestEnqueuedAtByPriority(t *testing.T) {
	j, _ := testJournal(t)

	if oldest, err := j.OldestEnqueuedAtByPriority(); err != nil || len(oldest) != 0 {
		t.Fatalf("empty queue: %v err=%v, want no entries", oldest, err)
	}

	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	pauseNew := Task{SandboxID: "sb-new", Generation: "gen-1", Priority: PriorityPause, EnqueuedAt: base.Add(time.Hour)}
	pauseOld := Task{SandboxID: "sb-old", Generation: "gen-2", Priority: PriorityPause, EnqueuedAt: base.Add(30 * time.Minute)}
	backfill := Task{SandboxID: "sb-bf", Generation: "gen-3", Priority: PriorityBestEffort, EnqueuedAt: base}
	for _, task := range []Task{pauseNew, pauseOld, backfill} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	oldest, err := j.OldestEnqueuedAtByPriority()
	if err != nil {
		t.Fatal(err)
	}
	// Tiers resolve independently: the hours-old best-effort backfill
	// backlog must not surface as the pause tier's age.
	if !oldest[PriorityPause].Equal(base.Add(30 * time.Minute)) {
		t.Fatalf("pause oldest = %s, want the older pause", oldest[PriorityPause])
	}
	if !oldest[PriorityBestEffort].Equal(base) {
		t.Fatalf("best-effort oldest = %s, want the backfill task", oldest[PriorityBestEffort])
	}
	if _, ok := oldest[PriorityCheckpoint]; ok {
		t.Fatal("empty checkpoint tier reported an age")
	}

	// A Nack defers readiness but the task is still backlog: age keeps
	// counting from the original enqueue.
	if err := j.Nack(backfill, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	oldest, err = j.OldestEnqueuedAtByPriority()
	if err != nil || !oldest[PriorityBestEffort].Equal(base) {
		t.Fatalf("post-nack best-effort oldest = %s err=%v, want %s", oldest[PriorityBestEffort], err, base)
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
	if _, err := j.Ack(task, "bucket", true); err != nil {
		t.Fatal(err)
	}
	if depth, err := j.OutboxDepth(); err != nil || depth != 1 {
		t.Fatalf("outbox depth after notify ack = %d err=%v, want 1", depth, err)
	}
	// Clear takes the entry as PendingNotifications returns it: the
	// outbox key is scoped by the entry's pinned bucket.
	pending, err := j.PendingNotifications(0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %d err=%v, want 1", len(pending), err)
	}
	if err := j.ClearNotification(pending[0]); err != nil {
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
	if _, err := j.Ack(redo, "bucket", false); err != nil {
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
	if _, err := j.Ack(stale, "bucket", false); !errors.Is(err, errClaimStolen) {
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
	if _, err := j.Ack(thief, "bucket", false); err != nil {
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
	if _, err := j.Ack(stale, "bucket", false); !errors.Is(err, errClaimStolen) {
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
	if _, err := j2.Ack(thief2, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if err := j2.Nack(stale2, now.Add(claimTTL)); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Nack after thief Ack = %v, want errClaimStolen", err)
	}
	if counts, _ := j2.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("pending after refused zombie Nack = %v, want empty", counts)
	}
}

// RecordVerification is a row write too: a stale worker recording
// mid-flight progress after its lease was stolen and resolved must not
// recreate the row — that would forge the durable row-presence evidence
// Ack and Nack fence on, reopening the exact stale-Ack index deletion
// the fence exists to prevent.
func TestStaleRecordVerificationCannotResurrectRow(t *testing.T) {
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
	thief, ok, err := j.Next(now.Add(claimTTL))
	if err != nil || !ok {
		t.Fatalf("steal Next = %v/%v", ok, err)
	}
	if err := j.Nack(thief, now.Add(claimTTL)); err != nil {
		t.Fatal(err)
	}
	// The stale worker's progress write is refused and recreates nothing
	// — but the verification history survives: those object bytes are
	// digest-verified in the bucket regardless of who owns the row, and
	// dropping the record would make the replacement's create-only
	// dedupe abandon a provably good generation.
	if err := j.RecordVerification(stale, "bucket\x00obj", now.Add(claimTTL)); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale RecordVerification = %v, want errClaimStolen", err)
	}
	if verified, err := j.WasVerified("bucket\x00obj", now.Add(claimTTL)); err != nil || !verified {
		t.Fatalf("WasVerified after refused stale record = %v/%v, want history preserved", verified, err)
	}
	// The full attack chain stays closed: the follow-up stale Ack is
	// still refused and the re-keyed row's index survives.
	if _, err := j.Ack(stale, "bucket", false); !errors.Is(err, errClaimStolen) {
		t.Fatalf("stale Ack = %v, want errClaimStolen", err)
	}
	if pending, err := j.HasPending("sb-a", "aaa"); err != nil || !pending {
		t.Fatalf("HasPending = %v/%v, want the re-keyed row still indexed", pending, err)
	}
	// A live-claim holder's progress writes still land.
	redo, ok, err := j.Next(now.Add(claimTTL + time.Hour))
	if err != nil || !ok {
		t.Fatalf("reclaim Next = %v/%v", ok, err)
	}
	if err := j.RecordVerification(redo, "bucket\x00obj", now.Add(claimTTL+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if verified, err := j.WasVerified("bucket\x00obj", now.Add(claimTTL+time.Hour)); err != nil || !verified {
		t.Fatalf("WasVerified = %v/%v after live-claim record", verified, err)
	}
}

// An abandonment carrying a stale snapshot must not clear a row that was
// upgraded since the attempt began: a live pause's staging or promotion
// supersedes the failure verdict, and the upgraded row keeps its staged
// files and retries on its own schedule. Completion acks always clear.
func TestAbandonmentDoesNotClearUpgradedRow(t *testing.T) {
	j, _ := testJournal(t)
	snapshot := Task{SandboxID: "sb", Generation: "gen",
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/orig", SHA256: "aa", Size: 1}},
		Priority: PriorityBestEffort, EnqueuedAt: time.Unix(1, 0)}
	if err := j.Enqueue(snapshot); err != nil {
		t.Fatal(err)
	}
	inflight, ok, err := j.Next(time.Unix(10, 0))
	if err != nil || !ok {
		t.Fatalf("Next: %v %v", ok, err)
	}

	// A live pause stages and promotes the same generation mid-attempt.
	upgraded := snapshot
	upgraded.Priority = PriorityPause
	upgraded.Staged = true
	upgraded.Files = []TaskFile{{Name: "rootfs.ext4", Path: "/staged", SHA256: "aa", Size: 1}}
	if err := j.Enqueue(upgraded); err != nil {
		t.Fatal(err)
	}

	cleared, err := j.Ack(inflight, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if cleared {
		t.Fatal("stale abandonment cleared the upgraded row")
	}
	got, ok, err := j.Next(time.Unix(20, 0))
	if err != nil || !ok {
		t.Fatalf("Next after abandonment: %v %v", ok, err)
	}
	if !got.Staged || got.Priority != PriorityPause || got.Files[0].Path != "/staged" {
		t.Fatalf("surviving row = %+v, want the staged promoted upgrade", got)
	}

	// A completion ack clears even an upgraded row: the generation is
	// durable regardless of what upgraded meanwhile.
	if cleared, err := j.Ack(got, "bucket", false); err != nil || !cleared {
		t.Fatalf("completion ack cleared=%v err=%v, want true", cleared, err)
	}
	if _, ok, _ := j.Next(time.Unix(30, 0)); ok {
		t.Fatal("row survived a completion ack")
	}
}

// The per-scope seed marker lives inside the outbox bucket but is not a
// notification: counting it would pin the depth gauge above zero forever
// and hold the outbox-stalled alert firing on every seeded host.
func TestOutboxDepthExcludesSeedMarker(t *testing.T) {
	j, _ := testJournal(t)
	if _, err := j.SeedOutboxFromCompletions(); err != nil {
		t.Fatal(err)
	}
	if depth, err := j.OutboxDepth(); err != nil || depth != 0 {
		t.Fatalf("depth after seed marker = %d err=%v, want 0", depth, err)
	}
	if pending, err := j.PendingNotifications(0); err != nil || len(pending) != 0 {
		t.Fatalf("pending after seed marker = %d err=%v, want 0", len(pending), err)
	}
}

func TestStagingRootsEmptyOnFirstBoot(t *testing.T) {
	j, _ := testJournal(t)
	if roots, err := j.StagingRoots(); err != nil || len(roots) != 0 {
		t.Fatalf("StagingRoots on a fresh journal = %v err=%v, want empty", roots, err)
	}
}

func TestStagingRootsRecordIsIdempotentAndRemoveDrops(t *testing.T) {
	j, _ := testJournal(t)
	for i := 0; i < 2; i++ { // recording twice must not duplicate
		if err := j.RecordStagingRoot("/mnt/backup-data/backup-staging"); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.RecordStagingRoot("/mnt/backup-data-2/backup-staging"); err != nil {
		t.Fatal(err)
	}
	roots, err := j.StagingRoots()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"/mnt/backup-data/backup-staging": true, "/mnt/backup-data-2/backup-staging": true}
	if len(roots) != len(want) {
		t.Fatalf("StagingRoots = %v, want exactly %v", roots, want)
	}
	for _, r := range roots {
		if !want[r] {
			t.Fatalf("unexpected root %q in %v", r, roots)
		}
	}

	if err := j.RemoveStagingRoot("/mnt/backup-data/backup-staging"); err != nil {
		t.Fatal(err)
	}
	roots, err = j.StagingRoots()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0] != "/mnt/backup-data-2/backup-staging" {
		t.Fatalf("StagingRoots after removing one = %v, want only the other", roots)
	}
}

// An upload slower than the lease must keep its task, or a sibling worker
// steals it and the transfer starts again from zero, forever.
func TestRenewClaimKeepsAStreamingTaskClaimed(t *testing.T) {
	j, _ := testJournal(t)
	now := time.Unix(1000, 0)
	task := Task{SandboxID: "sb-slow", Generation: "gen", EnqueuedAt: now,
		Files: []TaskFile{{Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 1}}}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}

	// Still streaming at half the lease, so the lease moves with it.
	if !j.RenewClaim(claimed, now.Add(claimTTL/2)) {
		t.Fatal("the owner could not renew its own lease")
	}
	if _, ok, err := j.Next(now.Add(claimTTL + time.Minute)); err != nil || ok {
		t.Fatal("the task was handed to another worker while its upload was still running")
	}

	// Past the renewed lease it is claimable again: a wedged worker must
	// still be recoverable.
	stolen, ok, err := j.Next(now.Add(claimTTL/2 + claimTTL + time.Minute))
	if err != nil || !ok {
		t.Fatalf("after the renewed lease expired: %v (%v)", ok, err)
	}
	// And the superseded attempt can no longer renew or resolve.
	if j.RenewClaim(claimed, now.Add(claimTTL)) {
		t.Fatal("a superseded attempt renewed a lease it no longer holds")
	}
	if err := j.Nack(claimed, now.Add(claimTTL)); !errors.Is(err, errClaimStolen) {
		t.Fatalf("superseded Nack = %v, want the steal reported", err)
	}
	if err := j.Nack(stolen, now.Add(claimTTL)); err != nil {
		t.Fatal(err)
	}
}

// soleClaimUntil reads the lease of the single claimed task, so a test
// can watch a renewal move it.
func soleClaimUntil(t *testing.T, j *Journal) time.Time {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.claims) != 1 {
		t.Fatalf("claims = %d, want exactly one", len(j.claims))
	}
	for _, c := range j.claims {
		return c.until
	}
	return time.Time{}
}

// A generation already queued keeps its paths on a re-enqueue, but not
// its blanks: a row written before allocation sizes were carried would
// otherwise report a generation of unknown size for as long as it waits.
func TestEnqueueAdoptsAllocationsOnDedupe(t *testing.T) {
	j, _ := testJournal(t)
	now := time.Unix(100, 0)
	queued := func(alloc int64) Task {
		return Task{
			SandboxID: "sb-a", Generation: "gen", EnqueuedAt: now,
			Files: []TaskFile{{
				Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 10,
				AllocatedBytes: alloc,
			}},
		}
	}
	if err := j.Enqueue(queued(-1)); err != nil {
		t.Fatal(err)
	}
	// An unchanged re-pause of the same generation, same staging state,
	// this time measuring what the artifact occupies.
	if err := j.Enqueue(queued(4096)); err != nil {
		t.Fatal(err)
	}

	got, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}
	if got.Files[0].AllocatedBytes != 4096 {
		t.Fatalf("allocated = %d, want the measurement the re-enqueue carried", got.Files[0].AllocatedBytes)
	}
}

// The ack is the last durable moment: it deletes the row and writes the
// completion record that stops any later sweep from correcting the
// number. A re-enqueue that measured sizes after the final artifact
// verified must still reach the notification, and must not cost the
// finalized object paths the upload actually wrote.
func TestAckAdoptsAllocationsMeasuredDuringTheUpload(t *testing.T) {
	j, _ := testJournal(t)
	now := time.Unix(500, 0)
	queued := func(alloc int64) Task {
		return Task{
			SandboxID: "sb-late", Generation: "gen", EnqueuedAt: now,
			Files: []TaskFile{{
				Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 10,
				AllocatedBytes: alloc,
			}},
		}
	}
	if err := j.Enqueue(queued(-1)); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}
	if err := j.RecordVerification(claimed, "k\x00sandboxes/sb-late/gen/rootfs", now); err != nil {
		t.Fatal(err)
	}
	// An unchanged re-pause lands after the last artifact verified, while
	// the manifest is being published.
	if err := j.Enqueue(queued(4096)); err != nil {
		t.Fatal(err)
	}

	// The upload acks with what IT finalized: the objects it wrote, and
	// the sizes it was handed at claim time.
	finalized := claimed
	finalized.Files = []TaskFile{{
		Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 10,
		AllocatedBytes: -1,
		Object:         "sandboxes/sb-late/gen/rootfs.p0000",
	}}
	if _, err := j.Ack(finalized, "test-bucket", true); err != nil {
		t.Fatal(err)
	}

	pending, err := j.PendingNotifications(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || len(pending[0].Files) != 1 {
		t.Fatalf("notifications = %+v", pending)
	}
	if got := pending[0].Files[0].AllocatedBytes; got != 4096 {
		t.Fatalf("notified allocated = %d, want the size measured during the upload", got)
	}
	if got := pending[0].Files[0].Object; got != "sandboxes/sb-late/gen/rootfs.p0000" {
		t.Fatalf("notified object = %q, want the object the upload wrote", got)
	}
}

// A pathless re-completion keeps the richer manifest already waiting in
// the outbox, but a size that only the later pass measured belongs on it:
// the paths and the measurement come from different passes.
func TestPreservedOutboxManifestAdoptsNewerAllocations(t *testing.T) {
	j, _ := testJournal(t)
	now := time.Unix(900, 0)
	queued := func(alloc int64) Task {
		return Task{
			SandboxID: "sb-keep", Generation: "gen", EnqueuedAt: now,
			Files: []TaskFile{{
				Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 10,
				AllocatedBytes: alloc,
			}},
		}
	}
	const object = "sandboxes/sb-keep/gen/rootfs.p0000"

	// A first completion banks the objects, with nothing measured.
	if err := j.Enqueue(queued(-1)); err != nil {
		t.Fatal(err)
	}
	first, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}
	first.Files = []TaskFile{{Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 10, AllocatedBytes: -1, Object: object}}
	if _, err := j.Ack(first, "test-bucket", true); err != nil {
		t.Fatal(err)
	}

	// An unchanged re-pause measures the artifact, and its manifest create
	// dedupes, so its own completion carries no paths.
	if err := j.Enqueue(queued(4096)); err != nil {
		t.Fatal(err)
	}
	second, ok, err := j.Next(now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("second claim = %v (%v)", ok, err)
	}
	if _, err := j.Ack(second, "test-bucket", true); err != nil {
		t.Fatal(err)
	}

	pending, err := j.PendingNotifications(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || len(pending[0].Files) != 1 {
		t.Fatalf("notifications = %+v", pending)
	}
	if got := pending[0].Files[0].Object; got != object {
		t.Fatalf("object = %q, want the path the first completion banked", got)
	}
	if got := pending[0].Files[0].AllocatedBytes; got != 4096 {
		t.Fatalf("allocated = %d, want the size the later pass measured", got)
	}
}

// Once a lease has run out the task belongs to whoever claims it next,
// even if nobody has yet and the old worker still holds the token:
// reviving it would postpone by another full lease the recovery that the
// expiry exists to allow.
func TestRenewClaimRefusesAnExpiredLease(t *testing.T) {
	j, _ := testJournal(t)
	now := time.Unix(2000, 0)
	task := Task{SandboxID: "sb-wedged", Generation: "gen", EnqueuedAt: now,
		Files: []TaskFile{{Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 1}}}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := j.Next(now)
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}

	// The worker wakes past its lease, before any other drain worker has
	// looked: the token still matches, and that is not enough.
	if j.RenewClaim(claimed, now.Add(claimTTL+time.Minute)) {
		t.Fatal("an expired lease was revived by the worker still holding its token")
	}
	if _, ok, err := j.Next(now.Add(claimTTL + 2*time.Minute)); err != nil || !ok {
		t.Fatalf("the task was not claimable after its lease expired: %v (%v)", ok, err)
	}
}

// A fully sparse artifact measures zero legitimately. Since a
// generation's identity covers apparent content and not physical layout,
// the same generation can be re-enqueued from a file laid out with
// allocated zero-filled extents — and that footprint belongs to the other
// layout, not to the paths this row keeps.
func TestMergeAllocationsKeepsARealZero(t *testing.T) {
	queued := []TaskFile{
		{Name: "sparse.ext4", AllocatedBytes: 0},
		{Name: "unmeasured.ext4", AllocatedBytes: -1},
	}
	incoming := []TaskFile{
		{Name: "sparse.ext4", AllocatedBytes: 4 << 20},
		{Name: "unmeasured.ext4", AllocatedBytes: 8192},
	}
	if !mergeAllocations(queued, incoming) {
		t.Fatal("the missing measurement was not adopted")
	}
	if queued[0].AllocatedBytes != 0 {
		t.Fatalf("a measured zero became %d, taking another layout's footprint", queued[0].AllocatedBytes)
	}
	if queued[1].AllocatedBytes != 8192 {
		t.Fatalf("the missing measurement = %d, want the incoming one", queued[1].AllocatedBytes)
	}
}

// A verification record is the only proof a write-only host has that an
// object already in the bucket holds the bytes a manifest claims. Expire
// one whose generation is still queued and that generation can never be
// completed: every retry meets its own objects as a dedupe nothing can
// vouch for, and abandons.
func TestPruneKeepsProofWhileItsGenerationIsQueued(t *testing.T) {
	j, _ := testJournal(t)
	stale := time.Now().Add(-15 * 24 * time.Hour)

	// Still queued, and deliberately less urgent so the ack below does not
	// claim it out of the queue.
	waiting := Task{
		SandboxID: "sb-waiting", Generation: "gen-waiting", EnqueuedAt: stale,
		Priority: PriorityCheckpoint,
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/disk", SHA256: "d", Size: 1}},
	}
	if err := j.Enqueue(waiting); err != nil {
		t.Fatal(err)
	}

	const (
		queuedProof  = "test-bucket\x00sandboxes/sb-waiting/gen-waiting/rootfs.ext4.p0000"
		settledProof = "test-bucket\x00sandboxes/sb-settled/gen-settled/rootfs.ext4.p0000"
		sharedProof  = "test-bucket\x00bases/" + "0000000000000000000000000000000000000000000000000000000000000000" + ".p0000"
	)
	for _, object := range []string{queuedProof, settledProof, sharedProof} {
		if err := j.RecordVerification(waiting, object, stale); err != nil {
			t.Fatal(err)
		}
	}

	// Any ack runs the bounded prune; this one is more urgent, so Next
	// takes it rather than the record under test.
	driver := Task{
		SandboxID: "sb-driver", Generation: "gen-driver", EnqueuedAt: time.Now(),
		Priority: PriorityPause,
		Files:    []TaskFile{{Name: "rootfs.ext4", Path: "/disk", SHA256: "d2", Size: 1}},
	}
	if err := j.Enqueue(driver); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := j.Next(time.Now())
	if err != nil || !ok {
		t.Fatalf("claim = %v (%v)", ok, err)
	}
	if claimed.SandboxID != driver.SandboxID {
		t.Fatalf("claimed %s, want the driver so the queued record stays queued", claimed.SandboxID)
	}
	if _, err := j.Ack(claimed, "test-bucket", false); err != nil {
		t.Fatal(err)
	}

	// Asked as of the moment it was recorded, so the answer is presence
	// rather than freshness.
	for _, tc := range []struct {
		name   string
		object string
		want   bool
	}{
		{"a queued generation keeps its proof", queuedProof, true},
		{"a settled generation's proof expires", settledProof, false},
		{"a shared base's history is only a shortcut", sharedProof, false},
	} {
		got, err := j.WasVerified(tc.object, stale)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%s: present = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An unvouchable generation cannot be completed by any later attempt, so
// it must stop being offered: otherwise every sweep re-enqueues work that
// abandons, which is what left a host retrying 25 template generations
// every five minutes indefinitely.
func TestEnqueueDeclinesAnUnvouchableGeneration(t *testing.T) {
	j, _ := testJournal(t)
	j.SetScope("test-bucket")
	now := time.Unix(4000, 0)
	stuck := Task{
		TemplateID: "tpl-a", BuildID: "build-a", Generation: "gen-stuck", EnqueuedAt: now,
		Priority: PriorityCheckpoint,
		Files:    []TaskFile{{Name: "mem.snap", Path: "/mem", SHA256: "m", Size: 1}},
	}

	if err := j.MarkUnvouchable("test-bucket", stuck, now); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(stuck); err != nil {
		t.Fatal(err)
	}
	if counts, err := j.Pending(); err != nil {
		t.Fatal(err)
	} else if counts[PriorityCheckpoint] != 0 {
		t.Fatalf("pending = %v, want the unvouchable generation declined", counts)
	}

	// A rebuild changes the artifacts, so it is a different generation and
	// must be accepted.
	rebuilt := stuck
	rebuilt.Generation = "gen-rebuilt"
	rebuilt.Files = []TaskFile{{Name: "mem.snap", Path: "/mem", SHA256: "m2", Size: 1}}
	if err := j.Enqueue(rebuilt); err != nil {
		t.Fatal(err)
	}
	if counts, err := j.Pending(); err != nil {
		t.Fatal(err)
	} else if counts[PriorityCheckpoint] != 1 {
		t.Fatalf("pending = %v, want the rebuilt generation queued", counts)
	}

	// Another bucket has not met those objects, so the mark does not carry.
	other, _ := testJournal(t)
	other.SetScope("other-bucket")
	if err := other.Enqueue(stuck); err != nil {
		t.Fatal(err)
	}
	if counts, err := other.Pending(); err != nil {
		t.Fatal(err)
	} else if counts[PriorityCheckpoint] != 1 {
		t.Fatalf("other bucket pending = %v, want the generation attempted there", counts)
	}
}
