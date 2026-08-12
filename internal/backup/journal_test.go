package backup

import (
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
		got, ok, err := j.Next(time.Unix(20, 0))
		if err != nil || !ok {
			t.Fatalf("Next: %v %v", ok, err)
		}
		if got.Priority != PriorityPause {
			t.Fatalf("row priority = %d, want the promotion kept", got.Priority)
		}
		if verified, err := j.WasVerified("obj-1", time.Unix(20, 0)); err != nil || !verified {
			t.Fatalf("WasVerified = %v (err %v), want the history recorded", verified, err)
		}
	})
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
	if _, err := j.Ack(task, "bucket", true); err != nil {
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

// OwnerCovered ties backfill-ledger trust to coverage NEWER than the
// mark: an older generation's completion must not mask an abandoned
// backfill upload, while any pending row or a completion after the mint
// keeps the skip.
func TestOwnerCoveredHonorsSinceBound(t *testing.T) {
	j, _ := testJournal(t)
	markTime := time.Now()

	// A generation completed BEFORE the mark does not cover.
	old := Task{SandboxID: "sb", Generation: "gen-old", EnqueuedAt: time.Unix(1, 0)}
	if err := j.Enqueue(old); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Ack(old, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if cov, err := j.OwnerCovered("bucket", "sb", markTime.Add(time.Minute)); err != nil || cov {
		t.Fatalf("covered by pre-mark completion = %v err=%v, want false", cov, err)
	}

	// A pending row covers regardless of age.
	pendingTask := Task{SandboxID: "sb", Generation: "gen-pending", EnqueuedAt: time.Unix(2, 0)}
	if err := j.Enqueue(pendingTask); err != nil {
		t.Fatal(err)
	}
	if cov, err := j.OwnerCovered("bucket", "sb", markTime.Add(time.Minute)); err != nil || !cov {
		t.Fatalf("covered with pending row = %v err=%v, want true", cov, err)
	}

	// A completion at/after the mark covers.
	if _, err := j.Ack(pendingTask, "bucket", false); err != nil {
		t.Fatal(err)
	}
	if cov, err := j.OwnerCovered("bucket", "sb", markTime); err != nil || !cov {
		t.Fatalf("covered by post-mark completion = %v err=%v, want true", cov, err)
	}

	// Scope isolation: another bucket's completions say nothing here.
	if cov, err := j.OwnerCovered("other-bucket", "sb", markTime); err != nil || cov {
		t.Fatalf("cross-bucket covered = %v err=%v, want false", cov, err)
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
