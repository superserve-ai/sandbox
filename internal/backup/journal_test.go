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
